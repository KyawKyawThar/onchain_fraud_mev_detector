//! The cascade engine (§16.2, Sprint 16 task 2): recomputes health factors off
//! [`crate::position::PositionTracker::current`] on every genuine
//! oracle/mark-price update ([`crate::price_source::PriceTick`]), and reports
//! every open position whose [`distance_band`] has worsened since it was last
//! observed — the caller (`main.rs`) turns each into a
//! `LiquidationRiskPredicted` event.
//!
//! Pure and I/O-free (mirrors [`crate::predict`]): [`CascadeEngine::on_price_tick`]
//! is a plain state fold over a [`PositionState`] snapshot and a price cache,
//! so the whole worsening/recovery/no-op state machine is unit-tested without
//! a live node or Kafka.
//!
//! # Valuation reuses `detector_api`'s enrichment idioms
//!
//! [`Position`]'s collateral/debt are raw base units (task 1's module docs);
//! turning them into USD reuses [`TokenMeta::to_whole`] and the same
//! finite-check discipline [`Enrichment::usd_value`](detector_api::Enrichment::usd_value)
//! applies, rather than re-deriving the decimal-scaling math a second time.
//!
//! # Direction: worsening only
//!
//! [`CascadeEngine`] remembers the last [`Severity`] band observed for every
//! `(protocol, account)` and reports a position only when its *new* band
//! outranks that memory — a recovery back to a safer band updates the memory
//! silently. This mirrors the rest of this pipeline's one-directional
//! forecast semantics (a `PredictedAlert` is never "un-predicted"): a risk
//! warning's job is to warn, not to announce an all-clear.

use std::collections::{BTreeMap, HashMap};

use alloy_primitives::{Address, U256};
use detector_api::{TokenMeta, UsdPrice};
use events::primitives::Severity;

use crate::position::{Position, PositionKey, PositionState};
use crate::price_source::PriceTick;

/// Default risk-band boundaries, in percentage points of [`RiskAssessment::distance_pct`]
/// — retuned per deployment via [`crate::config::CascadeConfig`], never
/// re-hardcoded elsewhere (single source of truth, same discipline as
/// `LiquidationThresholds::default`).
pub const DEFAULT_WARNING_DISTANCE_PCT: f64 = 15.0;
pub const DEFAULT_DANGER_DISTANCE_PCT: f64 = 5.0;
pub const DEFAULT_CRITICAL_DISTANCE_PCT: f64 = 0.0;

/// A [`RiskThresholds`] construction that doesn't satisfy `warning > danger >
/// critical` (all finite) — see [`RiskThresholds::try_new`].
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
#[error(
    "risk thresholds must be finite and strictly descending \
     (warning {warning} > danger {danger} > critical {critical})"
)]
pub struct InvalidRiskThresholds {
    pub warning: f64,
    pub danger: f64,
    pub critical: f64,
}

/// The configurable band boundaries [`distance_band`] classifies against (the
/// task's "configurable band"). Private fields + a validating constructor —
/// same discipline as `server::screen::Thresholds` — because [`distance_band`]'s
/// cascading `if distance_pct <= X` chain silently relies on the three bounds
/// being strictly descending: an inverted or equal pair (a plausible env-var
/// typo, since these are independently configurable — see
/// `crate::config::CascadeConfig`) wouldn't error, it would just misclassify
/// severities at boot with nothing to catch it. A naked `pub f64` triple made
/// that invariant representable but not enforced; this makes it
/// unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RiskThresholds {
    warning_distance_pct: f64,
    danger_distance_pct: f64,
    critical_distance_pct: f64,
}

impl RiskThresholds {
    /// Validate and construct a threshold triple: every bound finite, and
    /// strictly `warning > danger > critical` (the order [`distance_band`]'s
    /// classification chain assumes).
    pub fn try_new(
        warning_distance_pct: f64,
        danger_distance_pct: f64,
        critical_distance_pct: f64,
    ) -> Result<Self, InvalidRiskThresholds> {
        let all_finite = warning_distance_pct.is_finite()
            && danger_distance_pct.is_finite()
            && critical_distance_pct.is_finite();
        let descending = warning_distance_pct > danger_distance_pct
            && danger_distance_pct > critical_distance_pct;
        if !all_finite || !descending {
            return Err(InvalidRiskThresholds {
                warning: warning_distance_pct,
                danger: danger_distance_pct,
                critical: critical_distance_pct,
            });
        }
        Ok(Self {
            warning_distance_pct,
            danger_distance_pct,
            critical_distance_pct,
        })
    }

    pub fn warning_distance_pct(&self) -> f64 {
        self.warning_distance_pct
    }

    pub fn danger_distance_pct(&self) -> f64 {
        self.danger_distance_pct
    }

    pub fn critical_distance_pct(&self) -> f64 {
        self.critical_distance_pct
    }
}

impl Default for RiskThresholds {
    fn default() -> Self {
        Self::try_new(
            DEFAULT_WARNING_DISTANCE_PCT,
            DEFAULT_DANGER_DISTANCE_PCT,
            DEFAULT_CRITICAL_DISTANCE_PCT,
        )
        .expect("the built-in default risk thresholds are, themselves, valid")
    }
}

/// Band `distance_pct` falls into. `Low` means "not risky enough to report" —
/// [`CascadeEngine`] never includes a `Low`-banded position in its worsening
/// list.
pub fn distance_band(distance_pct: f64, thresholds: &RiskThresholds) -> Severity {
    if distance_pct <= thresholds.critical_distance_pct() {
        Severity::Critical
    } else if distance_pct <= thresholds.danger_distance_pct() {
        Severity::High
    } else if distance_pct <= thresholds.warning_distance_pct() {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// One position's risk, valued at the [`CascadeEngine`]'s current price cache.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RiskAssessment {
    /// Collateral (weighted by the position's blended liquidation threshold)
    /// over debt — below `1.0` is liquidatable.
    pub health_factor: f64,
    /// `(health_factor - 1.0) * 100.0`; negative means already liquidatable.
    pub distance_pct: f64,
    pub severity: Severity,
}

/// Value `position` at `prices`/`assets` and band the result, or `None` if it
/// can't be forecast: any nonzero-balance asset lacking metadata or a price
/// (conservative skip — the same convention
/// [`Enrichment::usd_value`](detector_api::Enrichment::usd_value) uses for a
/// missing price), zero debt (nothing to forecast — no different from
/// [`crate::predict::predict`]'s "`None` means nothing to forecast"
/// convention), or a non-finite result.
pub fn assess(
    position: &Position,
    assets: &HashMap<Address, TokenMeta>,
    prices: &HashMap<Address, UsdPrice>,
    thresholds: &RiskThresholds,
) -> Option<RiskAssessment> {
    let collateral_usd = valued_total(&position.collateral, assets, prices)?;
    let debt_usd = valued_total(&position.debt, assets, prices)?;
    if debt_usd <= 0.0 {
        return None;
    }

    let threshold_ratio = f64::from(position.liquidation_threshold.get()) / 10_000.0;
    let health_factor = (collateral_usd * threshold_ratio) / debt_usd;
    let distance_pct = (health_factor - 1.0) * 100.0;
    if !health_factor.is_finite() || !distance_pct.is_finite() {
        return None;
    }

    Some(RiskAssessment {
        health_factor,
        distance_pct,
        severity: distance_band(distance_pct, thresholds),
    })
}

/// Sum `TokenMeta::to_whole(amount) * price.get()` over every nonzero entry in
/// `book`. `None` if any nonzero-balance asset can't be valued.
///
/// `pub(crate)` — [`crate::reflexivity`]'s cascade-size figure
/// (`aggregate_at_risk_usd`) reuses this rather than re-deriving the
/// decimal-scaling/finite-check discipline a second time.
pub(crate) fn valued_total(
    book: &BTreeMap<Address, U256>,
    assets: &HashMap<Address, TokenMeta>,
    prices: &HashMap<Address, UsdPrice>,
) -> Option<f64> {
    let mut total = 0.0;
    for (&asset, &amount) in book {
        if amount.is_zero() {
            continue;
        }
        let meta = assets.get(&asset)?;
        let price = prices.get(&asset)?;
        let value = meta.to_whole(amount) * price.get();
        if !value.is_finite() {
            return None;
        }
        total += value;
    }
    Some(total)
}

/// Does `position` hold a nonzero *or* zero balance of `asset` at all — i.e.
/// would repricing `asset` change this position's valuation? Used to skip
/// positions a price tick can't possibly affect (the common case).
///
/// `pub(crate)` — [`crate::reflexivity`] reuses this to find every position a
/// shocked asset could reprice, the same "who does this asset touch" question
/// this engine already answers on every real tick.
pub(crate) fn touches(position: &Position, asset: Address) -> bool {
    position.collateral.contains_key(&asset) || position.debt.contains_key(&asset)
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Low => 0,
        Severity::Medium => 1,
        Severity::High => 2,
        Severity::Critical => 3,
    }
}

/// The cascade engine's running state: the latest known price per asset, and
/// the last risk band observed per position (module docs — "worsening only").
pub struct CascadeEngine {
    prices: HashMap<Address, UsdPrice>,
    last_severity: HashMap<PositionKey, Severity>,
    thresholds: RiskThresholds,
}

impl CascadeEngine {
    pub fn new(thresholds: RiskThresholds) -> Self {
        Self {
            prices: HashMap::new(),
            last_severity: HashMap::new(),
            thresholds,
        }
    }

    /// The engine's current price cache — every asset priced so far, at its
    /// latest tick. [`crate::reflexivity`]'s walk reads this rather than
    /// keeping a second cache in sync with this one.
    pub fn prices(&self) -> &HashMap<Address, UsdPrice> {
        &self.prices
    }

    /// Fold one genuine price update in, recompute every open position that
    /// touches the updated asset, and return the ones whose band just
    /// worsened past its last-observed band — the caller emits a
    /// `LiquidationRiskPredicted` for each. Always updates the last-observed
    /// band regardless of direction, so a later re-worsening from a dip is
    /// still a fresh crossing.
    pub fn on_price_tick(
        &mut self,
        tick: PriceTick,
        assets: &HashMap<Address, TokenMeta>,
        positions: &PositionState,
    ) -> Vec<(PositionKey, RiskAssessment)> {
        self.prices.insert(tick.asset, tick.price);

        let mut worsened = Vec::new();
        for (&key, position) in positions.iter() {
            if !touches(position, tick.asset) {
                continue;
            }
            let Some(assessment) = assess(position, assets, &self.prices, &self.thresholds) else {
                continue;
            };

            let previous_severity = self
                .last_severity
                .get(&key)
                .copied()
                .unwrap_or(Severity::Low);
            if severity_rank(assessment.severity) > severity_rank(previous_severity) {
                worsened.push((key, assessment));
            }
            self.last_severity.insert(key, assessment.severity);
        }

        // `PositionState::apply` (task 1) prunes a position the moment it
        // fully closes, but that closed key simply stops appearing in the
        // loop above — nothing otherwise removes its `last_severity` entry.
        // Left unpruned, this map would grow by one permanent entry for
        // every `(protocol, account)` that ever crossed a worsening band,
        // for the life of the process, even after the position closes.
        // Reconciling against the currently-open key set on every tick keeps
        // it bounded to "currently open positions with an observed band".
        self.last_severity
            .retain(|key, _| positions.get(key).is_some());

        worsened
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::position::{LiquidationThresholds, Protocol};
    use detector_api::Bps;

    fn addr(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }

    const ACCOUNT: u8 = 0x11;
    const WETH: u8 = 0xE0;
    const USDC: u8 = 0xC0;

    fn key() -> PositionKey {
        PositionKey {
            protocol: Protocol::Aave,
            account: addr(ACCOUNT),
        }
    }

    /// A position with `collateral_units` WETH (18 decimals) and
    /// `debt_units` USDC (6 decimals), at an 80% liquidation threshold.
    fn position(collateral_units: u64, debt_units: u64) -> Position {
        let mut collateral = BTreeMap::new();
        collateral.insert(addr(WETH), U256::from(collateral_units));
        let mut debt = BTreeMap::new();
        debt.insert(addr(USDC), U256::from(debt_units));
        Position {
            collateral,
            debt,
            liquidation_threshold: Bps::new(8_000),
        }
    }

    fn assets() -> HashMap<Address, TokenMeta> {
        let mut map = HashMap::new();
        map.insert(addr(WETH), TokenMeta::new(addr(WETH), None, 18));
        map.insert(addr(USDC), TokenMeta::new(addr(USDC), None, 6));
        map
    }

    fn prices(weth_usd: f64, usdc_usd: f64) -> HashMap<Address, UsdPrice> {
        let mut map = HashMap::new();
        map.insert(addr(WETH), UsdPrice::try_new(weth_usd).unwrap());
        map.insert(addr(USDC), UsdPrice::try_new(usdc_usd).unwrap());
        map
    }

    fn positions_with(position: Position) -> PositionState {
        let thresholds = LiquidationThresholds::default();
        let mut state = PositionState::default();
        state.apply(
            &crate::lending_decode::LendingEvent::Supply {
                protocol: Protocol::Aave,
                account: addr(ACCOUNT),
                asset: addr(WETH),
                amount: position.collateral[&addr(WETH)],
            },
            &thresholds,
        );
        state.apply(
            &crate::lending_decode::LendingEvent::Borrow {
                protocol: Protocol::Aave,
                account: addr(ACCOUNT),
                asset: addr(USDC),
                amount: position.debt[&addr(USDC)],
            },
            &thresholds,
        );
        state
    }

    #[test]
    fn assess_computes_health_factor_and_distance() {
        // 2 WETH @ $2,000 = $4,000 collateral, 80% threshold -> $3,200 weighted.
        // 3,000 USDC @ $1 debt. HF = 3200 / 3000 ≈ 1.0667, distance ≈ 6.67%
        // -> between the 5% danger and 15% warning boundary: Medium.
        let position = position(2_000_000_000_000_000_000, 3_000_000_000);
        let assessment = assess(
            &position,
            &assets(),
            &prices(2_000.0, 1.0),
            &RiskThresholds::default(),
        )
        .expect("valued and in debt");

        assert!((assessment.health_factor - 1.0666_6666).abs() < 1e-4);
        assert!((assessment.distance_pct - 6.666_6).abs() < 1e-2);
        assert_eq!(assessment.severity, Severity::Medium);
    }

    #[test]
    fn assess_is_none_without_debt() {
        let position = position(2_000_000_000_000_000_000, 0);
        assert!(assess(
            &position,
            &assets(),
            &prices(2_000.0, 1.0),
            &RiskThresholds::default()
        )
        .is_none());
    }

    #[test]
    fn assess_is_none_when_an_asset_has_no_price() {
        let position = position(2_000_000_000_000_000_000, 3_000_000_000);
        let mut prices = prices(2_000.0, 1.0);
        prices.remove(&addr(WETH));
        assert!(assess(&position, &assets(), &prices, &RiskThresholds::default()).is_none());
    }

    #[test]
    fn assess_is_none_when_an_asset_has_no_metadata() {
        let position = position(2_000_000_000_000_000_000, 3_000_000_000);
        let mut assets = assets();
        assets.remove(&addr(USDC));
        assert!(assess(
            &position,
            &assets,
            &prices(2_000.0, 1.0),
            &RiskThresholds::default()
        )
        .is_none());
    }

    #[test]
    fn distance_band_boundaries() {
        let thresholds = RiskThresholds::default();
        assert_eq!(distance_band(50.0, &thresholds), Severity::Low);
        assert_eq!(distance_band(15.0, &thresholds), Severity::Medium);
        assert_eq!(distance_band(5.0, &thresholds), Severity::High);
        assert_eq!(distance_band(0.0, &thresholds), Severity::Critical);
        assert_eq!(distance_band(-10.0, &thresholds), Severity::Critical);
    }

    #[test]
    fn try_new_accepts_a_strictly_descending_finite_triple() {
        let t = RiskThresholds::try_new(15.0, 5.0, 0.0).unwrap();
        assert_eq!(t.warning_distance_pct(), 15.0);
        assert_eq!(t.danger_distance_pct(), 5.0);
        assert_eq!(t.critical_distance_pct(), 0.0);
    }

    #[test]
    fn try_new_rejects_a_non_descending_triple() {
        // Inverted (an env-var swap): danger above warning.
        assert!(RiskThresholds::try_new(5.0, 15.0, 0.0).is_err());
        // Equal bounds: the middle band would be unreachable.
        assert!(RiskThresholds::try_new(15.0, 15.0, 0.0).is_err());
        assert!(RiskThresholds::try_new(15.0, 5.0, 5.0).is_err());
    }

    #[test]
    fn try_new_rejects_a_non_finite_bound() {
        assert!(RiskThresholds::try_new(f64::NAN, 5.0, 0.0).is_err());
        assert!(RiskThresholds::try_new(f64::INFINITY, 5.0, 0.0).is_err());
    }

    #[test]
    fn the_built_in_default_is_itself_valid() {
        // Guards `Default`'s internal `.expect(...)` — if the DEFAULT_* consts
        // above ever drift out of descending order, this fails loudly here
        // instead of panicking at first boot.
        let _ = RiskThresholds::default();
    }

    /// 1 WETH collateral, 700 USDC debt, 80% threshold: at $2,000/WETH,
    /// HF = 1,600/700 ≈ 2.29 (Low/safe). At $700/WETH, HF = 560/700 = 0.8,
    /// distance = -20% -> Critical (already liquidatable).
    fn safe_tick() -> PriceTick {
        PriceTick {
            asset: addr(WETH),
            price: UsdPrice::try_new(2_000.0).unwrap(),
            updated_at: U256::from(1u64),
        }
    }
    fn crash_tick(updated_at: u64) -> PriceTick {
        PriceTick {
            asset: addr(WETH),
            price: UsdPrice::try_new(700.0).unwrap(),
            updated_at: U256::from(updated_at),
        }
    }
    /// Seeds the engine's USDC price so a debt-side valuation is possible —
    /// `CascadeEngine` only caches prices it's been ticked for, and these
    /// tests only ever *reprice* WETH, so USDC's $1 price must be fed once up
    /// front (a real deployment would tick it from its own feed).
    fn usdc_seed_tick() -> PriceTick {
        PriceTick {
            asset: addr(USDC),
            price: UsdPrice::try_new(1.0).unwrap(),
            updated_at: U256::from(1u64),
        }
    }

    #[test]
    fn cascade_engine_reports_only_a_worsening_crossing() {
        let positions = positions_with(position(1_000_000_000_000_000_000, 700_000_000));
        let assets = assets();
        let mut engine = CascadeEngine::new(RiskThresholds::default());

        engine.on_price_tick(usdc_seed_tick(), &assets, &positions);
        assert!(engine
            .on_price_tick(safe_tick(), &assets, &positions)
            .is_empty());

        let worsened = engine.on_price_tick(crash_tick(2), &assets, &positions);
        assert_eq!(worsened.len(), 1);
        assert_eq!(worsened[0].0, key());
        assert_eq!(worsened[0].1.severity, Severity::Critical);
    }

    #[test]
    fn cascade_engine_stays_silent_on_recovery_and_same_band_re_ticks() {
        let positions = positions_with(position(1_000_000_000_000_000_000, 700_000_000));
        let assets = assets();
        let mut engine = CascadeEngine::new(RiskThresholds::default());

        engine.on_price_tick(usdc_seed_tick(), &assets, &positions);
        assert_eq!(
            engine
                .on_price_tick(crash_tick(1), &assets, &positions)
                .len(),
            1
        );

        // Another tick landing in the same Critical band: silent (not a
        // higher rank than the last-observed band).
        assert!(engine
            .on_price_tick(crash_tick(2), &assets, &positions)
            .is_empty());

        // Recovery back up: silent, but the last-observed band is now Low.
        let recover_tick = PriceTick {
            asset: addr(WETH),
            price: UsdPrice::try_new(2_000.0).unwrap(),
            updated_at: U256::from(3u64),
        };
        assert!(engine
            .on_price_tick(recover_tick, &assets, &positions)
            .is_empty());
    }

    #[test]
    fn cascade_engine_re_reports_a_worsening_that_follows_a_recovery() {
        // The module docs' claim: a later re-worsening from a dip is still a
        // fresh crossing, even though it lands in the same band as before.
        let positions = positions_with(position(1_000_000_000_000_000_000, 700_000_000));
        let assets = assets();
        let mut engine = CascadeEngine::new(RiskThresholds::default());

        engine.on_price_tick(usdc_seed_tick(), &assets, &positions);
        assert_eq!(
            engine
                .on_price_tick(crash_tick(1), &assets, &positions)
                .len(),
            1
        );

        let recover_tick = PriceTick {
            asset: addr(WETH),
            price: UsdPrice::try_new(2_000.0).unwrap(),
            updated_at: U256::from(2u64),
        };
        assert!(engine
            .on_price_tick(recover_tick, &assets, &positions)
            .is_empty());

        let worsened = engine.on_price_tick(crash_tick(3), &assets, &positions);
        assert_eq!(worsened.len(), 1);
        assert_eq!(worsened[0].1.severity, Severity::Critical);
    }

    #[test]
    fn closing_a_position_prunes_its_last_observed_severity_from_memory() {
        // Open, worsen (so a `last_severity` entry is recorded), then fully
        // close the position — `PositionState::apply` prunes the closed
        // entry out of `positions` (task 1), and the next tick must reconcile
        // `CascadeEngine`'s own memory against that, not carry the entry
        // forever.
        let thresholds = LiquidationThresholds::default();
        let mut positions = positions_with(position(1_000_000_000_000_000_000, 700_000_000));
        let assets = assets();
        let mut engine = CascadeEngine::new(RiskThresholds::default());

        engine.on_price_tick(usdc_seed_tick(), &assets, &positions);
        assert_eq!(
            engine
                .on_price_tick(crash_tick(1), &assets, &positions)
                .len(),
            1,
            "the worsening crossing recorded a last_severity entry"
        );
        assert_eq!(engine.last_severity.len(), 1);

        // Fully close the position: repay all debt, withdraw all collateral.
        positions.apply(
            &crate::lending_decode::LendingEvent::Repay {
                protocol: Protocol::Aave,
                account: addr(ACCOUNT),
                asset: addr(USDC),
                amount: U256::from(700_000_000u64),
            },
            &thresholds,
        );
        positions.apply(
            &crate::lending_decode::LendingEvent::Withdraw {
                protocol: Protocol::Aave,
                account: addr(ACCOUNT),
                asset: addr(WETH),
                amount: U256::from(1_000_000_000_000_000_000u64),
            },
            &thresholds,
        );
        assert!(positions.get(&key()).is_none(), "position fully closed");

        // Any further tick reconciles `last_severity` against the now-empty
        // position set, regardless of which asset it's for.
        engine.on_price_tick(usdc_seed_tick(), &assets, &positions);
        assert!(
            engine.last_severity.is_empty(),
            "the closed position's memory must not persist forever"
        );
    }

    #[test]
    fn cascade_engine_ignores_a_price_tick_for_an_asset_the_position_never_touches() {
        let position = position(1_000_000_000_000_000_000, 700_000_000);
        let positions = positions_with(position);
        let assets = assets();
        let mut engine = CascadeEngine::new(RiskThresholds::default());

        let unrelated_tick = PriceTick {
            asset: addr(0xAA),
            price: UsdPrice::try_new(1.0).unwrap(),
            updated_at: U256::from(1u64),
        };
        assert!(engine
            .on_price_tick(unrelated_tick, &assets, &positions)
            .is_empty());
    }
}
