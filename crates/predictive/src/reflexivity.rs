//! The reflexivity model (§16.3, Sprint 16 task 3): [`detect_cascade`] finds
//! `LiquidationCascadeWarned` — liquidating the currently at-risk positions
//! would itself move a mark price far enough (forced collateral sales) to
//! pull *more* positions underwater.
//!
//! # The position graph, and its hub-node cap (§8.2)
//!
//! There is no explicit position-graph data structure (task 1's module docs).
//! Two positions are graph-neighbors here iff one holds, as collateral, an
//! asset the other's liquidation would force-sell — so the walk's frontier is
//! kept in **assets**, not positions: at each hop, every collateral asset the
//! previous hop's newly-liquidatable positions hold becomes a shock source for
//! the next hop, mirroring [`crate::cascade::CascadeEngine::on_price_tick`]'s
//! own "which positions does this asset touch" question one level deeper.
//!
//! §8.2's hub-node discipline carries over directly: an asset held as
//! collateral by more open positions than [`ReflexivityLimits::degree_cap`] is
//! an infrastructure endpoint for this walk (the WETH-style "everyone holds
//! it" asset), not a shock source — modeling *its* price impact from one
//! cascade would be exactly the "unbounded 3-hop graph through a CEX hot
//! wallet" §8.2 warns against. The walk marks it and moves on rather than
//! crossing it, the same choice [`intelligence::graph::entity_graph`] makes for
//! a hub address.
//!
//! This module does *not* share a generic walk primitive with
//! `intelligence::graph::entity_graph`, even though both are level-synchronous,
//! degree/hop-bounded BFS. The two admit-a-neighbor decisions are shaped too
//! differently to unify honestly: `entity_graph` admits any in-budget neighbor
//! unconditionally (pure reachability), while this walk only admits a position
//! whose *reassessed risk* crosses a band under a mutated price overlay — that
//! logic can't be hoisted into a generic callback without the "shared"
//! abstraction becoming a thin wrapper around 100% caller-supplied behavior.
//! Forcing it would trade one honest duplication (a handful of loop lines) for
//! a worse one (a generic type that doesn't actually simplify either call
//! site). The two walks already share what's real: field-naming convention
//! (`degree_cap`/`max_hops` ~ `degree_cap`/`max_depth`) and this doc
//! cross-reference. Revisit if a third bounded-degree walk shows up.
//!
//! # The price-impact model: a stepped stress test, not a slippage curve
//!
//! Neither this crate nor its inputs have any notion of an asset's market
//! depth (an AMM pool's reserves, an order book) — [`assess`] itself only ever
//! reasons about *reference* prices (§6's enrichment discipline). Modeling a
//! real slippage curve is future work, so the model is a pluggable seam
//! ([`PriceImpactModel`]) rather than logic inlined in the walk — swapping in a
//! real depth-aware model later means a new trait impl, not a diff to
//! [`detect_cascade`]. The only implementation today, [`SteppedImpactModel`],
//! is a deliberately simple, honestly-labeled approximation (the same
//! "accepted first-cut" discipline task 1's Compound cToken netting used): an
//! asset first reached at hop `n` is assumed pushed down by
//! `bps_per_hop * (n + 1)` basis points from its real price.
//!
//! # Only reflexivity, never a bare risk snapshot
//!
//! [`detect_cascade`]'s [`CascadeOutcome::warning`] is `None` unless the walk
//! actually recruits at least one position *beyond* the naive at-risk set
//! (every open position already at [`Severity::High`]/[`Severity::Critical`]
//! at real prices) — a risk desk already gets that plain snapshot from
//! [`LiquidationRiskPredicted`] per worsening position; this event's entire
//! reason to exist is the knock-on effect ("cascade = reflexivity", §16.3).
//! [`CascadeOutcome::hub_capped`] is reported regardless, though: a walk that
//! gave up at a degree-capped hub and found nothing is exactly the case an
//! operator most needs visibility into (a possible false negative from too
//! tight a `degree_cap`), so it can't be allowed to hide inside a `None`.

use std::collections::{HashMap, HashSet};

use alloy_primitives::Address;
use detector_api::{TokenMeta, UsdPrice};
use events::primitives::{AccountAddress, Severity, UsdAmount};

use crate::cascade::{assess, touches, valued_total, RiskThresholds};
use crate::position::{PositionKey, PositionState};
use crate::price_source::PriceTick;

/// Bounds one reflexivity walk respects — the position-graph mirror of
/// [`intelligence::graph::GraphLimits`] (§8.2): a per-asset degree cap (the
/// hub-node cap, see module docs) and a hop ceiling bounding
/// `reflexive_depth`. The price-impact tunable lives on [`SteppedImpactModel`]
/// instead — it's a property of *how* a hop shocks a price, not of the walk's
/// shape, so it varies independently as [`PriceImpactModel`] gains
/// implementations.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReflexivityLimits {
    /// An asset held as collateral by more open positions than this is a hub
    /// — the walk stops propagating a shock through it rather than crossing
    /// it (§8.2).
    pub degree_cap: u32,
    /// How many hops out from the seed at-risk set the walk can reach —
    /// `reflexive_depth`'s ceiling.
    pub max_depth: u32,
}

impl Default for ReflexivityLimits {
    fn default() -> Self {
        Self {
            degree_cap: 50,
            max_depth: 3,
        }
    }
}

/// How a reflexive hop's forced selling is assumed to move an asset's real
/// price — the walk's one pluggable seam (module docs). A real
/// AMM-depth/order-book model only needs to implement this trait; it never
/// touches [`detect_cascade`] itself.
pub trait PriceImpactModel {
    /// `base`'s hypothetical price after forced selling at reflexive hop
    /// `hop_index` (0-based: the first hop an asset is reached at).
    fn shocked_price(&self, base: UsdPrice, hop_index: u32) -> UsdPrice;
}

/// The default, explicitly-approximate [`PriceImpactModel`] (module docs'
/// "stepped stress test, not a slippage curve"): a flat `bps_per_hop`
/// compounding step per hop, floored at a full wipeout.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SteppedImpactModel {
    pub bps_per_hop: u32,
}

impl Default for SteppedImpactModel {
    fn default() -> Self {
        Self { bps_per_hop: 500 }
    }
}

impl PriceImpactModel for SteppedImpactModel {
    fn shocked_price(&self, base: UsdPrice, hop_index: u32) -> UsdPrice {
        let impact_bps = self.bps_per_hop.saturating_mul(hop_index + 1);
        let factor = (1.0 - f64::from(impact_bps) / 10_000.0).max(0.0);
        UsdPrice::try_new(base.get() * factor).expect(
            "a finite non-negative price times a factor in [0, 1] stays finite and non-negative",
        )
    }
}

/// A genuine reflexive cascade, seeded from a real oracle tick. `main.rs`
/// adds the producer-side bookkeeping (`prediction_id`/`confidence`/
/// `provisional`, plus [`CascadeOutcome::hub_capped`]) to turn this into the
/// wire `LiquidationCascadeWarned` — mirrors [`crate::cascade::RiskAssessment`]
/// vs. `LiquidationRiskPredicted`.
#[derive(Debug, Clone, PartialEq)]
pub struct CascadeWarning {
    pub trigger_asset: Address,
    pub trigger_price: f64,
    pub reflexive_depth: u32,
    pub accounts: Vec<AccountAddress>,
    pub aggregate_at_risk_usd: UsdAmount,
}

/// Every [`detect_cascade`] call's outcome, including diagnostic detail even
/// when no cascade was found (module docs) — the type
/// [`crate::metrics::record_cascade_walk`] and `main.rs::run_cascade` both
/// read.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CascadeOutcome {
    pub warning: Option<CascadeWarning>,
    /// The walk reached a degree-capped hub asset (§8.2) and stopped
    /// propagating a shock through it *somewhere* during the walk — true
    /// regardless of whether that specific tick ultimately found a cascade.
    pub hub_capped: bool,
}

fn is_at_risk(severity: Severity) -> bool {
    matches!(severity, Severity::High | Severity::Critical)
}

/// Every open position that touches `asset` (collateral or debt) — both this
/// walk's per-asset "degree" (§8.2) and the set to reassess when `asset` is
/// shocked.
fn touching_position_keys(positions: &PositionState, asset: Address) -> Vec<PositionKey> {
    positions
        .iter()
        .filter(|(_, position)| touches(position, asset))
        .map(|(&key, _)| key)
        .collect()
}

/// Walk the position graph out from `trigger` (module docs) and report a
/// [`CascadeOutcome`]. `prices` is the real (unshocked) mark-price cache as of
/// `trigger` — the caller's [`crate::cascade::CascadeEngine::prices`] already
/// includes it.
#[tracing::instrument(
    skip_all,
    fields(trigger_asset = %trigger.asset, trigger_price = trigger.price.get())
)]
pub fn detect_cascade(
    trigger: PriceTick,
    assets: &HashMap<Address, TokenMeta>,
    prices: &HashMap<Address, UsdPrice>,
    positions: &PositionState,
    thresholds: &RiskThresholds,
    limits: &ReflexivityLimits,
    impact_model: &dyn PriceImpactModel,
) -> CascadeOutcome {
    // Seed: every open position already at Danger-or-worse at real prices —
    // the plain at-risk set `LiquidationRiskPredicted` already names.
    let mut at_risk: HashSet<PositionKey> = HashSet::new();
    for (&key, position) in positions.iter() {
        if let Some(assessment) = assess(position, assets, prices, thresholds) {
            if is_at_risk(assessment.severity) {
                at_risk.insert(key);
            }
        }
    }
    let seed_count = at_risk.len();
    let mut hub_capped = false;
    let mut reflexive_depth: u32 = 0;

    if !at_risk.is_empty() {
        // hop 0 frontier: every collateral asset a seed position holds —
        // force-liquidating the seed set force-sells all of it, not just
        // `trigger.asset`.
        let mut known_assets: HashSet<Address> = HashSet::new();
        let mut frontier: Vec<Address> = at_risk
            .iter()
            .filter_map(|key| positions.get(key))
            .flat_map(|position| position.collateral.keys().copied())
            .collect();
        frontier.sort();
        frontier.dedup();
        known_assets.extend(frontier.iter().copied());

        // The overlay this walk reasons against: real prices, progressively
        // overwritten with each shocked asset's hypothetical price as the
        // walk reaches it. One clone up front (bounded by the configured
        // feed count, not open-position count) beats re-merging a `shocked`
        // map into `assess` on every reassessment.
        let mut effective_prices = prices.clone();

        for hop in 0..limits.max_depth {
            if frontier.is_empty() {
                break;
            }
            let mut next: Vec<Address> = Vec::new();
            let mut grew_this_hop = false;

            for asset in &frontier {
                let touching = touching_position_keys(positions, *asset);
                if touching.len() as u32 > limits.degree_cap {
                    // Infrastructure asset (§8.2): a boundary, not a shock
                    // source — its true reflexive fan-out is unmodelable here.
                    hub_capped = true;
                    continue;
                }
                let Some(&base_price) = prices.get(asset) else {
                    continue; // unpriced asset: nothing to shock it with
                };
                effective_prices.insert(*asset, impact_model.shocked_price(base_price, hop));

                for key in touching {
                    if at_risk.contains(&key) {
                        continue;
                    }
                    let Some(position) = positions.get(&key) else {
                        continue;
                    };
                    let Some(assessment) = assess(position, assets, &effective_prices, thresholds)
                    else {
                        continue;
                    };
                    if !is_at_risk(assessment.severity) {
                        continue;
                    }
                    at_risk.insert(key);
                    grew_this_hop = true;
                    for collateral_asset in position.collateral.keys() {
                        if known_assets.insert(*collateral_asset) {
                            next.push(*collateral_asset);
                        }
                    }
                }
            }

            if grew_this_hop {
                reflexive_depth = hop + 1;
            }
            // Sorted for reproducible walk order (debugging/tests); `next`
            // can never hold a duplicate — every push is gated by
            // `known_assets.insert` above — so no `dedup()` is needed.
            next.sort();
            frontier = next;
        }
    }

    // No reflexive growth beyond the seed: not a cascade (module docs' "only
    // reflexivity" note) — `LiquidationRiskPredicted` already covers a plain
    // at-risk snapshot.
    let warning = (at_risk.len() > seed_count).then(|| {
        let aggregate_at_risk_usd: f64 = at_risk
            .iter()
            .filter_map(|key| positions.get(key))
            .filter_map(|position| valued_total(&position.collateral, assets, prices))
            .sum();

        let mut accounts: Vec<AccountAddress> = at_risk.iter().map(|key| key.account).collect();
        accounts.sort();
        accounts.dedup();

        CascadeWarning {
            trigger_asset: trigger.asset,
            trigger_price: trigger.price.get(),
            reflexive_depth,
            accounts,
            aggregate_at_risk_usd: UsdAmount::new(aggregate_at_risk_usd),
        }
    });

    tracing::debug!(
        seed_positions = seed_count,
        at_risk_positions = at_risk.len(),
        reflexive_depth,
        hub_capped,
        found_cascade = warning.is_some(),
        "reflexivity walk complete"
    );

    CascadeOutcome {
        warning,
        hub_capped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::position::{LiquidationThresholds, Protocol};
    use alloy_primitives::U256;

    fn addr(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }

    const WETH: u8 = 0xE0;
    const USDC: u8 = 0xC0;

    fn impact_model() -> SteppedImpactModel {
        SteppedImpactModel::default()
    }

    /// One account supplying `collateral_units` WETH and borrowing
    /// `debt_units` USDC on Aave.
    fn open_position(
        state: &mut PositionState,
        account: u8,
        collateral_units: u64,
        debt_units: u64,
    ) {
        let thresholds = LiquidationThresholds::default();
        state.apply(
            &crate::lending_decode::LendingEvent::Supply {
                protocol: Protocol::Aave,
                account: addr(account),
                asset: addr(WETH),
                amount: U256::from(collateral_units),
            },
            &thresholds,
        );
        state.apply(
            &crate::lending_decode::LendingEvent::Borrow {
                protocol: Protocol::Aave,
                account: addr(account),
                asset: addr(USDC),
                amount: U256::from(debt_units),
            },
            &thresholds,
        );
    }

    fn assets() -> HashMap<Address, TokenMeta> {
        let mut map = HashMap::new();
        map.insert(addr(WETH), TokenMeta::new(addr(WETH), None, 18));
        map.insert(addr(USDC), TokenMeta::new(addr(USDC), None, 6));
        map
    }

    fn prices(weth_usd: f64) -> HashMap<Address, UsdPrice> {
        let mut map = HashMap::new();
        map.insert(addr(WETH), UsdPrice::try_new(weth_usd).unwrap());
        map.insert(addr(USDC), UsdPrice::try_new(1.0).unwrap());
        map
    }

    fn tick(weth_usd: f64) -> PriceTick {
        PriceTick {
            asset: addr(WETH),
            price: UsdPrice::try_new(weth_usd).unwrap(),
            updated_at: U256::from(1u64),
        }
    }

    /// 1 WETH collateral (18dp), `debt_units` USDC (6dp) at an 80% threshold.
    fn position_with(collateral_weth: u64, debt_usdc: u64) -> (u64, u64) {
        (
            collateral_weth * 1_000_000_000_000_000_000,
            debt_usdc * 1_000_000,
        )
    }

    #[test]
    fn no_at_risk_positions_is_no_cascade() {
        let mut state = PositionState::default();
        // Safely overcollateralized: HF way above 1.0.
        let (collateral, debt) = position_with(10, 1_000);
        open_position(&mut state, 0x11, collateral, debt);

        let outcome = detect_cascade(
            tick(2_000.0),
            &assets(),
            &prices(2_000.0),
            &state,
            &RiskThresholds::default(),
            &ReflexivityLimits::default(),
            &impact_model(),
        );
        assert!(outcome.warning.is_none());
        assert!(!outcome.hub_capped);
    }

    #[test]
    fn a_lone_at_risk_position_with_no_knock_on_is_no_cascade() {
        let mut state = PositionState::default();
        // Only one open position: it can cross into Critical, but there's no
        // second position for its collateral dump to reprice into risk.
        let (collateral, debt) = position_with(1, 1_450);
        open_position(&mut state, 0x11, collateral, debt);

        let outcome = detect_cascade(
            tick(1_500.0),
            &assets(),
            &prices(1_500.0),
            &state,
            &RiskThresholds::default(),
            &ReflexivityLimits::default(),
            &impact_model(),
        );
        assert!(
            outcome.warning.is_none(),
            "a plain at-risk snapshot is LiquidationRiskPredicted's job, not a cascade"
        );
    }

    #[test]
    fn liquidating_the_seed_pulls_a_second_position_underwater() {
        let mut state = PositionState::default();
        // Account 0x11: already Critical at $1,500/WETH (the seed).
        let (c1, d1) = position_with(1, 1_450);
        open_position(&mut state, 0x11, c1, d1);
        // Account 0x22: safe at $1,500 but just barely — a further ~5% drop
        // (one reflexive hop's price-impact step) tips it into Danger/Critical.
        let (c2, d2) = position_with(1, 1_130);
        open_position(&mut state, 0x22, c2, d2);

        let outcome = detect_cascade(
            tick(1_500.0),
            &assets(),
            &prices(1_500.0),
            &state,
            &RiskThresholds::default(),
            &ReflexivityLimits::default(),
            &impact_model(),
        );
        assert!(!outcome.hub_capped);
        let warning = outcome
            .warning
            .expect("account 0x22 should be reflexively pulled in");

        assert_eq!(warning.trigger_asset, addr(WETH));
        assert_eq!(warning.trigger_price, 1_500.0);
        assert_eq!(warning.reflexive_depth, 1);
        assert_eq!(warning.accounts.len(), 2);
        assert!(warning.accounts.contains(&addr(0x11)));
        assert!(warning.accounts.contains(&addr(0x22)));
        assert!(warning.aggregate_at_risk_usd.get() > 0.0);
    }

    #[test]
    fn a_degree_capped_asset_is_a_boundary_not_a_shock_source() {
        let mut state = PositionState::default();
        let (c1, d1) = position_with(1, 1_450);
        open_position(&mut state, 0x11, c1, d1);
        let (c2, d2) = position_with(1, 1_130);
        open_position(&mut state, 0x22, c2, d2);

        let capped_limits = ReflexivityLimits {
            degree_cap: 1, // WETH is touched by 2 positions — over the cap.
            ..ReflexivityLimits::default()
        };

        let outcome = detect_cascade(
            tick(1_500.0),
            &assets(),
            &prices(1_500.0),
            &state,
            &RiskThresholds::default(),
            &capped_limits,
            &impact_model(),
        );
        assert!(
            outcome.warning.is_none(),
            "the only propagation path is hub-capped, so no measured growth is found"
        );
        assert!(
            outcome.hub_capped,
            "the hub cap must be visible even though no warning fired"
        );
    }

    #[test]
    fn max_depth_zero_never_walks_past_the_seed() {
        let mut state = PositionState::default();
        let (c1, d1) = position_with(1, 1_450);
        open_position(&mut state, 0x11, c1, d1);
        let (c2, d2) = position_with(1, 1_130);
        open_position(&mut state, 0x22, c2, d2);

        let zero_depth = ReflexivityLimits {
            max_depth: 0,
            ..ReflexivityLimits::default()
        };

        let outcome = detect_cascade(
            tick(1_500.0),
            &assets(),
            &prices(1_500.0),
            &state,
            &RiskThresholds::default(),
            &zero_depth,
            &impact_model(),
        );
        assert!(outcome.warning.is_none());
        assert!(!outcome.hub_capped);
    }

    #[test]
    fn stepped_impact_model_floors_at_zero_past_full_wipeout() {
        let price = UsdPrice::try_new(2_000.0).unwrap();
        let model = SteppedImpactModel { bps_per_hop: 5_000 };
        assert_eq!(model.shocked_price(price, 0).get(), 1_000.0); // 50% at hop 0
        assert_eq!(model.shocked_price(price, 1).get(), 0.0); // 100% at hop 1
        assert_eq!(model.shocked_price(price, 3).get(), 0.0); // still floored
    }
}
