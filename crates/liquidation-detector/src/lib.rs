//! `liquidation-v1.0` — the liquidation detector (§6, §22 Phase 3).
//!
//! A liquidation closes an under-collateralised loan: a liquidator **repays** a
//! borrower's debt token and, in the same tx, **seizes** the borrower's collateral
//! at a protocol-defined discount (the *liquidation bonus*, typically 5–10%). So on
//! chain the liquidator ends one token *down* (the debt they paid) and a different
//! token *up* (the collateral they took), worth strictly **more** than the debt —
//! that asymmetric, discounted swap is the structural signature.
//!
//! This detector reads the enrichment's decoded [`TokenTransfer`]s for the tx
//! sender and nets their flow per token: a liquidation is one token net-*negative*
//! (debt repaid) and another net-*positive* (collateral seized) whose USD value
//! exceeds the debt by at least the configured bonus. That net-negative-in-one /
//! net-positive-in-another shape is what separates it from an atomic arbitrage
//! (which nets *positive* in one cycled token and zero elsewhere — the arb
//! detector's signature) and from a fair swap (≈ zero net value change, below the
//! bonus floor).
//!
//! Pure, single-tx, [`Scope::Block`] and parallel-safe (§17); **attribution-blind**
//! (§6) — the liquidator/borrower addresses are facts, never labels. Because the
//! bonus *is* the signal, valuation is required: a liquidation whose tokens have no
//! reference price can't be told from a swap, so it is not reported (unlike the
//! structural-only fallback the sandwich/arb detectors allow). Output is
//! behaviour-only [`Evidence`] with a typed [`LiquidationDetail`].

use std::collections::BTreeMap;

use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};

use detector_api::{
    Bps, DetectionCtx, DetectorId, DetectorPlugin, Evidence, ModelKind, Scope, SemVer, TxActions,
    UsdPrice,
};
use events::primitives::{AlertKind, Confidence};

/// Default gate: ignore liquidations repaying less than `$100` of debt (dust).
const DEFAULT_MIN_DEBT_USD: f64 = 100.0;
/// Default minimum liquidation bonus, in basis points (`300` = 3%). A fair swap
/// sits near zero; a real liquidation bonus is well above this floor.
const DEFAULT_MIN_BONUS_BPS: u32 = 300;

// Confidence policy, facts-only (§6).
/// Base confidence for a discounted seizure clearing the bonus floor.
const CONF_BASE: f64 = 0.60;
/// Added per basis point of bonus beyond the floor — a fatter discount is a
/// clearer liquidation (a fair trade wouldn't leave value on the table).
const CONF_PER_BONUS_BP: f64 = 0.0002;
/// Cap on the bonus contribution, so a huge discount can't reach certainty.
const MAX_BONUS_CONTRIB: f64 = 0.30;

fn default_min_debt_usd() -> UsdPrice {
    UsdPrice::try_new(DEFAULT_MIN_DEBT_USD).expect("default min debt is a valid USD price")
}

fn default_min_bonus_bps() -> Bps {
    Bps::new(DEFAULT_MIN_BONUS_BPS)
}

/// Tunable thresholds for the liquidation detector. Serialized into the model
/// registry's `config_hash` (§6); deserializable so the service can load
/// `[detectors.liquidation]` from config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LiquidationConfig {
    /// Minimum debt repaid (valued via enrichment) for a seizure to be reported.
    #[serde(default = "default_min_debt_usd")]
    pub min_debt_usd: UsdPrice,
    /// Minimum liquidation bonus — the discount at which a seizure is
    /// distinguishable from a fair swap.
    #[serde(default = "default_min_bonus_bps")]
    pub min_bonus_bps: Bps,
}

impl Default for LiquidationConfig {
    fn default() -> Self {
        Self {
            min_debt_usd: default_min_debt_usd(),
            min_bonus_bps: default_min_bonus_bps(),
        }
    }
}

/// The `liquidation-v1.0` detector. Holds its [`LiquidationConfig`]; construct with
/// [`plugin`] for defaults or [`LiquidationDetector::new`] to override.
#[derive(Debug, Clone)]
pub struct LiquidationDetector {
    config: LiquidationConfig,
}

impl LiquidationDetector {
    /// This detector's stable id.
    pub const ID: DetectorId = DetectorId::new("liquidation");
    /// This build's version: `1.0.0`.
    pub const VERSION: SemVer = SemVer::new(1, 0, 0);

    /// Build the detector with explicit thresholds.
    pub fn new(config: LiquidationConfig) -> Self {
        Self { config }
    }

    /// The active config — what the model registry hashes into `config_hash`.
    pub fn config(&self) -> &LiquidationConfig {
        &self.config
    }
}

/// Construct the detector with default config, ready to register.
pub fn plugin() -> LiquidationDetector {
    LiquidationDetector::new(LiquidationConfig::default())
}

/// The typed detail payload of a liquidation [`Evidence`] (§6). Addresses are
/// facts, not identities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LiquidationDetail {
    /// The address that repaid debt and seized collateral — a fact, not a label.
    pub liquidator: Address,
    /// The token the liquidator paid out (the borrower's debt).
    pub debt_token: Address,
    /// The token the liquidator received (the seized collateral).
    pub collateral_token: Address,
    /// Debt repaid, in raw base units of `debt_token`.
    pub debt_repaid: U256,
    /// Collateral seized, in raw base units of `collateral_token`.
    pub collateral_seized: U256,
    /// Debt repaid, in USD.
    pub debt_usd: f64,
    /// Collateral seized, in USD (`> debt_usd`).
    pub collateral_usd: f64,
    /// The realised liquidation bonus.
    pub bonus_bps: Bps,
}

/// One side of the liquidator's netted flow: the dominant token, its net amount,
/// and that amount's USD value.
struct Leg {
    token: Address,
    amount: U256,
    usd: f64,
}

impl DetectorPlugin for LiquidationDetector {
    fn id(&self) -> DetectorId {
        Self::ID
    }

    fn version(&self) -> SemVer {
        Self::VERSION
    }

    fn kind(&self) -> ModelKind {
        ModelKind::Rule
    }

    fn scope(&self) -> Scope {
        Scope::Block
    }

    fn detect(&self, ctx: &DetectionCtx) -> Vec<Evidence> {
        // Each tx is at most one liquidation (one liquidator, one netted seizure).
        ctx.txs()
            .iter()
            .filter_map(|tx_hash| ctx.enrichment().tx(*tx_hash))
            .filter_map(|tx| self.detect_in_tx(ctx, tx))
            .collect()
    }
}

impl LiquidationDetector {
    fn detect_in_tx(&self, ctx: &DetectionCtx, tx: &TxActions) -> Option<Evidence> {
        // Net the liquidator's (the tx sender's) flow per token: collateral is
        // net-in, debt is net-out.
        let liquidator = tx.from;
        let mut received: BTreeMap<Address, U256> = BTreeMap::new();
        let mut spent: BTreeMap<Address, U256> = BTreeMap::new();
        for t in &tx.transfers {
            if t.to == liquidator {
                let e = received.entry(t.token).or_default();
                *e = e.saturating_add(t.amount);
            }
            if t.from == liquidator {
                let e = spent.entry(t.token).or_default();
                *e = e.saturating_add(t.amount);
            }
        }

        // Dominant collateral (largest priced net-in) and debt (largest priced
        // net-out). Both must be valued — the bonus is the whole signal.
        let collateral = dominant_leg(ctx, &received, &spent)?;
        let debt = dominant_leg(ctx, &spent, &received)?;
        // A liquidation swaps *distinct* tokens; same token both ways is a round
        // trip, not a seizure (and the flashloan detector's territory).
        if collateral.token == debt.token {
            return None;
        }

        if debt.usd < self.config.min_debt_usd.get() {
            return None;
        }
        // Bonus = how much more collateral is worth than the debt it cleared,
        // i.e. `(collateral - debt) / debt`. `Bps::from_ratio_f64` returns `None`
        // for a non-positive discount (a fair or losing trade — not a liquidation).
        let bonus_bps = Bps::from_ratio_f64(collateral.usd - debt.usd, debt.usd)?;
        if bonus_bps < self.config.min_bonus_bps {
            return None;
        }

        Some(build_evidence(
            tx.hash,
            liquidator,
            &debt,
            &collateral,
            bonus_bps,
        ))
    }
}

/// The token with the largest positive USD net of `plus - minus`, valued through
/// enrichment. `None` if no token nets positive with a known price. Used twice:
/// `(received, spent)` yields the collateral leg, `(spent, received)` the debt.
fn dominant_leg(
    ctx: &DetectionCtx,
    plus: &BTreeMap<Address, U256>,
    minus: &BTreeMap<Address, U256>,
) -> Option<Leg> {
    let mut best: Option<Leg> = None;
    for (&token, &gross) in plus {
        let offset = minus.get(&token).copied().unwrap_or(U256::ZERO);
        // Net only: a token that came back out isn't part of this side.
        let net = gross.saturating_sub(offset);
        if net.is_zero() {
            continue;
        }
        let Some(usd) = ctx.enrichment().usd_value(token, net) else {
            continue;
        };
        if best.as_ref().is_none_or(|b| usd > b.usd) {
            best = Some(Leg {
                token,
                amount: net,
                usd,
            });
        }
    }
    best
}

/// Assemble the [`Evidence`]. Confidence rises with the realised bonus (a fatter
/// discount is a clearer liquidation), capped so structure alone can't reach
/// certainty.
fn build_evidence(
    tx: alloy_primitives::B256,
    liquidator: Address,
    debt: &Leg,
    collateral: &Leg,
    bonus_bps: Bps,
) -> Evidence {
    let over_floor = f64::from(bonus_bps.get().saturating_sub(DEFAULT_MIN_BONUS_BPS));
    let contrib = (CONF_PER_BONUS_BP * over_floor).min(MAX_BONUS_CONTRIB);
    let confidence = Confidence::new(CONF_BASE + contrib);

    let detail = LiquidationDetail {
        liquidator,
        debt_token: debt.token,
        collateral_token: collateral.token,
        debt_repaid: debt.amount,
        collateral_seized: collateral.amount,
        debt_usd: debt.usd,
        collateral_usd: collateral.usd,
        bonus_bps,
    };
    Evidence::from_detail(AlertKind::Liquidation, vec![tx], confidence, &detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use detector_api::test_util::{addr, b256, transfer, CtxBuilder};
    use detector_api::TokenTransfer;

    const WETH: u8 = 0xAA; // collateral, $2000
    const USDC: u8 = 0xBB; // debt, $1
    const LIQUIDATOR: u8 = 0x11;
    const PROTOCOL: u8 = 0x99;
    const ETH: u128 = 1_000_000_000_000_000_000;
    const USDC_UNIT: u128 = 1_000_000; // 1 USDC (6 decimals)

    fn priced() -> CtxBuilder {
        CtxBuilder::new()
            .priced_token(addr(WETH), 18, 2000.0)
            .priced_token(addr(USDC), 6, 1.0)
    }

    fn detail_of(ev: &Evidence) -> LiquidationDetail {
        serde_json::from_value(ev.detail.clone()).expect("detail round-trips as LiquidationDetail")
    }

    /// Liquidator repays `debt_usdc` USDC of debt and seizes `collateral_eth` WETH.
    fn liquidation(debt_usdc: u128, collateral_eth_wei: u128) -> Vec<TokenTransfer> {
        vec![
            transfer(addr(USDC), addr(LIQUIDATOR), addr(PROTOCOL), debt_usdc),
            transfer(
                addr(WETH),
                addr(PROTOCOL),
                addr(LIQUIDATOR),
                collateral_eth_wei,
            ),
        ]
    }

    #[test]
    fn flags_a_discounted_seizure() {
        // Repay $2000 of USDC, seize 1.08 WETH = $2160 → 8% bonus.
        let c = priced()
            .transfer_tx(
                b256(1),
                addr(LIQUIDATOR),
                liquidation(2000 * USDC_UNIT, ETH + 8 * ETH / 100),
            )
            .build();
        let found = plugin().detect(&c);
        assert_eq!(found.len(), 1);
        let ev = &found[0];
        assert_eq!(ev.kind, AlertKind::Liquidation);
        assert_eq!(ev.txs, vec![b256(1)]);

        let d = detail_of(ev);
        assert_eq!(d.liquidator, addr(LIQUIDATOR));
        assert_eq!(d.debt_token, addr(USDC));
        assert_eq!(d.collateral_token, addr(WETH));
        assert_eq!(d.debt_usd, 2000.0);
        assert_eq!(d.collateral_usd, 2160.0);
        assert_eq!(d.bonus_bps, Bps::new(800));
    }

    #[test]
    fn ignores_a_fair_swap_below_the_bonus_floor() {
        // Repay $2000, receive $2000.20 back (1 bp) — a fair swap, not a seizure.
        let c = priced()
            .transfer_tx(
                b256(1),
                addr(LIQUIDATOR),
                liquidation(2000 * USDC_UNIT, ETH + ETH / 10000),
            )
            .build();
        assert!(plugin().detect(&c).is_empty());
    }

    #[test]
    fn ignores_a_losing_trade() {
        // Collateral worth *less* than the debt — never a liquidation.
        let c = priced()
            .transfer_tx(
                b256(1),
                addr(LIQUIDATOR),
                liquidation(2000 * USDC_UNIT, ETH / 2),
            )
            .build();
        assert!(plugin().detect(&c).is_empty());
    }

    #[test]
    fn debt_below_min_usd_is_filtered() {
        // A juicy 50% bonus, but only $10 of debt — below the $100 gate.
        let c = priced()
            .transfer_tx(
                b256(1),
                addr(LIQUIDATOR),
                liquidation(10 * USDC_UNIT, 15 * ETH / 2000),
            )
            .build();
        assert!(plugin().detect(&c).is_empty());
        let permissive = LiquidationDetector::new(LiquidationConfig {
            min_debt_usd: UsdPrice::try_new(0.0).unwrap(),
            min_bonus_bps: Bps::new(DEFAULT_MIN_BONUS_BPS),
        });
        assert_eq!(permissive.detect(&c).len(), 1);
    }

    #[test]
    fn unpriced_tokens_are_not_reported() {
        // The bonus is the whole signal; with no prices it can't be established, so
        // an unpriced seizure is silently skipped (no structural-only fallback).
        let c = CtxBuilder::new()
            .transfer_tx(
                b256(1),
                addr(LIQUIDATOR),
                liquidation(2000 * USDC_UNIT, 2 * ETH),
            )
            .build();
        assert!(plugin().detect(&c).is_empty());
    }

    #[test]
    fn empty_block_finds_nothing() {
        assert!(plugin().detect(&CtxBuilder::new().build()).is_empty());
    }

    #[test]
    fn config_round_trips_and_rejects_a_nonsense_threshold() {
        let cfg: LiquidationConfig =
            serde_json::from_str(r#"{"min_debt_usd": 500.0, "min_bonus_bps": 500}"#).unwrap();
        assert_eq!(cfg.min_debt_usd.get(), 500.0);
        assert_eq!(cfg.min_bonus_bps, Bps::new(500));
        assert!(serde_json::from_str::<LiquidationConfig>(r#"{"min_debt_usd": -1.0}"#).is_err());
        let defaulted: LiquidationConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(defaulted, LiquidationConfig::default());
    }

    #[test]
    fn exposes_its_identity_through_the_plugin_seam() {
        let detector = plugin();
        let plug: &dyn DetectorPlugin = &detector;
        assert_eq!(plug.id().as_str(), "liquidation");
        assert_eq!(plug.id(), LiquidationDetector::ID);
        assert_eq!(plug.version(), LiquidationDetector::VERSION);
        assert_eq!(plug.version().to_string(), "1.0.0");
        assert_eq!(plug.kind(), ModelKind::Rule);
        assert_eq!(plug.scope(), Scope::Block);
    }
}
