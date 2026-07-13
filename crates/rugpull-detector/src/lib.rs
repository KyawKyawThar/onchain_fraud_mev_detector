//! `rugpull-v1.0` — the liquidity-drain ("rug pull") detector (§6, §22 Phase 3).
//!
//! A rug pull ends a token's life: whoever controls the liquidity yanks most of it
//! out of the AMM pool in one move, collapsing the price and stranding every other
//! holder. The on-chain signature is blunt and structural — a **single tx drains a
//! large fraction of a pool's reserves**: a token flows *out of* a known pool
//! address in an amount that is a big share of what the pool held at this block.
//!
//! This detector reads the enrichment's decoded [`TokenTransfer`]s and the
//! per-block [`PoolState`](detector_api::PoolState) reserves. For each transfer
//! *from* a pool it knows the reserves of, it sums the outflow per `(pool, token)`
//! and compares it to the reserve: cross the configured fraction
//! ([`RugpullConfig::min_drain_bps`]) and it's a drain. Reading the reserve *at the
//! block* is what makes this a fraction, not a raw threshold — pulling 40 ETH is
//! nothing from a whale pool and everything from a shallow one.
//!
//! Pure, single-tx, [`Scope::Block`] and parallel-safe (§17); **attribution-blind**
//! (§6) — the recipient is the fact that they drained the pool, never an identity.
//! The USD gate ([`RugpullConfig::min_pool_usd`]) suppresses noise from dust pools;
//! a drain of an *unpriced* token is still reported (the fraction is structural),
//! at lower confidence. Output is behaviour-only [`Evidence`] with a typed
//! [`RugpullDetail`].
//!
//! # Known limitation (v1.0)
//!
//! A legitimate LP withdrawing their own large position is structurally identical
//! to a rug at this altitude — the difference is *intent* and *who* the LP is,
//! which is attribution (the intelligence service, §8) and simulation (§7), not the
//! fast path. This detector names the drain; downstream decides culpability.

use std::collections::BTreeMap;

use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};

use detector_api::{
    Bps, DetectionCtx, DetectorId, DetectorPlugin, Evidence, ModelKind, Scope, SemVer, TxActions,
    UsdPrice,
};
use events::primitives::{AlertKind, Confidence};

/// Default drain floor: pulling ≥ 50% of a reserve in one tx is the signal.
const DEFAULT_MIN_DRAIN_BPS: u32 = 5_000;
/// Default pool-size gate: ignore drains of pools holding less than `$10,000` of
/// the drained token (dust pools churn for benign reasons).
const DEFAULT_MIN_POOL_USD: f64 = 10_000.0;

// Confidence policy, facts-only (§6).
/// Base confidence for a qualifying drain whose value we could price.
const CONF_VALUED: f64 = 0.60;
/// Base when the drain is structural but the token has no reference price.
const CONF_UNVALUED: f64 = 0.50;
/// Added per basis point of drain beyond the floor — draining the whole pool is a
/// clearer rug than clearing the threshold by a hair.
const CONF_PER_DRAIN_BP: f64 = 0.00006;
/// Cap on the drain contribution.
const MAX_DRAIN_CONTRIB: f64 = 0.35;

fn default_min_drain_bps() -> Bps {
    Bps::new(DEFAULT_MIN_DRAIN_BPS)
}

fn default_min_pool_usd() -> UsdPrice {
    UsdPrice::try_new(DEFAULT_MIN_POOL_USD).expect("default min pool is a valid USD price")
}

/// Tunable thresholds for the rug-pull detector. Serialized into the model
/// registry's `config_hash` (§6); deserializable so the service can load
/// `[detectors.rugpull]` from config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RugpullConfig {
    /// Minimum fraction of a pool's reserve that a single tx must drain to be
    /// reported (`5_000` bps = 50%). A [`Bps`], not an `f64`, so config can't carry a
    /// `NaN`/negative fraction that silently disables the gate.
    #[serde(default = "default_min_drain_bps")]
    pub min_drain_bps: Bps,
    /// Minimum USD value of the drained amount for the drain to be reported. A
    /// validated [`UsdPrice`]. Applied only when the token has a reference price; an
    /// unvalued-but-structural drain is still reported, at lower confidence.
    #[serde(default = "default_min_pool_usd")]
    pub min_pool_usd: UsdPrice,
}

impl Default for RugpullConfig {
    fn default() -> Self {
        Self {
            min_drain_bps: default_min_drain_bps(),
            min_pool_usd: default_min_pool_usd(),
        }
    }
}

/// The `rugpull-v1.0` detector. Holds its [`RugpullConfig`]; construct with
/// [`plugin`] for defaults or [`RugpullDetector::new`] to override.
#[derive(Debug, Clone)]
pub struct RugpullDetector {
    config: RugpullConfig,
}

impl RugpullDetector {
    /// This detector's stable id.
    pub const ID: DetectorId = DetectorId::new("rugpull");
    /// This build's version: `1.0.0`.
    pub const VERSION: SemVer = SemVer::new(1, 0, 0);

    /// Build the detector with explicit thresholds.
    pub fn new(config: RugpullConfig) -> Self {
        Self { config }
    }

    /// The active config — what the model registry hashes into `config_hash`.
    pub fn config(&self) -> &RugpullConfig {
        &self.config
    }
}

/// Construct the detector with default config, ready to register.
pub fn plugin() -> RugpullDetector {
    RugpullDetector::new(RugpullConfig::default())
}

/// The typed detail payload of a rug-pull [`Evidence`] (§6). Addresses are facts,
/// not identities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RugpullDetail {
    /// The pool that was drained.
    pub pool: Address,
    /// The drained token.
    pub token: Address,
    /// The single recipient of the largest share of the drain — a fact, not a label.
    pub recipient: Address,
    /// Amount removed from the pool, in raw base units.
    pub drained: U256,
    /// The pool's reserve of the token at this block, before the drain.
    pub reserve_before: U256,
    /// Fraction of the reserve removed.
    pub drain_bps: Bps,
    /// The drained value in USD, when the token has a reference price; else `null`.
    pub drained_usd: Option<f64>,
}

/// One pool/token outflow accumulated across a tx's transfers.
#[derive(Default)]
struct Drain {
    drained: U256,
    /// The recipient of the single largest transfer in the drain.
    top_recipient: Address,
    top_amount: U256,
}

impl DetectorPlugin for RugpullDetector {
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
        ctx.txs()
            .iter()
            .filter_map(|tx_hash| ctx.enrichment().tx(*tx_hash))
            .flat_map(|tx| self.detect_in_tx(ctx, tx))
            .collect()
    }
}

impl RugpullDetector {
    fn detect_in_tx(&self, ctx: &DetectionCtx, tx: &TxActions) -> Vec<Evidence> {
        // Aggregate outflows from *known pools* per (pool, token). A transfer whose
        // sender isn't a pool we have reserves for can't be measured as a fraction,
        // so it's ignored.
        let mut drains: BTreeMap<(Address, Address), Drain> = BTreeMap::new();
        for t in &tx.transfers {
            if ctx.enrichment().pool(t.from).is_none() {
                continue;
            }
            let d = drains.entry((t.from, t.token)).or_default();
            d.drained = d.drained.saturating_add(t.amount);
            if t.amount > d.top_amount {
                d.top_amount = t.amount;
                d.top_recipient = t.to;
            }
        }

        let mut findings = Vec::new();
        for ((pool_addr, token), drain) in drains {
            let Some(reserve) = ctx
                .enrichment()
                .pool(pool_addr)
                .and_then(|p| p.reserve_of(token))
            else {
                continue;
            };
            let Some(drain_bps) = Bps::from_ratio_u256(drain.drained, reserve) else {
                continue;
            };
            if drain_bps < self.config.min_drain_bps {
                continue;
            }

            let drained_usd = ctx.enrichment().usd_value(token, drain.drained);
            if self.config.min_pool_usd.excludes(drained_usd) {
                continue;
            }

            findings.push(build_evidence(
                tx.hash,
                pool_addr,
                token,
                &drain,
                reserve,
                drain_bps,
                drained_usd,
            ));
        }
        findings
    }
}

/// Assemble the [`Evidence`]. Confidence rises with the drained fraction and with a
/// confirmed USD value, capped so structure alone can't reach certainty.
#[allow(clippy::too_many_arguments)]
fn build_evidence(
    tx: alloy_primitives::B256,
    pool: Address,
    token: Address,
    drain: &Drain,
    reserve_before: U256,
    drain_bps: Bps,
    drained_usd: Option<f64>,
) -> Evidence {
    let base = if drained_usd.is_some() {
        CONF_VALUED
    } else {
        CONF_UNVALUED
    };
    let over_floor = f64::from(drain_bps.get().saturating_sub(DEFAULT_MIN_DRAIN_BPS));
    let contrib = (CONF_PER_DRAIN_BP * over_floor).min(MAX_DRAIN_CONTRIB);
    let confidence = Confidence::new(base + contrib);

    let detail = RugpullDetail {
        pool,
        token,
        recipient: drain.top_recipient,
        drained: drain.drained,
        reserve_before,
        drain_bps,
        drained_usd,
    };
    Evidence::from_detail(AlertKind::Rugpull, vec![tx], confidence, &detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use detector_api::test_util::{addr, b256, transfer, CtxBuilder};

    const TKN: u8 = 0xAA; // the pool token being drained, $1
    const WETH: u8 = 0xBB;
    const POOL: u8 = 0xCC;
    const RUGGER: u8 = 0x11;

    /// A pool holding 1_000_000 TKN / 1_000 WETH, TKN priced at $1. TKN is declared
    /// with 0 decimals so raw base units read as whole tokens — keeping the reserve
    /// worth ~$1M (well over the pool-size gate) without 18-zero literals.
    fn priced() -> CtxBuilder {
        CtxBuilder::new()
            .priced_token(addr(TKN), 0, 1.0)
            .priced_token(addr(WETH), 18, 2000.0)
            .pool(addr(POOL), addr(TKN), addr(WETH), 1_000_000, 1_000)
    }

    fn detail_of(ev: &Evidence) -> RugpullDetail {
        serde_json::from_value(ev.detail.clone()).expect("detail round-trips as RugpullDetail")
    }

    #[test]
    fn flags_a_large_liquidity_drain() {
        // Pull 900_000 of the 1_000_000 TKN reserve → 90% drain.
        let c = priced()
            .transfer_tx(
                b256(1),
                addr(RUGGER),
                vec![transfer(addr(TKN), addr(POOL), addr(RUGGER), 900_000)],
            )
            .build();
        let found = plugin().detect(&c);
        assert_eq!(found.len(), 1);
        let ev = &found[0];
        assert_eq!(ev.kind, AlertKind::Rugpull);

        let d = detail_of(ev);
        assert_eq!(d.pool, addr(POOL));
        assert_eq!(d.token, addr(TKN));
        assert_eq!(d.recipient, addr(RUGGER));
        assert_eq!(d.drained, U256::from(900_000));
        assert_eq!(d.reserve_before, U256::from(1_000_000));
        assert_eq!(d.drain_bps, Bps::new(9_000));
    }

    #[test]
    fn ignores_a_small_withdrawal() {
        // Pull 10% — a routine LP move, below the 50% floor.
        let c = priced()
            .transfer_tx(
                b256(1),
                addr(RUGGER),
                vec![transfer(addr(TKN), addr(POOL), addr(RUGGER), 100_000)],
            )
            .build();
        assert!(plugin().detect(&c).is_empty());
    }

    #[test]
    fn ignores_an_outflow_from_a_non_pool_address() {
        // A big transfer whose sender isn't a known pool can't be measured as a
        // drain fraction, so it's ignored — this isn't a pool being emptied.
        let c = priced()
            .transfer_tx(
                b256(1),
                addr(RUGGER),
                vec![transfer(addr(TKN), addr(0x77), addr(RUGGER), 900_000)],
            )
            .build();
        assert!(plugin().detect(&c).is_empty());
    }

    #[test]
    fn value_below_min_pool_usd_is_filtered() {
        // A 90% drain, but the pool only holds ~$0.90 of TKN → below the $10k gate.
        let tiny = CtxBuilder::new()
            .priced_token(addr(TKN), 18, 1.0)
            .pool(addr(POOL), addr(TKN), addr(WETH), 1, 1)
            .transfer_tx(
                b256(1),
                addr(RUGGER),
                vec![transfer(addr(TKN), addr(POOL), addr(RUGGER), 1)],
            )
            .build();
        assert!(plugin().detect(&tiny).is_empty());
    }

    #[test]
    fn unpriced_drain_still_reports_structure_at_lower_confidence() {
        let c = CtxBuilder::new()
            .pool(addr(POOL), addr(TKN), addr(WETH), 1_000_000, 1_000)
            .transfer_tx(
                b256(1),
                addr(RUGGER),
                vec![transfer(addr(TKN), addr(POOL), addr(RUGGER), 1_000_000)],
            )
            .build();
        let found = plugin().detect(&c);
        assert_eq!(found.len(), 1);
        assert_eq!(detail_of(&found[0]).drained_usd, None);
        // 100% drain (10_000 bps), unvalued: base + 5000 bps × per-bp, below the cap.
        let expected = CONF_UNVALUED + CONF_PER_DRAIN_BP * 5_000.0;
        assert!((found[0].confidence.get() - expected).abs() < 1e-9);
    }

    #[test]
    fn empty_block_finds_nothing() {
        assert!(plugin().detect(&CtxBuilder::new().build()).is_empty());
    }

    #[test]
    fn config_round_trips_and_rejects_a_nonsense_threshold() {
        let cfg: RugpullConfig =
            serde_json::from_str(r#"{"min_drain_bps": 8000, "min_pool_usd": 50000.0}"#).unwrap();
        assert_eq!(cfg.min_drain_bps, Bps::new(8000));
        assert_eq!(cfg.min_pool_usd.get(), 50000.0);
        assert!(serde_json::from_str::<RugpullConfig>(r#"{"min_pool_usd": -1.0}"#).is_err());
        let defaulted: RugpullConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(defaulted, RugpullConfig::default());
    }

    #[test]
    fn exposes_its_identity_through_the_plugin_seam() {
        let detector = plugin();
        let plug: &dyn DetectorPlugin = &detector;
        assert_eq!(plug.id().as_str(), "rugpull");
        assert_eq!(plug.id(), RugpullDetector::ID);
        assert_eq!(plug.version(), RugpullDetector::VERSION);
        assert_eq!(plug.version().to_string(), "1.0.0");
        assert_eq!(plug.kind(), ModelKind::Rule);
        assert_eq!(plug.scope(), Scope::Block);
    }
}
