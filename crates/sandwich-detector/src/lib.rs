//! `sandwich-v1.2` — the sandwich-attack detector (§6, §22 Phase 2).
//!
//! A sandwich is a three-part pattern an attacker lands in a *single block*
//! around a victim's swap on one AMM pool:
//!
//! 1. **frontrun** — the attacker buys the token the victim is about to buy,
//!    pushing its price up;
//! 2. **victim** — the victim's swap executes at the worsened price;
//! 3. **backrun** — the attacker sells back into the pool, the same `from`
//!    address as the frontrun, in the *opposite* direction, recovering more of
//!    the input token than they spent.
//!
//! This detector is a pure, single-block function of a [`DetectionCtx`] — it
//! reasons only over the enrichment's decoded [`Swap`]s and each tx's sender, so
//! it's [`Scope::Block`] and parallel-safe across the roster (§17). It is
//! **attribution-blind** (§6): the sender address is an on-chain *fact* used to
//! pair the frontrun with the backrun, never a label — *who* that address is is
//! the intelligence service's job (§8).
//!
//! The structural signature (same sender bracketing ≥1 victim with opposite-
//! direction swaps on one pool, ending net-positive in the input token) is what
//! the detector keys on; the USD profit gate ([`SandwichConfig::min_profit_usd`])
//! suppresses dust. Output is the behaviour-only [`Evidence`] with a typed
//! [`SandwichDetail`] payload, which the service stamps with this build's
//! `(id, version, config_hash)` on emission (task 5).

use std::collections::{BTreeMap, HashSet};

use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

use detector_api::{
    DetectionCtx, DetectorId, DetectorPlugin, Evidence, ModelKind, Scope, SemVer, Swap, UsdPrice,
};
use events::primitives::{AlertKind, Confidence};

/// The spec's reference profit gate (§6, `[detectors.sandwich] min_profit_usd = 10.0`).
const DEFAULT_MIN_PROFIT_USD: f64 = 10.0;

// Confidence policy, facts-only (§6), gathered here so the scoring is reviewable
// in one place rather than scattered through the builder.
/// Base confidence for a structurally valid sandwich whose profit we could value.
const CONF_VALUED: f64 = 0.70;
/// Base when the structure holds but the profit couldn't be valued (no price).
const CONF_UNVALUED: f64 = 0.55;
/// Added per victim beyond the first — more victims is more clearly deliberate.
const CONF_PER_EXTRA_VICTIM: f64 = 0.05;
/// Cap on victims that contribute, so structure alone can't reach certainty.
const MAX_EXTRA_VICTIMS: usize = 4;

fn default_min_profit_usd() -> UsdPrice {
    UsdPrice::try_new(DEFAULT_MIN_PROFIT_USD).expect("default min profit is a valid USD price")
}

/// Tunable thresholds for the sandwich detector. Serialized into the model
/// registry's `config_hash` (§6, task 2/5), so two builds with different gates
/// are distinguishable when replaying historical evidence; deserializable so the
/// service can load `[detectors.sandwich]` from config (task 5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SandwichConfig {
    /// Minimum attacker profit (valued via enrichment) for a structurally valid
    /// sandwich to be reported. A validated [`UsdPrice`] — so a NaN/negative
    /// threshold can't slip in from config and silently disable the gate. Applied
    /// only when the input token has a known reference price; an unvalued-but-
    /// structural sandwich is still reported, at lower confidence (it can't be a
    /// false positive on the structure alone). Mirrors `[detectors.sandwich]
    /// min_profit_usd` (§6).
    #[serde(default = "default_min_profit_usd")]
    pub min_profit_usd: UsdPrice,
}

impl Default for SandwichConfig {
    fn default() -> Self {
        Self {
            min_profit_usd: default_min_profit_usd(),
        }
    }
}

/// The `sandwich-v1.2` detector. Holds its [`SandwichConfig`]; construct one with
/// [`plugin`] for the default thresholds or [`SandwichDetector::new`] to override.
#[derive(Debug, Clone)]
pub struct SandwichDetector {
    config: SandwichConfig,
}

impl SandwichDetector {
    /// This detector's stable id — the `sandwich` of `sandwich-v1.2`.
    pub const ID: DetectorId = DetectorId::new("sandwich");
    /// This build's version: `1.2.0`.
    pub const VERSION: SemVer = SemVer::new(1, 2, 0);

    /// Build the detector with explicit thresholds.
    pub fn new(config: SandwichConfig) -> Self {
        Self { config }
    }

    /// The active config — what the model registry hashes into `config_hash`.
    pub fn config(&self) -> &SandwichConfig {
        &self.config
    }
}

/// Construct the detector with default config, ready to register
/// (`b.register_if(flags.is_enabled(SandwichDetector::ID), sandwich_detector::plugin())`).
pub fn plugin() -> SandwichDetector {
    SandwichDetector::new(SandwichConfig::default())
}

/// One decoded swap together with where it sat in the block — enough to pair a
/// frontrun with its backrun and spot the victim between them.
struct SwapEntry<'a> {
    /// Position of the owning tx in block order.
    idx: usize,
    tx: B256,
    /// The tx sender — an on-chain fact used to match frontrun↔backrun, never a
    /// label (§6).
    from: Address,
    swap: &'a Swap,
}

impl SwapEntry<'_> {
    /// Same pool and same `token_in → token_out` direction as `other` — i.e. a
    /// swap that moves price the *same* way (a victim relative to the frontrun).
    fn same_direction(&self, other: &SwapEntry) -> bool {
        self.swap.pool == other.swap.pool
            && self.swap.token_in == other.swap.token_in
            && self.swap.token_out == other.swap.token_out
    }

    /// Same pool but the *reverse* direction of `other` — the backrun shape
    /// relative to the frontrun.
    fn opposite_direction(&self, other: &SwapEntry) -> bool {
        self.swap.pool == other.swap.pool
            && self.swap.token_in == other.swap.token_out
            && self.swap.token_out == other.swap.token_in
    }
}

/// The typed detail payload of a sandwich [`Evidence`] — the on-chain facts that
/// justify the finding (§6), and the contract a downstream consumer (the
/// simulation service, §7) deserializes rather than reaching into untyped JSON.
/// Addresses/hashes are facts, not identities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SandwichDetail {
    pub pool: Address,
    /// The token the attacker spends and recovers (the pool side they profit in).
    pub base_token: Address,
    /// The token whose price the attacker moves against the victim.
    pub target_token: Address,
    /// The sender common to the frontrun and backrun — a fact, not a label (§6).
    pub attacker: Address,
    pub frontrun_tx: B256,
    pub backrun_tx: B256,
    pub victim_txs: Vec<B256>,
    /// Attacker's net gain in `base_token`, in raw base units.
    pub profit_base: U256,
    /// That gain in USD, when `base_token` has a reference price; else `null`.
    pub profit_usd: Option<f64>,
}

impl DetectorPlugin for SandwichDetector {
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
        // Decides from one block alone — no cross-block state to reorg-version.
        Scope::Block
    }

    fn detect(&self, ctx: &DetectionCtx) -> Vec<Evidence> {
        // Gather every decoded swap in block order, tagged with its position and
        // sender, then bucket by pool — a sandwich lives entirely within one pool.
        let mut by_pool: BTreeMap<Address, Vec<SwapEntry>> = BTreeMap::new();
        for (idx, tx_hash) in ctx.txs().iter().enumerate() {
            let Some(tx) = ctx.enrichment().tx(*tx_hash) else {
                continue;
            };
            for swap in &tx.swaps {
                by_pool.entry(swap.pool).or_default().push(SwapEntry {
                    idx,
                    tx: tx.hash,
                    from: tx.from,
                    swap,
                });
            }
        }

        let mut findings = Vec::new();
        for entries in by_pool.values() {
            self.scan_pool(ctx, entries, &mut findings);
        }
        findings
    }
}

impl SandwichDetector {
    /// Greedily pair frontruns with backruns within one pool's swaps (already in
    /// block order), emitting one finding per non-overlapping sandwich.
    fn scan_pool(&self, ctx: &DetectionCtx, entries: &[SwapEntry], findings: &mut Vec<Evidence>) {
        // Txs already claimed by an emitted sandwich, so one tx isn't reused as
        // both a backrun and a later frontrun (deterministic, no double counting).
        let mut consumed: HashSet<usize> = HashSet::new();

        for (fi, front) in entries.iter().enumerate() {
            if consumed.contains(&front.idx) {
                continue;
            }
            // Find the nearest later swap by the same sender in the opposite
            // direction — the candidate backrun closing the sandwich.
            for back in entries[fi + 1..].iter() {
                if consumed.contains(&back.idx)
                    || back.from != front.from
                    || !back.opposite_direction(front)
                {
                    continue;
                }

                let victims: Vec<&SwapEntry> = entries[fi + 1..]
                    .iter()
                    .take_while(|e| e.idx < back.idx)
                    .filter(|e| {
                        e.from != front.from
                            && !consumed.contains(&e.idx)
                            && e.same_direction(front)
                    })
                    .collect();
                if victims.is_empty() {
                    continue;
                }

                // Attacker spent `front.amount_in` of the base token and recovered
                // `back.amount_out` of it; the net is their profit in that token.
                let base_token = front.swap.token_in;
                let profit = back.swap.amount_out.saturating_sub(front.swap.amount_in);
                if profit.is_zero() {
                    continue;
                }

                let profit_usd = ctx.enrichment().usd_value(base_token, profit);
                if profit_usd.is_some_and(|usd| usd < self.config.min_profit_usd.get()) {
                    continue;
                }

                findings.push(build_evidence(
                    front, back, &victims, base_token, profit, profit_usd,
                ));

                consumed.insert(front.idx);
                consumed.insert(back.idx);
                consumed.extend(victims.iter().map(|v| v.idx));
                break; // this frontrun is spent; move to the next candidate.
            }
        }
    }
}

/// Assemble the [`Evidence`] for one confirmed sandwich. Confidence is facts-only
/// (§6): a baseline for the unambiguous structure, lifted by a confirmed USD
/// profit and by each additional bracketed victim (see the `CONF_*` constants).
fn build_evidence(
    front: &SwapEntry,
    back: &SwapEntry,
    victims: &[&SwapEntry],
    base_token: Address,
    profit: U256,
    profit_usd: Option<f64>,
) -> Evidence {
    let mut score = if profit_usd.is_some() {
        CONF_VALUED
    } else {
        CONF_UNVALUED
    };
    let extra_victims = victims.len().saturating_sub(1).min(MAX_EXTRA_VICTIMS);
    score += CONF_PER_EXTRA_VICTIM * (extra_victims as f64);
    let confidence = Confidence::new(score);

    // Implicated txs in block order: frontrun, each victim, backrun.
    let mut txs = Vec::with_capacity(victims.len() + 2);
    txs.push(front.tx);
    txs.extend(victims.iter().map(|v| v.tx));
    txs.push(back.tx);

    let detail = SandwichDetail {
        pool: front.swap.pool,
        base_token,
        target_token: front.swap.token_out,
        attacker: front.from,
        frontrun_tx: front.tx,
        backrun_tx: back.tx,
        victim_txs: victims.iter().map(|v| v.tx).collect(),
        profit_base: profit,
        profit_usd,
    };
    let detail =
        serde_json::to_value(&detail).expect("SandwichDetail is plain data and always serializes");

    Evidence::new(AlertKind::Sandwich, txs, confidence).with_detail(detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use detector_api::test_util::{addr, b256, swap, CtxBuilder};

    // Pool of WETH (base token, 18 dec, $2000) / TKN (18 dec, $1).
    const WETH: u8 = 0xAA;
    const TKN: u8 = 0xBB;
    const POOL: u8 = 0xCC;
    const ATTACKER: u8 = 0x11;
    const VICTIM: u8 = 0x22;
    const ETH: u128 = 1_000_000_000_000_000_000; // 1e18 wei

    /// The priced pool every scenario starts from.
    fn priced() -> CtxBuilder {
        CtxBuilder::new()
            .priced_token(addr(WETH), 18, 2000.0)
            .priced_token(addr(TKN), 18, 1.0)
            .pool(addr(POOL), addr(WETH), addr(TKN), 1_000, 1_000)
    }

    fn buy_tkn(amount_out: u128) -> Vec<Swap> {
        vec![swap(addr(POOL), addr(WETH), addr(TKN), ETH, amount_out)]
    }
    fn sell_tkn(amount_out: u128) -> Vec<Swap> {
        vec![swap(addr(POOL), addr(TKN), addr(WETH), 90, amount_out)]
    }

    fn detail_of(ev: &Evidence) -> SandwichDetail {
        serde_json::from_value(ev.detail.clone()).expect("detail round-trips as SandwichDetail")
    }

    /// frontrun (attacker buys TKN), victim (buys TKN), backrun (attacker sells
    /// TKN back for more WETH than spent) — a textbook profitable sandwich.
    fn sandwich_ctx() -> DetectionCtx {
        priced()
            .tx(b256(1), addr(ATTACKER), buy_tkn(90))
            .tx(b256(2), addr(VICTIM), buy_tkn(80))
            .tx(b256(3), addr(ATTACKER), sell_tkn(ETH + ETH / 20)) // recover 1.05 WETH
            .build()
    }

    #[test]
    fn flags_a_textbook_sandwich() {
        let found = plugin().detect(&sandwich_ctx());
        assert_eq!(found.len(), 1);
        let ev = &found[0];
        assert_eq!(ev.kind, AlertKind::Sandwich);
        // frontrun, victim, backrun — in block order.
        assert_eq!(ev.txs, vec![b256(1), b256(2), b256(3)]);
        assert!(ev.confidence.get() > 0.6);

        let detail = detail_of(ev);
        // 0.05 ETH profit @ $2000 = $100.
        assert_eq!(detail.profit_usd, Some(100.0));
        assert_eq!(detail.attacker, addr(ATTACKER));
        assert_eq!(detail.base_token, addr(WETH));
        assert_eq!(detail.target_token, addr(TKN));
    }

    #[test]
    fn ignores_unprofitable_bracket() {
        // Backrun recovers *less* WETH than the frontrun spent — no profit.
        let c = priced()
            .tx(b256(1), addr(ATTACKER), buy_tkn(90))
            .tx(b256(2), addr(VICTIM), buy_tkn(80))
            .tx(b256(3), addr(ATTACKER), sell_tkn(ETH - ETH / 20))
            .build();
        assert!(plugin().detect(&c).is_empty());
    }

    #[test]
    fn ignores_bracket_with_no_victim_between() {
        // Attacker's own round trip with nobody sandwiched — not an attack.
        let c = priced()
            .tx(b256(1), addr(ATTACKER), buy_tkn(90))
            .tx(b256(3), addr(ATTACKER), sell_tkn(ETH + ETH / 20))
            .build();
        assert!(plugin().detect(&c).is_empty());
    }

    #[test]
    fn requires_same_sender_for_front_and_back() {
        // Front and back are different senders — a victim plus an unrelated
        // opposite trade, not one attacker's bracket.
        let c = priced()
            .tx(b256(1), addr(ATTACKER), buy_tkn(90))
            .tx(b256(2), addr(VICTIM), buy_tkn(80))
            .tx(b256(3), addr(0x33), sell_tkn(ETH + ETH / 20))
            .build();
        assert!(plugin().detect(&c).is_empty());
    }

    #[test]
    fn profit_below_min_usd_is_filtered() {
        // A real but tiny profit (1 wei of WETH ≈ $2e-15), below the $10 gate.
        let c = priced()
            .tx(b256(1), addr(ATTACKER), buy_tkn(90))
            .tx(b256(2), addr(VICTIM), buy_tkn(80))
            .tx(b256(3), addr(ATTACKER), sell_tkn(ETH + 1))
            .build();
        assert!(plugin().detect(&c).is_empty());
        // …but a permissive config admits it (proves the gate, not the structure,
        // is what rejected it).
        let permissive = SandwichDetector::new(SandwichConfig {
            min_profit_usd: UsdPrice::try_new(0.0).unwrap(),
        });
        assert_eq!(permissive.detect(&c).len(), 1);
    }

    #[test]
    fn unpriced_pool_still_reports_structure_at_lower_confidence() {
        // No reference price for the base token ⇒ profit can't be valued, but the
        // structure is unambiguous: report it, at the reduced confidence.
        let c = CtxBuilder::new()
            .tx(b256(1), addr(ATTACKER), buy_tkn(90))
            .tx(b256(2), addr(VICTIM), buy_tkn(80))
            .tx(b256(3), addr(ATTACKER), sell_tkn(ETH + ETH / 20))
            .build();

        let found = plugin().detect(&c);
        assert_eq!(found.len(), 1);
        assert_eq!(detail_of(&found[0]).profit_usd, None);
        assert!((found[0].confidence.get() - CONF_UNVALUED).abs() < 1e-9);
    }

    #[test]
    fn empty_block_finds_nothing() {
        assert!(plugin().detect(&CtxBuilder::new().build()).is_empty());
    }

    #[test]
    fn config_round_trips_and_rejects_a_nonsense_threshold() {
        // The validated `UsdPrice` is what makes the gate safe: config can't carry
        // a NaN/negative `min_profit_usd` that would silently disable filtering.
        let json = r#"{"min_profit_usd": 25.0}"#;
        let cfg: SandwichConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.min_profit_usd.get(), 25.0);
        assert!(serde_json::from_str::<SandwichConfig>(r#"{"min_profit_usd": -5.0}"#).is_err());
        // Omitted ⇒ the spec default.
        let defaulted: SandwichConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(defaulted, SandwichConfig::default());
    }

    #[test]
    fn exposes_its_identity_through_the_plugin_seam() {
        // Object-safe dispatch is the contract the registry/service rely on:
        // exercise the detector purely as a `&dyn DetectorPlugin`.
        let detector = plugin();
        let plug: &dyn DetectorPlugin = &detector;
        assert_eq!(plug.id().as_str(), "sandwich");
        assert_eq!(plug.id(), SandwichDetector::ID);
        assert_eq!(plug.version(), SandwichDetector::VERSION);
        assert_eq!(plug.version().to_string(), "1.2.0");
        assert_eq!(plug.kind(), ModelKind::Rule);
        assert_eq!(plug.scope(), Scope::Block);
    }
}
