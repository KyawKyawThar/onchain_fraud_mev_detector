//! `arb-v1.0` — the atomic-arbitrage detector (§6, §22 Phase 2).
//!
//! An atomic arbitrage is a *single transaction* that swaps through a closed
//! cycle of AMM pools — `A → B → … → A` — and ends holding **more** of the
//! starting token than it began with, risk-free, because the whole loop settles
//! in one tx. The on-chain signature is precise and unambiguous: across the tx's
//! swaps, exactly one token nets positive (the profit token, which is both spent
//! and received — it cycled) and every other token nets to *zero* (a pure
//! intermediate). A tx that ends net-negative in any token isn't a risk-free arb;
//! one that just accumulates a token it never spent is a buy, not a loop.
//!
//! This detector is a pure, single-block, single-tx function of a
//! [`DetectionCtx`] — it reasons only over each tx's decoded [`Swap`]s — so it's
//! [`Scope::Block`] and parallel-safe across the roster (§17). It is
//! **attribution-blind** (§6): it names the *behaviour* (a profitable closed
//! swap cycle), never the actor. The USD profit gate
//! ([`ArbConfig::min_profit_usd`]) suppresses dust; output is the behaviour-only
//! [`Evidence`] with a typed [`ArbDetail`] payload, stamped with this build's
//! `(id, version, config_hash)` on emission (task 5).
//!
//! # Known limitation (v1.0): high precision, lower recall
//!
//! The "every other token nets *exactly* zero" rule is deliberately strict — it
//! makes a match unambiguous (few false positives), but it misses real arbs that
//! leave dust in an intermediate, pay the gas/builder tip in-tx out of the cycled
//! token, or are only partially decoded by enrichment. That's an acceptable
//! starting stance for v1.0; the gate is a backtest-tunable knob (a tolerance, or
//! a "dominant profit token" relaxation) to revisit against labeled history with
//! the precision/recall harness (Sprint 4 / §18) — change it there, with numbers,
//! not by loosening the invariant on a hunch.

use std::collections::{BTreeMap, BTreeSet};

use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};

use detector_api::{
    DetectionCtx, DetectorId, DetectorPlugin, Evidence, ModelKind, Scope, SemVer, TxActions,
    UsdPrice,
};
use events::primitives::{AlertKind, Confidence};

/// Reference profit gate, matching the sandwich detector's default (§6).
const DEFAULT_MIN_PROFIT_USD: f64 = 10.0;

// Confidence policy, facts-only (§6), gathered here so the scoring is reviewable
// in one place rather than buried in the builder.
/// Base confidence for a closed-cycle arb whose profit we could value.
const CONF_VALUED: f64 = 0.80;
/// Base when the cycle is clean but the profit couldn't be valued (no price).
const CONF_UNVALUED: f64 = 0.60;
/// Added per swap beyond the minimal two-hop loop — a longer cycle is even less
/// likely to be incidental.
const CONF_PER_EXTRA_HOP: f64 = 0.03;
/// Cap on hops that contribute to the score.
const MAX_EXTRA_HOPS: usize = 3;

fn default_min_profit_usd() -> UsdPrice {
    UsdPrice::try_new(DEFAULT_MIN_PROFIT_USD).expect("default min profit is a valid USD price")
}

/// Tunable thresholds for the arb detector. Serialized into the model registry's
/// `config_hash` (§6, task 2/5), so two builds with different gates are
/// distinguishable when replaying historical evidence; deserializable so the
/// service can load `[detectors.arb]` from config (task 5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArbConfig {
    /// Minimum profit (valued via enrichment) for a closed-cycle arb to be
    /// reported. A validated [`UsdPrice`] — so a NaN/negative threshold can't slip
    /// in from config and silently disable the gate. Applied only when the profit
    /// token has a known reference price; an unvalued-but-structural arb is still
    /// reported, at lower confidence (the closed-cycle signature can't be a false
    /// positive on its own). Mirrors the `[detectors.*] min_profit_usd` shape (§6).
    #[serde(default = "default_min_profit_usd")]
    pub min_profit_usd: UsdPrice,
}

impl Default for ArbConfig {
    fn default() -> Self {
        Self {
            min_profit_usd: default_min_profit_usd(),
        }
    }
}

/// The `arb-v1.0` detector. Holds its [`ArbConfig`]; construct one with [`plugin`]
/// for the default thresholds or [`ArbDetector::new`] to override.
#[derive(Debug, Clone)]
pub struct ArbDetector {
    config: ArbConfig,
}

impl ArbDetector {
    /// This detector's stable id — the `arb` of `arb-v1.0`.
    pub const ID: DetectorId = DetectorId::new("arb");
    /// This build's version: `1.0.0`.
    pub const VERSION: SemVer = SemVer::new(1, 0, 0);

    /// Build the detector with explicit thresholds.
    pub fn new(config: ArbConfig) -> Self {
        Self { config }
    }

    /// The active config — what the model registry hashes into `config_hash`.
    pub fn config(&self) -> &ArbConfig {
        &self.config
    }
}

/// Construct the detector with default config, ready to register
/// (`b.register_if(flags.is_enabled(ArbDetector::ID), arb_detector::plugin())`).
pub fn plugin() -> ArbDetector {
    ArbDetector::new(ArbConfig::default())
}

/// The typed detail payload of an arb [`Evidence`] — the on-chain facts that
/// justify the finding (§6), and the contract a downstream consumer (the
/// simulation service, §7) deserializes rather than reaching into untyped JSON.
/// Addresses/hashes are facts, not identities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArbDetail {
    /// The token the cycle starts and ends in, profiting net.
    pub profit_token: Address,
    /// Net gain in `profit_token`, in raw base units.
    pub profit_amount: U256,
    /// That gain in USD, when `profit_token` has a reference price; else `null`.
    pub profit_usd: Option<f64>,
    /// The pools the cycle hopped through, in swap order.
    pub pools: Vec<Address>,
    /// Number of swaps in the cycle (≥ 2).
    pub hops: usize,
}

impl DetectorPlugin for ArbDetector {
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
        // Decides from one tx in one block — no cross-block state.
        Scope::Block
    }

    fn detect(&self, ctx: &DetectionCtx) -> Vec<Evidence> {
        let mut findings = Vec::new();
        for tx_hash in ctx.txs() {
            let Some(tx) = ctx.enrichment().tx(*tx_hash) else {
                continue;
            };
            if let Some(ev) = self.detect_in_tx(ctx, tx) {
                findings.push(ev);
            }
        }
        findings
    }
}

impl ArbDetector {
    /// Test one tx for the closed-cycle arb signature and, if it matches the
    /// profit gate, build its [`Evidence`]. The tx carries its own `hash`.
    fn detect_in_tx(&self, ctx: &DetectionCtx, tx: &TxActions) -> Option<Evidence> {
        // A single swap can't form a cycle.
        if tx.swaps.len() < 2 {
            return None;
        }

        // Net the trader's flow per token across the tx's swaps: each swap spends
        // `token_in` and receives `token_out`. Kept as two unsigned tallies so the
        // sign is read by comparing them — no signed bigint needed.
        let mut received: BTreeMap<Address, U256> = BTreeMap::new();
        let mut spent: BTreeMap<Address, U256> = BTreeMap::new();
        for s in &tx.swaps {
            let r = received.entry(s.token_out).or_insert(U256::ZERO);
            *r = r.saturating_add(s.amount_out);
            let p = spent.entry(s.token_in).or_insert(U256::ZERO);
            *p = p.saturating_add(s.amount_in);
        }

        let (profit_token, profit_amount) = closed_cycle_profit(&received, &spent)?;
        if profit_amount.is_zero() {
            return None;
        }

        let profit_usd = ctx.enrichment().usd_value(profit_token, profit_amount);
        if profit_usd.is_some_and(|usd| usd < self.config.min_profit_usd.get()) {
            return None;
        }

        let hops = tx.swaps.len();
        let mut score = if profit_usd.is_some() {
            CONF_VALUED
        } else {
            CONF_UNVALUED
        };
        let extra_hops = hops.saturating_sub(2).min(MAX_EXTRA_HOPS);
        score += CONF_PER_EXTRA_HOP * (extra_hops as f64);
        let confidence = Confidence::new(score);

        let detail = ArbDetail {
            profit_token,
            profit_amount,
            profit_usd,
            pools: tx.swaps.iter().map(|s| s.pool).collect(),
            hops,
        };
        let detail =
            serde_json::to_value(&detail).expect("ArbDetail is plain data and always serializes");

        Some(Evidence::new(AlertKind::Arbitrage, vec![tx.hash], confidence).with_detail(detail))
    }
}

/// The closed-cycle test: return `(token, net_gain)` iff exactly one token nets
/// positive *and* cycled (was both spent and received), while every other token
/// nets exactly zero. `None` otherwise — including any net loss (not risk-free)
/// or a token merely accumulated without being spent (a buy, not a loop). See the
/// module's "known limitation" note on why the zero-net rule is strict.
fn closed_cycle_profit(
    received: &BTreeMap<Address, U256>,
    spent: &BTreeMap<Address, U256>,
) -> Option<(Address, U256)> {
    let mut profit: Option<(Address, U256)> = None;
    // Unique tokens: the profit token appears in *both* maps, so chaining raw
    // keys would visit it twice and falsely trip the "second positive" guard.
    let tokens: BTreeSet<&Address> = received.keys().chain(spent.keys()).collect();
    for token in tokens {
        let r = received.get(token).copied().unwrap_or(U256::ZERO);
        let s = spent.get(token).copied().unwrap_or(U256::ZERO);
        match r.cmp(&s) {
            std::cmp::Ordering::Equal => {} // balanced intermediate (or untouched).
            std::cmp::Ordering::Greater => {
                // Net long in a token never spent ⇒ not a closed loop.
                if s.is_zero() {
                    return None;
                }
                // A second net-positive token ⇒ not a single clean cycle.
                if profit.is_some() {
                    return None;
                }
                profit = Some((*token, r - s));
            }
            std::cmp::Ordering::Less => return None, // net loss ⇒ not risk-free.
        }
    }
    profit
}

#[cfg(test)]
mod tests {
    use super::*;
    use detector_api::test_util::{addr, b256, swap, CtxBuilder};
    use detector_api::Swap;

    // Tokens: WETH ($2000), USDC ($1), DAI ($1) — all 18-dec here for simple
    // round numbers; valuation just needs decimals+price to line up.
    const WETH: u8 = 0xAA;
    const USDC: u8 = 0xBB;
    const DAI: u8 = 0xCC;
    const TRADER: u8 = 0x11;
    const ETH: u128 = 1_000_000_000_000_000_000;

    /// The three priced tokens every scenario starts from.
    fn priced() -> CtxBuilder {
        CtxBuilder::new()
            .priced_token(addr(WETH), 18, 2000.0)
            .priced_token(addr(USDC), 18, 1.0)
            .priced_token(addr(DAI), 18, 1.0)
    }

    fn leg(pool: u8, token_in: u8, token_out: u8, amount_in: u128, amount_out: u128) -> Swap {
        swap(
            addr(pool),
            addr(token_in),
            addr(token_out),
            amount_in,
            amount_out,
        )
    }

    /// A context with one tx (`hash(1)`, sent by the trader) carrying `swaps`.
    fn one_tx(swaps: Vec<Swap>) -> DetectionCtx {
        priced().tx(b256(1), addr(TRADER), swaps).build()
    }

    fn detail_of(ev: &Evidence) -> ArbDetail {
        serde_json::from_value(ev.detail.clone()).expect("detail round-trips as ArbDetail")
    }

    #[test]
    fn flags_a_two_hop_cycle_with_profit() {
        // WETH → USDC → WETH, ending with 1.05 WETH for 1.0 spent.
        let c = one_tx(vec![
            leg(0x01, WETH, USDC, ETH, 2000 * ETH),
            leg(0x02, USDC, WETH, 2000 * ETH, ETH + ETH / 20),
        ]);
        let found = plugin().detect(&c);
        assert_eq!(found.len(), 1);
        let ev = &found[0];
        assert_eq!(ev.kind, AlertKind::Arbitrage);
        assert_eq!(ev.txs, vec![b256(1)]);

        let detail = detail_of(ev);
        assert_eq!(detail.profit_token, addr(WETH));
        assert_eq!(detail.profit_usd, Some(100.0)); // 0.05 WETH @ $2000.
        assert_eq!(detail.hops, 2);
        assert!((ev.confidence.get() - CONF_VALUED).abs() < 1e-9);
    }

    #[test]
    fn flags_a_triangular_cycle_at_higher_confidence() {
        // WETH → USDC → DAI → WETH, net +0.1 WETH. Three hops ⇒ +0.03 confidence.
        let c = one_tx(vec![
            leg(0x01, WETH, USDC, ETH, 2000 * ETH),
            leg(0x02, USDC, DAI, 2000 * ETH, 2000 * ETH),
            leg(0x03, DAI, WETH, 2000 * ETH, ETH + ETH / 10),
        ]);
        let found = plugin().detect(&c);
        assert_eq!(found.len(), 1);
        assert_eq!(detail_of(&found[0]).hops, 3);
        assert!((found[0].confidence.get() - (CONF_VALUED + CONF_PER_EXTRA_HOP)).abs() < 1e-9);
    }

    #[test]
    fn ignores_a_single_swap() {
        // A lone swap is a trade, not a cycle — even if it looks lucrative.
        let c = one_tx(vec![leg(0x01, WETH, USDC, ETH, 3000 * ETH)]);
        assert!(plugin().detect(&c).is_empty());
    }

    #[test]
    fn ignores_a_losing_round_trip() {
        // WETH → USDC → WETH ending with *less* WETH than spent: net loss.
        let c = one_tx(vec![
            leg(0x01, WETH, USDC, ETH, 2000 * ETH),
            leg(0x02, USDC, WETH, 2000 * ETH, ETH - ETH / 20),
        ]);
        assert!(plugin().detect(&c).is_empty());
    }

    #[test]
    fn ignores_an_open_path_that_never_returns() {
        // WETH → USDC → DAI: ends net-long DAI, net-short WETH. Not a closed loop.
        let c = one_tx(vec![
            leg(0x01, WETH, USDC, ETH, 2000 * ETH),
            leg(0x02, USDC, DAI, 2000 * ETH, 2001 * ETH),
        ]);
        assert!(plugin().detect(&c).is_empty());
    }

    #[test]
    fn profit_below_min_usd_is_filtered() {
        // Closed cycle, but only +1 wei WETH (~$2e-15) — below the $10 gate.
        let c = one_tx(vec![
            leg(0x01, WETH, USDC, ETH, 2000 * ETH),
            leg(0x02, USDC, WETH, 2000 * ETH, ETH + 1),
        ]);
        assert!(plugin().detect(&c).is_empty());
        let permissive = ArbDetector::new(ArbConfig {
            min_profit_usd: UsdPrice::try_new(0.0).unwrap(),
        });
        assert_eq!(permissive.detect(&c).len(), 1);
    }

    #[test]
    fn unpriced_token_still_reports_structure_at_lower_confidence() {
        // A clean cycle whose profit token has no price: report it, lower
        // confidence, `profit_usd` null.
        let c = CtxBuilder::new()
            .tx(
                b256(1),
                addr(TRADER),
                vec![
                    leg(0x01, WETH, USDC, ETH, 2000 * ETH),
                    leg(0x02, USDC, WETH, 2000 * ETH, ETH + ETH / 20),
                ],
            )
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
        let cfg: ArbConfig = serde_json::from_str(r#"{"min_profit_usd": 50.0}"#).unwrap();
        assert_eq!(cfg.min_profit_usd.get(), 50.0);
        assert!(serde_json::from_str::<ArbConfig>(r#"{"min_profit_usd": -1.0}"#).is_err());
        let defaulted: ArbConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(defaulted, ArbConfig::default());
    }

    #[test]
    fn exposes_its_identity_through_the_plugin_seam() {
        let detector = plugin();
        let plug: &dyn DetectorPlugin = &detector;
        assert_eq!(plug.id().as_str(), "arb");
        assert_eq!(plug.id(), ArbDetector::ID);
        assert_eq!(plug.version(), ArbDetector::VERSION);
        assert_eq!(plug.version().to_string(), "1.0.0");
        assert_eq!(plug.kind(), ModelKind::Rule);
        assert_eq!(plug.scope(), Scope::Block);
    }
}
