//! Unit + property tests for `arb-v1.0` (§6, §18, Sprint 4 task 4).
//!
//! Complements the crate's own scenario tests (`src/lib.rs`) with the two things
//! task 4 asks for:
//!
//! 1. **Realistic, mainnet-shaped regression fixtures** — the canonical atomic
//!    arbitrage shape (a triangular cycle) with *real* token addresses
//!    (WETH/USDC/DAI) and plausible magnitudes, so a refactor that breaks on
//!    real-world scale is caught. These reconstruct the documented pattern; the
//!    detector is a pure function of decoded enrichment (no recorded-block replay
//!    harness exists yet), which we build directly.
//!
//! 2. **Property tests** (`proptest`) asserting invariants over the whole input
//!    space:
//!    - **recall**: a profitable closed-cycle arb planted as one tx, embedded at
//!      an arbitrary position among arbitrary noise transactions, is *always*
//!      found (arb is a per-tx decision, so noise can never mask it) — the
//!      property-test analogue of a known-MEV block with ground truth;
//!    - **soundness**: every finding — the planted cycle and any incidental one
//!      the multi-hop noise forms (rare under arb's strict zero-net rule) — is a
//!      genuine closed cycle: exactly one token nets positive (and it both
//!      entered and left the tx), every other token nets to zero, and the
//!      reported profit equals that net;
//!    - **determinism**: `detect` is pure;
//!    - **gate monotonicity**: raising `min_profit_usd` can only ever remove
//!      findings, never add them (per-tx independence makes this exact).
//!
//! The block-scenario scaffolding (`TxSpec`/`Scenario`/`planted_in_noise`) lives
//! in `detector_api::test_util`, shared with the other detectors' tests; only the
//! noise *strategy* (multi-hop txs) is local to this crate.

use std::collections::{BTreeMap, BTreeSet};

use alloy_primitives::{address, Address, B256, U256};
use proptest::prelude::*;

use arb_detector::{plugin, ArbConfig, ArbDetail, ArbDetector};
use detector_api::test_util::{
    addr, b256, detail, planted_in_noise, swap, CtxBuilder, Scenario, TxSpec,
};
use detector_api::{DetectorPlugin, Swap, UsdPrice};
use events::primitives::AlertKind;

const ETH: u128 = 1_000_000_000_000_000_000; // 1e18 wei

// ── 1. Realistic, mainnet-shaped regression fixtures ─────────────────────────

// Real mainnet token addresses — facts only, used to make the fixture concretely
// real-world-shaped (§6: addresses are facts, never labels). All 18-decimal here
// except USDC; valuation just needs decimals+price to line up.
const WETH: Address = address!("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
const USDC: Address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
const DAI: Address = address!("6B175474E89094C44Da98b954EedeAC495271d0F");

#[test]
fn flags_a_mainnet_shaped_triangular_arb() {
    // WETH → USDC → DAI → WETH in one tx, ending +0.1 WETH (~$300 @ $3000): a
    // textbook three-hop atomic arbitrage at realistic scale.
    let bot = address!("000000000000000000000000000000000000a4b0");
    let pool_weth_usdc = address!("000000000000000000000000000000000000d001");
    let pool_usdc_dai = address!("000000000000000000000000000000000000d002");
    let pool_dai_weth = address!("000000000000000000000000000000000000d003");

    let ctx = CtxBuilder::new()
        .priced_token(WETH, 18, 3000.0)
        .priced_token(USDC, 18, 1.0) // 18-dec stand-in keeps the round numbers clean
        .priced_token(DAI, 18, 1.0)
        .tx(
            b256(1),
            bot,
            vec![
                swap(pool_weth_usdc, WETH, USDC, 10 * ETH, 30_000 * ETH),
                swap(pool_usdc_dai, USDC, DAI, 30_000 * ETH, 30_000 * ETH),
                swap(pool_dai_weth, DAI, WETH, 30_000 * ETH, 10 * ETH + ETH / 10),
            ],
        )
        .build();

    let found = plugin().detect(&ctx);
    assert_eq!(found.len(), 1, "the arb must be flagged");
    let ev = &found[0];
    assert_eq!(ev.kind, AlertKind::Arbitrage);
    assert_eq!(ev.txs, vec![b256(1)]);

    let d: ArbDetail = detail(ev);
    assert_eq!(d.profit_token, WETH);
    assert_eq!(d.profit_amount, U256::from(ETH / 10));
    assert_eq!(d.profit_usd, Some(300.0)); // 0.1 WETH @ $3000
    assert_eq!(d.hops, 3);
    assert_eq!(d.pools, vec![pool_weth_usdc, pool_usdc_dai, pool_dai_weth]);
}

#[test]
fn ignores_a_mainnet_shaped_open_path() {
    // A real two-hop swap that ends holding DAI (a directional trade), not a
    // closed loop back to the start token — high precision means this is ignored.
    let trader = address!("000000000000000000000000000000000000beef");
    let pool_weth_usdc = address!("000000000000000000000000000000000000d001");
    let pool_usdc_dai = address!("000000000000000000000000000000000000d002");

    let ctx = CtxBuilder::new()
        .priced_token(WETH, 18, 3000.0)
        .priced_token(USDC, 18, 1.0)
        .priced_token(DAI, 18, 1.0)
        .tx(
            b256(1),
            trader,
            vec![
                swap(pool_weth_usdc, WETH, USDC, 10 * ETH, 30_000 * ETH),
                swap(pool_usdc_dai, USDC, DAI, 30_000 * ETH, 30_010 * ETH),
            ],
        )
        .build();

    assert!(plugin().detect(&ctx).is_empty());
}

// ── 2. Property tests ────────────────────────────────────────────────────────

const P_WETH: u8 = 0xAA; // profit token, priced (see `planted_prices`)
const P_USDC: u8 = 0xBB;
const P_POOL1: u8 = 0x50;
const P_POOL2: u8 = 0x51;
const P_BOT: u8 = 0x11;
const PLANTED_TX: u8 = 0xF1;

const NOISE_TOKENS: &[u8] = &[0x01, 0x02];
const NOISE_POOLS: &[u8] = &[0x40, 0x41];
const NOISE_SENDERS: &[u8] = &[0x80, 0x81];
const MAX_NOISE_TXS: usize = 8; // per-tx hash bytes (0..8) stay distinct from 0xF1

/// One arbitrary swap on a noise pool between noise tokens.
fn noise_swap() -> impl Strategy<Value = Swap> {
    (
        prop::sample::select(NOISE_POOLS),
        prop::sample::select(NOISE_TOKENS),
        prop::sample::select(NOISE_TOKENS),
        1u128..=1_000_000,
        1u128..=1_000_000,
    )
        .prop_map(|(pool, ti, to, ai, ao)| swap(addr(pool), addr(ti), addr(to), ai, ao))
}

/// A block of arbitrary noise transactions: `(sender_byte, swaps)` each. Up to
/// four swaps so a noise tx *can* accidentally form a cycle (exercised by the
/// soundness property).
fn noise_block() -> impl Strategy<Value = Vec<(u8, Vec<Swap>)>> {
    prop::collection::vec(
        (
            prop::sample::select(NOISE_SENDERS),
            prop::collection::vec(noise_swap(), 0..4),
        ),
        0..MAX_NOISE_TXS,
    )
}

/// The planted, comfortably-profitable arb: WETH → USDC → WETH in one tx, ending
/// +0.05 WETH (~$100 @ $2000).
fn planted_txs() -> Vec<TxSpec> {
    vec![TxSpec::new(
        b256(PLANTED_TX),
        addr(P_BOT),
        vec![
            swap(addr(P_POOL1), addr(P_WETH), addr(P_USDC), ETH, 2000 * ETH),
            swap(
                addr(P_POOL2),
                addr(P_USDC),
                addr(P_WETH),
                2000 * ETH,
                ETH + ETH / 20,
            ),
        ],
    )]
}

/// Only the planted tokens are priced (WETH dear), so valuation runs on the hot
/// path and the planted profit clears the gate; noise tokens stay unpriced.
fn planted_prices() -> Vec<(Address, u8, f64)> {
    vec![(addr(P_WETH), 18, 2000.0), (addr(P_USDC), 18, 1.0)]
}

/// The detector's own default profit gate — the source of truth the assertions
/// compare against, rather than a duplicated literal.
fn default_gate_usd() -> f64 {
    ArbConfig::default().min_profit_usd.get()
}

/// Re-derive net flow per token across a tx's swaps (an *independent* oracle, not
/// a call into the detector), returning `(received, spent)` maps.
fn net_flow(swaps: &[Swap]) -> (BTreeMap<Address, U256>, BTreeMap<Address, U256>) {
    let mut received: BTreeMap<Address, U256> = BTreeMap::new();
    let mut spent: BTreeMap<Address, U256> = BTreeMap::new();
    for s in swaps {
        let r = received.entry(s.token_out).or_insert(U256::ZERO);
        *r = r.saturating_add(s.amount_out);
        let p = spent.entry(s.token_in).or_insert(U256::ZERO);
        *p = p.saturating_add(s.amount_in);
    }
    (received, spent)
}

proptest! {
    /// Recall: the planted arb is always found, attributed to the planted tx,
    /// profiting the right token by the right amount — for any surrounding noise
    /// and any position. (Per-tx independence means noise can't interfere.)
    #[test]
    fn planted_arb_is_always_found(noise in noise_block(), at in 0usize..=MAX_NOISE_TXS) {
        let scenario = Scenario::from_specs(&planted_prices(), planted_in_noise(&noise, at, &planted_txs()));

        let ours: Vec<ArbDetail> = plugin()
            .detect(scenario.ctx())
            .iter()
            .filter(|e| e.txs == vec![b256(PLANTED_TX)])
            .map(detail::<ArbDetail>)
            .collect();

        prop_assert_eq!(ours.len(), 1, "the planted tx is reported exactly once");
        let d = &ours[0];
        prop_assert_eq!(d.profit_token, addr(P_WETH));
        prop_assert_eq!(d.profit_amount, U256::from(ETH / 20));
        prop_assert_eq!(d.hops, 2);
        prop_assert!(d.profit_usd.expect("profit token is priced") >= default_gate_usd());
    }

    /// Soundness: every finding is a genuine closed cycle — exactly one token
    /// nets positive (and both entered and left the tx), all others net zero, and
    /// the reported profit equals that net.
    #[test]
    fn every_finding_is_a_genuine_closed_cycle(noise in noise_block(), at in 0usize..=MAX_NOISE_TXS) {
        let scenario = Scenario::from_specs(&planted_prices(), planted_in_noise(&noise, at, &planted_txs()));

        for ev in plugin().detect(scenario.ctx()) {
            prop_assert_eq!(ev.kind, AlertKind::Arbitrage);
            prop_assert_eq!(ev.txs.len(), 1, "an arb finding implicates exactly its one tx");
            let c = ev.confidence.get();
            prop_assert!((0.0..=1.0).contains(&c), "confidence {} out of range", c);

            let d: ArbDetail = detail(&ev);
            let swaps = scenario.swaps_of(ev.txs[0]);
            prop_assert!(d.hops >= 2, "a cycle needs at least two hops");
            prop_assert_eq!(d.hops, swaps.len());
            prop_assert_eq!(d.pools.len(), d.hops);

            let (received, spent) = net_flow(swaps);
            // The profit token both entered and left the tx (it cycled), and its
            // net equals the reported profit.
            let r = received.get(&d.profit_token).copied().unwrap_or(U256::ZERO);
            let s = spent.get(&d.profit_token).copied().unwrap_or(U256::ZERO);
            prop_assert!(s > U256::ZERO, "profit token must have been spent (a real loop)");
            prop_assert!(r > s, "profit token must net positive");
            prop_assert_eq!(r - s, d.profit_amount);

            // Every *other* token nets exactly zero — the strict closed-cycle rule.
            let tokens: BTreeSet<&Address> = received.keys().chain(spent.keys()).collect();
            for token in tokens {
                if token == &d.profit_token {
                    continue;
                }
                let r = received.get(token).copied().unwrap_or(U256::ZERO);
                let s = spent.get(token).copied().unwrap_or(U256::ZERO);
                prop_assert_eq!(r, s, "intermediate token {} did not net to zero", token);
            }
        }
    }

    /// Determinism: `detect` is pure — same context, identical findings (§18).
    #[test]
    fn detect_is_deterministic(noise in noise_block(), at in 0usize..=MAX_NOISE_TXS) {
        let scenario = Scenario::from_specs(&planted_prices(), planted_in_noise(&noise, at, &planted_txs()));
        let det = plugin();
        prop_assert_eq!(det.detect(scenario.ctx()), det.detect(scenario.ctx()));
    }

    /// Gate monotonicity: raising `min_profit_usd` only ever removes findings.
    /// Arb decides each tx independently, so the strict roster is a strict subset
    /// of the permissive one — by tx, not merely by count.
    #[test]
    fn profit_gate_is_monotone(noise in noise_block(), at in 0usize..=MAX_NOISE_TXS) {
        let scenario = Scenario::from_specs(&planted_prices(), planted_in_noise(&noise, at, &planted_txs()));
        let found = |usd: f64| -> BTreeSet<B256> {
            ArbDetector::new(ArbConfig {
                min_profit_usd: UsdPrice::try_new(usd).expect("valid USD threshold"),
            })
            .detect(scenario.ctx())
            .iter()
            .flat_map(|e| e.txs.clone())
            .collect()
        };

        let strict = found(1_000_000_000.0);
        let permissive = found(0.0);
        prop_assert!(
            strict.is_subset(&permissive),
            "a higher gate must not surface a finding a lower gate missed",
        );
        // And the planted, valued arb is suppressed by the strict gate but kept
        // by the permissive one — the gate decides it, not the structure.
        prop_assert!(!strict.contains(&b256(PLANTED_TX)));
        prop_assert!(permissive.contains(&b256(PLANTED_TX)));
    }
}
