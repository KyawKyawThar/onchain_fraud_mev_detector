//! Unit + property tests for `sandwich-v1.2` (§6, §18, Sprint 4 task 4).
//!
//! The detector's own crate carries the small, hand-written scenario tests
//! (`src/lib.rs`). This file adds the two things task 4 asks for on top:
//!
//! 1. **Realistic, mainnet-shaped regression fixtures** — the canonical sandwich
//!    shape with *real* token addresses (WETH/USDC) and plausible magnitudes
//!    (whole-ETH frontruns, six-figure-USD victims), so a refactor that still
//!    passes the toy fixtures but breaks on real-world scale is caught. These are
//!    reconstructions of the documented pattern, not a replay of a recorded block
//!    (there is no block-replay harness yet — the detector is a pure function of
//!    decoded enrichment, which we build directly).
//!
//! 2. **Property tests** (`proptest`) that assert invariants over the *whole*
//!    input space rather than one example:
//!    - **recall**: a profitable sandwich planted on its own pool, embedded at an
//!      arbitrary position in an arbitrary block of unrelated "noise" swaps, is
//!      *always* found — the property-test analogue of a known-MEV block with
//!      ground truth;
//!    - **soundness**: every finding the detector emits — the planted one *and*
//!      any the dense noise incidentally forms — is structurally valid:
//!      front/back share a sender that equals the reported attacker, the victims
//!      sit between them with a different sender, profit is positive, and the
//!      implicated-tx list is exactly `[front, victims…, back]` in block order;
//!    - **determinism**: `detect` is a pure function — same context, same output;
//!    - **the profit gate filters, not the structure**: the same planted sandwich
//!      is suppressed under a gate above its profit and reported under a gate
//!      below it.
//!
//! The block-scenario scaffolding (`TxSpec`/`Scenario`/`planted_in_noise`) lives
//! in `detector_api::test_util`, shared with the other detectors' tests; only the
//! noise *strategy* is local, since a sandwich wants a dense shared pool.

use alloy_primitives::{address, Address, U256};
use proptest::prelude::*;

use detector_api::test_util::{
    addr, b256, detail, planted_in_noise, swap, CtxBuilder, Scenario, TxSpec,
};
use detector_api::{DetectorPlugin, Evidence, Swap, UsdPrice};
use events::primitives::AlertKind;
use sandwich_detector::{plugin, SandwichConfig, SandwichDetail, SandwichDetector};

const ETH: u128 = 1_000_000_000_000_000_000; // 1e18 wei
const USDC_UNIT: u128 = 1_000_000; // 1e6, USDC's six decimals

// ── 1. Realistic, mainnet-shaped regression fixtures ─────────────────────────

// Real mainnet token addresses — facts, used here only to make the fixture
// concretely real-world-shaped (§6: addresses are facts, never labels).
const WETH: Address = address!("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
const USDC: Address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
// A real Uniswap-v2-style WETH/USDC pool address.
const POOL_WETH_USDC: Address = address!("B4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc");

#[test]
fn flags_a_mainnet_shaped_weth_usdc_sandwich() {
    // The textbook shape at realistic scale: the attacker fronts with 10 WETH
    // into USDC, a victim buys ~$300k of USDC at the worsened price, and the
    // attacker backs out for 10.4 WETH — a 0.4 WETH (~$1.2k @ $3000) profit.
    let attacker = address!("000000000000000000000000000000000000a11c");
    let victim = address!("000000000000000000000000000000000000c1c7");

    let ctx = CtxBuilder::new()
        .priced_token(WETH, 18, 3000.0)
        .priced_token(USDC, 6, 1.0)
        .tx(
            b256(1),
            attacker,
            vec![swap(
                POOL_WETH_USDC,
                WETH,
                USDC,
                10 * ETH,
                30_000 * USDC_UNIT,
            )],
        )
        .tx(
            b256(2),
            victim,
            vec![swap(
                POOL_WETH_USDC,
                WETH,
                USDC,
                100 * ETH,
                300_000 * USDC_UNIT,
            )],
        )
        .tx(
            b256(3),
            attacker,
            vec![swap(
                POOL_WETH_USDC,
                USDC,
                WETH,
                30_000 * USDC_UNIT,
                10 * ETH + 4 * (ETH / 10), // recover 10.4 WETH
            )],
        )
        .build();

    let found = plugin().detect(&ctx);
    assert_eq!(found.len(), 1, "the sandwich must be flagged");
    let ev = &found[0];
    assert_eq!(ev.kind, AlertKind::Sandwich);
    assert_eq!(ev.txs, vec![b256(1), b256(2), b256(3)]);

    let d: SandwichDetail = detail(ev);
    assert_eq!(d.attacker, attacker);
    assert_eq!(d.pool, POOL_WETH_USDC);
    assert_eq!(d.base_token, WETH);
    assert_eq!(d.target_token, USDC);
    assert_eq!(d.victim_txs, vec![b256(2)]);
    // 0.4 WETH profit @ $3000 = $1200.
    assert_eq!(d.profit_base, U256::from(4 * (ETH / 10)));
    assert_eq!(d.profit_usd, Some(1200.0));
}

#[test]
fn ignores_organic_back_to_back_trades_at_mainnet_scale() {
    // Two different traders buying the same direction on the same pool — heavy
    // organic flow, but no opposite-direction backrun by either, so no sandwich.
    let trader_a = address!("00000000000000000000000000000000000000aa");
    let trader_b = address!("00000000000000000000000000000000000000bb");

    let ctx = CtxBuilder::new()
        .priced_token(WETH, 18, 3000.0)
        .priced_token(USDC, 6, 1.0)
        .tx(
            b256(1),
            trader_a,
            vec![swap(
                POOL_WETH_USDC,
                WETH,
                USDC,
                5 * ETH,
                15_000 * USDC_UNIT,
            )],
        )
        .tx(
            b256(2),
            trader_b,
            vec![swap(
                POOL_WETH_USDC,
                WETH,
                USDC,
                8 * ETH,
                24_000 * USDC_UNIT,
            )],
        )
        .build();

    assert!(plugin().detect(&ctx).is_empty());
}

// ── 2. Property tests ────────────────────────────────────────────────────────
//
// The planted sandwich lives on a pool, attacker, and victim drawn from byte
// ranges disjoint from the noise universe below, so its pool's swap bucket
// contains *only* the planted front/victim/back. That isolation is what makes
// the recall property hold for any surrounding noise and any insertion point.

const P_POOL: u8 = 0xCC;
const P_WETH: u8 = 0xAA; // base token, priced (see `planted_prices`)
const P_TKN: u8 = 0xBB; // target token, priced
const P_ATTACKER: u8 = 0x11;
const P_VICTIM: u8 = 0x22;
const FRONT: u8 = 0xF1;
const VICTIM_TX: u8 = 0xF2;
const BACK: u8 = 0xF3;

// Noise universe — all disjoint from the planted bytes above, and deliberately
// *dense* (few pools/tokens/senders) so unrelated swaps sometimes form an
// incidental sandwich (~1% of blocks, measured) — enough that the soundness
// property isn't only ever re-checking the planted finding across random CI
// seeds. Noise tokens are left unpriced (not in `planted_prices`), so those
// incidental findings are reported on the unvalued path rather than gated as dust.
const NOISE_TOKENS: &[u8] = &[0x01, 0x02];
const NOISE_POOLS: &[u8] = &[0x40, 0x41];
const NOISE_SENDERS: &[u8] = &[0x80, 0x81, 0x82];
const MAX_NOISE_TXS: usize = 8; // keeps per-tx hash bytes (0..8) distinct from 0xF*

/// One unrelated swap on a noise pool between noise tokens.
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

/// A block of arbitrary noise transactions: `(sender_byte, swaps)` each.
fn noise_block() -> impl Strategy<Value = Vec<(u8, Vec<Swap>)>> {
    prop::collection::vec(
        (
            prop::sample::select(NOISE_SENDERS),
            prop::collection::vec(noise_swap(), 0..3),
        ),
        0..MAX_NOISE_TXS,
    )
}

/// The planted, comfortably-profitable sandwich: front buys 1 WETH→TKN, victim
/// buys WETH→TKN, attacker backs out TKN→WETH for 1.05 WETH (~$100 profit).
fn planted_txs() -> Vec<TxSpec> {
    vec![
        TxSpec::new(
            b256(FRONT),
            addr(P_ATTACKER),
            vec![swap(addr(P_POOL), addr(P_WETH), addr(P_TKN), ETH, 90)],
        ),
        TxSpec::new(
            b256(VICTIM_TX),
            addr(P_VICTIM),
            vec![swap(addr(P_POOL), addr(P_WETH), addr(P_TKN), ETH, 80)],
        ),
        TxSpec::new(
            b256(BACK),
            addr(P_ATTACKER),
            vec![swap(
                addr(P_POOL),
                addr(P_TKN),
                addr(P_WETH),
                90,
                ETH + ETH / 20,
            )],
        ),
    ]
}

/// Only the planted base/target tokens are priced; WETH is dear so the planted
/// profit clears the gate. Noise tokens stay unpriced on purpose (see the noise
/// universe note).
fn planted_prices() -> Vec<(Address, u8, f64)> {
    vec![(addr(P_WETH), 18, 2000.0), (addr(P_TKN), 18, 1.0)]
}

/// The detector's own default profit gate — the source of truth the assertions
/// compare against, rather than a duplicated literal.
fn default_gate_usd() -> f64 {
    SandwichConfig::default().min_profit_usd.get()
}

proptest! {
    /// Recall: the planted sandwich is always found, on its own pool, with the
    /// right attacker/victim and a profit that clears the gate — regardless of
    /// the surrounding noise or where it sits in the block.
    #[test]
    fn planted_sandwich_is_always_found(noise in noise_block(), at in 0usize..=MAX_NOISE_TXS) {
        let scenario = Scenario::from_specs(&planted_prices(), planted_in_noise(&noise, at, &planted_txs()));

        let ours: Vec<SandwichDetail> = plugin()
            .detect(scenario.ctx())
            .iter()
            .map(detail::<SandwichDetail>)
            .filter(|d| d.pool == addr(P_POOL))
            .collect();

        prop_assert_eq!(ours.len(), 1, "exactly one sandwich on the planted pool");
        let d = &ours[0];
        prop_assert_eq!(d.attacker, addr(P_ATTACKER));
        prop_assert_eq!(d.frontrun_tx, b256(FRONT));
        prop_assert_eq!(d.backrun_tx, b256(BACK));
        prop_assert!(d.victim_txs.contains(&b256(VICTIM_TX)));
        prop_assert_eq!(d.profit_base, U256::from(ETH / 20));
        prop_assert!(d.profit_usd.expect("base token is priced") >= default_gate_usd());
    }

    /// Soundness: every finding the detector emits — planted or incidental — is
    /// structurally a valid sandwich when cross-checked against the context.
    #[test]
    fn every_finding_is_structurally_valid(noise in noise_block(), at in 0usize..=MAX_NOISE_TXS) {
        let scenario = Scenario::from_specs(&planted_prices(), planted_in_noise(&noise, at, &planted_txs()));

        for ev in plugin().detect(scenario.ctx()) {
            prop_assert_eq!(ev.kind, AlertKind::Sandwich);
            let c = ev.confidence.get();
            prop_assert!((0.0..=1.0).contains(&c), "confidence {} out of range", c);

            let d: SandwichDetail = detail(&ev);
            // Front and back are distinct txs by the *same* sender, and that
            // sender is exactly the reported attacker (a fact, never a label).
            prop_assert_ne!(d.frontrun_tx, d.backrun_tx);
            prop_assert_eq!(scenario.sender_of(d.frontrun_tx), d.attacker);
            prop_assert_eq!(scenario.sender_of(d.backrun_tx), d.attacker);
            // At least one victim, none of them the attacker.
            prop_assert!(!d.victim_txs.is_empty());
            for v in &d.victim_txs {
                prop_assert_ne!(scenario.sender_of(*v), d.attacker);
            }
            // Positive recovered profit, and if it could be valued it cleared the
            // default gate.
            prop_assert!(d.profit_base > U256::ZERO);
            if let Some(usd) = d.profit_usd {
                prop_assert!(usd.is_finite());
                prop_assert!(usd >= default_gate_usd());
            }
            // Implicated txs are exactly front, then victims in order, then back.
            let mut expected = vec![d.frontrun_tx];
            expected.extend(d.victim_txs.iter().copied());
            expected.push(d.backrun_tx);
            prop_assert_eq!(ev.txs, expected);
        }
    }

    /// Determinism: `detect` is pure — the same context yields identical findings
    /// every time (what makes a detector replayable in backtests, §18).
    #[test]
    fn detect_is_deterministic(noise in noise_block(), at in 0usize..=MAX_NOISE_TXS) {
        let scenario = Scenario::from_specs(&planted_prices(), planted_in_noise(&noise, at, &planted_txs()));
        let det = plugin();
        prop_assert_eq!(det.detect(scenario.ctx()), det.detect(scenario.ctx()));
    }

    /// The gate filters, not the structure: the planted sandwich (profit ~$100)
    /// is suppressed by a gate above it and reported by a permissive one — so a
    /// negative result is attributable to the threshold, not a structural miss.
    #[test]
    fn profit_gate_decides_planted_sandwich(noise in noise_block(), at in 0usize..=MAX_NOISE_TXS) {
        let scenario = Scenario::from_specs(&planted_prices(), planted_in_noise(&noise, at, &planted_txs()));
        let planted_on_pool = |findings: Vec<Evidence>| {
            findings
                .iter()
                .map(detail::<SandwichDetail>)
                .filter(|d| d.pool == addr(P_POOL))
                .count()
        };
        let gated = |usd: f64| {
            SandwichDetector::new(SandwichConfig {
                min_profit_usd: UsdPrice::try_new(usd).expect("valid USD threshold"),
            })
            .detect(scenario.ctx())
        };

        prop_assert_eq!(planted_on_pool(gated(1_000_000.0)), 0, "gate above profit suppresses it");
        prop_assert_eq!(planted_on_pool(gated(0.0)), 1, "permissive gate reports it");
    }
}
