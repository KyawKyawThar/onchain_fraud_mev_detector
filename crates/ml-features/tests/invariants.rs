//! The crate's contract-level invariants, enforced where drift would
//! otherwise be silent:
//!
//! 1. **The v1 schema and a golden vector are pinned as snapshots.** Any
//!    change to feature names, order, count, kinds, or extraction *semantics*
//!    fails here — the fix is a new frozen version module and a
//!    `FEATURE_VERSION` bump, never an in-place edit (§20.1: the version is
//!    stamped into every dataset and every deployed model, and §20.5's skew
//!    check compares it).
//! 2. **Extraction is total and well-formed on arbitrary blocks** (property
//!    test): finite values, schema-length vectors, version stamped, and each
//!    value inside the range its schema-declared [`FeatureKind`] promises.
//! 3. **Extraction is attribution-blind** (property test): renaming every
//!    address and tx hash through a bijection leaves every vector bit-for-bit
//!    unchanged — no feature can depend on *which* address acted, only on the
//!    structure of what happened (§6 as a checked property, not a comment).
//! 4. **The version registry resolves every shipped version**, and resolving
//!    the current one is the same computation as the crate-root functions.

use alloy_primitives::{Address, B256};
use detector_api::test_util::{swap, transfer, CtxBuilder};
use detector_api::{DetectionCtx, TxActions, TxGas};
use ml_features::{
    block_schema, current, extract_all_txs, extract_block, extract_tx, extractor_for, tx_schema,
    FeatureKind, FeatureVector, FeatureVersion, FEATURE_VERSION,
};
use proptest::prelude::*;

// ── 1. Snapshots: the frozen v1 contract ─────────────────────────────────────

#[test]
fn the_v1_schema_is_frozen() {
    // If this snapshot changes, you are changing the serving/training
    // contract: add a new frozen version module and bump FEATURE_VERSION
    // instead of accepting an in-place edit.
    let mut lock = format!("feature_version: {FEATURE_VERSION}\n");
    for schema in [block_schema(), tx_schema()] {
        lock.push_str(&format!(
            "\n[{:?}] {} features, content_hash {}\n",
            schema.granularity(),
            schema.len(),
            schema.content_hash()
        ));
        for def in schema.defs() {
            lock.push_str(&format!("  {} ({:?})\n", def.name, def.kind));
        }
    }
    insta::assert_snapshot!("v1_schema", lock);
}

/// The canonical scenario the golden vectors are extracted from: a priced
/// sandwich bracket (frontrun / victim / backrun on one pool, with gas facts)
/// plus an unrelated transfer — every feature family is exercised.
fn golden_ctx() -> DetectionCtx {
    let (weth, usdc, dai) = (addr_b(0x10), addr_b(0x11), addr_b(0x12));
    let pool = addr_b(0x20);
    CtxBuilder::new()
        .priced_token(weth, 18, 2_000.0)
        .priced_token(usdc, 6, 1.0)
        .token(dai, 18) // deliberately unpriced
        .pool(
            pool,
            weth,
            usdc,
            1_000_000_000_000_000_000_000,
            2_000_000_000_000,
        )
        .tx_actions(
            TxActions::new(hash_b(1), addr_b(1), Some(pool))
                .with_swaps(vec![swap(
                    pool,
                    weth,
                    usdc,
                    5_000_000_000_000_000_000, // frontrun: 5 WETH in
                    9_900_000_000,
                )])
                .with_gas(TxGas {
                    gas_used: 180_000,
                    effective_gas_price: 80_000_000_000, // 80 gwei — head premium
                }),
        )
        .tx_actions(
            TxActions::new(hash_b(2), addr_b(2), Some(pool))
                .with_swaps(vec![swap(
                    pool,
                    weth,
                    usdc,
                    1_000_000_000_000_000_000, // victim: 1 WETH in
                    1_900_000_000,
                )])
                .with_gas(TxGas {
                    gas_used: 150_000,
                    effective_gas_price: 20_000_000_000,
                }),
        )
        .tx_actions(
            TxActions::new(hash_b(3), addr_b(1), Some(pool))
                .with_swaps(vec![swap(
                    pool,
                    usdc,
                    weth,
                    11_800_000_000, // backrun: USDC back to WETH
                    5_940_000_000_000_000_000,
                )])
                .with_gas(TxGas {
                    gas_used: 170_000,
                    effective_gas_price: 19_000_000_000,
                }),
        )
        .tx_actions(
            TxActions::new(hash_b(4), addr_b(3), Some(addr_b(4))).with_transfers(vec![
                transfer(usdc, addr_b(3), addr_b(4), 250_000_000),
                transfer(dai, addr_b(3), addr_b(4), 42),
            ]),
        )
        .build()
}

fn render(vector: &FeatureVector) -> String {
    // 6-decimal rounding: enough to catch any semantic change, coarse enough
    // to be stable across platform libm implementations.
    vector
        .pairs()
        .expect("current version")
        .map(|(name, value)| format!("{name} = {value:.6}\n"))
        .collect()
}

#[test]
fn the_golden_block_vector_is_frozen() {
    insta::assert_snapshot!("golden_block_vector", render(&extract_block(&golden_ctx())));
}

#[test]
fn the_golden_tx_vector_is_frozen() {
    // The frontrun tx — the shape a supervised candidate scorer sees.
    let ctx = golden_ctx();
    let v = extract_tx(&ctx, hash_b(1)).expect("in the bundle");
    insta::assert_snapshot!("golden_tx_vector", render(&v));
}

// ── 2 + 3. Property tests over arbitrary blocks ──────────────────────────────

fn addr_b(byte: u8) -> Address {
    Address::repeat_byte(byte)
}

fn hash_b(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}

/// An abstract tx spec over small byte-identities, so the same block can be
/// materialized under different address/hash namings.
#[derive(Clone, Debug)]
struct SpecTx {
    sender: u8,
    to: Option<u8>,
    swaps: Vec<(u8, u8, u8, u64, u64)>, // (pool, token_in, token_out, in, out)
    transfers: Vec<(u8, u8, u8, u64)>,  // (token, from, to, amount)
    gas: Option<(u32, u64)>,            // (gas_used, price_wei)
}

/// Materialize `specs` into a context, naming every address through `ab` and
/// every tx hash through `hb` — both must be bijections over bytes for the
/// renaming property to be meaningful.
fn build(specs: &[SpecTx], ab: impl Fn(u8) -> Address, hb: impl Fn(u8) -> B256) -> DetectionCtx {
    // Fixed token/pool universe, named through the same bijection: two priced
    // tokens, one merely-known, one entirely unknown; two pools.
    let mut b = CtxBuilder::new()
        .priced_token(ab(0x10), 18, 2_000.0)
        .priced_token(ab(0x11), 6, 1.0)
        .token(ab(0x12), 18)
        .pool(ab(0x20), ab(0x10), ab(0x11), 1_000_000_000, 500_000_000)
        .pool(ab(0x21), ab(0x11), ab(0x12), 800_000_000, 900_000_000);
    for (i, spec) in specs.iter().enumerate() {
        let mut tx = TxActions::new(hb(i as u8 + 1), ab(spec.sender), spec.to.map(&ab));
        tx = tx.with_swaps(
            spec.swaps
                .iter()
                .map(|&(pool, tin, tout, ain, aout)| {
                    swap(
                        ab(pool),
                        ab(tin),
                        ab(tout),
                        u128::from(ain),
                        u128::from(aout),
                    )
                })
                .collect(),
        );
        tx = tx.with_transfers(
            spec.transfers
                .iter()
                .map(|&(token, from, to, amount)| {
                    transfer(ab(token), ab(from), ab(to), u128::from(amount))
                })
                .collect(),
        );
        if let Some((gas_used, price)) = spec.gas {
            tx = tx.with_gas(TxGas {
                gas_used: u64::from(gas_used),
                effective_gas_price: u128::from(price),
            });
        }
        b = b.tx_actions(tx);
    }
    b.build()
}

fn spec_tx() -> impl Strategy<Value = SpecTx> {
    let token = prop_oneof![Just(0x10u8), Just(0x11), Just(0x12), Just(0x13)];
    let pool = prop_oneof![Just(0x20u8), Just(0x21), Just(0x22)];
    let swap_s = (
        pool,
        token.clone(),
        token.clone(),
        1u64..=10u64.pow(12),
        1u64..=10u64.pow(12),
    );
    let transfer_s = (token, 1u8..=6, 1u8..=6, 1u64..=10u64.pow(12));
    (
        1u8..=6,
        proptest::option::of(1u8..=6),
        proptest::collection::vec(swap_s, 0..3),
        proptest::collection::vec(transfer_s, 0..3),
        proptest::option::of((21_000u32..=1_000_000, 1u64..=500_000_000_000)),
    )
        .prop_map(|(sender, to, swaps, transfers, gas)| SpecTx {
            sender,
            to,
            swaps,
            transfers,
            gas,
        })
}

fn assert_well_formed(v: &FeatureVector, len: usize) {
    assert_eq!(v.feature_version(), FEATURE_VERSION);
    assert_eq!(v.values().len(), len);
    // Each feature's legal range comes from its schema-declared kind — not
    // from name conventions — so a misclassified feature fails here.
    let schema = v.schema().expect("current version");
    for (def, &value) in schema.defs().iter().zip(v.values()) {
        let name = def.name;
        assert!(value.is_finite(), "{name} is not finite: {value}");
        assert!(value >= 0.0, "{name} is negative: {value}");
        if def.kind.unit_bounded() {
            assert!((0.0..=1.0).contains(&value), "{name} out of [0,1]: {value}");
        }
        if def.kind == FeatureKind::Indicator {
            assert!(
                value == 0.0 || value == 1.0,
                "{name} is an indicator but neither 0 nor 1: {value}"
            );
        }
    }
}

proptest! {
    #[test]
    fn every_vector_is_finite_versioned_and_schema_shaped(
        specs in proptest::collection::vec(spec_tx(), 0..8)
    ) {
        let ctx = build(&specs, Address::repeat_byte, B256::repeat_byte);
        assert_well_formed(&extract_block(&ctx), block_schema().len());
        for (_, v) in extract_all_txs(&ctx) {
            assert_well_formed(&v, tx_schema().len());
        }
    }

    #[test]
    fn extraction_is_deterministic_across_rebuilds(
        specs in proptest::collection::vec(spec_tx(), 0..8)
    ) {
        // Two independent materializations of the same spec (fresh HashMaps,
        // fresh iteration state) must agree bit-for-bit.
        let a = build(&specs, Address::repeat_byte, B256::repeat_byte);
        let b = build(&specs, Address::repeat_byte, B256::repeat_byte);
        prop_assert_eq!(extract_block(&a), extract_block(&b));
        prop_assert_eq!(extract_all_txs(&a), extract_all_txs(&b));
    }

    #[test]
    fn features_are_invariant_under_address_and_hash_renaming(
        specs in proptest::collection::vec(spec_tx(), 0..8),
        addr_mask in 1u8..=255,
        hash_mask in 1u8..=255,
    ) {
        // XOR with a non-zero constant is a bijection on bytes, hence on the
        // repeat-byte addresses/hashes the specs materialize to. If any
        // feature depended on an address's *identity* rather than the block's
        // structure, some mask would move it.
        let plain = build(&specs, Address::repeat_byte, B256::repeat_byte);
        let renamed = build(
            &specs,
            move |b| Address::repeat_byte(b ^ addr_mask),
            move |b| B256::repeat_byte(b ^ hash_mask),
        );
        prop_assert_eq!(extract_block(&plain), extract_block(&renamed));
        for (i, _) in specs.iter().enumerate() {
            let byte = i as u8 + 1;
            prop_assert_eq!(
                extract_tx(&plain, B256::repeat_byte(byte)),
                extract_tx(&renamed, B256::repeat_byte(byte ^ hash_mask))
            );
        }
    }
}

// ── 4. The version registry: the current version is one of many ──────────────

#[test]
fn the_registry_resolves_the_current_version_to_the_crate_root_functions() {
    // What t2 (dataset export) relies on: extracting "under version N" via
    // the registry is the same computation as the version's own module.
    let ctx = golden_ctx();
    let extractor = extractor_for(FEATURE_VERSION).expect("current version is registered");
    assert_eq!(extractor.version(), FEATURE_VERSION);
    assert_eq!(current().version(), FEATURE_VERSION);
    assert_eq!(extractor.extract_block(&ctx), extract_block(&ctx));
    assert_eq!(extractor.extract_all_txs(&ctx), extract_all_txs(&ctx));
    assert_eq!(
        extractor.extract_tx(&ctx, hash_b(1)),
        extract_tx(&ctx, hash_b(1))
    );
    let schema = extractor.schema(ml_features::Granularity::Block);
    assert_eq!(schema.content_hash(), block_schema().content_hash());
}

#[test]
fn an_unshipped_version_is_unresolvable() {
    assert!(extractor_for(FeatureVersion(999)).is_none());
}
