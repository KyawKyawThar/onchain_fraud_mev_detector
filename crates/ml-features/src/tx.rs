//! Per-transaction feature extraction: one vector placing a single tx against
//! the block it rode in — the input the supervised classifier scores for a
//! candidate the heuristic detectors shaped (§20.2), and the granularity the
//! dataset export joins to `DetectorTriggered` evidence (§20.1).
//!
//! Same determinism contract as [`crate::block`]: bundle-order iteration,
//! order-free aggregates, total arithmetic.

use std::collections::HashSet;

use alloy_primitives::{Address, B256};
use detector_api::DetectionCtx;

use crate::block::WEI_PER_GWEI;
use crate::schema::tx_schema;
use crate::stats::{fraction, log10_1p, median, ratio};
use crate::vector::FeatureVector;

/// Extract the per-tx [`FeatureVector`] for `tx_hash` within `ctx`, stamped
/// with the current `FEATURE_VERSION`.
///
/// `None` only when `tx_hash` is not in the block's bundle — asking about a
/// tx from some other block is a caller bug worth surfacing, not a zero
/// vector. A tx that *is* in the bundle but was never enriched (header-only
/// source) gets its honest vector: position + `is_enriched = 0`, everything
/// else zero.
pub fn extract_tx(ctx: &DetectionCtx, tx_hash: B256) -> Option<FeatureVector> {
    let order = ctx.txs();
    let idx = order.iter().position(|h| *h == tx_hash)?;
    let n_block = order.len();
    let enr = ctx.enrichment();

    let position = if n_block <= 1 {
        0.0
    } else {
        idx as f64 / (n_block - 1) as f64
    };

    // Block context the tx is measured against: the median known gas price.
    let mut block_gwei: Vec<f64> = order
        .iter()
        .filter_map(|h| enr.tx(*h).and_then(|t| t.gas))
        .map(|g| g.effective_gas_price as f64 / WEI_PER_GWEI)
        .collect();
    let median_gwei = median(&mut block_gwei);

    let mut is_enriched = 0.0;
    let mut is_creation = 0.0;
    let mut swap_count = 0usize;
    let mut transfer_count = 0usize;
    let mut sender_share = 0.0;
    let mut gas_known = 0.0;
    let mut gwei_log = 0.0;
    let mut gas_vs_median = 0.0;
    let mut gas_used_log = 0.0;
    let mut swap_in_usd = 0.0;
    let mut priced_swaps = 0usize;
    let mut transfer_usd = 0.0;
    let mut max_transfer_usd = 0.0f64;
    let mut pools: HashSet<Address> = HashSet::new();
    let mut tokens: HashSet<Address> = HashSet::new();
    let mut chain_overlap = 0.0;
    let mut self_round_trip = 0.0;
    let mut max_impact = 0.0f64;

    if let Some(tx) = enr.tx(tx_hash) {
        is_enriched = 1.0;
        is_creation = f64::from(tx.to.is_none());
        swap_count = tx.swaps.len();
        transfer_count = tx.transfers.len();

        // How much of the block's (enriched) activity this tx's sender
        // accounts for — > 1/n is the repeat-sender bracket shape.
        let enriched = order.iter().filter_map(|h| enr.tx(*h));
        let (mut same_sender, mut enriched_count) = (0usize, 0usize);
        for other in enriched {
            enriched_count += 1;
            if other.from == tx.from {
                same_sender += 1;
            }
        }
        sender_share = fraction(same_sender, enriched_count);

        if let Some(gas) = tx.gas {
            gas_known = 1.0;
            let gwei = gas.effective_gas_price as f64 / WEI_PER_GWEI;
            gwei_log = log10_1p(gwei);
            gas_vs_median = ratio(gwei, median_gwei);
            gas_used_log = log10_1p(gas.gas_used as f64);
        }

        let mut ins: HashSet<Address> = HashSet::new();
        let mut outs: HashSet<Address> = HashSet::new();
        let mut directions: HashSet<(Address, Address, Address)> = HashSet::new();
        for s in &tx.swaps {
            pools.insert(s.pool);
            tokens.insert(s.token_in);
            tokens.insert(s.token_out);
            ins.insert(s.token_in);
            outs.insert(s.token_out);
            directions.insert((s.pool, s.token_in, s.token_out));
            if let Some(usd) = enr.usd_value(s.token_in, s.amount_in) {
                priced_swaps += 1;
                swap_in_usd += usd;
            }
            if let Some(reserve) = enr.pool(s.pool).and_then(|p| p.reserve_of(s.token_in)) {
                max_impact = max_impact.max(ratio(f64::from(s.amount_in), f64::from(reserve)));
            }
        }
        // A token both entering and leaving this tx's swaps: the chained /
        // closed-cycle shape an arb takes (§22).
        chain_overlap = f64::from(!ins.is_disjoint(&outs));
        // The same pool traded in both directions inside one tx: the
        // single-tx wash / round-trip shape.
        self_round_trip = f64::from(
            directions
                .iter()
                .any(|&(p, a, b)| a != b && directions.contains(&(p, b, a))),
        );

        for t in &tx.transfers {
            tokens.insert(t.token);
            if let Some(usd) = enr.usd_value(t.token, t.amount) {
                transfer_usd += usd;
                max_transfer_usd = max_transfer_usd.max(usd);
            }
        }
    }

    let pairs = [
        // — tx structure —
        ("position_in_block", position),
        ("is_enriched", is_enriched),
        ("is_contract_creation", is_creation),
        ("swap_count_log", log10_1p(swap_count as f64)),
        ("transfer_count_log", log10_1p(transfer_count as f64)),
        ("sender_block_tx_share", sender_share),
        // — gas dynamics —
        ("gas_known", gas_known),
        ("gas_price_gwei_log", gwei_log),
        ("gas_price_vs_block_median", gas_vs_median),
        ("gas_used_log", gas_used_log),
        // — value flows —
        ("swap_in_usd_log", log10_1p(swap_in_usd)),
        ("priced_swap_fraction", fraction(priced_swaps, swap_count)),
        ("transfer_usd_log", log10_1p(transfer_usd)),
        ("max_transfer_usd_log", log10_1p(max_transfer_usd)),
        // — pool interactions —
        ("distinct_pool_count_log", log10_1p(pools.len() as f64)),
        ("distinct_token_count_log", log10_1p(tokens.len() as f64)),
        ("swap_chain_overlap", chain_overlap),
        ("self_pool_round_trip", self_round_trip),
        ("max_pool_impact_log", log10_1p(max_impact)),
    ];
    Some(FeatureVector::from_pairs(tx_schema(), &pairs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use detector_api::test_util::{addr, b256, swap, transfer, CtxBuilder};
    use detector_api::{TxActions, TxGas};

    fn value(v: &FeatureVector, name: &str) -> f64 {
        v.pairs()
            .expect("current version")
            .find(|(n, _)| *n == name)
            .unwrap_or_else(|| panic!("no feature named {name}"))
            .1
    }

    #[test]
    fn a_hash_outside_the_block_is_a_caller_bug_not_a_vector() {
        let ctx = CtxBuilder::new().tx(b256(1), addr(1), vec![]).build();
        assert!(extract_tx(&ctx, b256(0xEE)).is_none());
    }

    #[test]
    fn position_spans_the_block_and_a_singleton_sits_at_zero() {
        let ctx = CtxBuilder::new()
            .tx(b256(1), addr(1), vec![])
            .tx(b256(2), addr(2), vec![])
            .tx(b256(3), addr(3), vec![])
            .build();
        let at = |h| value(&extract_tx(&ctx, h).unwrap(), "position_in_block");
        assert_eq!(at(b256(1)), 0.0);
        assert_eq!(at(b256(2)), 0.5);
        assert_eq!(at(b256(3)), 1.0);

        let single = CtxBuilder::new().tx(b256(1), addr(1), vec![]).build();
        assert_eq!(
            value(&extract_tx(&single, b256(1)).unwrap(), "position_in_block"),
            0.0
        );
    }

    #[test]
    fn gas_features_measure_the_tx_against_its_block() {
        let mut builder = CtxBuilder::new();
        // Three txs at 10/20/40 gwei — median 20; the 40-gwei tx pays 2×.
        for (i, gwei) in [10u128, 20, 40].into_iter().enumerate() {
            builder = builder.tx_actions(
                TxActions::new(b256(i as u8 + 1), addr(i as u8 + 1), None).with_gas(TxGas {
                    gas_used: 100_000,
                    effective_gas_price: gwei * 1_000_000_000,
                }),
            );
        }
        let ctx = builder.build();
        let v = extract_tx(&ctx, b256(3)).unwrap();
        assert_eq!(value(&v, "gas_known"), 1.0);
        assert!((value(&v, "gas_price_vs_block_median") - 2.0).abs() < 1e-12);
        assert_eq!(value(&v, "gas_price_gwei_log"), (41.0f64).log10());
        assert_eq!(value(&v, "gas_used_log"), (100_001.0f64).log10());
    }

    #[test]
    fn an_unenriched_tx_in_the_bundle_is_position_plus_zeros() {
        // A header-only context: hashes in the bundle, nothing enriched. The
        // tx still vectorizes — position known, everything else honest zeros.
        let bare = detector_api::DetectionCtx::new(detector_api::BlockBundle::new(
            events::primitives::Chain::ETHEREUM,
            events::primitives::BlockRef::new(1, b256(0xff)),
            vec![b256(1), b256(2)],
        ));
        let v = extract_tx(&bare, b256(2)).unwrap();
        assert_eq!(value(&v, "position_in_block"), 1.0);
        assert_eq!(value(&v, "is_enriched"), 0.0);
        assert!(v.values().iter().all(|x| x.is_finite()));
    }

    #[test]
    fn swap_shape_features_see_cycles_and_round_trips() {
        let (a, b, c) = (addr(10), addr(11), addr(12));
        let (p1, p2) = (addr(20), addr(21));
        // Chained a→b→c across two pools: overlap yes, self round trip no.
        let chained = CtxBuilder::new()
            .tx(
                b256(1),
                addr(1),
                vec![swap(p1, a, b, 100, 90), swap(p2, b, c, 90, 80)],
            )
            .build();
        let v = extract_tx(&chained, b256(1)).unwrap();
        assert_eq!(value(&v, "swap_chain_overlap"), 1.0);
        assert_eq!(value(&v, "self_pool_round_trip"), 0.0);
        assert_eq!(value(&v, "distinct_pool_count_log"), (3.0f64).log10());
        assert_eq!(value(&v, "distinct_token_count_log"), (4.0f64).log10());

        // Same pool both directions in one tx: the wash shape.
        let wash = CtxBuilder::new()
            .tx(
                b256(1),
                addr(1),
                vec![swap(p1, a, b, 100, 90), swap(p1, b, a, 90, 99)],
            )
            .build();
        let v = extract_tx(&wash, b256(1)).unwrap();
        assert_eq!(value(&v, "self_pool_round_trip"), 1.0);
    }

    #[test]
    fn value_and_sender_features_combine_block_context() {
        let usdc = addr(10);
        let ctx = CtxBuilder::new()
            .priced_token(usdc, 6, 1.0)
            .transfer_tx(
                b256(1),
                addr(1),
                vec![transfer(usdc, addr(1), addr(2), 3_000_000)],
            )
            .tx(b256(2), addr(2), vec![])
            .tx(b256(3), addr(1), vec![])
            .build();
        let v = extract_tx(&ctx, b256(1)).unwrap();
        assert_eq!(value(&v, "transfer_usd_log"), (4.0f64).log10());
        assert_eq!(value(&v, "max_transfer_usd_log"), (4.0f64).log10());
        assert_eq!(value(&v, "sender_block_tx_share"), 2.0 / 3.0);
    }

    #[test]
    fn extraction_is_deterministic() {
        let ctx = CtxBuilder::new()
            .priced_token(addr(10), 18, 2_000.0)
            .pool(addr(20), addr(10), addr(11), 1_000_000, 500_000)
            .tx(
                b256(1),
                addr(1),
                vec![swap(addr(20), addr(10), addr(11), 10, 9)],
            )
            .build();
        assert_eq!(extract_tx(&ctx, b256(1)), extract_tx(&ctx, b256(1)));
    }
}
