//! Block-level feature extraction: one vector summarizing the whole
//! [`DetectionCtx`] — the input the unsupervised anomaly model scores to flag
//! blocks that look like *nothing seen before* (§20.2).
//!
//! Determinism contract (§20.1 — a dataset must be reproducible
//! byte-for-byte): transactions are iterated **in bundle order** (never the
//! enrichment map's), every set-shaped aggregate (distinct counts, maxima,
//! memberships) is order-independent by construction, and every arithmetic
//! path runs through the total helpers in [`crate::stats`], so the same
//! context always yields the same bits.

use std::collections::{HashMap, HashSet};

use alloy_primitives::Address;
use detector_api::{DetectionCtx, TxActions};

use crate::schema::block_schema;
use crate::stats::{fraction, log10_1p, mean, median, ratio, std_dev};
use crate::vector::FeatureVector;

pub(crate) const WEI_PER_GWEI: f64 = 1e9;

/// Extract the block-level [`FeatureVector`] for `ctx`, stamped with the
/// current `FEATURE_VERSION`.
///
/// Total over every context: an empty block, or a header-only source with no
/// enrichment at all, yields the all-zero vector with its `*_fraction`
/// presence features honestly at zero — absence of data is *encoded*, never
/// imputed (the same "don't guess" stance as a detector returning no findings
/// on an unenriched block).
pub fn extract_block(ctx: &DetectionCtx) -> FeatureVector {
    let order = ctx.txs();
    let n_block = order.len();
    let enr = ctx.enrichment();

    // The enriched txs, in bundle (block) order.
    let txs: Vec<&TxActions> = order.iter().filter_map(|h| enr.tx(*h)).collect();
    let n = txs.len();

    // ── tx structure ─────────────────────────────────────────────────────
    let mut sender_counts: HashMap<Address, usize> = HashMap::new();
    for tx in &txs {
        *sender_counts.entry(tx.from).or_insert(0) += 1;
    }
    let top_sender = sender_counts.values().copied().max().unwrap_or(0);
    // Txs whose sender appears more than once in the block — the
    // frontrun/backrun bracket shape (§22) as a block-level statistic.
    let repeat_sender_txs = txs.iter().filter(|t| sender_counts[&t.from] > 1).count();
    let creations = txs.iter().filter(|t| t.to.is_none()).count();

    // ── gas dynamics ─────────────────────────────────────────────────────
    // "Head" = the first tenth of block positions (at least one): priority
    // fees concentrate there when builders order by payment, so the premium
    // of head prices over the block median is an MEV-pressure signature.
    let head_len = (n_block / 10).max(1);
    let mut gas_known = 0usize;
    let mut gwei_prices = Vec::new(); // block order, known-gas txs only
    let mut head_prices = Vec::new();
    let mut gas_used_logs = Vec::new();
    for (idx, hash) in order.iter().enumerate() {
        let Some(gas) = enr.tx(*hash).and_then(|t| t.gas) else {
            continue;
        };
        gas_known += 1;
        let gwei = gas.effective_gas_price as f64 / WEI_PER_GWEI;
        if idx < head_len {
            head_prices.push(gwei);
        }
        gwei_prices.push(gwei);
        gas_used_logs.push(log10_1p(gas.gas_used as f64));
    }
    let gwei_logs: Vec<f64> = gwei_prices.iter().map(|&g| log10_1p(g)).collect();
    let head_mean_gwei = mean(&head_prices);
    let median_gwei = median(&mut gwei_prices);

    // ── value flows + pool interactions (one pass over the decoded actions) ──
    let mut swap_count = 0usize;
    let mut priced_swaps = 0usize;
    let mut swap_usd_total = 0.0;
    let mut transfer_count = 0usize;
    let mut priced_transfers = 0usize;
    let mut transfer_usd_total = 0.0;
    let mut max_transfer_usd = 0.0f64;
    let mut max_tx_flow = 0.0f64;
    let mut pool_swap_counts: HashMap<Address, usize> = HashMap::new();
    let mut pool_directions: HashSet<(Address, Address, Address)> = HashSet::new();
    let mut max_impact = 0.0f64;

    for tx in &txs {
        let mut tx_flow = 0.0;
        for s in &tx.swaps {
            swap_count += 1;
            *pool_swap_counts.entry(s.pool).or_insert(0) += 1;
            pool_directions.insert((s.pool, s.token_in, s.token_out));
            if let Some(usd) = enr.usd_value(s.token_in, s.amount_in) {
                priced_swaps += 1;
                swap_usd_total += usd;
                tx_flow += usd;
            }
            // Price-impact proxy: swap input vs. the pool's reserve of that
            // token at this block. A swap that moves a whole reserve is the
            // shape of a manipulation, whatever the token's identity.
            if let Some(reserve) = enr.pool(s.pool).and_then(|p| p.reserve_of(s.token_in)) {
                let impact = ratio(f64::from(s.amount_in), f64::from(reserve));
                max_impact = max_impact.max(impact);
            }
        }
        for t in &tx.transfers {
            transfer_count += 1;
            if let Some(usd) = enr.usd_value(t.token, t.amount) {
                priced_transfers += 1;
                transfer_usd_total += usd;
                tx_flow += usd;
                max_transfer_usd = max_transfer_usd.max(usd);
            }
        }
        max_tx_flow = max_tx_flow.max(tx_flow);
    }

    let distinct_pools = pool_swap_counts.len();
    let top_pool = pool_swap_counts.values().copied().max().unwrap_or(0);
    // Pools traded in *both* directions inside one block — the sandwich /
    // wash-trade round-trip signature, counted per pool.
    let round_trip_pools = pool_swap_counts
        .keys()
        .filter(|pool| {
            pool_directions
                .iter()
                .any(|&(p, a, b)| p == **pool && a != b && pool_directions.contains(&(p, b, a)))
        })
        .count();
    let total_flow = swap_usd_total + transfer_usd_total;

    let pairs = [
        // — tx structure —
        ("tx_count_log", log10_1p(n_block as f64)),
        ("enriched_tx_fraction", fraction(n, n_block)),
        ("contract_creation_fraction", fraction(creations, n)),
        ("distinct_sender_fraction", fraction(sender_counts.len(), n)),
        ("top_sender_tx_share", fraction(top_sender, n)),
        ("repeat_sender_tx_fraction", fraction(repeat_sender_txs, n)),
        // — gas dynamics —
        ("gas_known_fraction", fraction(gas_known, n)),
        ("gas_price_gwei_log_mean", mean(&gwei_logs)),
        ("gas_price_gwei_log_std", std_dev(&gwei_logs)),
        ("head_gas_premium", ratio(head_mean_gwei, median_gwei)),
        ("gas_used_log_mean", mean(&gas_used_logs)),
        // — value flows —
        ("swap_count_log", log10_1p(swap_count as f64)),
        ("transfer_count_log", log10_1p(transfer_count as f64)),
        ("swap_usd_volume_log", log10_1p(swap_usd_total)),
        ("priced_swap_fraction", fraction(priced_swaps, swap_count)),
        ("transfer_usd_volume_log", log10_1p(transfer_usd_total)),
        (
            "priced_transfer_fraction",
            fraction(priced_transfers, transfer_count),
        ),
        ("max_transfer_usd_log", log10_1p(max_transfer_usd)),
        ("flow_concentration", ratio(max_tx_flow, total_flow)),
        // — pool interactions —
        ("distinct_pool_count_log", log10_1p(distinct_pools as f64)),
        ("swaps_per_pool", fraction(swap_count, distinct_pools)),
        ("top_pool_swap_share", fraction(top_pool, swap_count)),
        (
            "pool_round_trip_fraction",
            fraction(round_trip_pools, distinct_pools),
        ),
        ("max_pool_impact_log", log10_1p(max_impact)),
    ];
    FeatureVector::from_pairs(block_schema(), &pairs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::FEATURE_VERSION;
    use detector_api::test_util::{addr, b256, swap, transfer, CtxBuilder};
    use detector_api::{BlockBundle, TxActions, TxGas};
    use events::primitives::{BlockRef, Chain};

    fn value(v: &FeatureVector, name: &str) -> f64 {
        v.pairs()
            .expect("current version")
            .find(|(n, _)| *n == name)
            .unwrap_or_else(|| panic!("no feature named {name}"))
            .1
    }

    #[test]
    fn an_empty_block_yields_the_all_zero_vector() {
        let ctx = CtxBuilder::new().build();
        let v = extract_block(&ctx);
        assert_eq!(v.feature_version(), FEATURE_VERSION);
        assert!(v.values().iter().all(|&x| x == 0.0));
    }

    #[test]
    fn a_header_only_source_encodes_absence_not_guesses() {
        // Txs in the bundle, nothing enriched (the live path today): the one
        // non-zero feature is the tx count; every presence fraction is 0.
        let ctx = detector_api::DetectionCtx::new(BlockBundle::new(
            Chain::ETHEREUM,
            BlockRef::new(1, b256(0xff)),
            vec![b256(1), b256(2), b256(3)],
        ));
        let v = extract_block(&ctx);
        assert!(value(&v, "tx_count_log") > 0.0);
        assert_eq!(value(&v, "enriched_tx_fraction"), 0.0);
        assert_eq!(value(&v, "gas_known_fraction"), 0.0);
        assert_eq!(value(&v, "swap_count_log"), 0.0);
    }

    #[test]
    fn sender_structure_sees_the_bracket_shape() {
        // Attacker (addr 1) brackets a victim (addr 2): 2 of 3 txs share a
        // sender.
        let ctx = CtxBuilder::new()
            .tx(b256(1), addr(1), vec![])
            .tx(b256(2), addr(2), vec![])
            .tx(b256(3), addr(1), vec![])
            .build();
        let v = extract_block(&ctx);
        assert_eq!(value(&v, "distinct_sender_fraction"), 2.0 / 3.0);
        assert_eq!(value(&v, "top_sender_tx_share"), 2.0 / 3.0);
        assert_eq!(value(&v, "repeat_sender_tx_fraction"), 2.0 / 3.0);
    }

    #[test]
    fn head_gas_premium_measures_top_of_block_pressure() {
        // 10 txs, head = first position. The head tx pays 100 gwei, the rest
        // pay 10: premium = 100 / 10 = 10.
        let mut builder = CtxBuilder::new();
        for i in 0..10u8 {
            let price = (if i == 0 { 100u128 } else { 10 }) * 1_000_000_000;
            builder = builder.tx_actions(TxActions::new(b256(i + 1), addr(i + 1), None).with_gas(
                TxGas {
                    gas_used: 21_000,
                    effective_gas_price: price,
                },
            ));
        }
        let v = extract_block(&builder.build());
        assert_eq!(value(&v, "gas_known_fraction"), 1.0);
        assert!((value(&v, "head_gas_premium") - 10.0).abs() < 1e-9);
    }

    #[test]
    fn uniform_gas_prices_have_premium_one_and_zero_spread() {
        let mut builder = CtxBuilder::new();
        for i in 0..4u8 {
            builder =
                builder.tx_actions(TxActions::new(b256(i + 1), addr(1), None).with_gas(TxGas {
                    gas_used: 50_000,
                    effective_gas_price: 20_000_000_000,
                }));
        }
        let v = extract_block(&builder.build());
        assert!((value(&v, "head_gas_premium") - 1.0).abs() < 1e-12);
        assert_eq!(value(&v, "gas_price_gwei_log_std"), 0.0);
    }

    #[test]
    fn pool_round_trip_counts_both_direction_pools() {
        let (a, b, c) = (addr(10), addr(11), addr(12));
        let (p1, p2) = (addr(20), addr(21));
        let ctx = CtxBuilder::new()
            .pool(p1, a, b, 1_000_000, 1_000_000)
            .pool(p2, b, c, 1_000_000, 1_000_000)
            // p1 traded both ways (round trip), p2 one way only.
            .tx(b256(1), addr(1), vec![swap(p1, a, b, 100, 90)])
            .tx(b256(2), addr(2), vec![swap(p2, b, c, 100, 90)])
            .tx(b256(3), addr(1), vec![swap(p1, b, a, 90, 99)])
            .build();
        let v = extract_block(&ctx);
        assert_eq!(value(&v, "pool_round_trip_fraction"), 0.5);
        assert_eq!(value(&v, "top_pool_swap_share"), 2.0 / 3.0);
        assert_eq!(value(&v, "swaps_per_pool"), 1.5);
    }

    #[test]
    fn value_flows_combine_prices_and_stay_honest_when_unpriced() {
        let (usdc, mystery) = (addr(10), addr(13));
        let ctx = CtxBuilder::new()
            .priced_token(usdc, 6, 1.0)
            .token(mystery, 18)
            // $2.00 priced transfer + one unpriced transfer.
            .transfer_tx(
                b256(1),
                addr(1),
                vec![
                    transfer(usdc, addr(1), addr(2), 2_000_000),
                    transfer(mystery, addr(1), addr(2), 5),
                ],
            )
            .build();
        let v = extract_block(&ctx);
        assert_eq!(value(&v, "priced_transfer_fraction"), 0.5);
        assert!((value(&v, "transfer_usd_volume_log") - (3.0f64).log10()).abs() < 1e-12);
        assert_eq!(value(&v, "max_transfer_usd_log"), (3.0f64).log10());
        // The single flow-bearing tx carries all of the block's flow.
        assert_eq!(value(&v, "flow_concentration"), 1.0);
    }

    #[test]
    fn max_pool_impact_scales_with_reserve_share() {
        let (a, b) = (addr(10), addr(11));
        let pool = addr(20);
        let ctx = CtxBuilder::new()
            .pool(pool, a, b, 1_000, 1_000)
            // Swap in half the reserve of `a`: impact 0.5.
            .tx(b256(1), addr(1), vec![swap(pool, a, b, 500, 300)])
            .build();
        let v = extract_block(&ctx);
        assert!((value(&v, "max_pool_impact_log") - 1.5f64.log10()).abs() < 1e-12);
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
            .tx(
                b256(2),
                addr(2),
                vec![swap(addr(20), addr(11), addr(10), 9, 10)],
            )
            .build();
        assert_eq!(extract_block(&ctx), extract_block(&ctx));
    }
}
