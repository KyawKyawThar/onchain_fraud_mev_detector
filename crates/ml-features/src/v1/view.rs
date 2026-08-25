//! The v1 extraction engine: one [`BlockFeatureView`] per block, built in a
//! single pass, then projected to vectors through two exhaustive `match`es.
//!
//! The view is the §17 amortization pattern applied to features: block-wide
//! context (gas median, sender census, tx position index) is computed once
//! and shared across every per-tx vector — the same way `DetectionCtx` itself
//! is built once and fanned across the detector roster. The serving-side
//! consumer (the anomaly detector, t4) holds one view per block; the one-shot
//! [`extract_tx`](super::extract_tx) convenience rebuilds it per call and
//! says so.
//!
//! Determinism contract (§20.1 — a dataset must be reproducible bit-for-bit,
//! across platforms): transactions are iterated **in bundle order** (never a
//! map's), set-shaped aggregates are order-free, every arithmetic path runs
//! through the total helpers in [`crate::stats`] (whose one transcendental is
//! pinned to `libm`), so the same context always yields the same bits.

use std::collections::{HashMap, HashSet};

use alloy_primitives::{Address, B256};
use detector_api::DetectionCtx;

use super::{block_schema, tx_schema, BlockFeature, TxFeature};
use crate::stats::{fraction, log10_1p, mean, median, ratio, std_dev};
use crate::vector::FeatureVector;
use strum::IntoEnumIterator;

const WEI_PER_GWEI: f64 = 1e9;

/// Per-block extraction context: raw aggregate quantities from one pass over
/// the bundle, projected to [`FeatureVector`]s on demand.
///
/// Build once per block ([`new`](Self::new) is `O(txs + actions)`), then
/// [`block_vector`](Self::block_vector) and every
/// [`tx_vector`](Self::tx_vector) are `O(schema + that tx's actions)` — no
/// per-call rescans of the block.
pub struct BlockFeatureView<'a> {
    ctx: &'a DetectionCtx,
    agg: BlockAggregates,
    /// Sender census over the enriched txs — shared by every tx's
    /// `sender_block_tx_share`.
    sender_counts: HashMap<Address, usize>,
    /// Bundle position by hash — `position_in_block` without a linear scan.
    index_of: HashMap<B256, usize>,
}

/// Raw block-wide quantities. Fields are *measurements*; the formulas that
/// turn them into features live in [`block_value`], one match arm per
/// [`BlockFeature`], so the whole schema reads as a single table.
struct BlockAggregates {
    n_block: usize,
    n_enriched: usize,
    creations: usize,
    distinct_senders: usize,
    top_sender_txs: usize,
    repeat_sender_txs: usize,
    gas_known: usize,
    /// `log10(1 + gwei)` per known-gas tx, in block order.
    gwei_logs: Vec<f64>,
    head_mean_gwei: f64,
    median_gwei: f64,
    gas_used_logs: Vec<f64>,
    swap_count: usize,
    priced_swaps: usize,
    swap_usd_total: f64,
    transfer_count: usize,
    priced_transfers: usize,
    transfer_usd_total: f64,
    max_transfer_usd: f64,
    max_tx_flow: f64,
    distinct_pools: usize,
    top_pool_swaps: usize,
    round_trip_pools: usize,
    max_impact: f64,
}

impl<'a> BlockFeatureView<'a> {
    /// Build the block context in one pass over the bundle.
    pub fn new(ctx: &'a DetectionCtx) -> Self {
        let order = ctx.txs();
        let n_block = order.len();
        let enr = ctx.enrichment();

        let index_of: HashMap<B256, usize> =
            order.iter().enumerate().map(|(i, h)| (*h, i)).collect();

        // ── tx structure ─────────────────────────────────────────────────
        let mut n_enriched = 0usize;
        let mut creations = 0usize;
        let mut sender_counts: HashMap<Address, usize> = HashMap::new();
        for hash in order {
            let Some(tx) = enr.tx(*hash) else { continue };
            n_enriched += 1;
            if tx.to.is_none() {
                creations += 1;
            }
            *sender_counts.entry(tx.from).or_insert(0) += 1;
        }
        let top_sender_txs = sender_counts.values().copied().max().unwrap_or(0);
        // Txs whose sender appears more than once in the block — the
        // frontrun/backrun bracket shape (§22) as a block-level statistic.
        let repeat_sender_txs = order
            .iter()
            .filter_map(|h| enr.tx(*h))
            .filter(|t| sender_counts[&t.from] > 1)
            .count();

        // ── gas dynamics ─────────────────────────────────────────────────
        // "Head" = the first tenth of block positions (at least one):
        // priority fees concentrate there when builders order by payment, so
        // the premium of head prices over the block median is an MEV-pressure
        // signature.
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

        // ── value flows + pool interactions (one pass over the actions) ──
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

        for tx in order.iter().filter_map(|h| enr.tx(*h)) {
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
                // Price-impact proxy: swap input vs. the pool's reserve of
                // that token at this block. A swap that moves a whole reserve
                // is the shape of a manipulation, whatever the token's
                // identity.
                if let Some(reserve) = enr.pool(s.pool).and_then(|p| p.reserve_of(s.token_in)) {
                    max_impact = max_impact.max(ratio(f64::from(s.amount_in), f64::from(reserve)));
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

        let agg = BlockAggregates {
            n_block,
            n_enriched,
            creations,
            distinct_senders: sender_counts.len(),
            top_sender_txs,
            repeat_sender_txs,
            gas_known,
            gwei_logs,
            head_mean_gwei,
            median_gwei,
            gas_used_logs,
            swap_count,
            priced_swaps,
            swap_usd_total,
            transfer_count,
            priced_transfers,
            transfer_usd_total,
            max_transfer_usd,
            max_tx_flow,
            distinct_pools: pool_swap_counts.len(),
            top_pool_swaps: pool_swap_counts.values().copied().max().unwrap_or(0),
            round_trip_pools,
            max_impact,
        };

        Self {
            ctx,
            agg,
            sender_counts,
            index_of,
        }
    }

    /// The block-level vector, stamped `v1`.
    pub fn block_vector(&self) -> FeatureVector {
        let values = BlockFeature::iter()
            .map(|f| block_value(f, &self.agg))
            .collect();
        FeatureVector::from_schema_values(block_schema(), values)
    }

    /// The per-tx vector for `tx_hash`, stamped `v1`. `None` only when the
    /// hash is not in the block's bundle — a caller bug worth surfacing, not
    /// a zero vector. A tx that *is* in the bundle but was never enriched
    /// (header-only source) gets its honest vector: position +
    /// `is_enriched = 0`, everything else zero.
    pub fn tx_vector(&self, tx_hash: B256) -> Option<FeatureVector> {
        let idx = *self.index_of.get(&tx_hash)?;
        let t = self.tx_aggregates(tx_hash, idx);
        let values = TxFeature::iter().map(|f| tx_value(f, &t)).collect();
        Some(FeatureVector::from_schema_values(tx_schema(), values))
    }

    /// Per-tx vectors for every transaction in the block, in block order.
    pub fn all_tx_vectors(&self) -> Vec<(B256, FeatureVector)> {
        self.ctx
            .txs()
            .iter()
            .map(|&hash| {
                let vector = self
                    .tx_vector(hash)
                    .expect("hash comes from the bundle itself");
                (hash, vector)
            })
            .collect()
    }

    fn tx_aggregates(&self, tx_hash: B256, idx: usize) -> TxAggregates {
        let enr = self.ctx.enrichment();
        let position = if self.agg.n_block <= 1 {
            0.0
        } else {
            idx as f64 / (self.agg.n_block - 1) as f64
        };

        let mut t = TxAggregates {
            position,
            ..TxAggregates::absent()
        };
        let Some(tx) = enr.tx(tx_hash) else { return t };

        t.is_enriched = true;
        t.is_creation = tx.to.is_none();
        t.swap_count = tx.swaps.len();
        t.transfer_count = tx.transfers.len();
        // How much of the block's (enriched) activity this tx's sender
        // accounts for — > 1/n is the repeat-sender bracket shape.
        t.sender_share = fraction(
            self.sender_counts.get(&tx.from).copied().unwrap_or(0),
            self.agg.n_enriched,
        );

        if let Some(gas) = tx.gas {
            let gwei = gas.effective_gas_price as f64 / WEI_PER_GWEI;
            t.gas = Some(GasFacts {
                gwei,
                vs_median: ratio(gwei, self.agg.median_gwei),
                used: gas.gas_used as f64,
            });
        }

        let mut ins: HashSet<Address> = HashSet::new();
        let mut outs: HashSet<Address> = HashSet::new();
        let mut pools: HashSet<Address> = HashSet::new();
        let mut tokens: HashSet<Address> = HashSet::new();
        let mut directions: HashSet<(Address, Address, Address)> = HashSet::new();
        for s in &tx.swaps {
            pools.insert(s.pool);
            tokens.insert(s.token_in);
            tokens.insert(s.token_out);
            ins.insert(s.token_in);
            outs.insert(s.token_out);
            directions.insert((s.pool, s.token_in, s.token_out));
            if let Some(usd) = enr.usd_value(s.token_in, s.amount_in) {
                t.priced_swaps += 1;
                t.swap_in_usd += usd;
            }
            if let Some(reserve) = enr.pool(s.pool).and_then(|p| p.reserve_of(s.token_in)) {
                t.max_impact = t
                    .max_impact
                    .max(ratio(f64::from(s.amount_in), f64::from(reserve)));
            }
        }
        // A token both entering and leaving this tx's swaps: the chained /
        // closed-cycle shape an arb takes (§22).
        t.chain_overlap = !ins.is_disjoint(&outs);
        // The same pool traded in both directions inside one tx: the
        // single-tx wash / round-trip shape.
        t.self_round_trip = directions
            .iter()
            .any(|&(p, a, b)| a != b && directions.contains(&(p, b, a)));

        for tr in &tx.transfers {
            tokens.insert(tr.token);
            if let Some(usd) = enr.usd_value(tr.token, tr.amount) {
                t.transfer_usd += usd;
                t.max_transfer_usd = t.max_transfer_usd.max(usd);
            }
        }
        t.distinct_pools = pools.len();
        t.distinct_tokens = tokens.len();
        t
    }
}

/// Receipt gas facts of one tx, block-relativized.
#[derive(Clone, Copy)]
struct GasFacts {
    gwei: f64,
    vs_median: f64,
    used: f64,
}

/// Raw per-tx quantities (same measurement/formula split as
/// [`BlockAggregates`]).
struct TxAggregates {
    position: f64,
    is_enriched: bool,
    is_creation: bool,
    swap_count: usize,
    transfer_count: usize,
    /// `same-sender txs / enriched txs`, computed against the view's block
    /// census (an unenriched tx has no sender: honestly zero).
    sender_share: f64,
    gas: Option<GasFacts>,
    swap_in_usd: f64,
    priced_swaps: usize,
    transfer_usd: f64,
    max_transfer_usd: f64,
    distinct_pools: usize,
    distinct_tokens: usize,
    chain_overlap: bool,
    self_round_trip: bool,
    max_impact: f64,
}

impl TxAggregates {
    /// The honest all-absent baseline an unenriched tx keeps.
    fn absent() -> Self {
        Self {
            position: 0.0,
            is_enriched: false,
            is_creation: false,
            swap_count: 0,
            transfer_count: 0,
            sender_share: 0.0,
            gas: None,
            swap_in_usd: 0.0,
            priced_swaps: 0,
            transfer_usd: 0.0,
            max_transfer_usd: 0.0,
            distinct_pools: 0,
            distinct_tokens: 0,
            chain_overlap: false,
            self_round_trip: false,
            max_impact: 0.0,
        }
    }
}

/// The v1 block formula table — one arm per [`BlockFeature`], exhaustive, so
/// the compiler proves every schema entry is computed.
fn block_value(f: BlockFeature, a: &BlockAggregates) -> f64 {
    use BlockFeature as F;
    match f {
        // — tx structure —
        F::TxCountLog => log10_1p(a.n_block as f64),
        F::EnrichedTxFraction => fraction(a.n_enriched, a.n_block),
        F::ContractCreationFraction => fraction(a.creations, a.n_enriched),
        F::DistinctSenderFraction => fraction(a.distinct_senders, a.n_enriched),
        F::TopSenderTxShare => fraction(a.top_sender_txs, a.n_enriched),
        F::RepeatSenderTxFraction => fraction(a.repeat_sender_txs, a.n_enriched),
        // — gas dynamics —
        F::GasKnownFraction => fraction(a.gas_known, a.n_enriched),
        F::GasPriceGweiLogMean => mean(&a.gwei_logs),
        F::GasPriceGweiLogStd => std_dev(&a.gwei_logs),
        F::HeadGasPremium => ratio(a.head_mean_gwei, a.median_gwei),
        F::GasUsedLogMean => mean(&a.gas_used_logs),
        // — value flows —
        F::SwapCountLog => log10_1p(a.swap_count as f64),
        F::TransferCountLog => log10_1p(a.transfer_count as f64),
        F::SwapUsdVolumeLog => log10_1p(a.swap_usd_total),
        F::PricedSwapFraction => fraction(a.priced_swaps, a.swap_count),
        F::TransferUsdVolumeLog => log10_1p(a.transfer_usd_total),
        F::PricedTransferFraction => fraction(a.priced_transfers, a.transfer_count),
        F::MaxTransferUsdLog => log10_1p(a.max_transfer_usd),
        F::FlowConcentration => ratio(a.max_tx_flow, a.swap_usd_total + a.transfer_usd_total),
        // — pool interactions —
        F::DistinctPoolCountLog => log10_1p(a.distinct_pools as f64),
        F::SwapsPerPool => fraction(a.swap_count, a.distinct_pools),
        F::TopPoolSwapShare => fraction(a.top_pool_swaps, a.swap_count),
        F::PoolRoundTripFraction => fraction(a.round_trip_pools, a.distinct_pools),
        F::MaxPoolImpactLog => log10_1p(a.max_impact),
    }
}

/// The v1 per-tx formula table — one arm per [`TxFeature`], exhaustive.
fn tx_value(f: TxFeature, t: &TxAggregates) -> f64 {
    use TxFeature as F;
    match f {
        // — tx structure —
        F::PositionInBlock => t.position,
        F::IsEnriched => f64::from(t.is_enriched),
        F::IsContractCreation => f64::from(t.is_creation),
        F::SwapCountLog => log10_1p(t.swap_count as f64),
        F::TransferCountLog => log10_1p(t.transfer_count as f64),
        F::SenderBlockTxShare => t.sender_share,
        // — gas dynamics —
        F::GasKnown => f64::from(t.gas.is_some()),
        F::GasPriceGweiLog => t.gas.map_or(0.0, |g| log10_1p(g.gwei)),
        F::GasPriceVsBlockMedian => t.gas.map_or(0.0, |g| g.vs_median),
        F::GasUsedLog => t.gas.map_or(0.0, |g| log10_1p(g.used)),
        // — value flows —
        F::SwapInUsdLog => log10_1p(t.swap_in_usd),
        F::PricedSwapFraction => fraction(t.priced_swaps, t.swap_count),
        F::TransferUsdLog => log10_1p(t.transfer_usd),
        F::MaxTransferUsdLog => log10_1p(t.max_transfer_usd),
        // — pool interactions —
        F::DistinctPoolCountLog => log10_1p(t.distinct_pools as f64),
        F::DistinctTokenCountLog => log10_1p(t.distinct_tokens as f64),
        F::SwapChainOverlap => f64::from(t.chain_overlap),
        F::SelfPoolRoundTrip => f64::from(t.self_round_trip),
        F::MaxPoolImpactLog => log10_1p(t.max_impact),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::{extract_all_txs, extract_block, extract_tx};
    use crate::FEATURE_VERSION;
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

    // ── block-level ──────────────────────────────────────────────────────

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
        assert!((value(&v, "max_transfer_usd_log") - (3.0f64).log10()).abs() < 1e-12);
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

    // ── per-tx ───────────────────────────────────────────────────────────

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
        assert!((value(&v, "gas_price_gwei_log") - (41.0f64).log10()).abs() < 1e-12);
        assert!((value(&v, "gas_used_log") - (100_001.0f64).log10()).abs() < 1e-12);
    }

    #[test]
    fn an_unenriched_tx_in_the_bundle_is_position_plus_zeros() {
        // A header-only context: hashes in the bundle, nothing enriched. The
        // tx still vectorizes — position known, everything else honest zeros.
        let bare = detector_api::DetectionCtx::new(BlockBundle::new(
            Chain::ETHEREUM,
            BlockRef::new(1, b256(0xff)),
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
        assert!((value(&v, "distinct_pool_count_log") - (3.0f64).log10()).abs() < 1e-12);
        assert!((value(&v, "distinct_token_count_log") - (4.0f64).log10()).abs() < 1e-12);

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
        assert!((value(&v, "transfer_usd_log") - (4.0f64).log10()).abs() < 1e-12);
        assert!((value(&v, "max_transfer_usd_log") - (4.0f64).log10()).abs() < 1e-12);
        assert_eq!(value(&v, "sender_block_tx_share"), 2.0 / 3.0);
    }

    // ── the view itself ──────────────────────────────────────────────────

    fn busy_ctx() -> detector_api::DetectionCtx {
        CtxBuilder::new()
            .priced_token(addr(10), 18, 2_000.0)
            .pool(addr(20), addr(10), addr(11), 1_000_000, 500_000)
            .tx_actions(
                TxActions::new(b256(1), addr(1), Some(addr(20)))
                    .with_swaps(vec![swap(addr(20), addr(10), addr(11), 10, 9)])
                    .with_gas(TxGas {
                        gas_used: 120_000,
                        effective_gas_price: 30_000_000_000,
                    }),
            )
            .tx(
                b256(2),
                addr(2),
                vec![swap(addr(20), addr(11), addr(10), 9, 10)],
            )
            .tx(b256(3), addr(1), vec![])
            .build()
    }

    #[test]
    fn one_view_answers_every_granularity_identically_to_the_one_shots() {
        // The amortized path and the convenience path must be the same
        // function — the view IS the implementation, so this locks the
        // wrappers to it.
        let ctx = busy_ctx();
        let view = BlockFeatureView::new(&ctx);
        assert_eq!(view.block_vector(), extract_block(&ctx));
        for hash in ctx.txs() {
            assert_eq!(view.tx_vector(*hash), extract_tx(&ctx, *hash));
        }
        assert_eq!(view.all_tx_vectors(), extract_all_txs(&ctx));
    }

    #[test]
    fn all_tx_vectors_cover_the_block_in_order() {
        let ctx = CtxBuilder::new()
            .tx(b256(3), addr(1), vec![])
            .tx(b256(1), addr(2), vec![])
            .tx(b256(2), addr(3), vec![])
            .build();
        let all = BlockFeatureView::new(&ctx).all_tx_vectors();
        // Block order, not hash order.
        assert_eq!(
            all.iter().map(|(h, _)| *h).collect::<Vec<_>>(),
            vec![b256(3), b256(1), b256(2)]
        );
        for (_, vector) in &all {
            assert_eq!(vector.feature_version(), FEATURE_VERSION);
        }
    }

    #[test]
    fn extraction_is_deterministic() {
        let ctx = busy_ctx();
        assert_eq!(extract_block(&ctx), extract_block(&ctx));
        assert_eq!(extract_tx(&ctx, b256(1)), extract_tx(&ctx, b256(1)));
    }
}
