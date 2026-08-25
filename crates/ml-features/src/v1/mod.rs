//! **Feature schema v1 — FROZEN.** Shipped 2026-08-25; do not edit anything
//! observable here (names, order, kinds, formulas). New or changed extraction
//! semantics are a new version module (`v2`) registered alongside this one —
//! see [`crate::registry`] for the policy and the one-page checklist.
//!
//! The enums below *are* the schema: variant declaration order is vector
//! order, variant names (strum `snake_case`) are the wire names, and the
//! extractor computes values by iterating the enum through one exhaustive
//! `match` per granularity ([`view`]) — so a missing, duplicated, or
//! reordered feature is a compile error, and the name list, the value list,
//! and the [`FeatureKind`] metadata cannot drift apart.
//!
//! Four families (§20.1): tx structure, gas dynamics, value flows, pool
//! interactions. Scaling conventions by [`FeatureKind`]: `LogMagnitude` is
//! `log10(1 + x)`; `Fraction` is `[0, 1]`; `Indicator` is exactly `0`/`1`;
//! `Ratio` is unbounded non-negative. Missing upstream data (header-only
//! source, unpriced token, receipt-less tx) is *encoded* through the presence
//! features, never imputed. Cross-block position deltas (§20.1's fifth
//! family) are deferred to a later version — they need a `CrossBlockState`
//! input this per-block API deliberately doesn't take.

mod view;

use std::sync::LazyLock;

use alloy_primitives::B256;
use detector_api::DetectionCtx;
use strum::{EnumIter, IntoEnumIterator, IntoStaticStr};

use crate::registry::VersionedExtractor;
use crate::schema::{FeatureDef, FeatureKind, FeatureSchema, FeatureVersion, Granularity};
use crate::vector::FeatureVector;

pub use view::BlockFeatureView;

/// The version stamped on every vector this module extracts.
pub const VERSION: FeatureVersion = FeatureVersion(1);

/// Block-level features, in vector order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum BlockFeature {
    // — tx structure —
    TxCountLog,
    EnrichedTxFraction,
    ContractCreationFraction,
    DistinctSenderFraction,
    TopSenderTxShare,
    RepeatSenderTxFraction,
    // — gas dynamics —
    GasKnownFraction,
    GasPriceGweiLogMean,
    GasPriceGweiLogStd,
    HeadGasPremium,
    GasUsedLogMean,
    // — value flows —
    SwapCountLog,
    TransferCountLog,
    SwapUsdVolumeLog,
    PricedSwapFraction,
    TransferUsdVolumeLog,
    PricedTransferFraction,
    MaxTransferUsdLog,
    FlowConcentration,
    // — pool interactions —
    DistinctPoolCountLog,
    SwapsPerPool,
    TopPoolSwapShare,
    PoolRoundTripFraction,
    MaxPoolImpactLog,
}

impl BlockFeature {
    /// The statistical kind — exhaustive, so a new variant cannot ship
    /// unclassified.
    pub fn kind(self) -> FeatureKind {
        use BlockFeature as F;
        match self {
            F::EnrichedTxFraction
            | F::ContractCreationFraction
            | F::DistinctSenderFraction
            | F::TopSenderTxShare
            | F::RepeatSenderTxFraction
            | F::GasKnownFraction
            | F::PricedSwapFraction
            | F::PricedTransferFraction
            | F::FlowConcentration
            | F::TopPoolSwapShare
            | F::PoolRoundTripFraction => FeatureKind::Fraction,
            F::HeadGasPremium | F::SwapsPerPool => FeatureKind::Ratio,
            F::TxCountLog
            | F::GasPriceGweiLogMean
            | F::GasPriceGweiLogStd
            | F::GasUsedLogMean
            | F::SwapCountLog
            | F::TransferCountLog
            | F::SwapUsdVolumeLog
            | F::TransferUsdVolumeLog
            | F::MaxTransferUsdLog
            | F::DistinctPoolCountLog
            | F::MaxPoolImpactLog => FeatureKind::LogMagnitude,
        }
    }
}

/// Per-transaction features, in vector order. Block-relative features
/// (`position_in_block`, `gas_price_vs_block_median`, …) place the tx against
/// the block it rode in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum TxFeature {
    // — tx structure —
    PositionInBlock,
    IsEnriched,
    IsContractCreation,
    SwapCountLog,
    TransferCountLog,
    SenderBlockTxShare,
    // — gas dynamics —
    GasKnown,
    GasPriceGweiLog,
    GasPriceVsBlockMedian,
    GasUsedLog,
    // — value flows —
    SwapInUsdLog,
    PricedSwapFraction,
    TransferUsdLog,
    MaxTransferUsdLog,
    // — pool interactions —
    DistinctPoolCountLog,
    DistinctTokenCountLog,
    SwapChainOverlap,
    SelfPoolRoundTrip,
    MaxPoolImpactLog,
}

impl TxFeature {
    /// The statistical kind — exhaustive, so a new variant cannot ship
    /// unclassified.
    pub fn kind(self) -> FeatureKind {
        use TxFeature as F;
        match self {
            F::PositionInBlock | F::SenderBlockTxShare | F::PricedSwapFraction => {
                FeatureKind::Fraction
            }
            F::IsEnriched
            | F::IsContractCreation
            | F::GasKnown
            | F::SwapChainOverlap
            | F::SelfPoolRoundTrip => FeatureKind::Indicator,
            F::GasPriceVsBlockMedian => FeatureKind::Ratio,
            F::SwapCountLog
            | F::TransferCountLog
            | F::GasPriceGweiLog
            | F::GasUsedLog
            | F::SwapInUsdLog
            | F::TransferUsdLog
            | F::MaxTransferUsdLog
            | F::DistinctPoolCountLog
            | F::DistinctTokenCountLog
            | F::MaxPoolImpactLog => FeatureKind::LogMagnitude,
        }
    }
}

fn defs_of<F>() -> Vec<FeatureDef>
where
    F: IntoEnumIterator + Into<&'static str> + Copy,
    F: HasKind,
{
    F::iter()
        .map(|f| FeatureDef {
            name: f.into(),
            kind: f.kind(),
        })
        .collect()
}

/// Internal glue so [`defs_of`] can ask any of this module's feature enums
/// for its kind.
trait HasKind {
    fn kind(self) -> FeatureKind;
}

impl HasKind for BlockFeature {
    fn kind(self) -> FeatureKind {
        BlockFeature::kind(self)
    }
}

impl HasKind for TxFeature {
    fn kind(self) -> FeatureKind {
        TxFeature::kind(self)
    }
}

/// The v1 block-level schema, derived from [`BlockFeature`].
pub fn block_schema() -> &'static FeatureSchema {
    static DEFS: LazyLock<Vec<FeatureDef>> = LazyLock::new(defs_of::<BlockFeature>);
    static SCHEMA: LazyLock<FeatureSchema> =
        LazyLock::new(|| FeatureSchema::new(VERSION, Granularity::Block, DEFS.as_slice()));
    &SCHEMA
}

/// The v1 per-transaction schema, derived from [`TxFeature`].
pub fn tx_schema() -> &'static FeatureSchema {
    static DEFS: LazyLock<Vec<FeatureDef>> = LazyLock::new(defs_of::<TxFeature>);
    static SCHEMA: LazyLock<FeatureSchema> =
        LazyLock::new(|| FeatureSchema::new(VERSION, Granularity::Tx, DEFS.as_slice()));
    &SCHEMA
}

/// Extract the block-level [`FeatureVector`] for `ctx`.
///
/// One-shot convenience over [`BlockFeatureView`]; total over every context —
/// an empty or header-only block yields the all-zero vector with its presence
/// fractions honestly at zero.
pub fn extract_block(ctx: &DetectionCtx) -> FeatureVector {
    BlockFeatureView::new(ctx).block_vector()
}

/// Extract the per-tx [`FeatureVector`] for `tx_hash` within `ctx`.
///
/// `None` only when `tx_hash` is not in the block's bundle — asking about a
/// tx from some other block is a caller bug worth surfacing, not a zero
/// vector. One-shot convenience: it builds the block context each call, so
/// for more than one tx of the same block hold a [`BlockFeatureView`].
pub fn extract_tx(ctx: &DetectionCtx, tx_hash: B256) -> Option<FeatureVector> {
    BlockFeatureView::new(ctx).tx_vector(tx_hash)
}

/// Per-tx vectors for every transaction in the block, in block order — the
/// shape the dataset-export binary (t2) writes rows in. Amortizes the block
/// context once via [`BlockFeatureView`].
pub fn extract_all_txs(ctx: &DetectionCtx) -> Vec<(B256, FeatureVector)> {
    BlockFeatureView::new(ctx).all_tx_vectors()
}

/// v1's entry in the version registry.
pub struct Extractor;

impl VersionedExtractor for Extractor {
    fn version(&self) -> FeatureVersion {
        VERSION
    }

    fn schema(&self, granularity: Granularity) -> &'static FeatureSchema {
        match granularity {
            Granularity::Block => block_schema(),
            Granularity::Tx => tx_schema(),
        }
    }

    fn extract_block(&self, ctx: &DetectionCtx) -> FeatureVector {
        extract_block(ctx)
    }

    fn extract_tx(&self, ctx: &DetectionCtx, tx_hash: B256) -> Option<FeatureVector> {
        extract_tx(ctx, tx_hash)
    }

    fn extract_all_txs(&self, ctx: &DetectionCtx) -> Vec<(B256, FeatureVector)> {
        extract_all_txs(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schemas_derive_from_the_enums() {
        assert_eq!(block_schema().len(), BlockFeature::iter().count());
        assert_eq!(tx_schema().len(), TxFeature::iter().count());
        // Spot-check the strum name derivation and def alignment.
        let first = block_schema().defs()[0];
        assert_eq!(first.name, "tx_count_log");
        assert_eq!(first.kind, FeatureKind::LogMagnitude);
        let overlap: &'static str = TxFeature::SwapChainOverlap.into();
        assert_eq!(overlap, "swap_chain_overlap");
        assert_eq!(TxFeature::SwapChainOverlap.kind(), FeatureKind::Indicator);
    }

    #[test]
    fn names_are_unique_within_each_schema() {
        for schema in [block_schema(), tx_schema()] {
            let mut seen = std::collections::HashSet::new();
            for name in schema.names() {
                assert!(seen.insert(name), "duplicate feature name {name:?}");
            }
        }
    }

    #[test]
    fn content_hash_distinguishes_the_granularities() {
        // Same version, different layouts — the digest must differ, or a
        // tx-schema model could pass the skew check against block vectors.
        assert_ne!(block_schema().content_hash(), tx_schema().content_hash());
    }
}
