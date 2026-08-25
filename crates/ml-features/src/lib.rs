//! Versioned, deterministic ML feature extraction from [`DetectionCtx`]
//! (§20.1, Sprint 18 t1).
//!
//! This crate is the contract between three places that never share a
//! process: the dataset-export binary (t2) writing training rows, offline
//! model training (any stack — the boundary is the ONNX artifact), and the
//! serving-side `anomaly-detector` (t4) building the same vector on the < 1s
//! fast path. Three rules make that contract hold:
//!
//! - **Versioned.** Every [`FeatureVector`] is stamped with the
//!   [`FEATURE_VERSION`] it was extracted under, and each version's schema
//!   ([`block_schema`]/[`tx_schema`]: names, order, semantics) is frozen
//!   forever once shipped — *any* observable change to extraction is a new
//!   version, because a model trained on v1 must be served v1 (the §20.5
//!   serving/training skew check compares exactly this stamp). A snapshot
//!   test pins the current schema and a golden vector so accidental drift
//!   fails CI instead of silently poisoning a model.
//! - **Deterministic.** The same context always yields the same bits:
//!   transactions are iterated in bundle (block) order, set-shaped aggregates
//!   are order-free, and every arithmetic path is total (no `NaN`/`inf` can
//!   reach a vector). Determinism is what makes a dataset defined by
//!   `(time window, feature_version, label rule)` reproducible
//!   byte-for-byte under event-store replay (§16, §20.1).
//! - **Attribution-blind (§6).** Features are structural and statistical
//!   quantities — counts, fractions, log-scaled magnitudes, block-relative
//!   ratios — and never encode *which* address did something. The
//!   [`DetectionCtx`] physically carries no labels, and on top of that this
//!   crate guarantees the stronger property that its output is invariant
//!   under a bijective renaming of every address and tx hash (checked by a
//!   property test): an ML model fed these vectors *cannot* become a
//!   list of known actors in disguise.
//!
//! Four feature families, mirroring what the heuristic detectors reason over:
//! transaction structure, gas dynamics, value flows, pool interactions.
//! Missing upstream data (a header-only source, an unpriced token, a
//! receipt-less tx) is *encoded* via explicit presence features
//! (`is_enriched`, `gas_known_fraction`, `priced_swap_fraction`, …) — never
//! imputed, so a model learns "we couldn't see" as its own signal.
//! Cross-block position deltas (§20.1's fifth family) land additively as a
//! later `FEATURE_VERSION` when the first cross-block ML consumer needs them
//! — they take a `CrossBlockState` input this pure per-block API deliberately
//! doesn't have.

mod block;
mod schema;
mod stats;
mod tx;
mod vector;

use alloy_primitives::B256;
use detector_api::DetectionCtx;

pub use block::extract_block;
pub use schema::{
    block_schema, schema_for, tx_schema, FeatureSchema, FeatureVersion, Granularity,
    FEATURE_VERSION,
};
pub use tx::extract_tx;
pub use vector::FeatureVector;

/// Extract the per-tx vector for every transaction in the block, in block
/// order — the shape the dataset-export binary (t2) writes rows in.
pub fn extract_all_txs(ctx: &DetectionCtx) -> Vec<(B256, FeatureVector)> {
    ctx.txs()
        .iter()
        .map(|&hash| {
            let vector = extract_tx(ctx, hash).expect("hash comes from the bundle itself");
            (hash, vector)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use detector_api::test_util::{addr, b256, CtxBuilder};

    #[test]
    fn extract_all_txs_covers_the_block_in_order() {
        let ctx = CtxBuilder::new()
            .tx(b256(3), addr(1), vec![])
            .tx(b256(1), addr(2), vec![])
            .tx(b256(2), addr(3), vec![])
            .build();
        let all = extract_all_txs(&ctx);
        // Block order, not hash order.
        assert_eq!(
            all.iter().map(|(h, _)| *h).collect::<Vec<_>>(),
            vec![b256(3), b256(1), b256(2)]
        );
        for (hash, vector) in &all {
            assert_eq!(Some(vector.clone()), extract_tx(&ctx, *hash));
            assert_eq!(vector.feature_version(), FEATURE_VERSION);
        }
    }
}
