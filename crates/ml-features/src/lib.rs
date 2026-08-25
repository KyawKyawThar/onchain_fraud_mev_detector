//! Versioned, deterministic ML feature extraction from [`DetectionCtx`]
//! (§20.1, Sprint 18 t1).
//!
//! This crate is the contract between three places that never share a
//! process: the dataset-export binary (t2) writing training rows, offline
//! model training (any stack — the boundary is the ONNX artifact), and the
//! serving-side `anomaly-detector` (t4) building the same vector on the < 1s
//! fast path. Three rules make that contract hold:
//!
//! - **Versioned, with versions kept forever.** Every [`FeatureVector`] is
//!   stamped with the [`FeatureVersion`] it was extracted under. Each shipped
//!   version is a frozen module whose feature *enums* are its schema —
//!   variant order is vector order, variant names are wire names, and one
//!   exhaustive `match` per granularity computes the values, so layout drift
//!   is a compile error. The current version is [`FEATURE_VERSION`] (the
//!   crate-root `extract_*` functions and schemas are its re-exports);
//!   historical versions stay resolvable through [`extractor_for`], because a
//!   dataset defined by `(window, feature_version, label rule)` must remain
//!   reproducible after the current version moves on (§20.1, §20.5). Snapshot
//!   tests pin the current schema and golden vectors so accidental drift
//!   fails CI; deliberate change means a new version module.
//! - **Deterministic — across platforms, not just per binary.** The same
//!   context always yields the same bits: transactions are iterated in
//!   bundle (block) order, set-shaped aggregates are order-free, every
//!   arithmetic path is total (no `NaN`/`inf` can reach a vector), and the
//!   one transcendental (`log10`) is pinned to the pure-Rust `libm` so a
//!   dataset exported on macOS matches one exported on Linux bit-for-bit.
//!   Determinism is what makes replay-materialized datasets reproducible
//!   (§16, §20.1).
//! - **Attribution-blind (§6).** Features are structural and statistical
//!   quantities — counts, fractions, log-scaled magnitudes, block-relative
//!   ratios — and never encode *which* address did something. The
//!   [`DetectionCtx`] physically carries no labels, and on top of that this
//!   crate guarantees the stronger property that its output is invariant
//!   under a bijective renaming of every address and tx hash (checked by a
//!   property test): an ML model fed these vectors *cannot* become a list of
//!   known actors in disguise. The arch-conformance rule keeps it that way
//!   structurally (`detector-api` only; `intelligence` forbidden).
//!
//! Each feature carries a [`FeatureKind`] in the schema (and in its
//! [`content_hash`](FeatureSchema::content_hash)) — the statistical shape
//! consumers key off (test bounds, drift statistics, normalization) instead
//! of re-deriving it from naming conventions.
//!
//! # Serving-side usage
//!
//! Per-tx vectors share block-wide context (gas median, sender census). The
//! crate-root one-shot functions rebuild that context per call — fine for a
//! single vector; a consumer extracting many vectors from one block (the
//! anomaly detector's fan-out, the dataset exporter) holds one
//! [`BlockFeatureView`] per block instead:
//!
//! ```
//! use detector_api::test_util::CtxBuilder;
//! use ml_features::BlockFeatureView;
//!
//! let ctx = CtxBuilder::new().build();
//! let view = BlockFeatureView::new(&ctx);
//! let block = view.block_vector();
//! let per_tx = view.all_tx_vectors();
//! # assert_eq!(per_tx.len(), ctx.txs().len());
//! ```

mod registry;
mod schema;
mod stats;
pub mod v1;
mod vector;

use alloy_primitives::B256;
use detector_api::DetectionCtx;

pub use registry::{current, extractor_for, VersionedExtractor};
pub use schema::{FeatureDef, FeatureKind, FeatureSchema, FeatureVersion, Granularity};
pub use v1::BlockFeatureView;
pub use vector::FeatureVector;

/// The current feature-extraction version — what the crate-root functions
/// produce and what new models train against.
pub const FEATURE_VERSION: FeatureVersion = v1::VERSION;

/// The current block-level schema ([`v1::block_schema`]).
pub fn block_schema() -> &'static FeatureSchema {
    v1::block_schema()
}

/// The current per-transaction schema ([`v1::tx_schema`]).
pub fn tx_schema() -> &'static FeatureSchema {
    v1::tx_schema()
}

/// Extract the block-level vector under the current [`FEATURE_VERSION`].
pub fn extract_block(ctx: &DetectionCtx) -> FeatureVector {
    v1::extract_block(ctx)
}

/// Extract the per-tx vector for `tx_hash` under the current
/// [`FEATURE_VERSION`]; `None` iff the hash is not in the block's bundle.
/// For many txs of one block, hold a [`BlockFeatureView`].
pub fn extract_tx(ctx: &DetectionCtx, tx_hash: B256) -> Option<FeatureVector> {
    v1::extract_tx(ctx, tx_hash)
}

/// Per-tx vectors for every transaction in the block, in block order, under
/// the current [`FEATURE_VERSION`] — the shape the dataset-export binary (t2)
/// writes rows in.
pub fn extract_all_txs(ctx: &DetectionCtx) -> Vec<(B256, FeatureVector)> {
    v1::extract_all_txs(ctx)
}
