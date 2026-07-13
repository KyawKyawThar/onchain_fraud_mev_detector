//! The detector seam (§6) — the stable contract every detector crate builds
//! against, independent of the detection *service*.
//!
//! This crate holds exactly what a detector needs and nothing more:
//!
//! - [`plugin::DetectorPlugin`] — the one trait a detector implements, plus its
//!   value types ([`plugin::DetectorId`], [`plugin::SemVer`],
//!   [`plugin::ModelKind`], [`plugin::Scope`], [`plugin::Evidence`]).
//! - [`ctx::DetectionCtx`] — what a detector sees about one block: a
//!   [`ctx::BlockBundle`] of raw facts plus the [`enrichment::Enrichment`]
//!   (token/pool/price + decoded per-tx swaps/transfers, **no labels**).
//!
//! It is split out from the [`detection`] service crate so the two decouple: the
//! service's internals (registry, model registry, feature flags, scheduler,
//! reorg-versioned cross-block state) can churn without recompiling — or even
//! being visible to — the detector crates, which depend only on this thin, stable
//! surface. That is also what lets a closed/premium detector (§6) live in a
//! separate repo behind a minimal dependency. The `detection` crate re-exports
//! everything here, so `detection::DetectorPlugin` and friends keep resolving.
//!
//! The seam is **attribution-blind** by construction: a detector is handed a
//! [`DetectionCtx`] carrying on-chain facts and enrichment but *no labels*, and
//! returns [`Evidence`] describing *behaviour*, never an actor (§6). Attribution
//! happens later, off the hot path, in the intelligence service (§8).
//!
//! [`detection`]: https://docs.rs/detection

pub mod bps;
pub mod cross_block;
pub mod ctx;
pub mod enrichment;
pub mod plugin;

/// Shared detector test doubles. Compiled only for this crate's tests or when a
/// downstream crate enables the `test-util` feature.
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

pub use bps::Bps;
pub use cross_block::CrossBlockDetector;
pub use ctx::{BlockBundle, DetectionCtx};
pub use enrichment::{
    Enrichment, EnrichmentBuilder, InvalidPrice, PoolState, Swap, TokenMeta, TokenTransfer,
    TxActions, UsdPrice,
};
pub use plugin::{
    DetectorId, DetectorPlugin, Evidence, ModelKind, Scope, SemVer, SemVerParseError,
};
