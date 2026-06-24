//! Detection service (§6) — the fast path: turn an assembled block into
//! provisional alerts in under a second, using on-chain heuristics only. No
//! simulation, no label lookups on the hot path; confidence is attribution-blind
//! (§6).
//!
//! Sprint 3 builds the service in five slices. **This crate currently delivers
//! task 1 — the plugin seam:**
//!
//! - [`plugin::DetectorPlugin`] — the one trait every detector crate implements,
//!   plus its value types ([`plugin::DetectorId`], [`plugin::SemVer`],
//!   [`plugin::ModelKind`], [`plugin::Scope`], [`plugin::Evidence`]).
//! - [`ctx::DetectionCtx`] — what a detector sees about one block. A skeleton
//!   here; enrichment (token/pool/price, **no labels**) lands in task 3.
//! - [`registry`] — **compile-time** detector registration: [`registry::Registry`]
//!   is the live roster, [`registry::register_builtins`] the single greppable
//!   place the linked detectors are named, each behind a Cargo feature (§6: no
//!   dynamic loading; selective open-sourcing).
//!
//! Still ahead this sprint, layering on these types: the model-registry metadata
//! (`config_hash`/`deployed_at`/`performance`, task 2), `DetectionCtx`
//! enrichment (task 3), the `sandwich-v1.2` / `arb-v1.0` detector crates (task
//! 4), and `DetectorTriggered`/`PreliminaryAlertCreated` emission with
//! reorg-versioned cross-block state (task 5).

pub mod ctx;
pub mod plugin;
pub mod registry;

/// Shared detector test doubles. Compiled only for this crate's tests or when a
/// downstream crate enables the `test-util` feature (task 4 detector crates).
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

pub use ctx::{BlockBundle, DetectionCtx};
pub use plugin::{DetectorId, DetectorPlugin, Evidence, ModelKind, Scope, SemVer};
pub use registry::{register_builtins, Registry, RegistryBuilder, RegistryError};
