//! Detection service (§6) — the fast path: turn an assembled block into
//! provisional alerts in under a second, using on-chain heuristics only. No
//! simulation, no label lookups on the hot path; confidence is attribution-blind
//! (§6).
//!
//! Sprint 3 builds the service in five slices. **This crate currently delivers
//! tasks 1–2 — the plugin seam and the model registry:**
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
//! - [`model`] — the **model registry** (task 2): the catalogue of what we know
//!   about each detector build ([`model::ModelCard`]: `config_hash`,
//!   `deployed_at`, `performance`, lifecycle status), kept separate from the live
//!   roster. Yields the `(id, version, config_hash)` [`DetectorRef`] stamped onto
//!   emitted events.
//! - [`flags`] — **per-detector feature flags** (task 2): the runtime on/off
//!   that gates [`registry::register_builtins`], complementing the compile-time
//!   feature gate.
//!
//! Still ahead this sprint, layering on these types: `DetectionCtx` enrichment
//! (task 3), the `sandwich-v1.2` / `arb-v1.0` detector crates (task 4), and
//! `DetectorTriggered`/`PreliminaryAlertCreated` emission with reorg-versioned
//! cross-block state (task 5).
//!
//! [`DetectorRef`]: events::primitives::DetectorRef

pub mod ctx;
pub mod flags;
pub mod model;
pub mod plugin;
pub mod registry;

/// Shared detector test doubles. Compiled only for this crate's tests or when a
/// downstream crate enables the `test-util` feature (task 4 detector crates).
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

pub use ctx::{BlockBundle, DetectionCtx};
pub use flags::FeatureFlags;
pub use model::{
    ConfigHash, LifecycleStatus, ModelCard, ModelRegistry, ModelRegistryBuilder,
    ModelRegistryError, Performance,
};
pub use plugin::{DetectorId, DetectorPlugin, Evidence, ModelKind, Scope, SemVer};
pub use registry::{register_builtins, Registry, RegistryBuilder, RegistryError};
