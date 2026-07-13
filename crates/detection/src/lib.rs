//! Detection service (§6) — the fast path: turn an assembled block into
//! provisional alerts in under a second, using on-chain heuristics only. No
//! simulation, no label lookups on the hot path; confidence is attribution-blind
//! (§6).
//!
//! The detector **seam** — the [`DetectorPlugin`] trait, the [`DetectionCtx`] a
//! detector reads, and the [`Evidence`] it returns — lives in the separate
//! [`detector_api`] crate so detectors decouple from this service crate (they
//! depend only on the small, stable seam, not on the registry/scheduler/state
//! that churn here). This crate re-exports it, so `detection::DetectorPlugin`
//! and friends keep resolving.
//!
//! This crate is the **service side**:
//!
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
//! - [`emit`] — **event emission** (task 5): the [`emit::DetectionPlan`] roster —
//!   every live detector paired with its model card at link time — runs over one
//!   block and turns each detector's `Evidence` into the
//!   `DetectorTriggered`/`PreliminaryAlertCreated` wire events, stamped with the
//!   exact [`DetectorRef`] triple. Pairing once and failing on an uncatalogued
//!   detector keeps the per-block emit path total (no fabricated `config_hash`).
//! - [`metrics`] — **per-detector metrics** (Sprint 4 task 3): the single
//!   [`metrics::record_detector_run`] every emit path calls per `detect`
//!   invocation, recording hit rate (`hits / runs`) and latency through the
//!   `metrics` facade (§19), exported by the binary via [`telemetry::metrics`].
//! - [`state`] — **reorg-versioned cross-block state** (task 5):
//!   [`state::CrossBlockState`], the per-block snapshot store a `Scope::CrossBlock`
//!   detector accumulates into so it can be rewound to a common ancestor on a reorg
//!   (§15). The container and its rewind primitive land in task 5; the async
//!   fan-out that feeds it per canonical block is Sprint 4 (task 2).
//! - [`reorg`] — **the event-driven rewind** (Sprint 4 task 1): the object-safe
//!   [`reorg::Rewindable`] view of a cross-block state, [`reorg::apply_reverts`] to
//!   replay one detector's tip-first `BlockReverted` stream onto it, and
//!   [`reorg::CrossBlockStates`] — the roster that owns every cross-block detector's
//!   (type-erased) state and rewinds all of them to the common ancestor on a reorg
//!   (§15). The consumer layer over the `state` primitive that the scheduler calls.
//!
//! Built-in detectors (`sandwich-v1.2`, `arb-v1.0`; task 4) are optional
//! dependencies linked through [`registry::register_builtins`] behind their Cargo
//! features.
//!
//! [`DetectorRef`]: events::primitives::DetectorRef

pub mod config;
pub mod emit;
pub mod flags;
pub mod metrics;
pub mod model;
pub mod registry;
pub mod reorg;
pub mod scheduler;
pub mod state;

// Re-export the detector seam so downstream code keeps using `detection::*`
// (e.g. `detection::DetectorPlugin`, `detection::DetectionCtx`) without caring
// that the seam now lives in its own crate.
pub use detector_api::{
    ctx, enrichment, plugin, BlockBundle, DetectionCtx, DetectorId, DetectorPlugin, Enrichment,
    EnrichmentBuilder, Evidence, InvalidPrice, ModelKind, PoolState, Scope, SemVer,
    SemVerParseError, Swap, TokenMeta, TokenTransfer, TxActions, UsdPrice,
};

pub use emit::{
    detector_triggered, implicated_addresses, preliminary_alert, DetectionPlan, UnlinkedDetector,
};
pub use flags::FeatureFlags;
pub use model::{
    ConfigHash, LifecycleStatus, ModelCard, ModelRegistry, ModelRegistryBuilder,
    ModelRegistryError, Performance,
};
pub use registry::{
    register_builtins, register_cross_block_builtins, Registry, RegistryBuilder, RegistryError,
};
pub use reorg::{
    apply_reverts, CrossBlockSlot, CrossBlockStates, ReorgRewind, Rewindable, RosterRewind,
};
pub use scheduler::{BlockEvent, Scheduler};
pub use state::CrossBlockState;
