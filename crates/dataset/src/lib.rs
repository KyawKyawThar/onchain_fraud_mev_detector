//! Dataset export (§20.1, Sprint 18 t2) — the training-data flywheel's
//! materialiser.
//!
//! > *"The event store is a deterministic training-data generator. A dataset is
//! > defined by `(time window, feature_version, label rule)` and materialized by
//! > replaying that window (§16) — reproducible byte-for-byte, because replay
//! > is."*
//!
//! This crate is that sentence, executable. It replays a window of the event
//! store, joins every `DetectorTriggered` to the `SimulationCompleted` outcome
//! that confirms or refutes it, extracts an `ml-features` vector for each, and
//! writes labeled `(features, label)` rows to ClickHouse and/or Parquet.
//!
//! ```text
//!   ┌──────────────┐  GET /v1/replay   ┌────────┐  ┌───────┐  ┌─────────────┐
//!   │ event store  │ ────────────────► │  join  │─►│ ctx   │─►│ ml-features │
//!   └──────────────┘   (§16 replay)    └────────┘  │ source│  └──────┬──────┘
//!                                          │       └───────┘         │
//!                          label rule ─────┘                         ▼
//!                                                          ClickHouse / Parquet
//!                                                          + a DatasetManifest
//! ```
//!
//! # Reproducible by construction — and checkable
//!
//! Four independent facts make an export deterministic:
//!
//! 1. The event store is append-only and its replay API returns rows in the
//!    table's own `(occurred_at, event_id)` total order, paginated by keyset on
//!    that same order (§4, §16).
//! 2. `ml-features` guarantees the same context yields the same *bits* on every
//!    platform — its one transcendental is pinned to pure-Rust `libm` for
//!    exactly this reason.
//! 3. The [`join`] is a pure fold: no clock, no random id, no hash-map
//!    iteration in the row-producing path.
//! 4. The [`label`] rule is a total function of the joined outcome.
//!
//! Determinism nobody checks is a comment, so every run emits a
//! [`DatasetManifest`] whose `content_hash` covers the rows (floats hashed by
//! bit pattern) and *not* the run — so two exports of one spec produce the same
//! hash, and any drift in the extractor, the label rule or the stored events
//! moves it.
//!
//! # The two honest gaps
//!
//! Neither is hidden; both are stamped on every row.
//!
//! - **The trigger→alert edge is reconstructed, not read.** `DetectorTriggered`
//!   carries no id and `PreliminaryAlertCreated` carries no block — the same
//!   schema gap that leaves `simulation`'s `JobResolver` stubbed. [`join`]
//!   rebuilds the edge in three layers and *marks* what it could not resolve
//!   ([`join::Binding`]); ambiguous findings are excluded by default.
//! - **The `DetectionCtx` is reconstructed, not replayed.** The event store
//!   holds events, not blocks, so a faithful context needs an archive node and
//!   the decode path that is not wired yet. [`ctx::CtxSource`] is therefore a
//!   seam: [`ctx::ReplayCtxSource`] backs it with what the window itself
//!   reveals, every context declares a [`ctx::Fidelity`], and `--min-fidelity`
//!   decides what is good enough to train on. When the archive-backed source
//!   lands, nothing else in this crate changes.
//!
//! # Attribution-blindness carries through
//!
//! Training data obeys the same rule as the detectors that will consume it
//! (§6, §20.1): features come only from `ml-features`, which extracts from a
//! `DetectionCtx` that physically carries no labels, and nothing in [`row`]
//! adds to that vector. The simulated `profit`/`victim_loss` sit *beside* the
//! label as metadata, never inside `features` — a model handed them would be
//! reading its own answer. The arch-conformance rule keeps `intelligence` off
//! this crate's dependency edge so the property stays structural.

pub mod config;
pub mod ctx;
pub mod export;
pub mod join;
pub mod label;
pub mod manifest;
pub mod metrics;
pub mod migrate;
pub mod row;
pub mod sink;
pub mod source;
pub mod spec;

pub use ctx::{
    CtxSource, CtxSourceFactory, Fidelity, MapCtxSource, ReplayCtxFactory, ReplayCtxSource,
    StaticCtxFactory,
};
pub use export::{run_export, ExportError, ExportOptions};
pub use join::{join, Binding, Finding, JoinResult, JoinStats};
pub use label::{Label, LabelRule, Outcome, LABEL_RULE_ID};
pub use manifest::{DatasetManifest, RowCounts};
pub use row::{DatasetRow, RowDigest};
pub use sink::{DatasetSink, FanOutSink, SinkError};
pub use source::{EventSource, HttpEventSource, RetryPolicy, VecEventSource};
pub use spec::{DatasetSpec, SpecError, DEFAULT_LOOKAHEAD_SECS};
