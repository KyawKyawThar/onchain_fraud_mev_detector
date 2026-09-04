//! **Projection rebuild** — rebuild a read model from the event store beside
//! the live one, prove it is byte-identical, and swap it in (readiness Epic B).
//!
//! §2 of the architecture says projections are *derived*: the event store is the
//! system of record and every read model — incidents, scores, dashboards — is a
//! fold over it that could be thrown away and recomputed. That is a claim, and
//! an untested claim about a distributed system is a hope. This crate is the
//! test, and the same code is the recovery procedure for every corruption
//! incident that follows.
//!
//! ```text
//!         ┌───────────────────────────────────────────────┐
//!         │  event store (ClickHouse, append-only, §4)    │
//!         └───────────────┬───────────────────────────────┘
//!            GET /v1/watermark  →  pin the cut W
//!            GET /v1/replay     →  [from, W)  ordered, keyset-paged
//!                     ┌──────▼───────┐
//!                     │ ReplaySource │  crate::source
//!                     └──────┬───────┘
//!   digest(live) ──► stage ──► fold via the model's OWN live path ──► digest(staged)
//!                     └──────┬───────┘        │
//!                     ┌──────▼───────┐        └──► diff ──► promote | discard
//!                     │  Projector   │  crate::model (impl'd by the owner
//!                     └──────────────┘                 service, e.g. simulation)
//! ```
//!
//! ## The four decisions worth knowing
//!
//! **1. Nothing is ever wiped.** A rebuild builds a replacement in a staging
//! namespace and swaps it in atomically ([`model::Stageable`]). That removes the
//! window where readers see an empty model, removes "wiped and partially
//! rebuilt" as a reachable state, and makes [`verify`] **non-destructive** — so
//! the drill can run on a timer against production instead of needing an outage.
//!
//! **2. The replay is bounded by a pinned watermark.** The log is appended to
//! while the rebuild runs, so an unbounded replay is a torn read across lanes
//! and reports every event that arrived during the run as a phantom divergence.
//! The cut is on **ingest** time, not event time. See [`driver`].
//!
//! **3. The fold goes through the live consumer, not a copy of it.**
//! [`model::Projector::apply`] is expected to call the same handler Kafka calls.
//! A rebuild that re-implements the fold proves only that the copy agrees with
//! itself. The reference implementation (`simulation::rebuild`) drives
//! `ProjectionConsumer::handle` directly, with the broker removed.
//!
//! **4. "Byte-identical" is over derived columns only, and the exclusions are
//! named.** Columns like `updated_at`/`appended_at` record when *a process wrote
//! the row*, not anything an event said; reproducing them would mean reproducing
//! a clock. Every other column — everything a query can hand a customer — is in
//! the digest. See [`digest`] for why the boundary sits there, and why a column
//! you *want* to exclude is usually a finding rather than an exemption.
//!
//! ## Three traits, not one
//!
//! [`model::Projector`] folds, [`model::Snapshotter`] fingerprints the live
//! model, [`model::Stageable`] builds and swaps the replacement. A read-only
//! [`fingerprint`] takes only a `Snapshotter` and so *cannot* fold an event or
//! promote anything — conventions §2's narrowest-trait corollary, applied.
//!
//! ## What a divergence means
//!
//! [`digest::Divergence`] classifies every disagreeing row, and the class is the
//! diagnosis:
//!
//! | class | live has it | staged has it | what it means |
//! |---|---|---|---|
//! | `lost` | ✓ | ✗ | nothing in the log produced this row — an audit-completeness hole (some path mutated state without emitting an event), or a hand-written row |
//! | `gained` | ✗ | ✓ | the live projection dropped a write it owed — e.g. a store fault between two writes of one event, then a redelivery that folded to a no-op |
//! | `changed` | ✓ | ✓ | the fold and the stored row disagree — usually projection logic deployed without a rebuild |
//!
//! ## Usage
//!
//! ```no_run
//! # async fn example(model: &dyn rebuild::ReadModel) -> anyhow::Result<()> {
//! use rebuild::{EventStoreReplay, RebuildPlan};
//! use tokio_util::sync::CancellationToken;
//!
//! let source = EventStoreReplay::new("http://event-store:8081")?;
//! let shutdown = CancellationToken::new();
//! // The drill: non-destructive, and any divergence is an error.
//! let report = rebuild::verify(model, &source, &RebuildPlan::full(), &shutdown).await?;
//! rebuild::observed::record_report(&report);
//! println!("{}", report.summarize(20));
//! # Ok(())
//! # }
//! ```

pub mod digest;
pub mod driver;
pub mod model;
pub mod observed;
pub mod source;

pub use digest::{Divergence, ModelDigest, RowDigest, RowEncoder};
pub use driver::{
    fingerprint, rebuild, verify, Outcome, RebuildError, RebuildPlan, RebuildReport, VerifyFailure,
};
pub use model::{
    ModelError, Projector, ReadModel, Scope, ScopeSupport, Snapshotter, Stageable, Staging,
};
pub use observed::ObservedReadModel;
pub use source::{
    EventStoreReplay, MergedReplay, PageRequest, ReplayError, ReplayPage, ReplaySource, Watermark,
    DEFAULT_PAGE, MAX_PAGE,
};
