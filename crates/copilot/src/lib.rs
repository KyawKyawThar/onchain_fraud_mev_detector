//! The §20.4 LLM investigation copilot — the service half of the `llm` seam
//! (Sprint 20 t2).
//!
//! It consumes `IncidentCreated`, reads the incident's complete audit stream
//! from event-store, and drafts a SAR narrative grounded in it. The draft is a
//! **proposal, never a fact**: it is not published as evidence, it does not
//! touch the entity graph, and nothing downstream may use it until a human
//! approves it (§20.4).
//!
//! # Shape: the slow path, not a plain consumer
//!
//! ```text
//!   IncidentCreated ──▶ CopilotConsumer ──▶ copilot_drafts (queued)
//!                          commits in ms          │
//!                                                 │  claim_batch
//!                                                 ▼   (SKIP LOCKED + lease)
//!                                          DraftWorkerPool
//!                                                 │
//!                        event-store audit ◀──────┤
//!                              llm::LlmClient ◀───┤
//!                                                 ▼
//!                                    copilot_drafts (ready → approved)
//! ```
//!
//! `event_bus::run_consumer` awaits its handler before committing the offset.
//! A completion over an audit stream takes minutes, so a handler that called
//! the model would blow `max.poll.interval.ms`, get evicted, rebalance, and
//! redeliver the record into a *second* run of the same expensive call. The
//! consumer therefore records a job and returns; [`worker`] drains the queue
//! on its own clock. This is the shape §7 already uses for simulation, with
//! one difference: the queue is a Postgres table rather than a broker, because
//! a draft is an auditable artifact with a lifecycle, not a command consumed
//! once (see [`store`]).
//!
//! # The row is also the cache
//!
//! `copilot_drafts` doubles as a cross-pod `llm::CompletionCache` keyed by
//! request digest ([`cache`]). Without it, every rebalance and rolling update
//! re-bills an in-flight draft *and* produces a second, differently-worded
//! version of a document a reviewer may already have read. With it, a
//! completion someone paid for is filed exactly where its audit record lives.
//!
//! # Scope (Sprint 20 t2)
//!
//! This task builds the pipeline: consumer, queue, worker pool, store,
//! approval state, and a v1 narrative prompt to exercise it end to end.
//! Deliberately not here: the per-claim `grounded_event_ids` contract, the
//! `IncidentNarrativeDrafted` emission and the Batch API backfill (t3);
//! natural-language rule drafting and its parse boundary (t4) — for which
//! `DraftKind::RuleDraft` and the kind-agnostic queue already exist; the
//! grounding audit and budget alarms (t5).

pub mod audit;
pub mod cache;
pub mod config;
pub mod consumer;
pub mod draft;
pub mod metrics;
pub mod model;
pub mod prompts;
pub mod store;
pub mod worker;

#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

pub use config::Config;
pub use consumer::CopilotConsumer;
pub use model::{
    Draft, DraftAnswer, DraftId, DraftJob, DraftKind, DraftStatus, Provenance, Review, Reviewed,
};
pub use store::{DraftCache, DraftQueue, DraftReview, DraftStore, DraftWorkQueue, PgDraftStore};
pub use worker::{DraftWorkerPool, GeneratorRegistry, PoolConfig};
