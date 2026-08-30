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
//! # The citation boundary (Sprint 20 t3)
//!
//! A narrative is only useful if a reviewer can check it against the record
//! rather than against the model, so every landed draft goes through
//! [`grounding`]: the citations are parsed out of the text, checked against
//! the window the model was shown, and the draft's `grounded_event_ids` is
//! narrowed from that window to what the narrative actually cites. A draft
//! that cites an event it was never shown is `blocked`, not `ready` — the
//! same statement a refusal makes, for the same reason.
//!
//! Every path that lands an answer applies that one rule through one write
//! ([`store`]'s `write_landing`): the worker's, the cross-pod cache's, and the
//! backfill's batch results. That write also files the
//! `IncidentNarrativeDrafted` announcement ([`announce`]) into
//! `copilot_outbox` **in the same transaction**, so the audit record is
//! exactly as durable as the draft it describes; [`outbox`] publishes it. The
//! draft then stays provisional until a human approves it over [`http`].
//!
//! # Scope
//!
//! Built: the pipeline (consumer, queue, worker pool, store, approval state),
//! the citation boundary, the drafting event, the review API, and the
//! half-price [`backfill`] over the Batch API.
//!
//! Deliberately not here: natural-language rule drafting and its parse
//! boundary (t4) — for which `DraftKind::RuleDraft` and the kind-agnostic
//! queue already exist; the grounding audit test and per-customer budget
//! alarms (t5).

pub mod announce;
pub mod audit;
pub mod backfill;
pub mod cache;
pub mod config;
pub mod consumer;
pub mod draft;
pub mod grounding;
pub mod http;
pub mod metrics;
pub mod model;
pub mod outbox;
pub mod prompts;
pub mod store;
pub mod worker;

#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

pub use backfill::{BackfillConfig, BackfillReport, BackfillRunner};
pub use config::Config;
pub use consumer::CopilotConsumer;
pub use grounding::{GroundingPolicy, GroundingSummary};
pub use model::{
    Draft, DraftAnswer, DraftId, DraftJob, DraftKind, DraftSource, DraftStatus, Provenance, Review,
    Reviewed,
};
pub use store::{
    DraftAttempt, DraftBatchQueue, DraftCache, DraftFilter, DraftQueue, DraftReview, DraftStore,
    DraftWorkQueue, Landing, LandingRule, PgDraftStore,
};
pub use worker::{DraftWorkerPool, GeneratorRegistry, PoolConfig};
