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
//! ([`store`]'s `write_landing`), which asks the kind's own capability
//! ([`capability::CheckRegistry`]): the worker's, the cross-pod cache's, and the
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
//! # A draft kind is one object ([`capability`])
//!
//! Everything a kind knows about itself — what to fetch, what to ask, whether
//! the answer is usable, what the audit trail records — lives on one
//! [`DraftCapability`](capability::DraftCapability). That is not tidiness: a
//! kind whose *answer-check* was forgotten would land `ready` with no boundary
//! applied, which is the one thing §20.4 exists to prevent, and a `match` arm
//! in another module cannot be made to fail the build. Two registries are built
//! from those objects, and they are deliberately different sets:
//! [`CheckRegistry`](capability::CheckRegistry) is **exhaustive** and held by
//! the store (every pod must be able to land every kind), while
//! [`GeneratorRegistry`](worker::GeneratorRegistry) is the subset this pod may
//! *run* and is the claim filter.
//!
//! # The rule parse boundary (Sprint 20 t4)
//!
//! Natural-language rule creation reuses every one of the above and adds one
//! idea: [`rule_draft`]. A customer's sentence arrives at
//! `POST /v1/rules/draft` with the owner taken from the verified token, is
//! enqueued as `DraftKind::RuleDraft` under a subject id **derived from the
//! request** (so asking twice costs once), and is drafted under a
//! structured-output schema generated from the rule engine's own wire form.
//!
//! The answer then goes through §9's *existing* parser and compiler
//! ([`rule_draft::compile_check`]) inside the same `store::land` the narrative
//! path uses. A hallucinated condition is a parse error, not a rule: the draft
//! lands `blocked` carrying the compiler's own message, exactly as an
//! ungrounded narrative does. A draft that compiles lands `ready` with a
//! plain-language echo rendered from the *compiled* definition, announces
//! `RuleDraftProposed`, and is activated — if the customer wants it — through
//! the ordinary `POST /v1/rules`, which validates it a second time under an
//! owner it takes from the token rather than from the draft.
//!
//! # The governance sweep (Sprint 20 t5)
//!
//! The citation boundary above runs at landing time, against the window the
//! worker was holding. [`grounding_audit`] runs the *same pure check* again —
//! months later, against event-store itself — and answers the question a
//! regulator actually asks: does every claim in this document still resolve in
//! the record? It is a job (`copilot audit`), not a monitor, and it reports
//! through an exit code because a short-lived process is not reliably scraped.
//!
//! Per-customer token budget alarms are the cost half of the same task, and
//! they live in the `usage` service rather than here: spend is a question about
//! the `UsageRecorded` stream every metering path already publishes to (§13),
//! and answering it in this crate would be a second, copilot-shaped view of a
//! number the platform already has one view of. It is an **alarm and not a
//! quota** — see `llm::admission`'s spend ceiling for the platform-wide valve,
//! and this product's "meter, never gate" stance for why nothing here refuses a
//! call on a customer's behalf.

pub mod announce;
pub mod audit;
pub mod backfill;
pub mod cache;
pub mod capability;
pub mod config;
pub mod consumer;
pub mod draft;
pub mod grounding;
pub mod grounding_audit;
pub mod http;
pub mod metrics;
pub mod model;
pub mod outbox;
pub mod prompts;
pub mod rule_draft;
pub mod store;
pub mod worker;

#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

pub use backfill::{BackfillConfig, BackfillReport, BackfillRunner};
pub use capability::{CheckRegistry, DraftCapability, Grounding, Landing, RegistryError};
pub use config::Config;
pub use consumer::CopilotConsumer;
pub use grounding::{GroundingPolicy, GroundingSummary};
pub use grounding_audit::{AuditConfig, AuditReport, GroundingAuditor, Outcome};
pub use model::{
    Draft, DraftAnswer, DraftId, DraftJob, DraftKind, DraftSource, DraftStatus, Provenance, Review,
    Reviewed,
};
pub use rule_draft::{compile_check, describe, CompiledDraft, RuleDraftError, RuleDrafter};
pub use store::{
    DraftAttempt, DraftBatchQueue, DraftCache, DraftFilter, DraftQueue, DraftReview, DraftStore,
    DraftWorkQueue, PgDraftStore,
};
pub use worker::{DraftWorkerPool, GeneratorRegistry, PoolConfig};
