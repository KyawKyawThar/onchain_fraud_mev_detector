//! The Postgres store (§14): the draft queue, the draft, its approval state,
//! and the cross-pod completion cache — one table, `copilot_drafts`, behind
//! the object-safe [`DraftStore`] seam so the consumer and the worker pool are
//! testable against the in-memory double ([`crate::test_util`]) with no
//! database.
//!
//! # Why the queue is a table and not a broker
//!
//! §7's slow path uses RabbitMQ for simulation jobs, and this deliberately
//! does not. A simulation job is a *command* consumed once; a draft is an
//! artifact with a lifecycle — queued, leased, answered, reviewed — that
//! outlives the work item by months, because a regulatory document has to be
//! auditable long after it was produced. Two stores for one object would need
//! a distributed transaction to stay agreed; one row needs none. (`lapin` is
//! also, by arch-conformance rule, simulation's alone.)
//!
//! # The row *is* the cache entry
//!
//! [`DraftStore::cached_completion`] and [`DraftStore::store_completion`] are
//! `llm::CompletionCache` in store form (see [`crate::cache`]). A completion
//! filed under `(model_digest, request_digest)` is a draft somebody already
//! paid for, so keeping it anywhere else would mean holding a billed answer
//! that no audit trail accounts for — and would let a rolling update produce a
//! second, differently-worded version of a document a reviewer has already
//! read.
//!
//! # Claiming
//!
//! [`DraftStore::claim_batch`] is `FOR UPDATE SKIP LOCKED` over runnable rows,
//! stamping a lease. Every pod runs the same query and they do not collide;
//! a pod that dies mid-call leaves a lease that expires, and the row is
//! reclaimed rather than lost. That is the whole reason the queue is not an
//! in-memory channel fed by the consumer: a channel dies with its process,
//! and the offset it committed says the work was done.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::primitives::{Chain, CustomerId};
use llm::batch::{BatchId, BatchItemOutcome};
use llm::cache::CacheKey;
use llm::{Completion, PromptDescriptor, StopReason, TokenUsage};
use sqlx::PgPool;
use std::str::FromStr;
use uuid::Uuid;

use crate::capability::{CheckRegistry, Landing};
use crate::grounding::{GroundingPolicy, GroundingSummary};
use crate::model::{
    ClaimedJob, Draft, DraftAnswer, DraftId, DraftJob, DraftKind, DraftSource, DraftStatus,
    Provenance, Review, Reviewed,
};

/// A failure reading or writing the draft store. Carries the retry/skip
/// *decision* via [`event_bus::Transience`] — the same contract every other
/// store in this system exposes.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A Postgres round-trip failed. Usually transient (connection/pool/
    /// server), but an encoding/schema fault is a bug that fails identically
    /// on every retry (classified via [`db::is_permanent`]).
    #[error("postgres round-trip failed")]
    Postgres(#[from] sqlx::Error),
    /// A stored column no longer parses into its domain type. Permanent: the
    /// row itself is bad, and retrying re-reads the same bytes.
    #[error("stored value is malformed: {what}")]
    Malformed { what: String },
    /// A review was applied to a draft that is not reviewable (still queued,
    /// or already reviewed). Permanent — the caller's state is wrong, not the
    /// store's.
    #[error("draft {draft_id} is {status} and cannot be reviewed")]
    NotReviewable { draft_id: DraftId, status: String },
    /// The draft named does not exist.
    #[error("no draft {draft_id}")]
    NotFound { draft_id: DraftId },
}

impl StoreError {
    pub(crate) fn malformed(what: impl Into<String>) -> Self {
        StoreError::Malformed { what: what.into() }
    }
}

impl event_bus::Transience for StoreError {
    fn is_transient(&self) -> bool {
        match self {
            StoreError::Postgres(err) => !db::is_permanent(err),
            StoreError::Malformed { .. }
            | StoreError::NotReviewable { .. }
            | StoreError::NotFound { .. } => false,
        }
    }
}

/// What [`DraftStore::enqueue`] decided.
///
/// The distinction is the consumer's whole idempotency story: a redelivered
/// `IncidentCreated` must resolve to the draft that already exists, never mint
/// a second billed one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enqueued {
    /// A new draft job was recorded under this id.
    Queued(DraftId),
    /// A draft for this `(kind, subject)` already existed — its id.
    AlreadyQueued(DraftId),
}

impl Enqueued {
    pub fn draft_id(self) -> DraftId {
        match self {
            Enqueued::Queued(id) | Enqueued::AlreadyQueued(id) => id,
        }
    }

    pub fn is_new(self) -> bool {
        matches!(self, Enqueued::Queued(_))
    }
}

/// How a claimed job ended, as the worker reports it.
///
/// Note what is *not* here: "retry". A worker never decides to retry; it
/// releases the job and the queue re-runs it on the outer clock. That split
/// is the same two-clocks distinction the LLM seam draws between
/// `Transience::is_transient` and `LlmError::retry_now`.
#[derive(Debug, Clone)]
pub enum DraftOutcome {
    /// A completion came back. Whether that is [`DraftStatus::Ready`] or
    /// [`DraftStatus::Blocked`] is read off `stop_reason` — a refusal or a
    /// truncation is a successful, billed call with an unusable answer.
    Completed(Box<Completion>),
    /// The attempt failed. `permanent` means no future attempt would fare
    /// better, so the draft goes straight to [`DraftStatus::Failed`] instead
    /// of burning the remaining attempts.
    Failed { reason: String, permanent: bool },
}

impl DraftOutcome {
    pub fn failed(reason: impl Into<String>, permanent: bool) -> Self {
        DraftOutcome::Failed {
            reason: reason.into(),
            permanent,
        }
    }
}

/// The status a completion resolves to, ignoring grounding. Kept as its own
/// step because it answers a different question than [`land`] does: *did the
/// model finish?*
pub fn status_for(stop_reason: &StopReason) -> DraftStatus {
    if stop_reason.is_complete() {
        DraftStatus::Ready
    } else {
        DraftStatus::Blocked
    }
}

/// Recording work. The **consumer's** whole view of the store (§7 fast half).
///
/// One method, on purpose: the thing that runs inside a Kafka handler should
/// be incapable of claiming, calling, or approving anything. A handler that
/// *could* reach the rest of this store is one an edit could accidentally
/// make slow, and a slow handler is the eviction-rebalance-redelivery loop
/// this whole crate is shaped to avoid.
#[async_trait]
pub trait DraftQueue: Send + Sync + std::fmt::Debug {
    /// Record a draft job, keyed on `(kind, subject_id)`. Idempotent: a
    /// redelivery returns [`Enqueued::AlreadyQueued`] with the existing id and
    /// writes nothing.
    async fn enqueue(&self, job: &DraftJob, at: DateTime<Utc>) -> Result<Enqueued, StoreError>;
}

/// Draining work. The **worker pool's** view (§7 slow half).
#[async_trait]
pub trait DraftWorkQueue: DraftAttempt {
    /// Lease up to `limit` runnable drafts **of the given kinds**
    /// (`FOR UPDATE SKIP LOCKED`), bumping `attempts` and stamping a lease of
    /// `lease` from `at`. A draft whose lease has expired is runnable again;
    /// one claimed `max_attempts` times is failed instead of re-leased.
    ///
    /// `kinds` is not a convenience filter — it is what keeps a pod from
    /// leasing work it cannot finish. The queue is deliberately kind-agnostic
    /// (t4's rule drafts share it), but a *pod* carries only the generators it
    /// was built with, and a claim is a **durable lease**: a draft leased by a
    /// replica with no generator for it is a draft nobody else may touch until
    /// that lease expires. Callers pass
    /// [`crate::worker::GeneratorRegistry::kinds`].
    ///
    /// The attempt-ceiling retirement this performs is scoped to the same
    /// kinds, so one call only ever touches rows the caller asked about.
    ///
    /// **Live drafts only.** Backfill drafts belong to the Batch API's
    /// lifecycle ([`DraftBatchQueue`]) and are drafted at half price there; a
    /// worker that could claim one would quietly pay double for a narrative
    /// nobody is waiting for.
    async fn claim_batch(
        &self,
        kinds: &[DraftKind],
        limit: usize,
        lease: std::time::Duration,
        max_attempts: i32,
        at: DateTime<Utc>,
    ) -> Result<Vec<ClaimedJob>, StoreError>;
}

/// The steps every *draining* path shares, whichever queue it claimed from
/// (§7 slow half).
///
/// A supertrait of both [`DraftWorkQueue`] and [`DraftBatchQueue`] rather than
/// three copies of the same three methods: a worker and the batch backfill
/// differ only in *how they claim* — one leases a job for a call, the other
/// hands it to a 24-hour server-side job — and must not differ at all in how
/// an attempt is recorded, released or finished. Splitting the claim from the
/// attempt is what lets each path hold a trait that cannot claim the other's
/// work while still sharing the write that lands an answer.
#[async_trait]
pub trait DraftAttempt: Send + Sync + std::fmt::Debug {
    /// Record the request this attempt is about to make, *before* the call.
    /// This is what gives the answer a row to land on: the cache write (which
    /// knows only the digest) matches on it, so a worker that dies between the
    /// provider's answer and its own bookkeeping still leaves the paid-for
    /// completion recorded.
    ///
    /// `prompt` is taken whole rather than as a loose id/digest pair, so the
    /// two halves of §20.4's provenance cannot be written apart (see
    /// [`crate::model::Provenance`]).
    async fn begin_attempt(
        &self,
        draft_id: DraftId,
        key: &CacheKey,
        prompt: Option<&PromptDescriptor>,
        grounded_event_ids: &[Uuid],
        at: DateTime<Utc>,
    ) -> Result<(), StoreError>;

    /// Apply a worker's verdict to one leased draft, clearing its lease.
    async fn finish(
        &self,
        draft_id: DraftId,
        outcome: DraftOutcome,
        at: DateTime<Utc>,
    ) -> Result<DraftStatus, StoreError>;

    /// Release a lease without a verdict — a shutdown caught mid-work, or a
    /// kind this pod cannot serve. The draft returns to
    /// [`DraftStatus::Queued`] for another pod immediately rather than after
    /// the lease expires. Deliberately does **not** consume an attempt:
    /// nothing was tried.
    async fn release(&self, draft_id: DraftId, at: DateTime<Utc>) -> Result<(), StoreError>;
}

/// The two operations the `llm` cache adapter needs, and nothing else
/// ([`crate::cache`]) — the narrowest surface a third-party seam holds an
/// `Arc` to.
#[async_trait]
pub trait DraftCache: Send + Sync + std::fmt::Debug {
    /// The cross-pod cache read: the newest usable completion filed under
    /// this `(model, request)` pair, if any.
    async fn cached_completion(&self, key: &CacheKey) -> Result<Option<Completion>, StoreError>;

    /// The cross-pod cache write: land `completion` on every in-flight draft
    /// awaiting this exact `(model, request)` pair.
    ///
    /// Matching on the digest rather than on a draft id is deliberate. Two
    /// pods that raced into the same question — the ordinary consequence of a
    /// rebalance — both get the *same* answer, which is precisely what
    /// "effectively once" has to mean for a document a human will read.
    /// Returns how many rows it landed on.
    async fn store_completion(
        &self,
        key: &CacheKey,
        completion: &Completion,
        at: DateTime<Utc>,
    ) -> Result<u64, StoreError>;
}

/// Reading a draft and deciding on it — the human-facing half (§20.4), which
/// the review API and the drafting announcement both build on.
#[async_trait]
pub trait DraftReview: Send + Sync + std::fmt::Debug {
    /// A human's verdict. Only a [`DraftStatus::Ready`] draft is reviewable —
    /// approving a blocked or failed one would approve an answer nobody has.
    async fn review(
        &self,
        draft_id: DraftId,
        review: Review,
        reviewer: &str,
        note: Option<&str>,
        at: DateTime<Utc>,
    ) -> Result<DraftStatus, StoreError>;

    /// Read one draft back — the reviewer's read.
    async fn get(&self, draft_id: DraftId) -> Result<Option<Draft>, StoreError>;

    /// A page of drafts, newest first — the review queue behind
    /// `GET /v1/drafts`.
    async fn list(&self, filter: &DraftFilter) -> Result<Vec<Draft>, StoreError>;
}

/// Narrowing for [`DraftReview::list`]. Every field optional: the reviewer's
/// default view is "everything, newest first", and each filter is one facet of
/// the queue (what state, which capability, which path produced it).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DraftFilter {
    pub status: Option<DraftStatus>,
    pub kind: Option<DraftKind>,
    pub source: Option<DraftSource>,
    /// One subject — the natural "show me this incident's draft" lookup, since
    /// callers know incident ids and not draft ids.
    pub subject_id: Option<Uuid>,
    pub limit: i64,
}

impl DraftFilter {
    /// A page of at most `limit` drafts (clamped to [`MAX_LIST_LIMIT`]).
    pub fn with_limit(limit: i64) -> Self {
        Self {
            limit: limit.clamp(1, MAX_LIST_LIMIT),
            ..Self::default()
        }
    }
}

/// Hard ceiling on one `list` page. A reviewer's queue is a queue; an
/// unbounded read of a table that holds every narrative ever drafted is how a
/// read API becomes an outage.
pub const MAX_LIST_LIMIT: i64 = 200;

/// The Batch API backfill's view (§20.4) — submit → poll → land, across
/// process restarts.
///
/// A separate trait from [`DraftWorkQueue`] because the two lifecycles are
/// genuinely different: a worker holds a lease for minutes and reports one
/// outcome; a backfill hands thousands of drafts to a server-side job that may
/// outlive the process that submitted it, and recovers them by *batch id*
/// rather than by lease.
#[async_trait]
pub trait DraftBatchQueue: DraftAttempt {
    /// Lease up to `limit` queued **backfill** drafts, exactly as
    /// [`DraftWorkQueue::claim_batch`] does but on the other side of the
    /// source split — and with a lease sized for a 24-hour batch rather than
    /// for one call.
    async fn claim_for_batch(
        &self,
        limit: usize,
        lease: std::time::Duration,
        max_attempts: i32,
        at: DateTime<Utc>,
    ) -> Result<Vec<ClaimedJob>, StoreError>;

    /// Record which batch these drafts were submitted in, and register the
    /// batch itself.
    ///
    /// One transaction, written immediately after the submit returns: a
    /// process that dies before this loses track of a batch it has already
    /// paid for, which is the one unrecoverable failure on this path.
    async fn attach_batch(
        &self,
        draft_ids: &[DraftId],
        batch_id: &BatchId,
        at: DateTime<Utc>,
    ) -> Result<(), StoreError>;

    /// Batches still owed an outcome — what a restarted backfill polls before
    /// submitting anything new.
    ///
    /// Read from the batch rows, not from a `DISTINCT` over drafts: a batch
    /// whose drafts have all moved on but whose results were never consumed is
    /// still open, and the draft-derived view could not see it.
    async fn open_batches(&self) -> Result<Vec<BatchId>, StoreError>;

    /// Claim the right to consume this batch's results, exactly once.
    ///
    /// **The Batch API reports token usage in the results stream**, so a
    /// second fetch bills the same tokens again into the §13 metering stream
    /// ([`llm::MeteredBatchClient`] meters on `results`). A conditional
    /// `UPDATE … WHERE results_fetched_at IS NULL` makes "exactly once" a
    /// property of the schema rather than a convention in a comment — and one
    /// that holds across two processes, not just two calls.
    ///
    /// Returns `false` when someone else already consumed them.
    async fn claim_results_fetch(
        &self,
        batch_id: &BatchId,
        at: DateTime<Utc>,
    ) -> Result<bool, StoreError>;

    /// Mark a batch finished, so the drain stops polling it. `reason` is
    /// `landed` (every item accounted for) or `released` (the results were
    /// short and the remainder went back to the queue).
    async fn close_batch(
        &self,
        batch_id: &BatchId,
        reason: &'static str,
        at: DateTime<Utc>,
    ) -> Result<(), StoreError>;

    /// Hand back the drafts a batch never accounted for.
    ///
    /// The bound on the drain: a batch can end with rows still `in_flight`
    /// under it — a result whose `custom_id` did not parse, a JSONL line the
    /// reader skipped, an item the provider simply never returned. Without
    /// this they are leased to a finished job forever, and the drain loop that
    /// keeps finding them never terminates. Returns how many were released.
    async fn release_batch_stragglers(
        &self,
        batch_id: &BatchId,
        reason: &str,
        at: DateTime<Utc>,
    ) -> Result<u64, StoreError>;

    /// Land one item's outcome onto its draft.
    ///
    /// Scoped to `(draft_id, batch_id, status = in_flight)`: a late result
    /// from a batch this draft is no longer part of — it was released,
    /// re-submitted, or already reviewed — must not overwrite the row. Returns
    /// whether it landed.
    async fn land_batch_outcome(
        &self,
        draft_id: DraftId,
        batch_id: &BatchId,
        outcome: BatchItemOutcome,
        at: DateTime<Utc>,
    ) -> Result<bool, StoreError>;
}

/// One announcement waiting to publish.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingAnnouncement {
    pub id: i64,
    /// The envelope exactly as the landing composed it. Handed back as raw
    /// JSON rather than a decoded `EventEnvelope` because the *flusher* owns
    /// the policy for a row it cannot decode (stamp it and move on, so one bad
    /// row cannot wedge the drain) — a store that decoded eagerly would have
    /// to invent that policy itself.
    pub envelope: serde_json::Value,
}

/// The announcement outbox (§20) — the publish half of a landing.
///
/// A seam rather than a raw `PgPool` read, for the reason every other seam in
/// this crate exists: [`crate::outbox`]'s flusher is where at-least-once
/// delivery, the undecodable-row policy and the ordering guarantee live, and
/// none of that should need Postgres to be exercised.
#[async_trait]
pub trait DraftOutbox: Send + Sync + std::fmt::Debug {
    /// Pending announcements, oldest first.
    async fn pending_announcements(
        &self,
        limit: i64,
    ) -> Result<Vec<PendingAnnouncement>, StoreError>;

    /// Stamp one row published. Called only after the sink accepted it.
    async fn mark_announced(&self, id: i64, at: DateTime<Utc>) -> Result<(), StoreError>;

    /// How many announcements are still waiting — the one number that says
    /// whether the event stream and the drafts table agree.
    async fn pending_announcement_count(&self) -> Result<i64, StoreError>;
}

/// Everything, for the one type that owns the table and for the contract
/// tests that exercise it end to end (`tests/draft_store.rs`).
///
/// Collaborators take the narrow trait they need; a concrete
/// `Arc<PgDraftStore>` coerces into any of them, so `main.rs` builds one store
/// and hands out a view per role. The blanket impl means a new backend gets
/// `DraftStore` for free by implementing them.
pub trait DraftStore:
    DraftQueue + DraftWorkQueue + DraftCache + DraftReview + DraftBatchQueue + DraftOutbox
{
}

impl<T> DraftStore for T where
    T: DraftQueue + DraftWorkQueue + DraftCache + DraftReview + DraftBatchQueue + DraftOutbox
{
}

/// Postgres-backed [`DraftStore`]. Cheap to clone (the pool is an `Arc`
/// internally).
#[derive(Debug, Clone)]
pub struct PgDraftStore {
    pool: PgPool,
    /// Every kind's landing boundary, resolved once.
    ///
    /// The store holds the **check** registry and not the generator registry,
    /// and the difference is load-bearing: a pod must be able to *land* any
    /// kind (the cross-pod cache lands rows other pods enqueued) while only
    /// being allowed to *run* the kinds it has generators for. It also means
    /// every path that lands an answer applies the same boundary — the
    /// worker's write, the cache's digest-keyed write, the backfill's batch
    /// results — instead of three callers each carrying their own.
    checks: Arc<CheckRegistry>,
}

impl PgDraftStore {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            checks: Arc::new(CheckRegistry::default()),
        }
    }

    /// Override the grounding policy (see [`GroundingPolicy`]).
    pub fn with_grounding(self, policy: GroundingPolicy) -> Self {
        Self {
            checks: Arc::new(CheckRegistry::with_grounding(policy)),
            ..self
        }
    }

    /// The pool, for the outbox flusher — which reads a table this store owns
    /// but is not itself a draft operation (see [`crate::outbox`]).
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Liveness probe for boot-time fail-fast.
    pub async fn ping(&self) -> Result<(), StoreError> {
        sqlx::query!("SELECT 1 AS one FROM copilot_drafts LIMIT 1")
            .fetch_optional(&self.pool)
            .await?;
        Ok(())
    }

    /// How many drafts sit in each status — the backlog gauge
    /// (`crate::metrics`) and the answer to "is the pool keeping up".
    pub async fn status_counts(&self) -> Result<Vec<(String, i64)>, StoreError> {
        let rows =
            sqlx::query!("SELECT status, COUNT(*) AS count FROM copilot_drafts GROUP BY status")
                .fetch_all(&self.pool)
                .await?;
        Ok(rows
            .into_iter()
            .map(|row| (row.status, row.count.unwrap_or(0)))
            .collect())
    }
}

/// A `chain` column back into its newtype. `as u64` would turn a negative id —
/// only reachable through a bad write, but that is what `Malformed` is for —
/// into a plausible-looking astronomically large chain rather than an error.
fn parse_chain(chain: i64) -> Result<Chain, StoreError> {
    u64::try_from(chain)
        .map(Chain)
        .map_err(|_| StoreError::malformed(format!("chain = {chain}")))
}

/// Parse a `kind`/`status` column back into its enum, naming the column in the
/// error — a value no build understands is a bad row, not a bad connection.
fn parse_enum<T: FromStr>(column: &str, value: &str) -> Result<T, StoreError> {
    T::from_str(value).map_err(|_| StoreError::malformed(format!("{column} = {value:?}")))
}

fn to_uuid_list(value: Option<serde_json::Value>) -> Result<Vec<Uuid>, StoreError> {
    match value {
        None => Ok(Vec::new()),
        Some(value) => serde_json::from_value(value)
            .map_err(|err| StoreError::malformed(format!("grounded_event_ids: {err}"))),
    }
}

/// A uuid list as the column holds it.
fn uuid_list_json(ids: &[Uuid]) -> Result<serde_json::Value, StoreError> {
    serde_json::to_value(ids)
        .map_err(|err| StoreError::malformed(format!("grounded_event_ids: {err}")))
}

/// The citation check's findings as the column holds them.
fn grounding_json(
    grounding: Option<&GroundingSummary>,
) -> Result<Option<serde_json::Value>, StoreError> {
    grounding
        .map(|summary| {
            serde_json::to_value(summary)
                .map_err(|err| StoreError::malformed(format!("grounding: {err}")))
        })
        .transpose()
}

fn grounding_from(
    value: Option<serde_json::Value>,
) -> Result<Option<GroundingSummary>, StoreError> {
    value
        .map(|value| {
            serde_json::from_value(value)
                .map_err(|err| StoreError::malformed(format!("grounding: {err}")))
        })
        .transpose()
}

/// The provenance pair (§20.4): both halves or neither.
fn provenance_from(
    prompt_id: Option<String>,
    prompt_digest: Option<String>,
) -> Result<Option<Provenance>, StoreError> {
    match (prompt_id, prompt_digest) {
        (Some(prompt_id), Some(prompt_digest)) => Ok(Some(Provenance {
            prompt_id,
            prompt_digest,
        })),
        (None, None) => Ok(None),
        _ => Err(StoreError::malformed("prompt_id without prompt_digest")),
    }
}

/// The answer group: five columns written in one statement, read as one value.
fn answer_from_row(
    body: Option<String>,
    model: Option<String>,
    stop_reason: Option<String>,
    completed_at: Option<DateTime<Utc>>,
    token_usage: Option<serde_json::Value>,
) -> Result<Option<DraftAnswer>, StoreError> {
    match (body, model, stop_reason, completed_at) {
        (Some(body), Some(model), Some(stop_reason), Some(completed_at)) => Ok(Some(DraftAnswer {
            body,
            model,
            stop_reason: stop_reason_from(&stop_reason),
            usage: usage_from(token_usage)?,
            completed_at,
        })),
        (None, None, None, _) => Ok(None),
        _ => Err(StoreError::malformed("partially written draft answer")),
    }
}

/// The review group, whose verdict is read off the status it was written with.
fn review_from_row(
    status: DraftStatus,
    reviewed_by: Option<String>,
    reviewed_at: Option<DateTime<Utc>>,
    review_note: Option<String>,
) -> Result<Option<Reviewed>, StoreError> {
    match (reviewed_by, reviewed_at) {
        (Some(by), Some(at)) => Ok(Some(Reviewed {
            verdict: match status {
                DraftStatus::Approved => Review::Approve,
                DraftStatus::Rejected => Review::Reject,
                other => {
                    return Err(StoreError::malformed(format!(
                        "reviewed draft is {}",
                        other.as_wire_str()
                    )))
                }
            },
            by,
            at,
            note: review_note,
        })),
        (None, None) => Ok(None),
        _ => Err(StoreError::malformed("reviewer without a review time")),
    }
}

/// A `source` column back into its enum.
fn parse_source(value: &str) -> Result<DraftSource, StoreError> {
    value
        .parse()
        .map_err(|_| StoreError::malformed(format!("source = {value:?}")))
}

fn usage_json(usage: &TokenUsage) -> serde_json::Value {
    // The four SKUs kept apart, exactly as the metering path keeps them —
    // a single "tokens" number here would invite someone to reconcile against
    // it, and it cannot be priced.
    serde_json::json!({
        "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens,
        "cache_creation_input_tokens": usage.cache_creation_input_tokens,
        "cache_read_input_tokens": usage.cache_read_input_tokens,
    })
}

/// The wire form of a stop reason. `Refusal`'s category is deliberately
/// dropped: it is an open set the provider controls, and it belongs in a log,
/// not in a column something might group by.
fn stop_reason_str(stop_reason: &StopReason) -> String {
    stop_reason.as_str().to_owned()
}

/// Rebuild a `StopReason` from what the column holds. `refusal` loses its
/// category on the round trip (see [`stop_reason_str`]) — the variant, which
/// is what callers branch on, survives.
fn stop_reason_from(value: &str) -> StopReason {
    match value {
        "end_turn" => StopReason::EndTurn,
        "max_tokens" => StopReason::MaxTokens,
        "refusal" => StopReason::Refusal { category: None },
        other => StopReason::Other(other.to_owned()),
    }
}

#[async_trait]
impl DraftQueue for PgDraftStore {
    async fn enqueue(&self, job: &DraftJob, at: DateTime<Utc>) -> Result<Enqueued, StoreError> {
        let chain = i64::try_from(job.chain.0)
            .map_err(|_| StoreError::malformed(format!("chain id {} exceeds i64", job.chain.0)))?;
        let inserted = sqlx::query!(
            "INSERT INTO copilot_drafts
                 (draft_id, kind, subject_id, customer_id, chain, source, source_text, status,
                  attempts, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, $9, $9)
             ON CONFLICT (kind, subject_id) DO NOTHING
             RETURNING draft_id",
            job.draft_id.0,
            job.kind.as_wire_str(),
            job.subject_id,
            job.customer_id.map(|c| c.0),
            chain,
            job.source.as_wire_str(),
            job.source_text.as_deref(),
            DraftStatus::Queued.as_wire_str(),
            at,
        )
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = inserted {
            return Ok(Enqueued::Queued(DraftId(row.draft_id)));
        }

        let existing = sqlx::query!(
            "SELECT draft_id FROM copilot_drafts WHERE kind = $1 AND subject_id = $2",
            job.kind.as_wire_str(),
            job.subject_id,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(Enqueued::AlreadyQueued(DraftId(existing.draft_id)))
    }
}

#[async_trait]
impl DraftWorkQueue for PgDraftStore {
    async fn claim_batch(
        &self,
        kinds: &[DraftKind],
        limit: usize,
        lease: std::time::Duration,
        max_attempts: i32,
        at: DateTime<Utc>,
    ) -> Result<Vec<ClaimedJob>, StoreError> {
        // A pod that serves nothing claims nothing, and says so without a
        // round trip. `= ANY('{}')` would also match no rows, but silently.
        if kinds.is_empty() {
            return Ok(Vec::new());
        }
        let kinds: Vec<String> = kinds
            .iter()
            .map(|kind| kind.as_wire_str().to_owned())
            .collect();

        // A draft that has burned its attempts is retired here rather than in
        // the claim: the claim's `attempts < $max` filter alone would leave it
        // *runnable but never claimed* — invisible in the backlog and stuck
        // forever. Both runnable statuses are covered, because a transiently
        // failed draft is put back as `queued` with its attempt count intact.
        sqlx::query!(
            "UPDATE copilot_drafts
                SET status = $1, updated_at = $2, lease_expires_at = NULL,
                    last_error = COALESCE(last_error, 'attempts exhausted')
              WHERE status = ANY($3::TEXT[])
                AND kind = ANY($5::TEXT[])
                AND source = $6
                AND attempts >= $4
                AND (lease_expires_at IS NULL OR lease_expires_at < $2)",
            DraftStatus::Failed.as_wire_str(),
            at,
            &runnable_statuses(),
            max_attempts,
            &kinds,
            DraftSource::Live.as_wire_str(),
        )
        .execute(&self.pool)
        .await?;

        let lease_until = at
            + chrono::Duration::from_std(lease)
                .map_err(|err| StoreError::malformed(format!("lease duration: {err}")))?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);

        let rows = sqlx::query!(
            r#"UPDATE copilot_drafts AS d
                  SET status = $1,
                      attempts = d.attempts + 1,
                      lease_expires_at = $2,
                      updated_at = $3
                 FROM (
                     SELECT draft_id
                       FROM copilot_drafts
                      WHERE (status = $4 OR (status = $1 AND lease_expires_at < $3))
                        AND kind = ANY($7::TEXT[])
                        AND source = $8
                        AND attempts < $5
                      ORDER BY created_at
                      FOR UPDATE SKIP LOCKED
                      LIMIT $6
                 ) AS claimable
                WHERE d.draft_id = claimable.draft_id
            RETURNING d.draft_id, d.kind, d.subject_id, d.customer_id, d.chain, d.source,
                      d.source_text, d.attempts,
                      d.lease_expires_at AS "lease_expires_at!""#,
            DraftStatus::InFlight.as_wire_str(),
            lease_until,
            at,
            DraftStatus::Queued.as_wire_str(),
            max_attempts,
            limit,
            &kinds,
            DraftSource::Live.as_wire_str(),
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(ClaimedJob {
                    job: DraftJob {
                        draft_id: DraftId(row.draft_id),
                        kind: parse_enum::<DraftKind>("kind", &row.kind)?,
                        subject_id: row.subject_id,
                        customer_id: row.customer_id.map(CustomerId),
                        chain: parse_chain(row.chain)?,
                        source: parse_source(&row.source)?,
                        source_text: row.source_text,
                    },
                    attempts: row.attempts,
                    lease_expires_at: row.lease_expires_at,
                })
            })
            .collect()
    }
}

#[async_trait]
impl DraftAttempt for PgDraftStore {
    async fn begin_attempt(
        &self,
        draft_id: DraftId,
        key: &CacheKey,
        prompt: Option<&PromptDescriptor>,
        grounded_event_ids: &[Uuid],
        at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        // Both halves or neither — the column pair is written from one
        // `Option`, so a half-attributed draft is unconstructible here rather
        // than merely unlikely.
        let prompt_id = prompt.map(PromptDescriptor::id);
        let prompt_digest = prompt.map(|p| p.digest().to_hex());
        sqlx::query!(
            "UPDATE copilot_drafts
                SET request_digest = $1, model_digest = $2, prompt_id = $3,
                    prompt_digest = $4, grounded_event_ids = $5, updated_at = $6
              WHERE draft_id = $7",
            key.request_digest().to_hex(),
            key.model_digest().to_hex(),
            prompt_id.as_deref(),
            prompt_digest.as_deref(),
            serde_json::to_value(grounded_event_ids)
                .map_err(|err| StoreError::malformed(format!("grounded_event_ids: {err}")))?,
            at,
            draft_id.0,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn finish(
        &self,
        draft_id: DraftId,
        outcome: DraftOutcome,
        at: DateTime<Utc>,
    ) -> Result<DraftStatus, StoreError> {
        match outcome {
            DraftOutcome::Completed(completion) => {
                // One transaction, because a landing is a *read* of the row
                // (its kind, and the window the attempt recorded) followed by
                // a write derived from it — plus the announcement, which must
                // be atomic with the draft becoming `ready`. Two statements
                // outside a transaction would let a concurrent release change
                // the row between them, and the answer would land on a draft
                // that is no longer waiting for it.
                let mut tx = self.pool.begin().await?;
                let row = landing_row(&mut tx, draft_id, None)
                    .await?
                    .ok_or(StoreError::NotFound { draft_id })?;
                let status = self.write_landing(&mut tx, &row, &completion, at).await?;
                tx.commit().await?;
                Ok(status)
            }
            DraftOutcome::Failed { reason, permanent } => {
                let status = if permanent {
                    DraftStatus::Failed
                } else {
                    // Back to the queue: the outer clock decides when, and
                    // `claim_batch`'s attempt ceiling decides whether ever.
                    DraftStatus::Queued
                };
                sqlx::query!(
                    "UPDATE copilot_drafts
                        SET status = $1, last_error = $2, lease_expires_at = NULL,
                            updated_at = $3
                      WHERE draft_id = $4",
                    status.as_wire_str(),
                    reason,
                    at,
                    draft_id.0,
                )
                .execute(&self.pool)
                .await?;
                Ok(status)
            }
        }
    }

    async fn release(&self, draft_id: DraftId, at: DateTime<Utc>) -> Result<(), StoreError> {
        sqlx::query!(
            "UPDATE copilot_drafts
                SET status = $1, lease_expires_at = NULL, updated_at = $2
              WHERE draft_id = $3 AND status = $4",
            DraftStatus::Queued.as_wire_str(),
            at,
            draft_id.0,
            DraftStatus::InFlight.as_wire_str(),
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl DraftCache for PgDraftStore {
    async fn cached_completion(&self, key: &CacheKey) -> Result<Option<Completion>, StoreError> {
        let row = sqlx::query!(
            "SELECT body, model, stop_reason, token_usage
               FROM copilot_drafts
              WHERE request_digest = $1
                AND model_digest = $2
                AND status = ANY($3::TEXT[])
                AND body IS NOT NULL
                AND model IS NOT NULL
                AND stop_reason IS NOT NULL
              ORDER BY completed_at DESC NULLS LAST
              LIMIT 1",
            key.request_digest().to_hex(),
            key.model_digest().to_hex(),
            &cacheable_statuses(),
        )
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else { return Ok(None) };
        // The three `IS NOT NULL` guards above are what make these
        // unwrap-shaped reads safe; a row that lost one is a malformed row,
        // not a cache miss to paper over.
        let (Some(text), Some(model), Some(stop_reason)) = (row.body, row.model, row.stop_reason)
        else {
            return Err(StoreError::malformed("cached draft is missing its answer"));
        };
        Ok(Some(Completion {
            text,
            stop_reason: stop_reason_from(&stop_reason),
            model,
            usage: usage_from(row.token_usage)?,
        }))
    }

    async fn store_completion(
        &self,
        key: &CacheKey,
        completion: &Completion,
        at: DateTime<Utc>,
    ) -> Result<u64, StoreError> {
        // Each waiting row is landed through the *same* write path the
        // worker's own `finish` uses — citation check, outbox announcement and
        // all. A cache write that skipped it would let a rebalance promote a
        // draft the worker would have blocked: the same text, ready on one
        // path and blocked on the other, decided by which pod finished first.
        let mut tx = self.pool.begin().await?;
        let waiting = sqlx::query!(
            r#"SELECT draft_id, kind, subject_id, customer_id, chain, source, source_text,
                      prompt_id, prompt_digest, grounded_event_ids
                 FROM copilot_drafts
                WHERE request_digest = $1
                  AND model_digest = $2
                  AND status = $3
                FOR UPDATE"#,
            key.request_digest().to_hex(),
            key.model_digest().to_hex(),
            DraftStatus::InFlight.as_wire_str(),
        )
        .fetch_all(&mut *tx)
        .await?;

        let mut landed = 0u64;
        for row in waiting {
            let row = LandingRow {
                draft_id: DraftId(row.draft_id),
                kind: parse_enum::<DraftKind>("kind", &row.kind)?,
                subject_id: row.subject_id,
                customer_id: row.customer_id.map(CustomerId),
                chain: parse_chain(row.chain)?,
                source: parse_source(&row.source)?,
                source_text: row.source_text,
                provenance: provenance_from(row.prompt_id, row.prompt_digest)?,
                window: to_uuid_list(Some(row.grounded_event_ids))?,
            };
            self.write_landing(&mut tx, &row, completion, at).await?;
            landed += 1;
        }
        tx.commit().await?;
        Ok(landed)
    }
}

#[async_trait]
impl DraftReview for PgDraftStore {
    async fn review(
        &self,
        draft_id: DraftId,
        review: Review,
        reviewer: &str,
        note: Option<&str>,
        at: DateTime<Utc>,
    ) -> Result<DraftStatus, StoreError> {
        let updated = sqlx::query!(
            "UPDATE copilot_drafts
                SET status = $1, reviewed_by = $2, reviewed_at = $3, review_note = $4,
                    updated_at = $3
              WHERE draft_id = $5 AND status = $6
            RETURNING draft_id",
            review.status().as_wire_str(),
            reviewer,
            at,
            note,
            draft_id.0,
            DraftStatus::Ready.as_wire_str(),
        )
        .fetch_optional(&self.pool)
        .await?;

        if updated.is_some() {
            return Ok(review.status());
        }

        // Say which of the two it was: "no such draft" and "that draft has no
        // answer to approve" send a reviewer to completely different places.
        let current = sqlx::query!(
            "SELECT status FROM copilot_drafts WHERE draft_id = $1",
            draft_id.0
        )
        .fetch_optional(&self.pool)
        .await?;
        match current {
            None => Err(StoreError::NotFound { draft_id }),
            Some(row) => Err(StoreError::NotReviewable {
                draft_id,
                status: row.status,
            }),
        }
    }

    async fn get(&self, draft_id: DraftId) -> Result<Option<Draft>, StoreError> {
        let row = sqlx::query_as!(
            DraftRow,
            r#"SELECT draft_id, kind, subject_id, customer_id, chain, source, source_text, status,
                      attempts, model, prompt_id, prompt_digest, stop_reason, body, token_usage,
                      grounded_event_ids, grounding, batch_id, last_error, reviewed_by,
                      reviewed_at, review_note, created_at, updated_at, completed_at
                 FROM copilot_drafts
                WHERE draft_id = $1"#,
            draft_id.0
        )
        .fetch_optional(&self.pool)
        .await?;
        row.map(DraftRow::into_draft).transpose()
    }

    async fn list(&self, filter: &DraftFilter) -> Result<Vec<Draft>, StoreError> {
        // Optional filters as `$n IS NULL OR column = $n`: one prepared
        // statement for every combination, which is what keeps this a
        // compile-time-checked query rather than a string builder.
        let rows = sqlx::query_as!(
            DraftRow,
            r#"SELECT draft_id, kind, subject_id, customer_id, chain, source, source_text, status,
                      attempts, model, prompt_id, prompt_digest, stop_reason, body, token_usage,
                      grounded_event_ids, grounding, batch_id, last_error, reviewed_by,
                      reviewed_at, review_note, created_at, updated_at, completed_at
                 FROM copilot_drafts
                WHERE ($1::TEXT IS NULL OR status = $1)
                  AND ($2::TEXT IS NULL OR kind = $2)
                  AND ($3::TEXT IS NULL OR source = $3)
                  AND ($4::UUID IS NULL OR subject_id = $4)
                ORDER BY created_at DESC
                LIMIT $5"#,
            filter.status.map(DraftStatus::as_wire_str),
            filter.kind.map(DraftKind::as_wire_str),
            filter.source.map(DraftSource::as_wire_str),
            filter.subject_id,
            filter.limit.clamp(1, MAX_LIST_LIMIT),
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(DraftRow::into_draft).collect()
    }
}

#[async_trait]
impl DraftOutbox for PgDraftStore {
    async fn pending_announcements(
        &self,
        limit: i64,
    ) -> Result<Vec<PendingAnnouncement>, StoreError> {
        let rows = sqlx::query!(
            r#"SELECT id, envelope AS "envelope: serde_json::Value"
                 FROM copilot_outbox
                WHERE published_at IS NULL
                ORDER BY id
                LIMIT $1"#,
            limit.max(1),
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| PendingAnnouncement {
                id: row.id,
                envelope: row.envelope,
            })
            .collect())
    }

    async fn mark_announced(&self, id: i64, at: DateTime<Utc>) -> Result<(), StoreError> {
        sqlx::query!(
            "UPDATE copilot_outbox SET published_at = $1 WHERE id = $2",
            at,
            id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn pending_announcement_count(&self) -> Result<i64, StoreError> {
        let row = sqlx::query!(
            r#"SELECT COUNT(*) AS "pending!" FROM copilot_outbox WHERE published_at IS NULL"#
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(row.pending)
    }
}

/// One `copilot_drafts` row, exactly as the two reads select it.
///
/// A named row type with `query_as!` rather than two anonymous `query!`
/// structs: the parse below is where a stored row becomes a domain value, and
/// it is the *only* place that conversion happens. The previous shape had two
/// copies of it and tempted a third — the announcement sweep re-read every
/// claimed row one id at a time, an N+1 that only looked harmless because the
/// batch was small.
#[derive(Debug)]
struct DraftRow {
    draft_id: Uuid,
    kind: String,
    subject_id: Uuid,
    customer_id: Option<Uuid>,
    chain: i64,
    source: String,
    source_text: Option<String>,
    status: String,
    attempts: i32,
    model: Option<String>,
    prompt_id: Option<String>,
    prompt_digest: Option<String>,
    stop_reason: Option<String>,
    body: Option<String>,
    token_usage: Option<serde_json::Value>,
    grounded_event_ids: serde_json::Value,
    grounding: Option<serde_json::Value>,
    batch_id: Option<String>,
    last_error: Option<String>,
    reviewed_by: Option<String>,
    reviewed_at: Option<DateTime<Utc>>,
    review_note: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
}

impl DraftRow {
    /// Parse, don't validate: the column groups that are only ever written
    /// together are re-assembled here, once, and a half-written group is a
    /// malformed row rather than a `None` every later reader has to
    /// second-guess against the status.
    fn into_draft(self) -> Result<Draft, StoreError> {
        let status = parse_enum::<DraftStatus>("status", &self.status)?;
        Ok(Draft {
            draft_id: DraftId(self.draft_id),
            kind: parse_enum::<DraftKind>("kind", &self.kind)?,
            subject_id: self.subject_id,
            customer_id: self.customer_id.map(CustomerId),
            chain: parse_chain(self.chain)?,
            source: parse_source(&self.source)?,
            source_text: self.source_text,
            status,
            attempts: self.attempts,
            provenance: provenance_from(self.prompt_id, self.prompt_digest)?,
            answer: answer_from_row(
                self.body,
                self.model,
                self.stop_reason,
                self.completed_at,
                self.token_usage,
            )?,
            review: review_from_row(status, self.reviewed_by, self.reviewed_at, self.review_note)?,
            grounded_event_ids: to_uuid_list(Some(self.grounded_event_ids))?,
            grounding: grounding_from(self.grounding)?,
            batch_id: self.batch_id,
            last_error: self.last_error,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[async_trait]
impl DraftBatchQueue for PgDraftStore {
    async fn claim_for_batch(
        &self,
        limit: usize,
        lease: std::time::Duration,
        max_attempts: i32,
        at: DateTime<Utc>,
    ) -> Result<Vec<ClaimedJob>, StoreError> {
        let lease_until = at
            + chrono::Duration::from_std(lease)
                .map_err(|err| StoreError::malformed(format!("lease duration: {err}")))?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);

        // Same claim as the worker pool's, on the other side of the source
        // split — and deliberately *not* a shared helper with a `source`
        // parameter: the two differ in what a lease means (one call vs. a
        // 24-hour server-side job), and a single query would invite someone to
        // give them a single lease too.
        let rows = sqlx::query!(
            r#"UPDATE copilot_drafts AS d
                  SET status = $1,
                      attempts = d.attempts + 1,
                      lease_expires_at = $2,
                      updated_at = $3
                 FROM (
                     SELECT draft_id
                       FROM copilot_drafts
                      WHERE (status = $4 OR (status = $1 AND lease_expires_at < $3))
                        AND source = $7
                        AND attempts < $5
                      ORDER BY created_at
                      FOR UPDATE SKIP LOCKED
                      LIMIT $6
                 ) AS claimable
                WHERE d.draft_id = claimable.draft_id
            RETURNING d.draft_id, d.kind, d.subject_id, d.customer_id, d.chain, d.source,
                      d.source_text, d.attempts,
                      d.lease_expires_at AS "lease_expires_at!""#,
            DraftStatus::InFlight.as_wire_str(),
            lease_until,
            at,
            DraftStatus::Queued.as_wire_str(),
            max_attempts,
            limit,
            DraftSource::Backfill.as_wire_str(),
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(ClaimedJob {
                    job: DraftJob {
                        draft_id: DraftId(row.draft_id),
                        kind: parse_enum::<DraftKind>("kind", &row.kind)?,
                        subject_id: row.subject_id,
                        customer_id: row.customer_id.map(CustomerId),
                        chain: parse_chain(row.chain)?,
                        source: parse_source(&row.source)?,
                        source_text: row.source_text,
                    },
                    attempts: row.attempts,
                    lease_expires_at: row.lease_expires_at,
                })
            })
            .collect()
    }

    async fn attach_batch(
        &self,
        draft_ids: &[DraftId],
        batch_id: &BatchId,
        at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        if draft_ids.is_empty() {
            return Ok(());
        }
        let ids: Vec<Uuid> = draft_ids.iter().map(|id| id.0).collect();
        // The batch row and the drafts' pointers to it go in together: a batch
        // registered with no drafts would be polled forever, and drafts
        // pointing at an unregistered batch would never be polled at all.
        let mut tx = self.pool.begin().await?;
        sqlx::query!(
            "INSERT INTO copilot_batches (batch_id, items, submitted_at)
             VALUES ($1, $2, $3)
             ON CONFLICT (batch_id) DO NOTHING",
            batch_id.0,
            i32::try_from(ids.len()).unwrap_or(i32::MAX),
            at,
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            "UPDATE copilot_drafts
                SET batch_id = $1, updated_at = $2
              WHERE draft_id = ANY($3::UUID[])",
            batch_id.0,
            at,
            &ids,
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn open_batches(&self) -> Result<Vec<BatchId>, StoreError> {
        let rows = sqlx::query!(
            "SELECT batch_id FROM copilot_batches
              WHERE closed_at IS NULL
              ORDER BY submitted_at",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|row| BatchId(row.batch_id)).collect())
    }

    async fn claim_results_fetch(
        &self,
        batch_id: &BatchId,
        at: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        let claimed = sqlx::query!(
            "UPDATE copilot_batches
                SET results_fetched_at = $1
              WHERE batch_id = $2 AND results_fetched_at IS NULL
            RETURNING batch_id",
            at,
            batch_id.0,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(claimed.is_some())
    }

    async fn close_batch(
        &self,
        batch_id: &BatchId,
        reason: &'static str,
        at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        sqlx::query!(
            "UPDATE copilot_batches
                SET closed_at = $1, closed_reason = $2
              WHERE batch_id = $3 AND closed_at IS NULL",
            at,
            reason,
            batch_id.0,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn release_batch_stragglers(
        &self,
        batch_id: &BatchId,
        reason: &str,
        at: DateTime<Utc>,
    ) -> Result<u64, StoreError> {
        // Back to `queued` with the batch pointer cleared, so the next run
        // re-submits them rather than waiting on a job that is over. The
        // attempt count is left alone — the claim already consumed one, and
        // the ceiling is what stops an item that can never be matched from
        // circulating forever.
        let released = sqlx::query!(
            "UPDATE copilot_drafts
                SET status = $1, batch_id = NULL, lease_expires_at = NULL,
                    last_error = $2, updated_at = $3
              WHERE batch_id = $4 AND status = $5",
            DraftStatus::Queued.as_wire_str(),
            reason,
            at,
            batch_id.0,
            DraftStatus::InFlight.as_wire_str(),
        )
        .execute(&self.pool)
        .await?;
        Ok(released.rows_affected())
    }

    async fn land_batch_outcome(
        &self,
        draft_id: DraftId,
        batch_id: &BatchId,
        outcome: BatchItemOutcome,
        at: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        // Scoped to this batch *and* to `in_flight`: a late result from a
        // batch the draft has since left must never overwrite a row somebody
        // has already reviewed.
        let Some(row) = landing_row(&mut tx, draft_id, Some(batch_id)).await? else {
            return Ok(false);
        };

        match outcome {
            BatchItemOutcome::Answered(completion) => {
                self.write_landing(&mut tx, &row, &completion, at).await?;
            }
            other => {
                // Everything else went back to the queue or died there. A
                // retryable outcome (expired, canceled, a server-side error)
                // clears the batch id so the next run re-submits it; a
                // permanent one fails the draft, because the same request will
                // be rejected identically forever.
                let (status, batch) = if other.is_retryable() {
                    (DraftStatus::Queued, None)
                } else {
                    (DraftStatus::Failed, Some(batch_id.0.as_str()))
                };
                sqlx::query!(
                    "UPDATE copilot_drafts
                        SET status = $1, last_error = $2, batch_id = $3,
                            lease_expires_at = NULL, updated_at = $4
                      WHERE draft_id = $5",
                    status.as_wire_str(),
                    batch_failure(&other),
                    batch,
                    at,
                    draft_id.0,
                )
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
        Ok(true)
    }
}

/// The columns a landing reads before it writes — everything the update needs,
/// plus everything the announcement needs, in one `FOR UPDATE` read.
#[derive(Debug, Clone)]
struct LandingRow {
    draft_id: DraftId,
    kind: DraftKind,
    subject_id: Uuid,
    /// Whose draft this is. For a rule draft it is the owner the announcement
    /// names — read from the row, never from the answer.
    customer_id: Option<CustomerId>,
    chain: Chain,
    source: DraftSource,
    /// The customer's own request, for a rule draft — the announcement hashes
    /// it rather than carrying it.
    source_text: Option<String>,
    provenance: Option<Provenance>,
    /// The audit window the attempt recorded — what the citation check checks
    /// against.
    window: Vec<Uuid>,
}

/// Read one draft's landing row `FOR UPDATE`, optionally scoped to the batch
/// that is allowed to land it.
async fn landing_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    draft_id: DraftId,
    batch_id: Option<&BatchId>,
) -> Result<Option<LandingRow>, StoreError> {
    let row = sqlx::query!(
        r#"SELECT draft_id, kind, subject_id, customer_id, chain, source, source_text,
                  prompt_id, prompt_digest, grounded_event_ids
             FROM copilot_drafts
            WHERE draft_id = $1
              AND ($2::TEXT IS NULL OR (batch_id = $2 AND status = $3))
            FOR UPDATE"#,
        draft_id.0,
        batch_id.map(|id| id.0.as_str()),
        DraftStatus::InFlight.as_wire_str(),
    )
    .fetch_optional(&mut **tx)
    .await?;

    row.map(|row| {
        Ok(LandingRow {
            draft_id: DraftId(row.draft_id),
            kind: parse_enum::<DraftKind>("kind", &row.kind)?,
            subject_id: row.subject_id,
            customer_id: row.customer_id.map(CustomerId),
            chain: parse_chain(row.chain)?,
            source: parse_source(&row.source)?,
            source_text: row.source_text,
            provenance: provenance_from(row.prompt_id, row.prompt_digest)?,
            window: to_uuid_list(Some(row.grounded_event_ids))?,
        })
    })
    .transpose()
}

impl PgDraftStore {
    /// **The** write that turns a completion into stored state.
    ///
    /// One function, three callers (the worker's `finish`, the cross-pod
    /// cache's digest-keyed write, the backfill's batch landing) — which is
    /// what makes "a narrative is `ready` under exactly these conditions" a
    /// fact about the code rather than a coincidence between three copies of
    /// an `UPDATE`. It also owns the two things that must not drift from that
    /// decision:
    ///
    /// * the §19 grounding metrics, recorded here rather than inside the pure
    ///   rule, so the rule can be asked hypothetical questions;
    /// * the `IncidentNarrativeDrafted` announcement, written into
    ///   `copilot_outbox` **in this transaction** so the audit record is
    ///   exactly as durable as the draft it describes.
    async fn write_landing(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        row: &LandingRow,
        completion: &Completion,
        at: DateTime<Utc>,
    ) -> Result<DraftStatus, StoreError> {
        let landing = self.checks.apply(row.kind, &row.window, completion);

        // Recorded once per landing, on every path and for every draft —
        // passing or not. A sample of only the rejections cannot tell an
        // operator where the threshold should be.
        if let Some(summary) = landing.grounding.as_ref() {
            crate::metrics::record_grounding(summary, landing.rejected);
        }
        // A rule draft has no grounding summary — its boundary is the
        // compiler — so its rejection is counted on its own series. Same
        // shape, same "alert on this" story: a rising rate means the model is
        // proposing rules the engine will not accept.
        if row.kind == DraftKind::RuleDraft {
            crate::metrics::record_rule_draft(landing.rejected);
        }

        sqlx::query!(
            "UPDATE copilot_drafts
                SET status = $1, model = $2, stop_reason = $3, body = $4,
                    token_usage = $5, last_error = $6, grounding = $7,
                    grounded_event_ids = $8, lease_expires_at = NULL,
                    completed_at = $9, updated_at = $9
              WHERE draft_id = $10",
            landing.status.as_wire_str(),
            completion.model,
            stop_reason_str(&completion.stop_reason),
            completion.text,
            usage_json(&completion.usage),
            landing.last_error,
            grounding_json(landing.grounding.as_ref())?,
            uuid_list_json(&landing.grounded_event_ids)?,
            at,
            row.draft_id.0,
        )
        .execute(&mut **tx)
        .await?;

        if landing.status == DraftStatus::Ready {
            self.announce(tx, row, completion, &landing, at).await?;
        }
        Ok(landing.status)
    }

    /// File the announcement in the outbox, in the landing's transaction.
    ///
    /// Silent when the draft is unattributable (no prompt provenance): the
    /// event's whole purpose is to say *what produced this narrative*, and an
    /// announcement that cannot answer that is worse than none. It is logged
    /// at `error` because it means an attempt wrote an answer without ever
    /// declaring its request — a bug in the worker, not a state to tolerate.
    async fn announce(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        row: &LandingRow,
        completion: &Completion,
        landing: &Landing,
        at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let Some(provenance) = row.provenance.as_ref() else {
            tracing::error!(
                draft_id = %row.draft_id,
                "a landed draft has no prompt provenance; it cannot be announced"
            );
            return Ok(());
        };
        let facts = crate::announce::DraftedFacts {
            draft_id: row.draft_id,
            kind: row.kind,
            subject_id: row.subject_id,
            owner: row.customer_id,
            chain: row.chain,
            source: row.source,
            source_text: row.source_text.as_deref(),
            provenance,
            model: &completion.model,
            body: &completion.text,
            completed_at: at,
            grounding: landing.grounding.as_ref(),
            grounded_event_ids: &landing.grounded_event_ids,
        };
        let Some(envelope) = self.checks.announce(row.kind, facts) else {
            // Nothing announceable — a draft whose facts do not add up to an
            // audit record (see `announce::drafted_event`).
            return Ok(());
        };
        let envelope = serde_json::to_value(&envelope)
            .map_err(|err| StoreError::malformed(format!("announcement envelope: {err}")))?;

        // `ON CONFLICT DO NOTHING` on the draft id: two landings racing the
        // same draft — a worker write and a cache write, the ordinary
        // consequence of a rebalance — announce it once.
        sqlx::query!(
            "INSERT INTO copilot_outbox (draft_id, envelope, created_at)
             VALUES ($1, $2, $3)
             ON CONFLICT (draft_id) DO NOTHING",
            row.draft_id.0,
            envelope,
            at,
        )
        .execute(&mut **tx)
        .await?;
        Ok(())
    }
}

/// A non-answer batch outcome as the sentence written to `last_error`.
pub fn batch_failure(outcome: &BatchItemOutcome) -> String {
    match outcome {
        BatchItemOutcome::Answered(_) => "answered".to_owned(),
        BatchItemOutcome::Errored { kind, message, .. } => {
            format!("batch item errored ({kind}): {message}")
        }
        BatchItemOutcome::Canceled => "batch canceled before this item ran".to_owned(),
        BatchItemOutcome::Expired => {
            "batch expired with this item unfinished (24h deadline)".to_owned()
        }
    }
}

/// The statuses a worker may still pick up — the claim scan's domain, and the
/// domain of the exhausted-attempt retirement that precedes it.
fn runnable_statuses() -> Vec<String> {
    use strum::IntoEnumIterator;
    DraftStatus::iter()
        .filter(|status| status.is_runnable())
        .map(|status| status.as_wire_str().to_owned())
        .collect()
}

/// The statuses [`DraftStore::cached_completion`] will serve from — a billed
/// answer, whatever a human later decided about it. `failed` is absent by
/// construction: a fault is the one case where trying again might work.
fn cacheable_statuses() -> Vec<String> {
    use strum::IntoEnumIterator;
    DraftStatus::iter()
        .filter(|status| status.is_cacheable())
        .map(|status| status.as_wire_str().to_owned())
        .collect()
}

fn usage_from(value: Option<serde_json::Value>) -> Result<TokenUsage, StoreError> {
    let Some(value) = value else {
        return Ok(TokenUsage::default());
    };
    let read = |field: &str| -> u64 {
        value
            .get(field)
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    };
    Ok(TokenUsage {
        input_tokens: read("input_tokens"),
        output_tokens: read("output_tokens"),
        cache_creation_input_tokens: read("cache_creation_input_tokens"),
        cache_read_input_tokens: read("cache_read_input_tokens"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_is_blocked_and_a_finished_answer_is_ready() {
        assert_eq!(status_for(&StopReason::EndTurn), DraftStatus::Ready);
        assert_eq!(
            status_for(&StopReason::Refusal { category: None }),
            DraftStatus::Blocked
        );
        assert_eq!(
            status_for(&StopReason::MaxTokens),
            DraftStatus::Blocked,
            "a truncated SAR draft stored as an answer is a lie"
        );
    }

    #[test]
    fn a_failed_draft_is_never_served_from_the_cache() {
        let statuses = cacheable_statuses();
        assert!(!statuses.contains(&"failed".to_owned()));
        assert!(!statuses.contains(&"queued".to_owned()));
        assert!(statuses.contains(&"blocked".to_owned()));
        assert!(statuses.contains(&"ready".to_owned()));
    }

    #[test]
    fn a_stop_reason_survives_the_column_round_trip() {
        for reason in [
            StopReason::EndTurn,
            StopReason::MaxTokens,
            StopReason::Refusal { category: None },
            StopReason::Other("pause_turn".into()),
        ] {
            assert_eq!(stop_reason_from(&stop_reason_str(&reason)), reason);
        }
        // The category is dropped deliberately — an open set the provider
        // controls belongs in a log, not a column.
        assert_eq!(
            stop_reason_from(&stop_reason_str(&StopReason::Refusal {
                category: Some("financial_crime".into())
            })),
            StopReason::Refusal { category: None }
        );
    }

    #[test]
    fn the_four_token_skus_survive_the_json_round_trip() {
        let usage = TokenUsage {
            input_tokens: 1,
            output_tokens: 2,
            cache_creation_input_tokens: 3,
            cache_read_input_tokens: 4,
        };
        assert_eq!(usage_from(Some(usage_json(&usage))).unwrap(), usage);
        assert_eq!(usage_from(None).unwrap(), TokenUsage::default());
    }
}
