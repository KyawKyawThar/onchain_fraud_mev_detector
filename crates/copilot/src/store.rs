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

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::primitives::{Chain, CustomerId};
use llm::cache::CacheKey;
use llm::{Completion, PromptDescriptor, StopReason, TokenUsage};
use sqlx::PgPool;
use std::str::FromStr;
use uuid::Uuid;

use crate::model::{
    ClaimedJob, Draft, DraftAnswer, DraftId, DraftJob, DraftKind, DraftStatus, Provenance, Review,
    Reviewed,
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

/// The status a completion resolves to. Shared by the worker's own write and
/// the cache's write-behind (see [`crate::cache`]) so the two can never
/// disagree about what a refusal means.
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
pub trait DraftWorkQueue: Send + Sync + std::fmt::Debug {
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
    async fn claim_batch(
        &self,
        kinds: &[DraftKind],
        limit: usize,
        lease: std::time::Duration,
        max_attempts: i32,
        at: DateTime<Utc>,
    ) -> Result<Vec<ClaimedJob>, StoreError>;

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
/// t4's draft API and t3's event emission both build on.
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

    /// Read one draft back — the reviewer's read, and t3's source for the
    /// `IncidentNarrativeDrafted` emission.
    async fn get(&self, draft_id: DraftId) -> Result<Option<Draft>, StoreError>;
}

/// Everything, for the one type that owns the table and for the contract
/// tests that exercise it end to end (`tests/draft_store.rs`).
///
/// Collaborators take the narrow trait they need; a concrete
/// `Arc<PgDraftStore>` coerces into any of them, so `main.rs` builds one store
/// and hands out four views of it. The blanket impl means a new backend gets
/// `DraftStore` for free by implementing the four roles.
pub trait DraftStore: DraftQueue + DraftWorkQueue + DraftCache + DraftReview {}

impl<T> DraftStore for T where T: DraftQueue + DraftWorkQueue + DraftCache + DraftReview {}

/// Postgres-backed [`DraftStore`]. Cheap to clone (the pool is an `Arc`
/// internally).
#[derive(Debug, Clone)]
pub struct PgDraftStore {
    pool: PgPool,
}

impl PgDraftStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
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
                 (draft_id, kind, subject_id, customer_id, chain, status, attempts,
                  created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, 0, $7, $7)
             ON CONFLICT (kind, subject_id) DO NOTHING
             RETURNING draft_id",
            job.draft_id.0,
            job.kind.as_wire_str(),
            job.subject_id,
            job.customer_id.map(|c| c.0),
            chain,
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
                AND attempts >= $4
                AND (lease_expires_at IS NULL OR lease_expires_at < $2)",
            DraftStatus::Failed.as_wire_str(),
            at,
            &runnable_statuses(),
            max_attempts,
            &kinds,
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
                        AND attempts < $5
                      ORDER BY created_at
                      FOR UPDATE SKIP LOCKED
                      LIMIT $6
                 ) AS claimable
                WHERE d.draft_id = claimable.draft_id
            RETURNING d.draft_id, d.kind, d.subject_id, d.customer_id, d.chain,
                      d.attempts, d.lease_expires_at AS "lease_expires_at!""#,
            DraftStatus::InFlight.as_wire_str(),
            lease_until,
            at,
            DraftStatus::Queued.as_wire_str(),
            max_attempts,
            limit,
            &kinds,
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
                    },
                    attempts: row.attempts,
                    lease_expires_at: row.lease_expires_at,
                })
            })
            .collect()
    }

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
        let status = match &outcome {
            DraftOutcome::Completed(completion) => status_for(&completion.stop_reason),
            DraftOutcome::Failed { permanent, .. } => {
                if *permanent {
                    DraftStatus::Failed
                } else {
                    // Back to the queue: the outer clock decides when, and
                    // `claim_batch`'s attempt ceiling decides whether ever.
                    DraftStatus::Queued
                }
            }
        };

        match outcome {
            DraftOutcome::Completed(completion) => {
                sqlx::query!(
                    "UPDATE copilot_drafts
                        SET status = $1, model = $2, stop_reason = $3, body = $4,
                            token_usage = $5, last_error = $6, lease_expires_at = NULL,
                            completed_at = $7, updated_at = $7
                      WHERE draft_id = $8",
                    status.as_wire_str(),
                    completion.model,
                    stop_reason_str(&completion.stop_reason),
                    completion.text,
                    usage_json(&completion.usage),
                    (!completion.stop_reason.is_complete())
                        .then(|| format!("unusable answer: {}", completion.stop_reason.as_str())),
                    at,
                    draft_id.0,
                )
                .execute(&self.pool)
                .await?;
            }
            DraftOutcome::Failed { reason, .. } => {
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
            }
        }
        Ok(status)
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
        let status = status_for(&completion.stop_reason);
        let result = sqlx::query!(
            "UPDATE copilot_drafts
                SET status = $1, model = $2, stop_reason = $3, body = $4,
                    token_usage = $5, lease_expires_at = NULL,
                    completed_at = $6, updated_at = $6
              WHERE request_digest = $7
                AND model_digest = $8
                AND status = $9",
            status.as_wire_str(),
            completion.model,
            stop_reason_str(&completion.stop_reason),
            completion.text,
            usage_json(&completion.usage),
            at,
            key.request_digest().to_hex(),
            key.model_digest().to_hex(),
            DraftStatus::InFlight.as_wire_str(),
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
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
        let row = sqlx::query!(
            "SELECT draft_id, kind, subject_id, customer_id, chain, status, attempts,
                    model, prompt_id, prompt_digest, stop_reason, body, token_usage,
                    grounded_event_ids, last_error, reviewed_by, reviewed_at,
                    review_note, created_at, updated_at, completed_at
               FROM copilot_drafts
              WHERE draft_id = $1",
            draft_id.0
        )
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else { return Ok(None) };
        let status = parse_enum::<DraftStatus>("status", &row.status)?;

        // Parse, don't validate: the column groups that are only ever written
        // together are re-assembled here, once, and a half-written group is a
        // malformed row rather than a `None` every later reader has to
        // second-guess against the status.
        let provenance = match (row.prompt_id, row.prompt_digest) {
            (Some(prompt_id), Some(prompt_digest)) => Some(Provenance {
                prompt_id,
                prompt_digest,
            }),
            (None, None) => None,
            _ => return Err(StoreError::malformed("prompt_id without prompt_digest")),
        };
        let answer = match (row.body, row.model, row.stop_reason, row.completed_at) {
            (Some(body), Some(model), Some(stop_reason), Some(completed_at)) => Some(DraftAnswer {
                body,
                model,
                stop_reason: stop_reason_from(&stop_reason),
                usage: usage_from(row.token_usage)?,
                completed_at,
            }),
            (None, None, None, _) => None,
            _ => return Err(StoreError::malformed("partially written draft answer")),
        };
        let review = match (row.reviewed_by, row.reviewed_at) {
            (Some(by), Some(at)) => Some(Reviewed {
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
                note: row.review_note,
            }),
            (None, None) => None,
            _ => return Err(StoreError::malformed("reviewer without a review time")),
        };

        Ok(Some(Draft {
            draft_id: DraftId(row.draft_id),
            kind: parse_enum::<DraftKind>("kind", &row.kind)?,
            subject_id: row.subject_id,
            customer_id: row.customer_id.map(CustomerId),
            chain: parse_chain(row.chain)?,
            status,
            attempts: row.attempts,
            provenance,
            answer,
            review,
            grounded_event_ids: to_uuid_list(Some(row.grounded_event_ids))?,
            last_error: row.last_error,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }))
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
