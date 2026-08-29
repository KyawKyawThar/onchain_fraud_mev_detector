//! In-memory doubles, behind the `test-util` feature.
//!
//! [`InMemoryDraftStore`] implements the *whole* [`DraftStore`] contract —
//! including the claim/lease semantics and the digest-keyed cache — rather
//! than a convenient subset. That is the point: the consumer's idempotency
//! and the pool's lease behaviour are the parts most likely to be wrong, and a
//! double that fakes them would test nothing. The Postgres implementation is
//! held to the same assertions by `tests/draft_store.rs` against a real
//! container.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::primitives::{AlertKind, Chain, IncidentId, Severity, SuggestedAction};
use events::simulation::IncidentCreated;
use events::{DomainEvent, EventEnvelope};
use llm::cache::CacheKey;
use llm::{Completion, CompletionRequest, ContentDigest, PromptDescriptor, StopReason, TokenUsage};
use uuid::Uuid;

use crate::audit::{AuditError, AuditSource, AuditStream};
use crate::model::{
    ClaimedJob, Draft, DraftAnswer, DraftId, DraftJob, DraftKind, DraftStatus, Provenance, Review,
    Reviewed,
};
use crate::store::{
    status_for, DraftCache, DraftOutcome, DraftQueue, DraftReview, DraftWorkQueue, Enqueued,
    StoreError,
};

/// A stand-in `EventEnvelope` for prompt/consumer tests — deliberately an
/// event the copilot does *not* act on, so a test that asserts "nothing was
/// enqueued" is asserting about routing rather than about parsing.
pub fn envelope(seq: u32) -> EventEnvelope {
    EventEnvelope::with_metadata(
        Uuid::from_u128(u128::from(seq) + 1),
        chrono::DateTime::from_timestamp(1_700_000_000 + i64::from(seq), 0).unwrap(),
        Chain::ETHEREUM,
        DomainEvent::BlockFinalized(events::chain::BlockFinalized {
            block: events::primitives::BlockRef::new(u64::from(seq), Default::default()),
        }),
    )
}

/// An envelope carrying attacker-authored free text — the shape a prompt
/// renderer has to survive (a token name, an ENS name, a rule explanation are
/// all chosen by the party under investigation).
pub fn hostile_envelope(text: &str) -> EventEnvelope {
    EventEnvelope::new(
        Chain::ETHEREUM,
        DomainEvent::RuleAlertCreated(events::rule_engine::RuleAlertCreated {
            alert_id: events::primitives::AlertId::new(),
            rule_id: events::primitives::RuleId::new(),
            owner: events::primitives::CustomerId::new(),
            address: Default::default(),
            explanation: text.to_owned(),
        }),
    )
}

/// One `IncidentCreated` envelope for `incident_id`.
pub fn incident_created(incident_id: IncidentId) -> EventEnvelope {
    EventEnvelope::new(
        Chain::ETHEREUM,
        DomainEvent::IncidentCreated(IncidentCreated {
            incident_id,
            alert_id: events::primitives::AlertId::new(),
            kind: AlertKind::Sandwich,
            txs: vec![Default::default()],
            profit: 1.5,
            victim_loss: 2.0,
            impact_usd: None,
            severity: Severity::High,
            suggested_action: SuggestedAction::Investigate,
            victim_address: None,
            victim_loss_usd: None,
        }),
    )
}

/// A minimal request for cache tests.
pub fn request() -> CompletionRequest {
    CompletionRequest::new("incident_narrative", "draft a narrative")
}

/// A finished completion.
pub fn completion(text: &str) -> Completion {
    Completion {
        text: text.to_owned(),
        stop_reason: StopReason::EndTurn,
        model: "claude-opus-5".to_owned(),
        usage: TokenUsage::default(),
    }
}

/// A claimed job for the prompt renderer's tests.
pub fn claimed(kind: DraftKind) -> ClaimedJob {
    ClaimedJob {
        job: DraftJob {
            draft_id: DraftId(Uuid::from_u128(7)),
            kind,
            subject_id: Uuid::from_u128(9),
            customer_id: None,
            chain: Chain::ETHEREUM,
        },
        attempts: 1,
        lease_expires_at: Utc::now(),
    }
}

/// An [`AuditSource`] that only ever fails — for asserting that a failed
/// grounding read never reaches (and never bills) the model.
#[derive(Debug, Clone, Copy)]
pub struct FailingAuditSource {
    transient: bool,
}

impl FailingAuditSource {
    pub fn transient() -> Self {
        Self { transient: true }
    }

    pub fn permanent() -> Self {
        Self { transient: false }
    }
}

#[async_trait]
impl AuditSource for FailingAuditSource {
    async fn audit_stream(
        &self,
        _incident_id: IncidentId,
        _max_events: usize,
    ) -> Result<AuditStream, AuditError> {
        Err(AuditError::Status {
            status: if self.transient { 503 } else { 400 },
            body: "test".into(),
        })
    }
}

/// The double's one place that turns a completion into a stored answer —
/// the mirror of the store's single `SET` clause, so the two backends cannot
/// drift on what "an answer landed" means.
fn answer_from(completion: &Completion, at: DateTime<Utc>) -> DraftAnswer {
    DraftAnswer {
        body: completion.text.clone(),
        model: completion.model.clone(),
        stop_reason: completion.stop_reason.clone(),
        usage: completion.usage,
        completed_at: at,
    }
}

#[derive(Debug, Clone)]
struct Row {
    draft: Draft,
    lease_expires_at: Option<DateTime<Utc>>,
    request_digest: Option<ContentDigest>,
    model_digest: Option<ContentDigest>,
}

/// In-memory [`DraftStore`], with the real claim/lease and cache semantics.
#[derive(Debug, Default)]
pub struct InMemoryDraftStore {
    rows: Mutex<HashMap<Uuid, Row>>,
    /// When set, every call fails with the given transience — how a test
    /// drives the consumer's retry-or-park decision.
    fail: Mutex<Option<bool>>,
}

impl InMemoryDraftStore {
    /// Make every call fail with a transient fault.
    pub fn failing_transiently(self) -> Self {
        *self.fail.lock().unwrap() = Some(true);
        self
    }

    /// Every draft, oldest first.
    pub fn drafts(&self) -> Vec<Draft> {
        let mut drafts: Vec<Draft> = self
            .rows
            .lock()
            .unwrap()
            .values()
            .map(|row| row.draft.clone())
            .collect();
        drafts.sort_by_key(|draft| (draft.created_at, draft.draft_id.0));
        drafts
    }

    fn guard(&self) -> Result<(), StoreError> {
        match *self.fail.lock().unwrap() {
            Some(true) => Err(StoreError::Postgres(sqlx::Error::PoolClosed)),
            Some(false) => Err(StoreError::malformed("injected")),
            None => Ok(()),
        }
    }

    fn with_row<T>(
        &self,
        draft_id: DraftId,
        f: impl FnOnce(&mut Row) -> T,
    ) -> Result<T, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        let row = rows
            .get_mut(&draft_id.0)
            .ok_or(StoreError::NotFound { draft_id })?;
        Ok(f(row))
    }
}

#[async_trait]
impl DraftQueue for InMemoryDraftStore {
    async fn enqueue(&self, job: &DraftJob, at: DateTime<Utc>) -> Result<Enqueued, StoreError> {
        self.guard()?;
        let mut rows = self.rows.lock().unwrap();
        if let Some(existing) = rows
            .values()
            .find(|row| row.draft.kind == job.kind && row.draft.subject_id == job.subject_id)
        {
            return Ok(Enqueued::AlreadyQueued(existing.draft.draft_id));
        }
        rows.insert(
            job.draft_id.0,
            Row {
                draft: Draft {
                    draft_id: job.draft_id,
                    kind: job.kind,
                    subject_id: job.subject_id,
                    customer_id: job.customer_id,
                    chain: job.chain,
                    status: DraftStatus::Queued,
                    attempts: 0,
                    provenance: None,
                    answer: None,
                    review: None,
                    grounded_event_ids: Vec::new(),
                    last_error: None,
                    created_at: at,
                    updated_at: at,
                },
                lease_expires_at: None,
                request_digest: None,
                model_digest: None,
            },
        );
        Ok(Enqueued::Queued(job.draft_id))
    }
}

#[async_trait]
impl DraftWorkQueue for InMemoryDraftStore {
    async fn claim_batch(
        &self,
        kinds: &[DraftKind],
        limit: usize,
        lease: std::time::Duration,
        max_attempts: i32,
        at: DateTime<Utc>,
    ) -> Result<Vec<ClaimedJob>, StoreError> {
        self.guard()?;
        if kinds.is_empty() {
            return Ok(Vec::new());
        }
        let lease = chrono::Duration::from_std(lease)
            .map_err(|err| StoreError::malformed(format!("lease: {err}")))?;
        let mut rows = self.rows.lock().unwrap();

        for row in rows
            .values_mut()
            .filter(|row| kinds.contains(&row.draft.kind))
        {
            let expired = row.lease_expires_at.is_none_or(|expires| expires < at);
            // Both runnable statuses, not just `in_flight`: a transiently
            // failed draft goes back as `queued` with its attempts intact,
            // and would otherwise sit runnable-but-unclaimable forever.
            if row.draft.status.is_runnable() && row.draft.attempts >= max_attempts && expired {
                row.draft.status = DraftStatus::Failed;
                row.draft
                    .last_error
                    .get_or_insert_with(|| "attempts exhausted".to_owned());
                row.lease_expires_at = None;
            }
        }

        let mut claimable: Vec<&mut Row> = rows
            .values_mut()
            .filter(|row| {
                kinds.contains(&row.draft.kind)
                    && row.draft.attempts < max_attempts
                    && (row.draft.status == DraftStatus::Queued
                        || (row.draft.status == DraftStatus::InFlight
                            && row.lease_expires_at.is_some_and(|expires| expires < at)))
            })
            .collect();
        claimable.sort_by_key(|row| (row.draft.created_at, row.draft.draft_id.0));

        Ok(claimable
            .into_iter()
            .take(limit)
            .map(|row| {
                row.draft.status = DraftStatus::InFlight;
                row.draft.attempts += 1;
                row.draft.updated_at = at;
                row.lease_expires_at = Some(at + lease);
                ClaimedJob {
                    job: DraftJob {
                        draft_id: row.draft.draft_id,
                        kind: row.draft.kind,
                        subject_id: row.draft.subject_id,
                        customer_id: row.draft.customer_id,
                        chain: row.draft.chain,
                    },
                    attempts: row.draft.attempts,
                    lease_expires_at: at + lease,
                }
            })
            .collect())
    }

    async fn begin_attempt(
        &self,
        draft_id: DraftId,
        key: &CacheKey,
        prompt: Option<&PromptDescriptor>,
        grounded_event_ids: &[Uuid],
        at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        self.guard()?;
        let provenance = prompt.map(|prompt| Provenance {
            prompt_id: prompt.id(),
            prompt_digest: prompt.digest().to_hex(),
        });
        self.with_row(draft_id, |row| {
            row.request_digest = Some(key.request_digest());
            row.model_digest = Some(key.model_digest());
            row.draft.provenance = provenance;
            row.draft.grounded_event_ids = grounded_event_ids.to_vec();
            row.draft.updated_at = at;
        })
    }

    async fn finish(
        &self,
        draft_id: DraftId,
        outcome: DraftOutcome,
        at: DateTime<Utc>,
    ) -> Result<DraftStatus, StoreError> {
        self.guard()?;
        self.with_row(draft_id, |row| {
            let status = match &outcome {
                DraftOutcome::Completed(completion) => {
                    let status = status_for(&completion.stop_reason);
                    row.draft.answer = Some(answer_from(completion, at));
                    row.draft.last_error = (!completion.stop_reason.is_complete())
                        .then(|| format!("unusable answer: {}", completion.stop_reason.as_str()));
                    status
                }
                DraftOutcome::Failed { reason, permanent } => {
                    row.draft.last_error = Some(reason.clone());
                    if *permanent {
                        DraftStatus::Failed
                    } else {
                        DraftStatus::Queued
                    }
                }
            };
            row.draft.status = status;
            row.draft.updated_at = at;
            row.lease_expires_at = None;
            status
        })
    }

    async fn release(&self, draft_id: DraftId, at: DateTime<Utc>) -> Result<(), StoreError> {
        self.guard()?;
        self.with_row(draft_id, |row| {
            if row.draft.status == DraftStatus::InFlight {
                row.draft.status = DraftStatus::Queued;
                row.lease_expires_at = None;
                row.draft.updated_at = at;
            }
        })
    }
}

#[async_trait]
impl DraftCache for InMemoryDraftStore {
    async fn cached_completion(&self, key: &CacheKey) -> Result<Option<Completion>, StoreError> {
        self.guard()?;
        let rows = self.rows.lock().unwrap();
        let mut hits: Vec<&Row> = rows
            .values()
            .filter(|row| {
                row.request_digest == Some(key.request_digest())
                    && row.model_digest == Some(key.model_digest())
                    && row.draft.status.is_cacheable()
                    && row.draft.answer.is_some()
            })
            .collect();
        hits.sort_by_key(|row| row.draft.answer.as_ref().map(|answer| answer.completed_at));
        Ok(hits.last().and_then(|row| {
            row.draft.answer.as_ref().map(|answer| Completion {
                text: answer.body.clone(),
                stop_reason: answer.stop_reason.clone(),
                model: answer.model.clone(),
                usage: answer.usage,
            })
        }))
    }

    async fn store_completion(
        &self,
        key: &CacheKey,
        completion: &Completion,
        at: DateTime<Utc>,
    ) -> Result<u64, StoreError> {
        self.guard()?;
        let mut rows = self.rows.lock().unwrap();
        let mut landed = 0u64;
        for row in rows.values_mut() {
            if row.request_digest == Some(key.request_digest())
                && row.model_digest == Some(key.model_digest())
                && row.draft.status == DraftStatus::InFlight
            {
                row.draft.status = status_for(&completion.stop_reason);
                row.draft.answer = Some(answer_from(completion, at));
                row.draft.updated_at = at;
                row.lease_expires_at = None;
                landed += 1;
            }
        }
        Ok(landed)
    }
}

#[async_trait]
impl DraftReview for InMemoryDraftStore {
    async fn review(
        &self,
        draft_id: DraftId,
        review: Review,
        reviewer: &str,
        note: Option<&str>,
        at: DateTime<Utc>,
    ) -> Result<DraftStatus, StoreError> {
        self.guard()?;
        let mut rows = self.rows.lock().unwrap();
        let row = rows
            .get_mut(&draft_id.0)
            .ok_or(StoreError::NotFound { draft_id })?;
        if row.draft.status != DraftStatus::Ready {
            return Err(StoreError::NotReviewable {
                draft_id,
                status: row.draft.status.as_wire_str().to_owned(),
            });
        }
        row.draft.status = review.status();
        row.draft.review = Some(Reviewed {
            verdict: review,
            by: reviewer.to_owned(),
            at,
            note: note.map(str::to_owned),
        });
        row.draft.updated_at = at;
        Ok(row.draft.status)
    }

    async fn get(&self, draft_id: DraftId) -> Result<Option<Draft>, StoreError> {
        self.guard()?;
        Ok(self
            .rows
            .lock()
            .unwrap()
            .get(&draft_id.0)
            .map(|row| row.draft.clone()))
    }
}
