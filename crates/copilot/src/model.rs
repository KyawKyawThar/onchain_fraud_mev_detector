//! The copilot's domain vocabulary: what a draft is, where it is in its
//! lifecycle, and who it belongs to.
//!
//! Every type here is storage-facing — `kind` and `status` are literal column
//! values — so the enum→string mapping is derived rather than hand-written
//! (`strum`), the same reason `notification::model::ChannelKind` is.

use chrono::{DateTime, Utc};
use events::primitives::{Chain, CustomerId, IncidentId};
use llm::{StopReason, TokenUsage};
use uuid::Uuid;

/// A draft's identity. Minted once at enqueue and stable across every retry —
/// a redelivered `IncidentCreated` resolves to the *existing* id (see
/// [`crate::store::DraftStore::enqueue`]), never a second one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DraftId(pub Uuid);

impl DraftId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for DraftId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for DraftId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Which §20.4 capability a draft belongs to.
///
/// The wire string is three things at once — the `kind` column, the prompt
/// artifact's purpose, and the `CompletionRequest::purpose` metrics label — so
/// the set stays small and static by construction (a per-incident label would
/// be a cardinality incident).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    strum::IntoStaticStr,
    strum::EnumString,
    strum::EnumIter,
)]
#[strum(serialize_all = "snake_case")]
pub enum DraftKind {
    /// An incident narrative / SAR draft grounded in the incident's audit
    /// stream.
    IncidentNarrative,
    /// A natural-language rule draft. Enqueued by t4's `POST
    /// /v1/rules/draft`, never by this crate's consumer — declared here so
    /// the queue, the store and the worker pool are already kind-agnostic.
    RuleDraft,
}

impl DraftKind {
    /// Every kind, for a caller that deliberately serves all of them (tests,
    /// and a single-process deployment). Production pods pass
    /// [`crate::worker::GeneratorRegistry::kinds`] instead — claiming work
    /// this pod cannot finish is how a draft ends up leased by a replica that
    /// can only release it again.
    pub const ALL: &'static [DraftKind] = &[DraftKind::IncidentNarrative, DraftKind::RuleDraft];

    pub fn as_wire_str(self) -> &'static str {
        self.into()
    }
}

/// Where a draft is in its lifecycle.
///
/// The split that matters is [`Failed`](DraftStatus::Failed) vs
/// [`Blocked`](DraftStatus::Blocked): a failure is a call that did not
/// produce an answer and might succeed later, while a blocked draft is a
/// *successful, billed* call whose answer is unusable. Retrying a refusal
/// buys a second identical refusal at full price, so the two can never share
/// a status.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    strum::IntoStaticStr,
    strum::EnumString,
    strum::EnumIter,
)]
#[strum(serialize_all = "snake_case")]
pub enum DraftStatus {
    /// Recorded by the consumer, waiting for a worker.
    Queued,
    /// Leased by a worker. A lease that expires without an outcome is
    /// reclaimed — that is what makes a killed pod's work re-runnable.
    InFlight,
    /// A complete answer is stored, awaiting human review. **Not** delivered
    /// anywhere: §20.4 drafts are provisional forever until approved.
    Ready,
    /// The model answered but the answer is unusable — a refusal, or a
    /// `max_tokens` truncation (a truncated SAR draft stored as an answer is
    /// a lie). Terminal; a human looks at `last_error`.
    Blocked,
    /// Attempts exhausted against a fault that kept failing. Terminal until
    /// an operator requeues it.
    Failed,
    /// A human approved the draft. The only state from which anything
    /// downstream may use it.
    Approved,
    /// A human rejected it. Kept, not deleted — the audit record of a draft
    /// that was produced and refused is the point.
    Rejected,
}

impl DraftStatus {
    pub fn as_wire_str(self) -> &'static str {
        self.into()
    }

    /// Whether a worker may still pick this draft up. Only these two states
    /// are scanned by the claim query — everything else is terminal or
    /// already reviewed.
    pub fn is_runnable(self) -> bool {
        matches!(self, DraftStatus::Queued | DraftStatus::InFlight)
    }

    /// Whether the row holds an answer worth serving from the cross-pod
    /// cache. [`Blocked`](DraftStatus::Blocked) is included deliberately: a
    /// cached refusal is what stops a redelivery loop from paying for the
    /// same decline repeatedly (see `llm::cache`).
    pub fn is_cacheable(self) -> bool {
        matches!(
            self,
            DraftStatus::Ready
                | DraftStatus::Blocked
                | DraftStatus::Approved
                | DraftStatus::Rejected
        )
    }
}

/// A queued unit of work, as the consumer records it.
///
/// Deliberately thin: it names *what to draft*, never the prompt or the audit
/// stream. Materialising the input is the worker's job, minutes later and in
/// another process — a job row carrying a rendered prompt would be a snapshot
/// of an audit stream that has since grown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftJob {
    pub draft_id: DraftId,
    pub kind: DraftKind,
    /// The incident this draft is about (a rule-draft request id for t4).
    pub subject_id: Uuid,
    /// Who the tokens bill to (§13). `None` for platform-internal work with
    /// no customer in scope — which is every incident-stream draft today.
    pub customer_id: Option<CustomerId>,
    pub chain: Chain,
}

impl DraftJob {
    /// The narrative job one `IncidentCreated` implies.
    pub fn narrative(incident_id: IncidentId, chain: Chain) -> Self {
        Self {
            draft_id: DraftId::new(),
            kind: DraftKind::IncidentNarrative,
            subject_id: incident_id.0,
            customer_id: None,
            chain,
        }
    }
}

/// A job a worker holds a lease on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedJob {
    pub job: DraftJob,
    /// How many times this draft has been claimed, including now. Counts
    /// *claims*, not provider calls — the LLM seam runs its own bounded retry
    /// underneath a single claim.
    pub attempts: i32,
    /// When this pod's exclusive hold expires and another may reclaim it.
    pub lease_expires_at: DateTime<Utc>,
}

/// Which versioned prompt artifact produced a draft (§20.4).
///
/// Both halves or neither: an id names the artifact that was *meant*, the
/// digest names the bytes that actually ran, and a draft carrying one without
/// the other is unattributable — which is the whole thing the pair exists to
/// prevent. Set together when the attempt declares its request, so the type
/// makes the invariant rather than a convention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// `"incident_narrative@v1"` — `PromptDescriptor::id`.
    pub prompt_id: String,
    /// The artifact's content hash, hex.
    pub prompt_digest: String,
}

/// What the model returned — present only once a call has produced something.
///
/// The five fields land in one `UPDATE` and are meaningless apart: a `body`
/// with no `model` cannot be attributed, a `stop_reason` with no `body` says
/// nothing about an answer. Grouping them means a caller cannot read
/// `draft.body` on a queued draft and take the `None` for "the model returned
/// nothing" when it means "no call has happened yet" — the distinction that
/// decides whether a reviewer is looking at a bug or at a queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftAnswer {
    pub body: String,
    /// The model that *actually* answered, from the response — with
    /// server-side refusal fallbacks that is not always the one asked (§20.4).
    pub model: String,
    /// Why it stopped. [`DraftStatus::Ready`] iff this `is_complete()`; the
    /// refusal category is deliberately not persisted (an open set the
    /// provider controls belongs in a log, not a column).
    pub stop_reason: StopReason,
    /// The four SKUs, kept apart because they are four different prices (§13).
    pub usage: TokenUsage,
    pub completed_at: DateTime<Utc>,
}

/// A human's verdict, once one exists (§20.4).
///
/// `by` and `at` are written in the same statement as the status, so a draft
/// that is `approved` without a reviewer, or carries a reviewer without a
/// timestamp, is a corrupt row rather than a state this type can hold. For a
/// document that leaves the platform on a person's say-so, "who, and when" is
/// not optional metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reviewed {
    pub verdict: Review,
    pub by: String,
    pub at: DateTime<Utc>,
    pub note: Option<String>,
}

/// A stored draft, as a reviewer (and t3's event emission) reads it back.
///
/// The three `Option<struct>` fields below replace eight loose `Option<T>`s.
/// The old shape could represent a draft that was reviewed but never
/// answered, or answered by nobody — states the lifecycle cannot reach, which
/// meant every reader had to re-derive "is this really set?" from the status.
/// Now the store parses those combinations once, at the boundary, and a
/// half-written row is [`crate::store::StoreError::Malformed`] instead of a
/// plausible-looking value (parse, don't validate).
#[derive(Debug, Clone, PartialEq)]
pub struct Draft {
    pub draft_id: DraftId,
    pub kind: DraftKind,
    pub subject_id: Uuid,
    pub customer_id: Option<CustomerId>,
    pub chain: Chain,
    pub status: DraftStatus,
    pub attempts: i32,
    /// The prompt half of §20.4's provenance triple; the model half lives on
    /// [`DraftAnswer`], because it is only known once the response arrives.
    /// `None` until an attempt declares its request.
    pub provenance: Option<Provenance>,
    /// `None` until a call returns. Present on `ready` and `blocked` alike —
    /// a refusal is an answer the platform was billed for.
    pub answer: Option<DraftAnswer>,
    /// `None` until a human decides. Nothing in this service ever sets it.
    pub review: Option<Reviewed>,
    /// The event ids the model was grounded in (§20.4). t3 narrows this from
    /// "the window it was shown" to "the ids the narrative cites".
    pub grounded_event_ids: Vec<Uuid>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Draft {
    /// The drafted text, if a call has produced one.
    pub fn body(&self) -> Option<&str> {
        self.answer.as_ref().map(|answer| answer.body.as_str())
    }

    /// The model that actually answered, if one has.
    pub fn model(&self) -> Option<&str> {
        self.answer.as_ref().map(|answer| answer.model.as_str())
    }

    /// Whether this draft has cleared §20.4's validating boundary — the one
    /// question anything downstream of the copilot is allowed to act on.
    pub fn is_approved(&self) -> bool {
        matches!(self.status, DraftStatus::Approved)
    }
}

/// A human's verdict on a draft (§20.4 — the validating boundary an incident
/// narrative must cross before it can leave the platform).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Review {
    Approve,
    Reject,
}

impl Review {
    pub fn status(self) -> DraftStatus {
        match self {
            Review::Approve => DraftStatus::Approved,
            Review::Reject => DraftStatus::Rejected,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use strum::IntoEnumIterator;

    #[test]
    fn every_status_round_trips_through_its_column_value() {
        for status in DraftStatus::iter() {
            assert_eq!(
                DraftStatus::from_str(status.as_wire_str()).unwrap(),
                status,
                "a stored status must read back as the variant that wrote it"
            );
        }
        for kind in DraftKind::iter() {
            assert_eq!(DraftKind::from_str(kind.as_wire_str()).unwrap(), kind);
        }
    }

    #[test]
    fn every_kind_is_in_all() {
        // `ALL` is hand-written (a const slice cannot be derived), so this is
        // what stops a new variant from being silently unclaimable.
        let listed: Vec<DraftKind> = DraftKind::ALL.to_vec();
        for kind in DraftKind::iter() {
            assert!(
                listed.contains(&kind),
                "{kind:?} missing from DraftKind::ALL"
            );
        }
        assert_eq!(listed.len(), DraftKind::iter().count());
    }

    #[test]
    fn a_failure_is_retryable_and_a_refusal_is_not() {
        assert!(
            !DraftStatus::Failed.is_cacheable(),
            "a fault might succeed later — caching it would pin the failure"
        );
        assert!(
            DraftStatus::Blocked.is_cacheable(),
            "a refusal refuses again; caching it is what stops paying twice"
        );
        assert!(!DraftStatus::Blocked.is_runnable());
        assert!(DraftStatus::Queued.is_runnable() && DraftStatus::InFlight.is_runnable());
    }
}
