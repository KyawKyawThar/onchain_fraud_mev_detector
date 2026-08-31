//! The copilot's domain vocabulary: what a draft is, where it is in its
//! lifecycle, and who it belongs to.
//!
//! Every type here is storage-facing — `kind` and `status` are literal column
//! values — so the enum→string mapping is derived rather than hand-written
//! (`strum`), the same reason `notification::model::ChannelKind` is.

use chrono::{DateTime, Utc};
use events::copilot::NarrativeSource;
use events::primitives::{Chain, CustomerId, IncidentId};
use llm::{StopReason, TokenUsage};
use uuid::Uuid;

use crate::grounding::GroundingSummary;

/// Which path a draft is produced by — the synchronous worker pool, or the
/// half-price Batch API backfill (§20.4).
///
/// This is [`events::copilot::NarrativeSource`] and not a second enum beside
/// it: the column, the claim filter and the emitted event all mean the same
/// thing by it, and a copy would eventually disagree with the wire form about
/// what `"backfill"` is.
pub type DraftSource = NarrativeSource;

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

    /// Whether `self -> next` is a transition the lifecycle allows.
    ///
    /// The state machine written down once, instead of implied by a `WHERE
    /// status = …` clause in each of the store's writes. Those clauses stay —
    /// they are what makes each write atomic — but this is the table they must
    /// agree with, and [`Self::transitions`] is the test that they do.
    ///
    /// Reading it as a graph: work is claimed (`queued -> in_flight`) and
    /// either comes back with an answer (`ready`/`blocked`), fails
    /// (`failed`), or is handed back (`in_flight -> queued`, a release or a
    /// transient fault). Only `ready` is reviewable, and a review is
    /// terminal — there is no path out of `approved`/`rejected`, because a
    /// regulatory document that could be un-approved is not an audit trail.
    pub fn can_transition(self, next: DraftStatus) -> bool {
        use DraftStatus::*;
        match (self, next) {
            // The claim, and the two ways a claim comes back without an
            // answer: released (no attempt consumed) or transiently failed.
            (Queued, InFlight) | (InFlight, Queued) => true,
            // An answer landed — usable, or billed-but-unusable.
            (InFlight, Ready | Blocked) => true,
            // A permanent fault, or the attempt ceiling retiring a draft that
            // is still runnable.
            (Queued | InFlight, Failed) => true,
            // The §20.4 boundary: a human decides, once.
            (Ready, Approved | Rejected) => true,
            // An operator requeues a terminal draft (a new prompt version, a
            // provider outage that has since cleared). Deliberately allowed
            // from `failed` and `blocked` — and deliberately *not* from a
            // reviewed one.
            (Failed | Blocked, Queued) => true,
            _ => false,
        }
    }

    /// Every legal transition, for tests and for documentation that cannot go
    /// stale.
    pub fn transitions() -> Vec<(DraftStatus, DraftStatus)> {
        use strum::IntoEnumIterator;
        DraftStatus::iter()
            .flat_map(|from| DraftStatus::iter().map(move |to| (from, to)))
            .filter(|(from, to)| from.can_transition(*to))
            .collect()
    }

    /// Whether a human may still decide on this draft (§20.4).
    pub fn is_reviewable(self) -> bool {
        matches!(self, DraftStatus::Ready)
    }

    /// Whether the lifecycle is over unless an operator intervenes.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            DraftStatus::Failed
                | DraftStatus::Blocked
                | DraftStatus::Approved
                | DraftStatus::Rejected
        )
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
    /// Which path must drain this job. Load-bearing, not descriptive: the
    /// synchronous pool claims only `live` rows and the backfill only
    /// `backfill` ones, so a historical draft cannot be picked up by a worker
    /// and paid for at full price (§20.4 — backfill is half price precisely
    /// because nobody is waiting for it).
    pub source: DraftSource,
    /// What the customer asked for, in their own words — the *whole* input to
    /// a rule draft (§20.4 t4).
    ///
    /// `None` for a narrative, and the asymmetry is deliberate rather than an
    /// oversight. A narrative's subject is an incident the platform recorded,
    /// so the job names it and the worker reads the current stream; carrying a
    /// rendered copy would be a snapshot of a stream that has since grown. A
    /// rule request is the opposite: it is the input itself, immutable, and
    /// stored nowhere else in the system. Re-drafting it after a rebalance
    /// means reading it back from this row.
    pub source_text: Option<String>,
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
            source: DraftSource::Live,
            source_text: None,
        }
    }

    /// The rule-draft job one `POST /v1/rules/draft` implies (§20.4 t4).
    ///
    /// The subject is **derived from the request**
    /// ([`crate::rule_draft::subject_for`]), not minted: the enqueue is keyed
    /// on `(kind, subject_id)`, so a customer who submits the same sentence
    /// twice — a double-clicked button, a retried request — resolves to the
    /// draft that already exists instead of paying for a second, differently
    /// worded answer to the same question.
    pub fn rule_draft(owner: CustomerId, chain: Chain, request: impl Into<String>) -> Self {
        let request = request.into();
        Self {
            draft_id: DraftId::new(),
            kind: DraftKind::RuleDraft,
            subject_id: crate::rule_draft::subject_for(owner, &request),
            // Always billed to the customer who asked (§13) — unlike a
            // narrative, a rule draft has one by construction.
            customer_id: Some(owner),
            chain,
            source: DraftSource::Live,
            source_text: Some(request),
        }
    }

    /// The same job, for an incident being backfilled from the archive —
    /// drained through the Batch API instead of the worker pool.
    pub fn backfilled_narrative(incident_id: IncidentId, chain: Chain) -> Self {
        Self {
            source: DraftSource::Backfill,
            ..Self::narrative(incident_id, chain)
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
    pub source: DraftSource,
    /// The customer's own request, for a kind whose subject is one
    /// ([`DraftJob::source_text`]). `None` for a narrative.
    pub source_text: Option<String>,
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
    /// The event ids this draft stands on (§20.4).
    ///
    /// Two meanings, in sequence, and the transition is the point: the worker
    /// writes the *window* it showed the model before the call (so the draft
    /// records what it was allowed to see), and the landing narrows it to the
    /// ids the narrative actually **cites** ([`crate::grounding`]). Keeping
    /// the window first is what makes the narrowing checkable — a citation
    /// outside it is a fabrication, not a wider view.
    pub grounded_event_ids: Vec<Uuid>,
    /// What the citation check found. `None` until a call has landed, and for
    /// kinds that make no citable claims.
    pub grounding: Option<GroundingSummary>,
    /// The Batch API job this draft rode, if it was backfilled. Durable state,
    /// not a log line: a backfill process that dies mid-run recovers its
    /// outstanding batches from this column rather than submitting (and
    /// paying for) them a second time.
    pub batch_id: Option<String>,
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

    /// The incident this narrative is about, for a draft that is one.
    pub fn incident_id(&self) -> Option<IncidentId> {
        (self.kind == DraftKind::IncidentNarrative).then_some(IncidentId(self.subject_id))
    }

    /// The compiled rule this draft proposes, for a rule draft that landed a
    /// usable answer (§20.4 t4).
    ///
    /// Re-parsed from the body rather than stored a second time: the body *is*
    /// the definition, and a parsed copy beside it is one more thing that can
    /// disagree with what the customer reads. The parse cannot fail on a
    /// `ready` draft — clearing [`crate::rule_draft::compile_check`] is what
    /// made it `ready` — so a failure here is a corrupt row and reads as
    /// `None`.
    ///
    /// Returns [`CompiledDraft`](crate::rule_draft::CompiledDraft), not a bare
    /// definition: a caller receiving this cannot confuse it with something
    /// that merely deserialized, and activating it still requires supplying the
    /// id and owner the model was never allowed to choose.
    pub fn compiled_rule(&self) -> Option<crate::rule_draft::CompiledDraft> {
        if self.kind != DraftKind::RuleDraft {
            return None;
        }
        crate::rule_draft::compile_check(self.body()?).ok()
    }

    /// The facts an `IncidentNarrativeDrafted` is built from, once this draft
    /// has an answer and an attributable prompt.
    ///
    /// The store's landing path builds the same announcement from raw columns
    /// inside its transaction; this is the read-side equivalent, so the two
    /// can be tested against each other rather than trusted to agree.
    pub fn drafted_facts(&self) -> Option<crate::announce::DraftedFacts<'_>> {
        Some(crate::announce::DraftedFacts {
            draft_id: self.draft_id,
            kind: self.kind,
            subject_id: self.subject_id,
            owner: self.customer_id,
            chain: self.chain,
            source: self.source,
            source_text: self.source_text.as_deref(),
            provenance: self.provenance.as_ref()?,
            model: self.answer.as_ref()?.model.as_str(),
            body: self.answer.as_ref()?.body.as_str(),
            completed_at: self.answer.as_ref()?.completed_at,
            grounding: self.grounding.as_ref(),
            grounded_event_ids: &self.grounded_event_ids,
        })
    }

    /// Where a reviewer reads and approves this draft — the `narrative_ref`
    /// on `IncidentNarrativeDrafted`, and the `draft_ref` on
    /// `RuleDraftProposed`.
    ///
    /// A reference and not the prose: an unapproved machine-written document
    /// has no business being replicated into an immutable audit log (see
    /// [`events::copilot`]).
    pub fn narrative_ref(&self) -> String {
        format!("copilot://drafts/{}", self.draft_id)
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

    /// The transitions the store's `WHERE status = …` clauses are allowed to
    /// perform. If a write starts doing something this table forbids, one of
    /// the two is wrong — and this is where the argument happens.
    #[test]
    fn the_lifecycle_graph_is_the_one_the_store_writes() {
        use DraftStatus::*;
        for (from, to) in [
            (Queued, InFlight),
            (InFlight, Ready),
            (InFlight, Blocked),
            (InFlight, Failed),
            (InFlight, Queued),
            (Queued, Failed),
            (Ready, Approved),
            (Ready, Rejected),
            (Failed, Queued),
            (Blocked, Queued),
        ] {
            assert!(from.can_transition(to), "{from:?} -> {to:?} must be legal");
        }

        // A review is final: nothing may walk an approved narrative back into
        // the queue, or re-decide one that was rejected.
        for from in [Approved, Rejected] {
            for to in DraftStatus::iter() {
                assert!(
                    !from.can_transition(to),
                    "{from:?} -> {to:?} must not be legal: a decided draft is decided"
                );
            }
        }
        // …and nothing skips the claim.
        assert!(!Queued.can_transition(Ready));
        assert!(!Queued.can_transition(Approved));
        // A landed draft is not reviewable until it is `ready`.
        assert!(Ready.is_reviewable());
        for status in [Queued, InFlight, Blocked, Failed, Approved, Rejected] {
            assert!(
                !status.is_reviewable(),
                "{status:?} has no answer to approve"
            );
        }
        assert!(!DraftStatus::transitions().is_empty());
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
