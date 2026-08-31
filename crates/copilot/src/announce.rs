//! Building the copilot's audit records (§20.4) — `IncidentNarrativeDrafted`
//! and `RuleDraftProposed`: that a draft exists, who wrote it, and what it
//! stands on.
//!
//! # The announcement is written with the draft, not after it
//!
//! A narrative reaching `ready` and the platform announcing it are one fact,
//! and this crate has exactly one place where that fact happens: the landing
//! transaction in [`crate::store`]. It writes the draft row **and** the
//! envelope into `copilot_outbox` together, and [`crate::outbox`] drains the
//! pending rows onto Kafka afterwards.
//!
//! The alternatives were both considered and are both worse:
//!
//! * **publish after the update** leaves a window where a narrative exists
//!   that the audit trail never heard about;
//! * **stamp-then-publish** (claim the announcement on the draft row, publish,
//!   and hope) loses the event outright on a crash between the two — and it
//!   invents a second mechanism for a problem this workspace already solved
//!   once, in `rule_engine::outbox`.
//!
//! The outbox costs one INSERT inside a transaction that was already open, and
//! makes the announcement exactly as durable as the draft it describes.
//!
//! # What is in the event
//!
//! For a narrative: a **reference**, never the prose. An unapproved,
//! machine-written document has no business being replicated into an immutable
//! log as if it were evidence (see [`events::copilot`]), so the event carries
//! the provenance triple, the cited event ids, the claim counts, and a pointer
//! to where a human reads it.
//!
//! For a rule draft: the **definition itself**, plus a hash of the request and
//! no copy of it. The asymmetry is not an inconsistency — it follows from what
//! each artifact is. Prose is unbounded and unverifiable, so the log gets a
//! pointer; a rule definition is a closed structure that already passed §9's
//! compiler, cannot act on anything until a customer activates it through
//! `POST /v1/rules`, and is exactly the thing an auditor will later want to
//! diff against what *was* activated. The customer's sentence, meanwhile, is
//! their free text and not a platform fact, so only its hash travels.
//!
//! # Only `ready` drafts are announced
//!
//! A refusal, a truncation, an ungrounded narrative and a rule that did not
//! compile are all `blocked`: billed, terminal, and with nothing for anyone to
//! read or activate. Announcing them would put "a draft was produced" in the
//! audit trail for subjects where none was. They are visible where they
//! belong — the drafts table and the
//! `copilot_drafts_finished_total{status="blocked"}` series.

use chrono::{DateTime, Utc};
use events::copilot::{IncidentNarrativeDrafted, RuleDraftProposed};
use events::primitives::{Chain, CustomerId, IncidentId};
use events::{DomainEvent, EventEnvelope};
use uuid::Uuid;

use crate::grounding::GroundingSummary;
use crate::model::{DraftId, DraftKind, DraftSource, Provenance};
use crate::rule_draft;

/// Everything an announcement is built from.
///
/// A borrowed view rather than a `&Draft`, because the authoritative caller is
/// the store's landing transaction, which holds raw columns and a fresh
/// `llm::Completion` — not a re-read `Draft`. `Draft::drafted_facts` builds
/// the same view on the read side, which is how the two paths stay honest
/// about producing the same event.
#[derive(Debug, Clone, Copy)]
pub struct DraftedFacts<'a> {
    pub draft_id: DraftId,
    pub kind: DraftKind,
    pub subject_id: Uuid,
    /// Whose draft it is. Required for a rule draft (a rule has an owner);
    /// `None` for a narrative, which has no customer in scope.
    pub owner: Option<CustomerId>,
    pub chain: Chain,
    pub source: DraftSource,
    /// The customer's own request, for a rule draft — hashed into the event,
    /// never copied into it.
    pub source_text: Option<&'a str>,
    /// The prompt half of §20.4's provenance. Required: an unattributable
    /// regulatory document is not one worth announcing.
    pub provenance: &'a Provenance,
    /// The model that *actually* answered, from the response — with
    /// server-side refusal fallbacks that is not always the one asked.
    pub model: &'a str,
    /// What the model actually returned. For a rule draft this *is* the
    /// definition, which is why the announcement re-reads it through the parse
    /// boundary rather than trusting a second copy.
    pub body: &'a str,
    pub completed_at: DateTime<Utc>,
    pub grounding: Option<&'a GroundingSummary>,
    /// The narrowed ids — what the narrative cites, not the window it saw.
    pub grounded_event_ids: &'a [Uuid],
}

/// Where a reviewer reads and approves a draft — the narrative event's
/// `narrative_ref` and the rule event's `draft_ref`.
pub fn narrative_ref(draft_id: DraftId) -> String {
    format!("copilot://drafts/{draft_id}")
}

/// Build the event, or `None` if these facts do not describe an announceable
/// narrative.
///
/// Pure, so the mapping — which is where §20.4's provenance requirements
/// actually land — is testable without a store, a broker, or a model.
pub fn drafted_event(facts: DraftedFacts<'_>) -> Option<IncidentNarrativeDrafted> {
    if facts.kind != DraftKind::IncidentNarrative {
        return None;
    }
    let summary = facts.grounding.cloned().unwrap_or_default();
    Some(IncidentNarrativeDrafted {
        incident_id: IncidentId(facts.subject_id),
        draft_id: facts.draft_id.0,
        narrative_ref: narrative_ref(facts.draft_id),
        model_id: facts.model.to_owned(),
        prompt_id: prompt_name(&facts.provenance.prompt_id),
        prompt_version: prompt_version(&facts.provenance.prompt_id),
        prompt_digest: facts.provenance.prompt_digest.clone(),
        grounded_event_ids: facts.grounded_event_ids.to_vec(),
        claims: summary.claims as u32,
        cited_claims: summary.cited_claims as u32,
        source: facts.source,
        drafted_at: facts.completed_at,
    })
}

/// Build the rule-draft record, or `None` if these facts do not describe an
/// announceable proposal.
///
/// Three ways that happens, and each is a corrupt row rather than a state to
/// tolerate: no owner (a rule with no customer is not a rule anyone can
/// activate), no request text (nothing to hash), or a body that does not pass
/// the parse boundary. The last cannot occur on a landing that reached `ready`
/// — clearing [`rule_draft::compile_check`] is what made it `ready` — so it is
/// belt to the landing's braces, and it fails closed.
pub fn proposed_event(facts: DraftedFacts<'_>) -> Option<RuleDraftProposed> {
    if facts.kind != DraftKind::RuleDraft {
        return None;
    }
    let owner = facts.owner?;
    let request = facts.source_text?;
    let definition = rule_draft::compile_check(facts.body).ok()?;
    Some(RuleDraftProposed {
        draft_id: facts.draft_id.0,
        owner,
        source_text_hash: rule_draft::source_text_hash(owner, request),
        draft_ref: narrative_ref(facts.draft_id),
        definition: serde_json::to_value(definition.definition()).ok()?,
        model_id: facts.model.to_owned(),
        prompt_id: prompt_name(&facts.provenance.prompt_id),
        prompt_version: prompt_version(&facts.provenance.prompt_id),
        prompt_digest: facts.provenance.prompt_digest.clone(),
        proposed_at: facts.completed_at,
    })
}

/// The narrative announcement, as an envelope ready to publish verbatim.
///
/// Note what is *not* here any more: a `match` on kind. Each kind's capability
/// returns its own envelope ([`crate::capability::DraftCapability::announce`]),
/// so this module stays a set of pure mappings and the dispatch lives in the
/// one place that also owns the kind's prompt and its landing check.
pub fn narrative_envelope(facts: DraftedFacts<'_>) -> Option<EventEnvelope> {
    let chain = facts.chain;
    drafted_event(facts)
        .map(|event| EventEnvelope::new(chain, DomainEvent::IncidentNarrativeDrafted(event)))
}

/// The rule-draft announcement, likewise.
pub fn rule_draft_envelope(facts: DraftedFacts<'_>) -> Option<EventEnvelope> {
    let chain = facts.chain;
    proposed_event(facts)
        .map(|event| EventEnvelope::new(chain, DomainEvent::RuleDraftProposed(event)))
}

/// `"incident_narrative@v2"` -> `"incident_narrative"`.
fn prompt_name(prompt_id: &str) -> String {
    prompt_id
        .split_once('@')
        .map(|(name, _)| name)
        .unwrap_or(prompt_id)
        .to_owned()
}

/// `"incident_narrative@v2"` -> `"v2"`. An id without a version reads as
/// `"unknown"` rather than silently as the whole id: a version field that
/// sometimes holds a name is worse than one that admits it doesn't know.
fn prompt_version(prompt_id: &str) -> String {
    prompt_id
        .split_once('@')
        .map(|(_, version)| version.to_owned())
        .unwrap_or_else(|| "unknown".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Draft, DraftAnswer, DraftStatus};
    use llm::{StopReason, TokenUsage};

    fn draft(status: DraftStatus) -> Draft {
        Draft {
            draft_id: DraftId(Uuid::from_u128(7)),
            kind: DraftKind::IncidentNarrative,
            subject_id: Uuid::from_u128(0x1C),
            customer_id: None,
            chain: Chain::ETHEREUM,
            source: DraftSource::Live,
            source_text: None,
            status,
            attempts: 1,
            provenance: Some(Provenance {
                prompt_id: "incident_narrative@v2".into(),
                prompt_digest: "3f9c".into(),
            }),
            answer: Some(DraftAnswer {
                body: "a narrative".into(),
                model: "claude-opus-4-8".into(),
                stop_reason: StopReason::EndTurn,
                usage: TokenUsage::default(),
                completed_at: Utc::now(),
            }),
            review: None,
            grounded_event_ids: vec![Uuid::from_u128(1)],
            grounding: Some(GroundingSummary {
                claims: 4,
                cited_claims: 3,
                cited_event_ids: vec![Uuid::from_u128(1)],
                unknown_event_ids: Vec::new(),
            }),
            batch_id: None,
            last_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// The provenance contract: the event names the model that *answered*, the
    /// prompt version that ran, and the ids the narrative cites — never the
    /// prose.
    #[test]
    fn the_event_carries_provenance_and_a_reference_not_the_narrative() {
        let draft = draft(DraftStatus::Ready);
        let event =
            drafted_event(draft.drafted_facts().expect("announceable")).expect("a narrative draft");

        assert_eq!(event.incident_id, IncidentId(draft.subject_id));
        assert_eq!(event.model_id, "claude-opus-4-8", "the responding model");
        assert_eq!(event.prompt_id, "incident_narrative");
        assert_eq!(event.prompt_version, "v2");
        assert_eq!(event.prompt_digest, "3f9c");
        assert_eq!(event.grounded_event_ids, vec![Uuid::from_u128(1)]);
        assert_eq!((event.claims, event.cited_claims), (4, 3));
        assert_eq!(event.narrative_ref, narrative_ref(draft.draft_id));

        let json = serde_json::to_string(&event).unwrap();
        assert!(
            !json.contains("a narrative"),
            "an unapproved draft's prose must not enter the audit log: {json}"
        );
    }

    #[test]
    fn an_unattributable_draft_has_no_announcement() {
        let mut no_answer = draft(DraftStatus::Ready);
        no_answer.answer = None;
        assert!(no_answer.drafted_facts().is_none());

        let mut unattributed = draft(DraftStatus::Ready);
        unattributed.provenance = None;
        assert!(
            unattributed.drafted_facts().is_none(),
            "an unattributable regulatory document is not worth announcing"
        );
    }

    #[test]
    fn a_rule_draft_is_not_a_narrative_announcement() {
        let mut rule = draft(DraftStatus::Ready);
        rule.kind = DraftKind::RuleDraft;
        assert!(drafted_event(rule.drafted_facts().unwrap()).is_none());
    }

    /// A ready rule draft, as the landing hands it over.
    fn rule_draft() -> Draft {
        let mut rule = draft(DraftStatus::Ready);
        rule.kind = DraftKind::RuleDraft;
        rule.customer_id = Some(CustomerId(Uuid::from_u128(0xC0)));
        rule.source_text = Some(REQUEST.to_owned());
        rule.grounded_event_ids = Vec::new();
        rule.grounding = None;
        rule.provenance = Some(Provenance {
            prompt_id: "rule_draft@v1".into(),
            prompt_digest: "7c41".into(),
        });
        if let Some(answer) = rule.answer.as_mut() {
            answer.body = DEFINITION.to_owned();
        }
        rule
    }

    const REQUEST: &str = "alert me on any wallet with a risk score over 80";
    const DEFINITION: &str = r#"{"name":"High risk","conditions":[{"risk_score":{"gt":80}}],
        "logic":"all","actions":[{"tag_address":{"label":"risky"}}]}"#;

    /// The rule event's contract, and the two halves of the asymmetry with the
    /// narrative's: the definition travels, the customer's sentence does not.
    #[test]
    fn the_rule_event_carries_the_definition_and_only_the_requests_hash() {
        let draft = rule_draft();
        let event =
            proposed_event(draft.drafted_facts().expect("announceable")).expect("a rule draft");

        assert_eq!(event.draft_id, draft.draft_id.0);
        assert_eq!(event.owner, CustomerId(Uuid::from_u128(0xC0)));
        assert_eq!(event.prompt_id, "rule_draft");
        assert_eq!(event.prompt_version, "v1");
        assert_eq!(event.draft_ref, narrative_ref(draft.draft_id));
        assert_eq!(event.definition["name"], "High risk");
        assert_eq!(
            event.source_text_hash,
            rule_draft::source_text_hash(CustomerId(Uuid::from_u128(0xC0)), REQUEST),
            "the hash must be the same derivation the subject id uses"
        );

        let json = serde_json::to_string(&event).unwrap();
        assert!(
            !json.contains("alert me on any wallet"),
            "the customer's own sentence must not enter the audit log: {json}"
        );
    }

    /// A rule draft with no owner cannot be announced: nobody could activate
    /// the rule it proposes, so the record would name a proposal to no one.
    #[test]
    fn an_ownerless_rule_draft_has_no_announcement() {
        let mut orphan = rule_draft();
        orphan.customer_id = None;
        assert!(proposed_event(orphan.drafted_facts().unwrap()).is_none());

        let mut wordless = rule_draft();
        wordless.source_text = None;
        assert!(proposed_event(wordless.drafted_facts().unwrap()).is_none());
    }

    /// The dispatch: each kind announces as its own event, and neither can be
    /// filed as the other's.
    #[test]
    fn the_envelope_names_the_event_the_kind_implies() {
        let rule = rule_draft();
        let envelope = rule_draft_envelope(rule.drafted_facts().unwrap()).expect("an envelope");
        assert!(matches!(
            envelope.payload,
            DomainEvent::RuleDraftProposed(_)
        ));
        assert!(drafted_event(rule.drafted_facts().unwrap()).is_none());

        let narrative = draft(DraftStatus::Ready);
        assert!(proposed_event(narrative.drafted_facts().unwrap()).is_none());
    }

    /// The belt on the landing's braces: a body that does not survive the
    /// parse boundary is not announced. Unreachable on a `ready` draft — that
    /// is what made it ready — and it fails closed rather than announcing a
    /// definition nobody can read back.
    #[test]
    fn a_rule_draft_whose_body_does_not_compile_is_not_announced() {
        let mut broken = rule_draft();
        if let Some(answer) = broken.answer.as_mut() {
            answer.body = r#"{"name":"x","conditions":[{"telepathy":{}}],"logic":"all",
                "actions":[]}"#
                .to_owned();
        }
        assert!(proposed_event(broken.drafted_facts().unwrap()).is_none());
        assert!(rule_draft_envelope(broken.drafted_facts().unwrap()).is_none());
    }

    #[test]
    fn the_envelope_is_chain_stamped_and_carries_the_event() {
        let draft = draft(DraftStatus::Ready);
        let envelope = narrative_envelope(draft.drafted_facts().unwrap()).expect("an envelope");
        assert_eq!(envelope.chain, Chain::ETHEREUM);
        assert!(matches!(
            envelope.payload,
            DomainEvent::IncidentNarrativeDrafted(_)
        ));
    }
}
