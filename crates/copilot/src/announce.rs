//! Building `IncidentNarrativeDrafted` (§20.4) — the audit record that a
//! narrative exists, who wrote it, and what it stands on.
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
//! A **reference**, never the prose. An unapproved, machine-written document
//! has no business being replicated into an immutable log as if it were
//! evidence (see [`events::copilot`]), so the event carries the provenance
//! triple, the cited event ids, the claim counts, and a pointer to where a
//! human reads it.
//!
//! # Only `ready` drafts are announced
//!
//! A refusal, a truncation and an ungrounded draft are all `blocked`: billed,
//! terminal, and with no narrative for anyone to read. Announcing them would
//! put "a narrative was drafted" in the audit trail for incidents where none
//! was. They are visible where they belong — the drafts table and the
//! `copilot_drafts_finished_total{status="blocked"}` series.

use chrono::{DateTime, Utc};
use events::copilot::IncidentNarrativeDrafted;
use events::primitives::{Chain, IncidentId};
use events::{DomainEvent, EventEnvelope};
use uuid::Uuid;

use crate::grounding::GroundingSummary;
use crate::model::{DraftId, DraftKind, DraftSource, Provenance};

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
    pub chain: Chain,
    pub source: DraftSource,
    /// The prompt half of §20.4's provenance. Required: an unattributable
    /// regulatory document is not one worth announcing.
    pub provenance: &'a Provenance,
    /// The model that *actually* answered, from the response — with
    /// server-side refusal fallbacks that is not always the one asked.
    pub model: &'a str,
    pub completed_at: DateTime<Utc>,
    pub grounding: Option<&'a GroundingSummary>,
    /// The narrowed ids — what the narrative cites, not the window it saw.
    pub grounded_event_ids: &'a [Uuid],
}

/// Where a reviewer reads and approves a draft — the event's `narrative_ref`.
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

/// The envelope to file in the outbox, ready to publish verbatim.
pub fn drafted_envelope(facts: DraftedFacts<'_>) -> Option<EventEnvelope> {
    let chain = facts.chain;
    drafted_event(facts)
        .map(|event| EventEnvelope::new(chain, DomainEvent::IncidentNarrativeDrafted(event)))
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

    #[test]
    fn the_envelope_is_chain_stamped_and_carries_the_event() {
        let draft = draft(DraftStatus::Ready);
        let envelope = drafted_envelope(draft.drafted_facts().unwrap()).expect("an envelope");
        assert_eq!(envelope.chain, Chain::ETHEREUM);
        assert!(matches!(
            envelope.payload,
            DomainEvent::IncidentNarrativeDrafted(_)
        ));
    }
}
