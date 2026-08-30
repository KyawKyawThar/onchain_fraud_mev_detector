//! AI copilot events (§20.4) — the audit record of what the model was asked,
//! what produced the answer, and which stored facts the answer stands on.
//!
//! # The rule these events are shaped by
//!
//! **LLM output is a proposal, never a fact.** Nothing here carries the
//! drafted prose. A domain event is an immutable, replicated fact about the
//! platform, and an *unreviewed* narrative is neither: putting it in the log
//! would make a machine-written document permanent, replayable, and
//! indistinguishable — to any later reader — from the evidence it was derived
//! from. So the event says a draft *exists*, names what produced it, and
//! points at where a human can read and approve it
//! ([`IncidentNarrativeDrafted::narrative_ref`]). The text lives in the
//! copilot's own store behind that approval.
//!
//! # Why it is an event at all
//!
//! Because "who drafted this, from what, under which instructions" is exactly
//! the question a regulator asks about a SAR narrative months later, and the
//! answer has to outlive the model default, the prompt file, and the
//! dashboard. It is the same argument `ModelDriftDetected` makes for a
//! reading that a gauge could have shown: the durable, queryable record is the
//! event, not the metric.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::primitives::IncidentId;

/// A SAR-draft narrative was produced for an incident and is waiting for a
/// human (§20.4).
///
/// Emitted once per draft that reached a reviewable state — never for a
/// refusal, a truncation, or a draft that failed its grounding check, because
/// there is no narrative for a reviewer to read in those cases and the
/// copilot's own store is where an operator looks at them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IncidentNarrativeDrafted {
    pub incident_id: IncidentId,
    /// The copilot draft this record is about — the join key between this
    /// event, the store row a reviewer approves, and any later re-draft.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = Uuid))]
    pub draft_id: Uuid,
    /// Where the narrative can be read and approved
    /// (`copilot://drafts/{draft_id}`), **not** the narrative. See the module
    /// docs: an unapproved draft has no business being replicated into the
    /// audit log as if it were a finding.
    pub narrative_ref: String,
    /// The model that *actually* answered, read from the response — with
    /// server-side refusal fallbacks that is not always the one asked for, and
    /// a draft must be attributable to what produced it.
    pub model_id: String,
    /// The prompt artifact's id (`incident_narrative`) …
    pub prompt_id: String,
    /// … its version (`v2`) …
    pub prompt_version: String,
    /// … and the hash of the bytes that actually ran. The version alone cannot
    /// catch an edit made underneath it, which is the whole reason a prompt is
    /// a content-hashed artifact (§20.4).
    pub prompt_digest: String,
    /// The event ids the narrative's claims cite — narrowed to what the draft
    /// actually stands on, not the window the model was shown. Every id here
    /// resolves in the event store, which is what lets a reviewer check the
    /// draft against the record instead of against the model.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub grounded_event_ids: Vec<Uuid>,
    /// Assertions the narrative makes, and how many of them carry a citation.
    /// Both numbers, not a ratio: a ratio cannot distinguish "two claims, one
    /// cited" from "two hundred claims, one hundred cited", and a reviewer
    /// triaging a queue needs the size as much as the proportion.
    pub claims: u32,
    pub cited_claims: u32,
    /// How the draft was produced — the synchronous worker pool, or the
    /// half-price Batch API backfill (§20.4). Kept on the wire because the two
    /// paths have different cost and different latency, and a cost
    /// reconciliation that cannot tell them apart is guesswork.
    pub source: NarrativeSource,
    pub drafted_at: DateTime<Utc>,
}

/// Which path produced a narrative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum NarrativeSource {
    /// Drafted by the worker pool from a live `IncidentCreated`.
    Live,
    /// Drafted by the historical backfill through the Batch API, at half cost
    /// (§20.4 — narrative generation is never latency-critical).
    Backfill,
}

impl NarrativeSource {
    pub fn as_wire_str(self) -> &'static str {
        match self {
            NarrativeSource::Live => "live",
            NarrativeSource::Backfill => "backfill",
        }
    }
}

impl std::str::FromStr for NarrativeSource {
    type Err = UnknownNarrativeSource;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "live" => Ok(NarrativeSource::Live),
            "backfill" => Ok(NarrativeSource::Backfill),
            other => Err(UnknownNarrativeSource {
                value: other.to_owned(),
            }),
        }
    }
}

/// A stored/wire value that is not a [`NarrativeSource`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown narrative source {value:?}")]
pub struct UnknownNarrativeSource {
    pub value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_source_round_trips_through_its_wire_string() {
        for source in [NarrativeSource::Live, NarrativeSource::Backfill] {
            assert_eq!(
                source.as_wire_str().parse::<NarrativeSource>().unwrap(),
                source
            );
            // The stored column value and the JSON tag are the same string —
            // one name for one concept, everywhere.
            assert_eq!(
                serde_json::to_value(source).unwrap(),
                serde_json::Value::String(source.as_wire_str().to_owned())
            );
        }
        assert!("batch".parse::<NarrativeSource>().is_err());
    }
}
