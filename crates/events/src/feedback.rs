//! Analyst feedback on a confirmed incident (§19, production-readiness Epic E)
//! — the one signal in this platform that comes from a **human** rather than
//! from a detector, a simulator or a model.
//!
//! Everything else the platform knows about its own accuracy is self-reported:
//! a detector fires, simulation confirms or refutes it, and the §20.1 flywheel
//! turns that into a label. That loop measures whether the *simulator* agrees
//! with the *detector*; it cannot see the incident that both of them got right
//! and the customer still calls noise. The false-positive rate in §19's panel
//! is exactly that number, and it can only come from outside the system.
//!
//! # What a verdict is, and what it is not
//!
//! A verdict is a **customer's adjudication of one incident**, not a platform
//! truth. Two customers may disagree about the same incident and both rows are
//! kept (the ledger is keyed by `(incident_id, customer_id)`), because "the
//! liquidation bot's own operator does not consider this an attack" and "the
//! victim does" are different facts, not a conflict to resolve. Aggregation
//! decides what to do with disagreement, and it does so where the SLI is
//! computed — never by dropping a verdict here.
//!
//! It is also **not a retraction**. [`IncidentRetracted`](crate::simulation::IncidentRetracted)
//! is the platform withdrawing its own finding (a reorg, a contradicting
//! re-run) and it changes the incident's lifecycle state. Feedback changes
//! nothing about the incident: the finding stands, a human disagreed with it,
//! and both statements are on the record. Wiring one into the other would make
//! the FP rate unfalsifiable — the platform would be scoring itself again.

use crate::primitives::{CustomerId, IncidentId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A customer's adjudication of one incident (§19, Epic E). Emitted by the API
/// service from `POST /v1/incidents/{incident_id}/feedback`; folded into the
/// simulation service's feedback ledger, which is what the §19 false-positive
/// panel and its SLO read.
///
/// Deliberately thin. It names the incident and the verdict, and nothing that
/// can be derived by joining to the incident the simulation service already
/// projects (`kind`, `severity`, the detector that raised it). A copy of those
/// here would be a second, staler description of the same incident — and the
/// first thing to diverge after a re-projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AlertFeedbackRecorded {
    /// The confirmed incident being adjudicated. Incident-keyed rather than
    /// alert-keyed: a customer sees incidents (§11), and the provisional alert
    /// id behind one is an internal correlation key they are never handed.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = Uuid))]
    pub incident_id: IncidentId,
    /// Who adjudicated. Always taken from the bearer token at the API boundary
    /// — a request body can never name another customer (§9's owner-from-JWT
    /// isolation rule, applied to the write side of feedback).
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = Uuid))]
    pub customer_id: CustomerId,
    /// The verdict itself.
    pub verdict: FeedbackVerdict,
    /// **Why**, as a closed set. This is the field that makes the loop
    /// actionable: at ten thousand verdicts nobody reads prose, and
    /// "`threshold_too_sensitive` on the sandwich detector, 300 times" is a
    /// config change where three hundred paragraphs are a research project.
    /// Defaulted on read ([`FeedbackReason::Unspecified`]) so a verdict
    /// recorded before this field existed still decodes (SCHEMA.md's
    /// additive-field policy).
    #[serde(default)]
    pub reason_code: FeedbackReason,
    /// The customer's own words, free-form and length-capped at the API
    /// boundary. Never parsed, and never required: [`Self::reason_code`] is
    /// what the platform acts on.
    ///
    /// **This field carries a warning.** It lands on an append-only backbone
    /// under the §18 statutory window, where nothing can be edited and only a
    /// whole-record purge can remove anything — so a customer who pastes a
    /// counterparty's name, an email or a wallet owner's identity into it has
    /// created an erasure problem the platform cannot answer by editing a row.
    /// The API boundary says so in its OpenAPI description, caps the length,
    /// and the platform never routes on it.
    pub reason: Option<String>,
    /// Which sample this verdict belongs to — the difference between a number
    /// that can back a published claim and one that cannot (see
    /// [`FeedbackCohort`]). Defaulted to
    /// [`FeedbackCohort::Volunteered`] on read, which is the conservative
    /// reading: an unlabelled verdict is self-selected until proven otherwise.
    #[serde(default)]
    pub cohort: FeedbackCohort,
    /// When the customer submitted it (the API service's clock at the moment
    /// it answered). This is the ledger's last-writer key: a customer who
    /// changes their mind emits a second event, and the later `submitted_at`
    /// wins — which is also what makes the fold idempotent under redelivery
    /// (§4), since a redelivered event carries the same instant.
    pub submitted_at: DateTime<Utc>,
}

/// What the customer says the incident was.
///
/// Three values, not two, and the third is the important one. A binary
/// confirmed/false-positive choice forces an analyst who *cannot tell* to pick
/// a side, and the side they pick under time pressure is the one that closes
/// the ticket. [`FeedbackVerdict::Unclear`] keeps that non-answer out of both
/// halves of the rate: it counts as an adjudication attempt and contributes to
/// neither the numerator nor the denominator, exactly as an unadjudicated
/// finding does in the replay corpus (`corpus`'s open-world rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, strum::IntoStaticStr)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum FeedbackVerdict {
    /// The incident was real: the behaviour happened and it mattered.
    TruePositive,
    /// The incident was noise — the numerator of the §19 false-positive rate.
    FalsePositive,
    /// Looked at, could not decide. Counted as neither.
    Unclear,
}

impl FeedbackVerdict {
    /// The stable snake_case wire name (`"true_positive"`, …) — the ledger's
    /// stored form and the metric label value, so the three readers of this
    /// enum cannot spell it three ways.
    pub fn as_str(&self) -> &'static str {
        self.into()
    }

    /// Whether this verdict resolves the incident one way or the other — the
    /// denominator test for the false-positive rate. [`Self::Unclear`] is the
    /// only value for which this is false.
    pub fn is_decisive(&self) -> bool {
        matches!(self, Self::TruePositive | Self::FalsePositive)
    }
}

/// Why the customer reached that verdict, as a closed set.
///
/// A free-text `reason` cannot be aggregated, cannot be alerted on, and cannot
/// be turned into a metric label without unbounded cardinality. A code can be
/// all three — and the codes are deliberately written as *the customer's*
/// explanation rather than the platform's taxonomy, because the customer is
/// the one clicking.
///
/// [`Self::Unspecified`] is the default rather than an error: a verdict with
/// no code is still a verdict, and refusing it to force a dropdown would cost
/// samples in a measurement that has few.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, strum::IntoStaticStr,
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum FeedbackReason {
    /// The flagged activity was the customer's own — their bot, their
    /// rebalancer, their treasury movement.
    OurOwnActivity,
    /// A counterparty they know and expect to transact with.
    KnownCounterparty,
    /// The pattern is real, but below the bar they care about. A *threshold*
    /// complaint, not a correctness one — the most actionable code here, and
    /// the one most often miscoded as a plain false positive.
    ThresholdTooSensitive,
    /// They had already seen this finding. A correlation defect rather than a
    /// detection one: the incident is real and the alert is still noise.
    DuplicateAlert,
    /// Confirmed harm — the natural code beside a `true_positive`.
    ConfirmedHarm,
    /// No code given.
    #[default]
    Unspecified,
}

impl FeedbackReason {
    /// The stable snake_case wire name — the stored form and the metric label
    /// value, so the three readers cannot spell it three ways.
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// Which sample a verdict belongs to, and therefore what it may be used to
/// claim.
///
/// This distinction is the difference between a number that survives review
/// and one that does not. People report the alerts that annoyed them; almost
/// nobody clicks "this was correct". A rate computed over **volunteered**
/// verdicts is therefore a self-selected sample, biased toward false
/// positives, and it is a fine product signal and a poor accuracy claim.
///
/// A **solicited** verdict comes from an incident the platform picked — by a
/// rule that has nothing to do with how the alert looked — and asked about.
/// Its bias is non-response (who replies), not self-selection (what they
/// report), which is the weaker of the two and is measurable: the response
/// rate is `alert_feedback_recorded_total{cohort="solicited"}` over
/// `alert_feedback_solicited_total`.
///
/// The two are kept as separate series rather than merged, on purpose. Merging
/// them would let volume from the volunteered path silently dominate the
/// number a README quotes.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    Serialize,
    Deserialize,
    strum::IntoStaticStr,
    strum::EnumString,
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum FeedbackCohort {
    /// The customer chose to tell us, unprompted. Self-selected.
    #[default]
    Volunteered,
    /// The platform asked about this incident specifically, having picked it
    /// without looking at the finding.
    Solicited,
}

impl FeedbackCohort {
    /// The stable snake_case wire name — stored form and metric label.
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_wire_names_match_the_stored_and_labelled_form() {
        assert_eq!(FeedbackVerdict::TruePositive.as_str(), "true_positive");
        assert_eq!(FeedbackVerdict::FalsePositive.as_str(), "false_positive");
        assert_eq!(FeedbackVerdict::Unclear.as_str(), "unclear");
        // The serde form is the same string — one spelling, three readers.
        assert_eq!(
            serde_json::to_string(&FeedbackVerdict::FalsePositive).unwrap(),
            "\"false_positive\""
        );
    }

    #[test]
    fn an_unlabelled_verdict_decodes_as_volunteered_and_uncoded() {
        // The conservative reading of a verdict written before either field
        // existed: self-selected until proven otherwise, and no reason given.
        let json = r#"{"incident_id":"00000000-0000-0000-0000-00000000001c",
                       "customer_id":"00000000-0000-0000-0000-0000000000c0",
                       "verdict":"false_positive","reason":null,
                       "submitted_at":"2023-11-14T22:13:20Z"}"#;
        let decoded: AlertFeedbackRecorded = serde_json::from_str(json).expect("decodes");
        assert_eq!(decoded.cohort, FeedbackCohort::Volunteered);
        assert_eq!(decoded.reason_code, FeedbackReason::Unspecified);
    }

    #[test]
    fn cohort_and_reason_wire_names_are_the_label_values() {
        assert_eq!(FeedbackCohort::Solicited.as_str(), "solicited");
        assert_eq!(
            FeedbackReason::ThresholdTooSensitive.as_str(),
            "threshold_too_sensitive"
        );
    }

    #[test]
    fn only_a_decided_verdict_counts_toward_the_rate() {
        assert!(FeedbackVerdict::TruePositive.is_decisive());
        assert!(FeedbackVerdict::FalsePositive.is_decisive());
        assert!(!FeedbackVerdict::Unclear.is_decisive());
    }
}
