//! System events (§2). Cross-cutting facts not owned by a single domain
//! service — metered usage (feeds billing, §13) and the counterparty-
//! screening access-audit trail (§11).

use crate::intelligence::RiskFactor;
use crate::primitives::{AccountAddress, CustomerId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A billable usage event, emitted from every metering producer (§11, §13).
///
/// `customer_id` is `None` for system-/chain-wide facts that have no customer
/// in scope at the point they're measured — [`UsageEventType::EventProcessed`],
/// [`UsageEventType::DetectorRun`], [`UsageEventType::SimulationRun`],
/// [`UsageEventType::ChainMonitored`] and [`UsageEventType::IncidentGenerated`]
/// all happen once per block/job regardless of who (if anyone) is watching —
/// forcing a fake customer onto them would make the field lie. `Some` for
/// everything attributable to one customer (`ApiCallMade`, `ScreeningCall`,
/// `RuleEvaluated`, `AlertDelivered`, `EntityQueried`, …). See
/// [`DomainEvent::business_partition_key`](crate::DomainEvent::business_partition_key)
/// for how partitioning falls back to chain-keying when there's no customer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UsageRecorded {
    pub customer_id: Option<CustomerId>,
    pub event_type: String,
    pub quantity: u64,
    pub timestamp: DateTime<Utc>,
}

/// The kind of billable action a [`UsageRecorded`] meters — the closed §13
/// `UsageEventType` vocabulary, owned here on the schema crate so that *every*
/// producer of usage (API, notification, ingestion, …) draws the metered
/// `event_type` strings from one source and they can't drift apart between
/// services (a divergent string is an unreconcilable billing SKU, §13).
///
/// Deliberately kept *separate* from [`UsageRecorded::event_type`], which stays
/// a plain `String` on the wire: a consumer built against an older schema must
/// still deserialize an envelope carrying a newer variant it doesn't recognise
/// (forward compatibility, §2), so the wire stays permissive while producers
/// stay strict. Emit through [`UsageEventType::as_wire_str`] — never hand-write
/// the string at a call site.
///
/// Variants mirror §13's enum exactly; a producer wires one up when it ships
/// (the API service emits [`UsageEventType::ApiCallMade`] today, and
/// [`UsageEventType::ScreeningCall`] once `POST /v1/address/{addr}/screen`
/// lands, §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum UsageEventType {
    EventProcessed,
    DetectorRun,
    SimulationRun,
    IncidentGenerated,
    AlertDelivered,
    ApiCallMade,
    ScreeningCall,
    RuleEvaluated,
    ChainMonitored,
    WalletMonitored,
    EntityQueried,
    WalletMevExposureQueried,
    TimingRecommendationQueried,
}

impl UsageEventType {
    /// The snake_case wire string written to [`UsageRecorded::event_type`]
    /// (`ApiCallMade` → `"api_call_made"`). The single point where the typed
    /// vocabulary becomes a wire value.
    pub fn as_wire_str(self) -> &'static str {
        self.into()
    }
}

/// The synchronous counterparty-screening outcome (§11): the closed,
/// spec-defined `allow`/`review`/`block` vocabulary. A *typed* field on the
/// wire (like [`crate::primitives::AlertKind`]/[`crate::primitives::Severity`],
/// not the open-ended `String` [`UsageRecorded::event_type`] uses) — the set
/// is fixed by §11, so a compliance consumer of [`ScreeningDecisionRecorded`]
/// matches an enum rather than re-parsing a raw string. The API service's
/// decision kernel produces this same type (`server::screen::Decision` is a
/// re-export), so the response, the event, and the kernel can never disagree
/// on the wire form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum ScreeningDecision {
    /// No blocking signals (score below the policy's review threshold).
    Allow,
    /// Hold for manual compliance review.
    Review,
    /// Reject the counterparty (score at/above the block threshold, or a
    /// sanctions match — regardless of policy).
    Block,
}

/// Which rule produced a [`ScreeningDecision`] — the first line of the §11
/// explainability contract, alongside [`ScreeningDecisionRecorded::factors`].
/// Typed on the wire for the same reason as [`ScreeningDecision`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ScreeningDecisionBasis {
    /// A sanctions-list match hard-blocked, bypassing the policy's thresholds
    /// entirely (§8.5).
    SanctionsHardBlock,
    /// The score fell through the policy's thresholds.
    ScoreThresholds,
}

/// One synchronous counterparty-screening decision (§11, Sprint 14 t3): the
/// access-audit record `POST /v1/address/{addr}/screen` writes onto the
/// backbone the moment it answers. Independent of [`UsageRecorded`] —
/// `ScreeningCall` (t4) meters *that* the call happened, this event records
/// *what it decided*, so a `block`/`review` (or `allow`) is reconstructible
/// after the fact without a second round-trip to intelligence: `factors`
/// carries the full per-factor breakdown with `evidence_ref`s that produced
/// `score`, the same explainability discipline as `RiskScoreUpdated` (§8.3),
/// and `policy_name`/`policy_version` pin the exact thresholds that decided
/// it even after the customer retunes the policy later.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ScreeningDecisionRecorded {
    pub customer_id: CustomerId,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub address: AccountAddress,
    pub decision: ScreeningDecision,
    pub decision_basis: ScreeningDecisionBasis,
    pub policy_name: String,
    pub policy_version: i32,
    /// 0-100, "how risky" (§8.3).
    pub score: u32,
    /// 0-1, "how sure".
    pub confidence: f64,
    /// The address matched at least one sanctions list (§8.5).
    pub sanctioned: bool,
    pub model_version: String,
    /// The full per-factor breakdown behind `score`, each with its
    /// `evidence_ref` — present regardless of `decision` so an `allow` that
    /// was close to the line is just as reconstructible as a `block`.
    pub factors: Vec<RiskFactor>,
    pub timestamp: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::UsageEventType;

    #[test]
    fn wire_str_is_snake_case() {
        assert_eq!(UsageEventType::ApiCallMade.as_wire_str(), "api_call_made");
        assert_eq!(
            UsageEventType::ScreeningCall.as_wire_str(),
            "screening_call"
        );
        assert_eq!(
            UsageEventType::EventProcessed.as_wire_str(),
            "event_processed"
        );
    }
}
