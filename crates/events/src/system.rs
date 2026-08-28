//! System events (§2). Cross-cutting facts not owned by a single domain
//! service — metered usage (feeds billing, §13) and the counterparty-
//! screening access-audit trail (§11).

use crate::intelligence::RiskFactor;
use crate::primitives::{AccountAddress, CustomerId, DetectorRef};
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

/// A deployed model's serving-time feature distribution has moved away from the
/// training snapshot it was exported with (§20.5).
///
/// # Why this is an event and not only a gauge
///
/// Drift already exports metrics, and a metric answers "is it drifting now?".
/// This answers the questions a metric structurally cannot: *which weights*
/// were serving when it drifted, what the distribution looked like at the time,
/// and — months later, during an audit of an incident those weights produced —
/// whether anyone could have known. Prometheus retention is days; the event
/// store is the audit trail (§4). §20.5 asks for drift to "flag the model
/// version"; the durable, queryable flag is this record, keyed by the exact
/// `(id, version, config_hash)` triple the model's findings were stamped with.
///
/// # Emitted per completed window, not per breach
///
/// One event when a window closes with at least one feature past the
/// deployment's threshold — not one per drifted feature, and nothing at all for
/// a quiet window. A drifted model usually moves several correlated features at
/// once, so per-feature events would multiply one condition into a burst that
/// buries the rest of the stream; and a quiet window is the normal case, which
/// has no business in an audit log.
///
/// # Wire types, not `ml-features` types
///
/// `feature_version`, `granularity` and `window_closed_by` are a `u32` and two
/// `String`s rather than the richer types the drift monitor works in. This
/// crate is the schema everything else depends on, so it cannot depend on
/// `ml-features` — and shouldn't: a consumer built against an older schema must
/// still deserialize a newer producer's payload (§2), which a closed enum on
/// the wire would break the first time a `FEATURE_VERSION` or a window policy
/// gained a variant. The producer converts at the boundary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ModelDriftDetected {
    /// The served model, as its descriptor names it (`anomaly-iforest`).
    pub model_id: String,
    /// The detector build serving it — the same `(id, version, config_hash)`
    /// triple its `DetectorTriggered`s carry, which is what makes this record
    /// joinable to the findings produced under the drifted distribution.
    pub detector: DetectorRef,
    /// The feature schema the observed vectors were extracted under.
    pub feature_version: u32,
    /// `"block"` or `"tx"`.
    pub granularity: String,
    /// Content hash of the training snapshot drift was measured against —
    /// re-deriving a baseline changes what "normal" means, so a reading is only
    /// interpretable against the one it used.
    pub baseline_hash: String,
    /// Vectors in the window behind these numbers.
    pub samples: u64,
    /// `"full"` (reached its configured vector count) or `"aged"` (hit the
    /// latency bound with fewer). An aged window is a real reading over a
    /// smaller sample, and a reader should weigh it accordingly.
    pub window_closed_by: String,
    /// The deployment's breach threshold at the time, so a historical record
    /// stays interpretable after someone retunes it.
    pub threshold: f64,
    /// The worst feature's magnitude — including features *below* the
    /// threshold, so this is the honest headline number and not just the max of
    /// what happened to breach.
    pub max_magnitude: f64,
    /// The features at or past `threshold`, worst first. Only the breached
    /// ones: the full vector is on the gauges, and an audit record wants the
    /// finding, not the raw telemetry.
    pub drifted: Vec<DriftedFeature>,
    pub observed_at: DateTime<Utc>,
}

/// One feature's drift, as carried on [`ModelDriftDetected`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DriftedFeature {
    /// The schema's own name for it (`tx_count_log`), so a reader can look it
    /// up in the frozen feature schema for that `feature_version`.
    pub feature: String,
    /// `max(|shift|, |ln spread|)` — the number compared against the threshold.
    pub magnitude: f64,
    /// Median deviation across the window, in training spreads. Positive means
    /// the serving window sits above where training did.
    pub shift: f64,
    /// The window's own spread, relative to training's. `1.0` is unchanged;
    /// below `1` the feature has collapsed, above it has fanned out.
    pub spread: f64,
}
