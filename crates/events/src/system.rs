//! System events (§2). Cross-cutting facts not owned by a single domain
//! service — currently just metered usage, which feeds billing (§13).

use crate::primitives::CustomerId;
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
}

impl UsageEventType {
    /// The snake_case wire string written to [`UsageRecorded::event_type`]
    /// (`ApiCallMade` → `"api_call_made"`). The single point where the typed
    /// vocabulary becomes a wire value.
    pub fn as_wire_str(self) -> &'static str {
        self.into()
    }
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
