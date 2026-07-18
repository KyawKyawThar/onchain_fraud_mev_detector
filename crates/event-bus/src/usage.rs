//! The one place every metering producer builds and ships a [`UsageRecorded`]
//! fact (§13) — so the envelope construction (wire `event_type`, timestamp,
//! chain stamp) and its observability (the counter below) can't drift between
//! producers.
//!
//! `customer_id` is `Some` for anything attributable to one customer
//! (`ApiCallMade`, `RuleEvaluated`, `AlertDelivered`, `EntityQueried`, …) and
//! `None` for block-/job-level facts with no customer in scope
//! (`EventProcessed`, `DetectorRun`, `SimulationRun`, `ChainMonitored`,
//! `IncidentGenerated`) — see [`UsageRecorded`] and
//! [`DomainEvent::business_partition_key`] for how partitioning handles both.
//!
//! ## Two delivery contracts, deliberately different (read before "fixing" either)
//!
//! There are two ways a [`UsageRecorded`] fact reaches this module's
//! [`UsageFact::record`], and they trade off latency against loss in opposite
//! directions — both on purpose:
//!
//! * **The API service's hot path** (`server::usage::UsageRecorder`) is a
//!   bounded `mpsc` channel: `record()` never blocks the request it's
//!   metering, and a full queue (broker behind, at the moment of an outage)
//!   *drops* the fact — logged and counted (`USAGE_DROPPED_TOTAL`), but the
//!   customer's call is never held up by a metering hiccup. A request must
//!   never wait on Kafka to answer a customer.
//! * **Every background producer** (ingestion, detection, simulation,
//!   rule-engine) calls [`UsageFact::record`] **inline**, which retries
//!   through [`publish_resilient`] until it succeeds or shutdown cancels it —
//!   the same at-least-once policy as the domain events these producers
//!   already publish. A Kafka blip stalls that producer's block/job/fire loop
//!   rather than silently losing a billable fact.
//!
//! The asymmetry is the point: an HTTP request has a customer waiting on it
//! and a fact that's cheap to lose (§11 latency SLA wins); a background
//! producer has no one waiting and a fact that must be exact and reconcilable
//! (§13 correctness wins). **Do not** unify these by making the background
//! path drop-on-backpressure, or the HTTP path block-until-published — each
//! is the correct trade for its caller, not an inconsistency to clean up.

use std::time::Duration;

use chrono::Utc;
use events::primitives::{Chain, CustomerId};
use events::system::{UsageEventType, UsageRecorded};
use events::{DomainEvent, EventEnvelope};
use tokio_util::sync::CancellationToken;

use crate::{publish_resilient, EventSink};

/// Counter (labeled by `event_type`), incremented once a fact is handed to
/// [`publish_resilient`] — the same moment [`server::usage::UsageRecorder`]
/// counts "accepted for delivery" on its own path, so the two sum to one
/// system-wide view (`sum by (event_type) (usage_events_recorded_total)`)
/// regardless of which producer emitted it.
///
/// **Known limitation**: [`publish_resilient`] returns `()`, not a
/// success/abandoned verdict, so this counts *submission*, not confirmed
/// delivery — identical to the HTTP path's own caveat. A shutdown that cuts a
/// retry short still increments this counter even though the fact may not
/// have landed; the event store's own delivery guarantees (§7) are what
/// actually vouch for the wire. Distinguishing "submitted" from "confirmed"
/// would need `publish_resilient` to report its own outcome — a larger,
/// workspace-wide change, not scoped here.
pub const USAGE_RECORDED_TOTAL: &str = "usage_events_recorded_total";

/// One [`UsageRecorded`] fact under construction — the builder every metering
/// producer goes through instead of hand-assembling the struct (§13). Two
/// required fields (`event_type`, `quantity`) plus the one that varies by
/// producer (`customer_id`), so a call site reads as intent:
///
/// ```ignore
/// UsageFact::new(UsageEventType::DetectorRun, detector_runs)
///     .record(sink, chain, backoff, shutdown)
///     .await;
///
/// UsageFact::new(UsageEventType::RuleEvaluated, 1)
///     .for_customer(fire.owner)
///     .record(sink, chain, backoff, shutdown)
///     .await;
/// ```
pub struct UsageFact {
    event_type: UsageEventType,
    quantity: u64,
    customer_id: Option<CustomerId>,
}

impl UsageFact {
    /// Start a fact for `event_type`, batched to `quantity` (the count known
    /// at the call site — e.g. "N detectors ran this block") rather than one
    /// envelope per unit; exact either way. No customer by default — call
    /// [`for_customer`](Self::for_customer) for anything attributable to one.
    pub fn new(event_type: UsageEventType, quantity: u64) -> Self {
        Self {
            event_type,
            quantity,
            customer_id: None,
        }
    }

    /// Attribute this fact to `customer_id`. Skip this for block-/job-level
    /// facts with no customer in scope — see the module docs.
    pub fn for_customer(mut self, customer_id: CustomerId) -> Self {
        self.customer_id = Some(customer_id);
        self
    }

    /// Publish the fact through `sink`, retrying a transient broker blip over
    /// `backoff` until it succeeds or `shutdown` fires — see the module docs
    /// for why this blocks the caller rather than dropping (the background-
    /// producer contract; the HTTP path uses its own buffered recorder
    /// instead of this method).
    pub async fn record(
        self,
        sink: &dyn EventSink,
        chain: Chain,
        backoff: Duration,
        shutdown: &CancellationToken,
    ) {
        let usage = UsageRecorded {
            customer_id: self.customer_id,
            event_type: self.event_type.as_wire_str().to_owned(),
            quantity: self.quantity,
            timestamp: Utc::now(),
        };
        metrics::counter!(USAGE_RECORDED_TOTAL, "event_type" => self.event_type.as_wire_str())
            .increment(self.quantity);
        publish_resilient(
            sink,
            EventEnvelope::new(chain, DomainEvent::UsageRecorded(usage)),
            backoff,
            shutdown,
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::RecordingSink;
    use std::time::Duration;
    use uuid::Uuid;

    #[tokio::test]
    async fn records_and_publishes_a_usage_envelope_with_the_given_quantity() {
        let sink = RecordingSink::default();
        let shutdown = CancellationToken::new();

        UsageFact::new(UsageEventType::DetectorRun, 5)
            .for_customer(CustomerId(Uuid::from_u128(1)))
            .record(&sink, Chain::ETHEREUM, Duration::from_millis(1), &shutdown)
            .await;

        let published = sink.envelopes();
        assert_eq!(published.len(), 1);
        let DomainEvent::UsageRecorded(ref usage) = published[0].payload else {
            panic!("expected a UsageRecorded payload");
        };
        assert_eq!(usage.customer_id, Some(CustomerId(Uuid::from_u128(1))));
        assert_eq!(usage.event_type, UsageEventType::DetectorRun.as_wire_str());
        assert_eq!(usage.quantity, 5);
    }

    #[tokio::test]
    async fn a_system_fact_with_no_customer_publishes_customer_id_none() {
        let sink = RecordingSink::default();
        let shutdown = CancellationToken::new();

        UsageFact::new(UsageEventType::EventProcessed, 3)
            .record(&sink, Chain::ETHEREUM, Duration::from_millis(1), &shutdown)
            .await;

        let published = sink.envelopes();
        let DomainEvent::UsageRecorded(ref usage) = published[0].payload else {
            panic!("expected a UsageRecorded payload");
        };
        assert_eq!(usage.customer_id, None);
        assert_eq!(usage.quantity, 3);
    }
}
