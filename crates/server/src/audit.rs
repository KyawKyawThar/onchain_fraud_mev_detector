//! `ScreeningDecisionRecorded` emission (§11, Sprint 14 t3) — the
//! counterparty-screening **access-audit trail**: `POST /v1/address/{addr}/screen`
//! is a blocking, legally-weighty decision, so every call's outcome (the
//! `allow`/`review`/`block` decision, its basis, the exact policy identity
//! that produced it, and the full per-factor breakdown with `evidence_ref`s)
//! is recorded onto the Kafka backbone — independent of `crate::usage`'s
//! `ScreeningCall` metering fact, which only counts that the call happened,
//! never what it decided.
//!
//! Same non-blocking-request-path shape as `crate::usage`, for the identical
//! reason: `/screen` carries a p50 < 100ms SLO (§19), so recording the audit
//! fact must never add latency to the response. [`AuditRecorder::record`] is
//! a bounded-channel `try_send` the handler calls after building the
//! response; [`run`] drains the channel onto [`event_bus::EventSink`] in the
//! background, with the same graceful-shutdown flush contract `crate::usage`
//! documents (queued-at-shutdown records are still published, bounded by
//! the shared flush grace so a broker down at shutdown can't hang the process).

use std::sync::Arc;
use std::time::Duration;

use event_bus::{drain_to_backbone, BackboneProducer, EventSink, BACKBONE_FLUSH_GRACE};
use events::primitives::Chain;
use events::system::ScreeningDecisionRecorded;
use events::{DomainEvent, EventEnvelope};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Counter: audit records actually queued for publish.
pub const AUDIT_RECORDED_TOTAL: &str = "screening_audit_events_recorded_total";
/// Counter: audit records *lost* — dropped because the publish queue was full
/// or still queued at shutdown past the flush grace. Any non-zero rate is a
/// gap in the access-audit trail; alert on it the same way
/// `crate::usage::USAGE_DROPPED_TOTAL` is alerted on.
pub const AUDIT_DROPPED_TOTAL: &str = "screening_audit_events_dropped_total";

/// The non-blocking handle `POST /v1/address/{addr}/screen` records the
/// access-audit fact through. Cloned into `AppState`; the paired receiver is
/// drained by [`run`].
#[derive(Clone)]
pub struct AuditRecorder {
    tx: mpsc::Sender<ScreeningDecisionRecorded>,
}

impl AuditRecorder {
    /// Build a recorder and the receiver [`run`] drains. `capacity` bounds how
    /// many records may be queued awaiting publish before further ones drop.
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<ScreeningDecisionRecorded>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self { tx }, rx)
    }

    /// Record one screening decision, now. Never blocks and never fails the
    /// caller: a full queue (publisher behind — broker outage) or a closed
    /// one (shutdown) drops the record with a `warn` + a
    /// [`AUDIT_DROPPED_TOTAL`] bump, because an audit-recording hiccup must
    /// not take down the screening call it is recording.
    pub fn record(&self, fact: ScreeningDecisionRecorded) {
        match self.tx.try_send(fact) {
            Ok(()) => {
                metrics::counter!(AUDIT_RECORDED_TOTAL).increment(1);
            }
            Err(err) => {
                metrics::counter!(AUDIT_DROPPED_TOTAL).increment(1);
                tracing::warn!(
                    error = %err,
                    "screening access-audit record dropped (queue full or publisher gone)"
                );
            }
        }
    }
}

/// Drain the recorder's channel onto the Kafka backbone via the shared
/// [`drain_to_backbone`] discipline (identical two-phase graceful flush to
/// `crate::usage::run`, differing only in the payload and metric). Each record
/// ships as its own [`ScreeningDecisionRecorded`] envelope.
///
/// Not chain-scoped (screening takes a bare address, no chain) — stamped
/// [`Chain::ETHEREUM`] like `crate::usage`, so the stamp only decides partition
/// placement; the event's own `business_partition_key` override keys it by
/// customer instead (`events::DomainEvent::business_partition_key`). Anything
/// the flush deadline cuts off bumps [`AUDIT_DROPPED_TOTAL`] so a gap in the
/// legal trail has a cause.
pub async fn run(
    sink: Arc<dyn EventSink>,
    rx: mpsc::Receiver<ScreeningDecisionRecorded>,
    backoff: Duration,
    shutdown: CancellationToken,
) {
    drain_to_backbone(
        sink,
        rx,
        backoff,
        shutdown,
        BackboneProducer {
            to_envelope: |fact| {
                EventEnvelope::new(
                    Chain::ETHEREUM,
                    DomainEvent::ScreeningDecisionRecorded(fact),
                )
            },
            on_dropped: |_fact: &ScreeningDecisionRecorded| {
                metrics::counter!(AUDIT_DROPPED_TOTAL).increment(1);
            },
            flush_grace: BACKBONE_FLUSH_GRACE,
            name: "screening-audit",
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use event_bus::test_util::RecordingSink;
    use events::primitives::CustomerId;
    use events::system::{ScreeningDecision, ScreeningDecisionBasis};

    fn customer() -> CustomerId {
        CustomerId(uuid::Uuid::from_u128(0xc0))
    }

    fn fact() -> ScreeningDecisionRecorded {
        ScreeningDecisionRecorded {
            customer_id: customer(),
            address: alloy_primitives::Address::ZERO,
            decision: ScreeningDecision::Block,
            decision_basis: ScreeningDecisionBasis::SanctionsHardBlock,
            policy_name: "default".into(),
            policy_version: 1,
            score: 87,
            confidence: 0.7,
            sanctioned: true,
            model_version: "risk-v1".into(),
            factors: vec![],
            timestamp: Utc::now(),
        }
    }

    #[tokio::test]
    async fn recorded_decision_is_published_as_a_screening_decision_recorded_envelope() {
        let sink = Arc::new(RecordingSink::default());
        let (recorder, rx) = AuditRecorder::channel(8);
        let shutdown = CancellationToken::new();

        recorder.record(fact());
        drop(recorder); // close the channel so `run` drains and returns

        run(sink.clone(), rx, Duration::from_millis(1), shutdown).await;

        let published = sink.envelopes();
        assert_eq!(published.len(), 1);
        let envelope = &published[0];
        assert_eq!(envelope.event_type(), "ScreeningDecisionRecorded");
        assert_eq!(envelope.chain, Chain::ETHEREUM);
        let DomainEvent::ScreeningDecisionRecorded(ref recorded) = envelope.payload else {
            panic!("expected a ScreeningDecisionRecorded payload");
        };
        assert_eq!(recorded.customer_id, customer());
        assert_eq!(recorded.decision, ScreeningDecision::Block);
        assert_eq!(
            recorded.decision_basis,
            ScreeningDecisionBasis::SanctionsHardBlock
        );
    }

    #[tokio::test]
    async fn full_queue_drops_the_record_without_blocking() {
        let (recorder, mut rx) = AuditRecorder::channel(1);

        recorder.record(fact());
        recorder.record(fact());

        assert!(rx.try_recv().is_ok());
        assert!(
            rx.try_recv().is_err(),
            "the overflow record must be dropped"
        );
    }

    #[tokio::test]
    async fn queued_records_are_flushed_on_shutdown_not_discarded() {
        let sink = Arc::new(RecordingSink::default());
        let (recorder, rx) = AuditRecorder::channel(8);
        let shutdown = CancellationToken::new();
        shutdown.cancel();

        recorder.record(fact());
        drop(recorder);

        run(sink.clone(), rx, Duration::from_millis(1), shutdown).await;

        assert_eq!(
            sink.len(),
            1,
            "a queued record must be flushed on shutdown, not lost"
        );
    }
}
