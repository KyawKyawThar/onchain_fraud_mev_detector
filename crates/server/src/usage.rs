//! `UsageRecorded` emission (§11 → §13) — the API service's metering side.
//! Every authenticated `/v1` call is a billable [`UsageEventType::ApiCallMade`]
//! fact, keyed to the customer the JWT names (see `auth.rs`, which resolves
//! `sub` into the [`CustomerId`] request extension this module reads).
//!
//! Split the same way every producer in this workspace is: [`UsageRecorder`]
//! is the cheap, non-blocking handle the request path holds (a bounded mpsc
//! `try_send` — metering must never add latency to a customer call, §11), and
//! [`run`] is the background task that drains the channel onto the Kafka
//! backbone through the shared `event-bus` seam (`EventSink` +
//! `publish_resilient`, the same at-least-once policy ingestion/detection/
//! intelligence use). The topic (`mev.events.UsageRecorded`) is already
//! provisioned by event-store's `ensure_topics` and drained by its ingest, so
//! usage is queryable/reconcilable in the event store today — the §13 billing
//! service (Sprint 12) becomes a second consumer, not a schema change.
//!
//! ## Not losing billable events (§13 — metering is legally-weighty)
//!
//! - **Backpressure never blocks the caller.** A full queue (publisher behind a
//!   broker outage) drops with a `warn` *and* a [`USAGE_DROPPED_TOTAL`] bump so
//!   the loss is alertable, not just grep-able.
//! - **Graceful shutdown flushes, it doesn't discard.** The sender lives in the
//!   HTTP state, so the channel only closes *after* the server has drained —
//!   [`run`] keeps publishing until then, so a call metered during shutdown is
//!   still delivered. The shared [`event_bus::BACKBONE_FLUSH_GRACE`] window
//!   caps that drain so a broker that's down *at* shutdown can't hang the
//!   process; anything the deadline cuts off is counted (metric + log), never
//!   silently dropped.
//!
//! The honest residual: at-least-once holds from the moment [`run`] picks an
//! event up. Exact reconciliation across a hard crash (SIGKILL, OOM) is the
//! billing service's own ledger, not this emission side.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use axum::Extension;
use chrono::Utc;
use event_bus::usage::USAGE_RECORDED_TOTAL;
use event_bus::{drain_to_backbone, BackboneProducer, EventSink, BACKBONE_FLUSH_GRACE};
use events::primitives::{Chain, CustomerId};
use events::system::{UsageEventType, UsageRecorded};
use events::{DomainEvent, EventEnvelope};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Counter (labeled by `event_type`): usage events *lost* — dropped because the
/// publish queue was full (broker backlog) or still queued at shutdown past
/// the flush grace. Any non-zero rate is a billing gap; alert on it (§13).
///
/// No background-producer counterpart: `event_bus::usage::UsageFact::record`
/// blocks and retries instead of dropping (see its module docs) — "dropped"
/// is a concept unique to this bounded-queue, never-block-the-request path.
pub const USAGE_DROPPED_TOTAL: &str = "usage_events_dropped_total";

/// The non-blocking handle the request path records usage through. Cloned into
/// `AppState`/middleware; the paired receiver is drained by [`run`].
#[derive(Clone)]
pub struct UsageRecorder {
    tx: mpsc::Sender<UsageRecorded>,
}

impl UsageRecorder {
    /// Build a recorder and the receiver [`run`] drains. `capacity` bounds how
    /// many events may be queued awaiting publish before further calls drop
    /// (`USAGE_CHANNEL_CAPACITY`).
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<UsageRecorded>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self { tx }, rx)
    }

    /// Record one billable unit of `event_type` for `customer_id`, now. Never
    /// blocks and never fails the caller: a full queue (publisher behind — broker
    /// outage) or a closed one (shutdown) drops the event with a `warn` + a
    /// [`USAGE_DROPPED_TOTAL`] bump, because a metering hiccup must not take down
    /// the customer-facing call it is metering.
    pub fn record(&self, customer_id: CustomerId, event_type: UsageEventType) {
        let usage = UsageRecorded {
            customer_id: Some(customer_id),
            event_type: event_type.as_wire_str().to_owned(),
            quantity: 1,
            timestamp: Utc::now(),
        };
        match self.tx.try_send(usage) {
            Ok(()) => {
                metrics::counter!(USAGE_RECORDED_TOTAL, "event_type" => event_type.as_wire_str())
                    .increment(1);
            }
            Err(err) => {
                metrics::counter!(USAGE_DROPPED_TOTAL, "event_type" => event_type.as_wire_str())
                    .increment(1);
                tracing::warn!(
                    %customer_id,
                    event_type = event_type.as_wire_str(),
                    error = %err,
                    "usage event dropped (queue full or publisher gone)"
                );
            }
        }
    }
}

/// Middleware over the JWT-gated `/v1` routes: one [`UsageEventType::ApiCallMade`]
/// per request, attributed to the [`CustomerId`] `require_jwt` resolved from the
/// token's `sub` and injected as a request extension.
///
/// Taking the customer as an [`Extension`] *extractor* (rather than reaching
/// into the extension map by hand) puts the invariant on the framework: layered
/// inside the JWT gate, the extension is always present, and if a future
/// mis-layering ever removed it, axum fails the request with a loud 500 instead
/// of serving an *unmetered* one. On a metered product an unbillable call is a
/// bug to surface, not to paper over (§13).
///
/// Counts every authenticated call regardless of response status — "ApiCallMade"
/// is the fact that the customer made the call, not that it succeeded (a 502
/// from a proxied upstream still bills). A `/v1/stream` WebSocket connection
/// meters as one call (the upgrade), not per delivered alert — per-alert
/// `AlertDelivered` is the notification service's meter (§12), not this one.
pub async fn record_usage(
    State(recorder): State<UsageRecorder>,
    Extension(customer): Extension<CustomerId>,
    req: Request,
    next: Next,
) -> Response {
    let response = next.run(req).await;
    recorder.record(customer, UsageEventType::ApiCallMade);
    response
}

/// Drain the recorder's channel onto the Kafka backbone via the shared
/// [`drain_to_backbone`] discipline (the same two-phase graceful flush the
/// screening access-audit producer uses, §11). Publishes until the channel
/// closes — every [`UsageRecorder`] dropped — which, because the sender lives
/// in the HTTP state, happens only *after* the server has gracefully drained;
/// so a call metered during shutdown is still published, not lost.
///
/// Usage is not chain-scoped, but the envelope's partition key is (§20) —
/// events are stamped [`Chain::ETHEREUM`], the same single-chain-MVP posture
/// the intelligence consumers take; §13 aggregates by `customer_id`, never by
/// chain, so the stamp only decides partition placement. Anything the flush
/// deadline cuts off bumps [`USAGE_DROPPED_TOTAL`] (labeled by `event_type`)
/// so a §13 discrepancy has a cause.
pub async fn run(
    sink: Arc<dyn EventSink>,
    rx: mpsc::Receiver<UsageRecorded>,
    backoff: Duration,
    shutdown: CancellationToken,
) {
    drain_to_backbone(
        sink,
        rx,
        backoff,
        shutdown,
        BackboneProducer {
            to_envelope: |usage| {
                EventEnvelope::new(Chain::ETHEREUM, DomainEvent::UsageRecorded(usage))
            },
            on_dropped: |usage: &UsageRecorded| {
                metrics::counter!(USAGE_DROPPED_TOTAL, "event_type" => usage.event_type.clone())
                    .increment(1);
            },
            flush_grace: BACKBONE_FLUSH_GRACE,
            name: "usage",
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_bus::test_util::RecordingSink;

    fn customer() -> CustomerId {
        CustomerId(uuid::Uuid::from_u128(0xc0))
    }

    #[tokio::test]
    async fn recorded_usage_is_published_as_a_usage_recorded_envelope() {
        let sink = Arc::new(RecordingSink::default());
        let (recorder, rx) = UsageRecorder::channel(8);
        let shutdown = CancellationToken::new();

        recorder.record(customer(), UsageEventType::ApiCallMade);
        drop(recorder); // close the channel so `run` drains and returns

        run(sink.clone(), rx, Duration::from_millis(1), shutdown).await;

        let published = sink.envelopes();
        assert_eq!(published.len(), 1);
        let envelope = &published[0];
        assert_eq!(envelope.event_type(), "UsageRecorded");
        assert_eq!(envelope.topic(), "mev.events.UsageRecorded");
        assert_eq!(envelope.chain, Chain::ETHEREUM);
        let DomainEvent::UsageRecorded(ref usage) = envelope.payload else {
            panic!("expected a UsageRecorded payload");
        };
        assert_eq!(usage.customer_id, Some(customer()));
        assert_eq!(usage.event_type, UsageEventType::ApiCallMade.as_wire_str());
        assert_eq!(usage.quantity, 1);
    }

    #[tokio::test]
    async fn full_queue_drops_the_event_without_blocking() {
        let (recorder, mut rx) = UsageRecorder::channel(1);

        // Second record hits a full channel — must return (not await space)
        // and drop, leaving exactly the first event queued.
        recorder.record(customer(), UsageEventType::ApiCallMade);
        recorder.record(customer(), UsageEventType::ApiCallMade);

        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err(), "the overflow event must be dropped");
    }

    #[tokio::test]
    async fn queued_events_are_flushed_on_shutdown_not_discarded() {
        // The production win over "drop everything on shutdown": an event that
        // was queued when shutdown fired is still published on the way out.
        let sink = Arc::new(RecordingSink::default());
        let (recorder, rx) = UsageRecorder::channel(8);
        let shutdown = CancellationToken::new();
        shutdown.cancel();

        recorder.record(customer(), UsageEventType::ApiCallMade);
        drop(recorder); // close the channel so the flush completes promptly

        run(sink.clone(), rx, Duration::from_millis(1), shutdown).await;

        assert_eq!(
            sink.len(),
            1,
            "a queued event must be flushed on shutdown, not lost"
        );
    }

    // The shutdown-flush *bound* (broker hangs at shutdown → drain still returns
    // within its grace) is a property of the shared `event_bus::drain_to_backbone`
    // and is tested there, not re-proven per producer.
}
