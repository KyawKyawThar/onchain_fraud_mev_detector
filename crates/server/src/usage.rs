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
//!   still delivered. A [`FLUSH_GRACE`]-bounded window caps that drain so a
//!   broker that's down *at* shutdown can't hang the process; anything the
//!   deadline cuts off is counted (metric + log), never silently dropped.
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
use event_bus::{publish_resilient, EventSink};
use events::primitives::{Chain, CustomerId};
use events::system::{UsageEventType, UsageRecorded};
use events::{DomainEvent, EventEnvelope};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Counter (labeled by `event_type`): usage events accepted onto the publish
/// queue — the "billable actions seen at the API boundary" count, the
/// denominator a §13 reconciliation checks event-store's landed rows against.
pub const USAGE_RECORDED_TOTAL: &str = "usage_events_recorded_total";
/// Counter (labeled by `event_type`): usage events *lost* — dropped because the
/// publish queue was full (broker backlog) or still queued at shutdown past
/// [`FLUSH_GRACE`]. Any non-zero rate is a billing gap; alert on it (§13).
pub const USAGE_DROPPED_TOTAL: &str = "usage_events_dropped_total";

/// How long, after shutdown is signalled, [`run`] keeps draining its queue
/// before abandoning the remainder. Bounds shutdown when the broker is down
/// *at* shutdown (often the very reason a backlog exists) so it can't hang the
/// process — a healthy shutdown drains fully in well under this. Anything still
/// queued when it expires is counted as dropped, not silently lost.
const FLUSH_GRACE: Duration = Duration::from_secs(5);

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
            customer_id,
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

/// Drain the recorder's channel onto the Kafka backbone. Publishes until the
/// channel closes — every [`UsageRecorder`] dropped — which, because the sender
/// lives in the HTTP state, happens only *after* the server has gracefully
/// drained; so a call metered during shutdown is still published, not lost.
///
/// See [`FLUSH_GRACE`] for the post-shutdown bound. Each event ships as its own
/// [`EventEnvelope`] through [`publish_resilient`], so a broker blip retries
/// (over `backoff`) while running rather than losing a billable fact.
pub async fn run(
    sink: Arc<dyn EventSink>,
    rx: mpsc::Receiver<UsageRecorded>,
    backoff: Duration,
    shutdown: CancellationToken,
) {
    drain(sink, rx, backoff, shutdown, FLUSH_GRACE).await
}

/// The body of [`run`], with the flush window as a parameter so tests can drive
/// it without waiting the production [`FLUSH_GRACE`].
///
/// Usage is not chain-scoped, but the envelope's partition key is (§20) —
/// events are stamped [`Chain::ETHEREUM`], the same single-chain-MVP posture the
/// intelligence consumers take; §13 aggregates by `customer_id`, never by chain,
/// so the stamp only decides partition placement.
async fn drain(
    sink: Arc<dyn EventSink>,
    mut rx: mpsc::Receiver<UsageRecorded>,
    backoff: Duration,
    shutdown: CancellationToken,
    flush_grace: Duration,
) {
    // Phase 1 — normal operation: publish each event until shutdown is
    // signalled, or the channel closes on its own (all senders gone).
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            maybe = rx.recv() => match maybe {
                Some(usage) => publish_one(sink.as_ref(), usage, backoff, &shutdown).await,
                None => {
                    tracing::info!("usage publisher stopped; channel drained");
                    return;
                }
            },
        }
    }

    // Phase 2 — shutdown signalled: keep flushing what's queued (the server may
    // still be draining in-flight requests that meter), but hard-bound the whole
    // drain by `flush_grace` so a broker that's down at shutdown can't hang exit.
    // `timeout` cancels the drain mid-publish if the deadline hits, so the bound
    // holds even against a single stuck send.
    let flushed = tokio::time::timeout(flush_grace, async {
        while let Some(usage) = rx.recv().await {
            publish_one(sink.as_ref(), usage, backoff, &shutdown).await;
        }
    })
    .await;

    if flushed.is_err() {
        // Deadline cut the drain off — whatever is still queued is a billable
        // loss. Count it (metric + log) so a §13 discrepancy has a cause.
        let mut lost = 0u64;
        while let Ok(usage) = rx.try_recv() {
            lost += 1;
            metrics::counter!(USAGE_DROPPED_TOTAL, "event_type" => usage.event_type).increment(1);
        }
        tracing::warn!(
            lost,
            "usage flush deadline exceeded at shutdown; queued events not published"
        );
    }
    tracing::info!("usage publisher stopped");
}

/// Publish one metered event as its own envelope. Split out so [`drain`]'s two
/// phases share exactly one produce path.
async fn publish_one(
    sink: &dyn EventSink,
    usage: UsageRecorded,
    backoff: Duration,
    shutdown: &CancellationToken,
) {
    let envelope = EventEnvelope::new(Chain::ETHEREUM, DomainEvent::UsageRecorded(usage));
    publish_resilient(sink, envelope, backoff, shutdown).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use event_bus::PublishError;
    use std::sync::Mutex;
    use std::time::Instant;

    /// Captures published envelopes — same double every producer test in this
    /// workspace uses.
    #[derive(Default)]
    struct RecordingSink {
        published: Mutex<Vec<EventEnvelope>>,
    }

    #[async_trait]
    impl EventSink for RecordingSink {
        async fn publish(&self, envelope: EventEnvelope) -> Result<(), PublishError> {
            self.published.lock().unwrap().push(envelope);
            Ok(())
        }
    }

    /// A sink whose publish never resolves — models a broker that hangs at
    /// shutdown, to prove the flush is bounded rather than open-ended.
    struct HangingSink;

    #[async_trait]
    impl EventSink for HangingSink {
        async fn publish(&self, _envelope: EventEnvelope) -> Result<(), PublishError> {
            std::future::pending().await
        }
    }

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

        let published = sink.published.lock().unwrap();
        assert_eq!(published.len(), 1);
        let envelope = &published[0];
        assert_eq!(envelope.event_type(), "UsageRecorded");
        assert_eq!(envelope.topic(), "mev.events.UsageRecorded");
        assert_eq!(envelope.chain, Chain::ETHEREUM);
        let DomainEvent::UsageRecorded(ref usage) = envelope.payload else {
            panic!("expected a UsageRecorded payload");
        };
        assert_eq!(usage.customer_id, customer());
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
            sink.published.lock().unwrap().len(),
            1,
            "a queued event must be flushed on shutdown, not lost"
        );
    }

    #[tokio::test]
    async fn shutdown_flush_is_bounded_even_if_publishing_hangs() {
        // Broker down at shutdown with the channel still open: only the flush
        // deadline can end the drain. It must return within its grace, not hang.
        let (recorder, rx) = UsageRecorder::channel(8);
        let shutdown = CancellationToken::new();
        recorder.record(customer(), UsageEventType::ApiCallMade);
        shutdown.cancel();

        let start = Instant::now();
        tokio::time::timeout(
            Duration::from_secs(2),
            drain(
                Arc::new(HangingSink),
                rx,
                Duration::from_millis(1),
                shutdown,
                Duration::from_millis(50), // tiny grace so the test is fast
            ),
        )
        .await
        .expect("drain must return within its flush grace, not hang on a stuck broker");

        // Proves the bound came from the deadline, not the channel closing.
        drop(recorder);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "flush must be bounded by its grace window"
        );
    }
}
