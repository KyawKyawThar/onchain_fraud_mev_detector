//! Sprint 0 deliverable: one trace span propagates end-to-end across a stub
//! producer/consumer.
//!
//! This stands in for the real Kafka path (Sprint 1) with an in-process channel
//! so it runs with no infra. A "producer" task starts a root span, injects the
//! W3C trace context into message headers, and sends an [`events`]-shaped
//! envelope. A "consumer" task receives it, rebuilds the parent context from the
//! headers, and enters its own span — which inherits the producer's `trace_id`.
//!
//! Run it:  `cargo run -p telemetry --example trace_propagation`
//! (or `just trace-demo`). Watch the two `trace_id=…` lines match.

use std::collections::HashMap;

use telemetry::propagation::{self, HeaderCarrier};
use tracing::{info, info_span, Instrument};

/// The headers + body a transport would carry. Mirrors a Kafka record:
/// `headers` carry trace context, `payload` is the serialized event.
struct Message {
    headers: HashMap<String, String>,
    payload: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _guard = telemetry::init(telemetry::TelemetryConfig::from_env(
        "trace-propagation-demo",
    ))?;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(1);

    // ── Producer: emit one event, carrying the current trace context ──
    let producer = async move {
        let span = info_span!("produce", event_type = "BlockAssembled");
        let trace_id = {
            let _entered = span.enter();
            let mut carrier = HeaderCarrier::new();
            propagation::inject_current_context(&mut carrier);
            let trace_id = propagation::current_trace_id();
            info!(trace_id, "producing event with injected trace context");

            tx.send(Message {
                headers: carrier.into_map(),
                payload: r#"{"type":"BlockAssembled","payload":{"block":{"number":19800000}}}"#
                    .to_owned(),
            })
            .await
            .expect("consumer alive");
            trace_id
        };
        trace_id
    }
    .instrument(info_span!("producer_task"));

    // ── Consumer: continue the producer's trace ──
    let consumer = async move {
        let msg = rx.recv().await.expect("one message");
        let carrier = HeaderCarrier::from_map(msg.headers);

        let span = info_span!("consume", event_type = "BlockAssembled");
        propagation::set_parent_from_headers(&span, &carrier);

        let _entered = span.enter();
        let trace_id = propagation::current_trace_id();
        info!(trace_id, payload = %msg.payload, "consumed event; trace continues");
        trace_id
    }
    .instrument(info_span!("consumer_task"));

    let (produced, consumed) = tokio::join!(producer, consumer);

    assert_eq!(
        produced, consumed,
        "trace_id must propagate from producer to consumer"
    );
    info!(trace_id = %consumed, "✅ trace propagated end-to-end across the stub producer/consumer");
    Ok(())
}
