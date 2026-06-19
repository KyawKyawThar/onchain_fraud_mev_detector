//! Verifies the Sprint 0 deliverable in CI: a span's trace context survives a
//! round trip through message headers (producer → consumer), keeping the same
//! `trace_id`. Runs in-process, no infra.
//!
//! nextest runs each test in its own process, so the one-shot global tracing
//! init here is safe.

use std::collections::HashMap;

use telemetry::propagation::{self, HeaderCarrier};
use tracing::info_span;

#[test]
fn trace_id_survives_header_round_trip() {
    // Explicit config — no reliance on ambient env in the test.
    let _guard = telemetry::init(telemetry::TelemetryConfig::new("propagation-test"))
        .expect("init telemetry");

    // Producer: start a span, capture its trace id, inject context into headers.
    let (producer_trace_id, headers): (String, HashMap<String, String>) = {
        let span = info_span!("produce");
        let _entered = span.enter();

        let mut carrier = HeaderCarrier::new();
        propagation::inject_current_context(&mut carrier);

        let id = propagation::current_trace_id();
        // A real trace context must have been established and serialized.
        assert_ne!(id, "00000000000000000000000000000000", "no active trace");
        assert!(
            carrier.as_map().contains_key("traceparent"),
            "W3C traceparent header must be injected, got {:?}",
            carrier.as_map()
        );
        (id, carrier.into_map())
    };

    // Consumer: rebuild parent context from headers, enter a fresh span.
    let consumer_trace_id = {
        let carrier = HeaderCarrier::from_map(headers);
        let span = info_span!("consume");
        propagation::set_parent_from_headers(&span, &carrier);
        let _entered = span.enter();
        propagation::current_trace_id()
    };

    assert_eq!(
        producer_trace_id, consumer_trace_id,
        "trace_id must propagate across the producer/consumer boundary"
    );
}
