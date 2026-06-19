//! W3C trace-context propagation across message boundaries (§19).
//!
//! The producer calls [`inject_current_context`] to write `traceparent` (and
//! friends) into a [`HeaderCarrier`]; those headers ride along on the message.
//! The consumer rebuilds the carrier from the received headers and calls
//! [`set_parent_from_headers`] on the span it's about to enter — and the trace
//! continues, same `trace_id`, across the process boundary.
//!
//! The carrier is a `String → String` map on purpose: it is transport-agnostic,
//! so the Kafka producer/consumer (Sprint 1) can convert it to/from
//! `rdkafka` record headers without this crate depending on Kafka.

use std::collections::HashMap;

use opentelemetry::propagation::{Extractor, Injector};
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// A set of message headers acting as a propagation carrier. Backed by a plain
/// map so it round-trips trivially to any transport's header type.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HeaderCarrier {
    headers: HashMap<String, String>,
}

impl HeaderCarrier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a carrier from already-received headers (consumer side).
    pub fn from_map(headers: HashMap<String, String>) -> Self {
        Self { headers }
    }

    /// Borrow the underlying headers (e.g. to copy onto an outbound message).
    pub fn as_map(&self) -> &HashMap<String, String> {
        &self.headers
    }

    /// Consume the carrier, yielding its headers.
    pub fn into_map(self) -> HashMap<String, String> {
        self.headers
    }
}

impl Injector for HeaderCarrier {
    fn set(&mut self, key: &str, value: String) {
        self.headers.insert(key.to_owned(), value);
    }
}

impl Extractor for HeaderCarrier {
    fn get(&self, key: &str) -> Option<&str> {
        self.headers.get(key).map(String::as_str)
    }

    fn keys(&self) -> Vec<&str> {
        self.headers.keys().map(String::as_str).collect()
    }
}

/// Write the current span's trace context into `carrier` (producer side).
pub fn inject_current_context(carrier: &mut HeaderCarrier) {
    let cx = Span::current().context();
    opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&cx, carrier);
    });
}

/// Adopt the trace context carried in `carrier` as `span`'s parent (consumer
/// side). After this, `span` and its children share the producer's `trace_id`.
pub fn set_parent_from_headers(span: &Span, carrier: &HeaderCarrier) {
    let parent_cx =
        opentelemetry::global::get_text_map_propagator(|propagator| propagator.extract(carrier));
    span.set_parent(parent_cx);
}

/// The current span's trace id as a 32-char hex string. Useful for assertions
/// and for logging a correlation id. Returns the all-zero id when there is no
/// active OpenTelemetry context.
pub fn current_trace_id() -> String {
    use opentelemetry::trace::TraceContextExt;
    Span::current()
        .context()
        .span()
        .span_context()
        .trace_id()
        .to_string()
}
