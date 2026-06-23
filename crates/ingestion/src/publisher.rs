//! Publishing chain events onto the Kafka backbone (§20) — the ingestion
//! service is the system's first *producer*.
//!
//! [`EventSink`] is the seam the [`crate::pipeline`] writes against, so the
//! reorg/lifecycle logic can be unit-tested against an in-memory sink with no
//! broker. [`KafkaEventSink`] is the production impl: it routes each envelope to
//! its schema-derived topic ([`EventEnvelope::topic`]), keys it by chain so a
//! chain's events keep their order on one partition (§20), and injects the
//! current W3C trace context into the record headers so the event-store consumer
//! continues the same distributed trace across the broker (§19).
//!
//! Delivery is at-least-once: a send is awaited and a failure surfaces to the
//! caller. The event store dedupes on `event_id` (§7), so a redelivered envelope
//! is harmless — but a *dropped* one is a gap in the audit log, so the pipeline
//! treats a publish error as fatal-to-that-head rather than swallowing it.

use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use events::{EventEnvelope, EventError};
use rdkafka::message::{Header, OwnedHeaders};
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::ClientConfig;
use telemetry::propagation::{self, HeaderCarrier};

/// How long a single produce may take before it's reported as failed. The record
/// is also bounded by librdkafka's own `message.timeout.ms` (set below); this is
/// the await ceiling on top of it.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// Why publishing one event failed. Deliberately **transport-agnostic** (the
/// delivery detail is a `String`, not an `rdkafka` type) so the [`EventSink`]
/// seam doesn't leak Kafka into the pipeline — the same reason
/// [`telemetry::propagation::HeaderCarrier`] is a plain map.
///
/// [`PublishError::is_transient`] mirrors the event-store's `StoreError`: it is
/// what the pipeline branches on to decide *retry* (a broker blip) vs *skip* (an
/// encode bug that can never succeed) — see [`crate::pipeline`].
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    /// The broker rejected or never acked the record (timeout, no leader, …).
    /// Retriable: the same envelope can be re-sent once the broker recovers.
    #[error("kafka delivery failed: {0}")]
    Delivery(String),

    /// The envelope could not be serialized — a bug in our own types, identical
    /// on every retry. Not retriable.
    #[error("encoding envelope failed")]
    Encode(#[from] EventError),
}

impl PublishError {
    /// Whether re-sending the *same* envelope could plausibly succeed later. A
    /// delivery failure is transient (broker recovers); an encode failure is not.
    pub fn is_transient(&self) -> bool {
        matches!(self, PublishError::Delivery(_))
    }
}

/// Where domain events go after the pipeline builds them. Object-safe so the
/// pipeline can hold a `dyn EventSink` and swap the Kafka producer for a test
/// double without generics rippling through it.
#[async_trait]
pub trait EventSink: Send + Sync {
    /// Publish one envelope, returning only once it is accepted by the transport
    /// (at-least-once). An `Err` means the event is *not* on the wire; the caller
    /// uses [`PublishError::is_transient`] to decide whether to retry it.
    async fn publish(&self, envelope: EventEnvelope) -> Result<(), PublishError>;
}

/// The production [`EventSink`]: a librdkafka [`FutureProducer`].
pub struct KafkaEventSink {
    producer: FutureProducer,
}

impl KafkaEventSink {
    /// Build a producer against `brokers` (comma-separated bootstrap list).
    ///
    /// `acks=all` + idempotence make the producer safe to retry internally
    /// without duplicating or reordering on a partition — the right default for
    /// an audit log where order-per-chain matters (§20).
    pub fn new(brokers: &str) -> Result<Self> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("acks", "all")
            .set("enable.idempotence", "true")
            .set("message.timeout.ms", "30000")
            .create()
            .context("creating Kafka producer")?;
        Ok(Self { producer })
    }
}

#[async_trait]
impl EventSink for KafkaEventSink {
    async fn publish(&self, envelope: EventEnvelope) -> Result<(), PublishError> {
        let topic = envelope.topic();
        // Chain is the partition key (§20): every event for one chain lands on
        // the same partition, preserving the per-chain order the reorg walk
        // emits revert→canonicalize in.
        let key = envelope.chain.id().to_string();
        let payload = envelope.to_json_vec()?; // EventError → PublishError::Encode
        let headers = trace_headers();

        let record = FutureRecord::to(&topic)
            .key(&key)
            .payload(&payload)
            .headers(headers);

        self.producer
            .send(record, SEND_TIMEOUT)
            .await
            .map_err(|(err, _msg)| PublishError::Delivery(err.to_string()))?;
        Ok(())
    }
}

/// Serialize the current span's W3C trace context into Kafka record headers, so
/// the event-store consumer adopts it as the parent span and the trace continues
/// unbroken across the broker (§19). Mirrors the consumer's `header_carrier`.
fn trace_headers() -> OwnedHeaders {
    let mut carrier = HeaderCarrier::new();
    propagation::inject_current_context(&mut carrier);
    let mut headers = OwnedHeaders::new();
    for (key, value) in carrier.as_map() {
        headers = headers.insert(Header {
            key,
            value: Some(value),
        });
    }
    headers
}
