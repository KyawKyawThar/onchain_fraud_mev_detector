//! The shared event-publishing seam (§20) — how every *producer* service ships
//! domain events onto the Kafka backbone.
//!
//! [`EventSink`] is the object-safe seam each producer's logic writes against, so
//! the interesting parts (the ingestion reorg walk, the detection fan-out) can be
//! unit-tested against an in-memory sink with no broker. [`KafkaEventSink`] is the
//! production impl: it routes each envelope to its schema-derived topic
//! ([`EventEnvelope::topic`]), keys it via [`EventEnvelope::partition_key`] (by
//! chain for per-chain order, §20 — but the simulation result path by its
//! incident business key so it dedups per incident, §7), and injects the current
//! W3C trace context into
//! the record headers so a downstream consumer continues the same distributed
//! trace across the broker (§19).
//!
//! Delivery is at-least-once: a send is awaited and a failure surfaces to the
//! caller. The event store dedupes on `event_id` (§7), so a redelivered envelope
//! is harmless — but a *dropped* one is a gap in the audit log, so
//! [`publish_resilient`] retries a transient broker blip until it succeeds or
//! shutdown, and only gives up on a permanent (encode) failure that can never
//! succeed.

use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use events::{EventEnvelope, EventError};
use rdkafka::message::{Header, OwnedHeaders};
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::ClientConfig;
use telemetry::propagation::{self, HeaderCarrier};
use tokio_util::sync::CancellationToken;

/// How long a single produce may take before it's reported as failed. The record
/// is also bounded by librdkafka's own `message.timeout.ms` (set below); this is
/// the await ceiling on top of it.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// Default back-off between retries of a transient publish failure, so a broker
/// blip doesn't hot-loop the producer. Producers pass their own (tests shrink it).
pub const PUBLISH_BACKOFF: Duration = Duration::from_secs(1);

/// Why publishing one event failed. Deliberately **transport-agnostic** (the
/// delivery detail is a `String`, not an `rdkafka` type) so the [`EventSink`]
/// seam doesn't leak Kafka into the producer logic — the same reason
/// [`telemetry::propagation::HeaderCarrier`] is a plain map.
///
/// [`PublishError::is_transient`] is what a producer branches on to decide
/// *retry* (a broker blip) vs *skip* (an encode bug that can never succeed) — see
/// [`publish_resilient`].
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

/// Where domain events go after a producer builds them. Object-safe so a producer
/// can hold a `dyn EventSink` and swap the Kafka producer for a test double
/// without generics rippling through it.
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
        // The record key: chain by default, so a chain's events keep their order
        // on one partition (§20) — but the simulation confirm/retract result path
        // is keyed by its incident business key (`alert_id`/`incident_id`) so a
        // redelivered result dedups and stays ordered per incident (§7). The
        // choice lives on the envelope (a typed `PartitionKey`) so producers
        // can't drift from it; `Display` is the wire rendering.
        let key = envelope.partition_key().to_string();
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

/// Publish one envelope through `sink`, retrying a *transient* failure (broker
/// blip) over `backoff` until it succeeds or `shutdown` is cancelled — so a
/// momentary outage can't leave a permanent hole in the audit stream (the events
/// are derived from in-memory state that has already advanced, so a dropped
/// publish can't be re-derived later). A *permanent* failure (encode bug) is
/// logged and skipped — it can never succeed.
///
/// The shared at-least-once policy for every producer: ingestion's pipeline and
/// detection's scheduler both call this so the retry/skip discipline lives once.
/// The caller fixes the envelope's `event_id` across retries (by cloning one
/// envelope) so a redelivery is deduped downstream (§7).
pub async fn publish_resilient(
    sink: &dyn EventSink,
    envelope: EventEnvelope,
    backoff: Duration,
    shutdown: &CancellationToken,
) {
    loop {
        match sink.publish(envelope.clone()).await {
            Ok(()) => return,
            Err(err) if err.is_transient() => {
                tracing::warn!(
                    error = %err,
                    event_type = envelope.event_type(),
                    "transient publish failure; retrying after backoff"
                );
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => {
                        tracing::error!(
                            event_type = envelope.event_type(),
                            "shutdown during publish retry; event not delivered"
                        );
                        return;
                    }
                    _ = tokio::time::sleep(backoff) => {}
                }
            }
            Err(err) => {
                tracing::error!(
                    error = %err,
                    event_type = envelope.event_type(),
                    "permanent publish failure; dropping event"
                );
                return;
            }
        }
    }
}

/// Serialize the current span's W3C trace context into Kafka record headers, so
/// the consumer adopts it as the parent span and the trace continues unbroken
/// across the broker (§19). Mirrors the event-store consumer's `header_carrier`.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use events::primitives::Chain;
    use events::DomainEvent;

    /// A sink that fails transiently `remaining_failures` times, then records —
    /// to prove `publish_resilient` retries over a broker blip.
    struct FlakySink {
        remaining_failures: Mutex<u32>,
        delivered: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl EventSink for FlakySink {
        async fn publish(&self, envelope: EventEnvelope) -> Result<(), PublishError> {
            let mut left = self.remaining_failures.lock().unwrap();
            if *left > 0 {
                *left -= 1;
                return Err(PublishError::Delivery("broker blip".into()));
            }
            self.delivered
                .lock()
                .unwrap()
                .push(envelope.event_type().to_owned());
            Ok(())
        }
    }

    fn an_envelope() -> EventEnvelope {
        EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::BlockFinalized(events::chain::BlockFinalized {
                block: events::primitives::BlockRef::new(1, Default::default()),
            }),
        )
    }

    #[test]
    fn delivery_failure_is_transient_encode_is_not() {
        assert!(PublishError::Delivery("x".into()).is_transient());
        assert!(!PublishError::Encode(EventError::UnsupportedSchemaVersion {
            found: 999,
            supported: 1
        })
        .is_transient());
    }

    #[tokio::test]
    async fn resilient_publish_retries_a_transient_failure_until_it_succeeds() {
        let sink = FlakySink {
            remaining_failures: Mutex::new(2),
            delivered: Mutex::new(vec![]),
        };
        publish_resilient(
            &sink,
            an_envelope(),
            Duration::from_millis(1),
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(*sink.delivered.lock().unwrap(), vec!["BlockFinalized"]);
    }

    #[tokio::test]
    async fn resilient_publish_gives_up_on_shutdown_rather_than_blocking_forever() {
        let sink = FlakySink {
            remaining_failures: Mutex::new(u32::MAX), // never succeeds
            delivered: Mutex::new(vec![]),
        };
        let shutdown = CancellationToken::new();
        shutdown.cancel(); // already cancelled → the retry select takes this arm
        publish_resilient(&sink, an_envelope(), Duration::from_secs(3600), &shutdown).await;
        assert!(sink.delivered.lock().unwrap().is_empty());
    }
}
