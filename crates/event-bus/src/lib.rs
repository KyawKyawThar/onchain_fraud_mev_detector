//! The shared Kafka-backbone seam (§20) — the one place every service's produce
//! *and* consume policy lives, so neither can drift per-service.
//!
//! **Produce.** [`EventSink`] is the object-safe seam each producer's logic writes
//! against, so the interesting parts (the ingestion reorg walk, the detection
//! fan-out) can be unit-tested against an in-memory sink with no broker.
//! [`KafkaEventSink`] is the production impl: it routes each envelope to its
//! schema-derived topic ([`EventEnvelope::topic`]), keys it via
//! [`EventEnvelope::partition_key`] (by chain for per-chain order, §20 — but the
//! simulation result path by its incident business key so it dedups per incident,
//! §7), and injects the current W3C trace context into the record headers so a
//! downstream consumer continues the same distributed trace across the broker
//! (§19). Delivery is at-least-once: [`publish_resilient`] retries a transient
//! broker blip until it succeeds or shutdown, and only gives up on a permanent
//! (encode) failure that can never succeed.
//!
//! **Consume.** [`run_consumer`] is the symmetric half: the resilient at-least-once
//! consume loop every simple stream consumer (the simulation dispatcher, the reorg
//! consumer, the event-store ingest) was hand-rolling — subscribe, shutdown-aware
//! receive, decode-or-skip-poison, trace-span continuation, and commit-vs-retry —
//! now in one tested place. A service supplies only its per-record decision as an
//! [`EventHandler`] returning a [`Handled`] verdict; the loop owns everything else.
//! (Detection's consumer is deliberately *not* built on this — it decodes to a
//! domain command, hands off to a bounded channel, and commits in a separate stage
//! to preserve per-chain ordering, a genuinely different shape.)

/// Shared test doubles (the recording [`EventSink`]) behind the `test-util`
/// feature — the producer-seam counterpart to `detector-api::test_util`, so
/// every producer crate's tests share one double instead of copying it.
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use events::{EventEnvelope, EventError};
use rdkafka::consumer::{CommitMode, Consumer, StreamConsumer};
use rdkafka::message::{BorrowedMessage, Header, Headers, OwnedHeaders};
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::{ClientConfig, Message};
use telemetry::propagation::{self, HeaderCarrier};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

/// How long a single produce may take before it's reported as failed. The record
/// is also bounded by librdkafka's own `message.timeout.ms` (set below); this is
/// the await ceiling on top of it.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// Default back-off between retries of a transient publish failure, so a broker
/// blip doesn't hot-loop the producer. Producers pass their own (tests shrink it).
pub const PUBLISH_BACKOFF: Duration = Duration::from_secs(1);

/// The workspace-wide transient-vs-permanent classification every retry/skip
/// decision keys on (§4): *transient* means retrying the same operation could
/// plausibly succeed (an I/O blip — broker, store, RPC); *permanent* means it
/// fails identically on every retry (a parse/encode bug, a corrupt row).
///
/// One trait instead of twenty inherent `is_transient` methods so (a) a new
/// error type can't silently drift out of the shared retry/skip contract, and
/// (b) the consume-loop helper ([`handled`]) can take *any* classified error —
/// a wrapper enum implements it by delegating to its children, and the
/// compiler's exhaustiveness check keeps every future variant classified.
pub trait Transience {
    /// Whether retrying the same operation could plausibly succeed.
    fn is_transient(&self) -> bool;
}

/// Why publishing one event failed. Deliberately **transport-agnostic** (the
/// delivery detail is a `String`, not an `rdkafka` type) so the [`EventSink`]
/// seam doesn't leak Kafka into the producer logic — the same reason
/// [`telemetry::propagation::HeaderCarrier`] is a plain map.
///
/// Its [`Transience`] classification is what a producer branches on to decide
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

impl Transience for PublishError {
    /// Whether re-sending the *same* envelope could plausibly succeed later. A
    /// delivery failure is transient (broker recovers); an encode failure is not.
    fn is_transient(&self) -> bool {
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
    /// uses the error's [`Transience`] classification to decide whether to retry it.
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

// ── Consume seam (the symmetric half of EventSink) ───────────────────────────

/// What an [`EventHandler`] decided should happen to a consumed record's offset —
/// the three outcomes the at-least-once consume policy needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handled {
    /// Fully handled (stored/published) *or* an un-actionable record deliberately
    /// skipped — advance the offset either way, so a poison record can't wedge the
    /// stream.
    Commit,
    /// A transient fault (a downstream store/broker blip): leave the offset, back
    /// off, and let the broker redeliver. The handler must be idempotent, since a
    /// redelivery re-runs it.
    Retry,
    /// Stop the consumer without committing (a graceful shutdown caught mid-work):
    /// the record is left for redelivery when the service restarts.
    Stop,
}

/// One service's per-record decision — the only part of a stream consumer that
/// varies. Object-safe-friendly (used behind a generic in [`run_consumer`]); the
/// handler sees a fully-decoded [`EventEnvelope`] (poison is skipped by the loop
/// before it gets here) and returns a [`Handled`] verdict.
#[async_trait]
pub trait EventHandler: Send + Sync {
    /// Handle one decoded event. `&self` (not `&mut`) because handlers hold their
    /// collaborators behind `Arc`; concurrency, if any, is the handler's own.
    async fn handle(&self, envelope: EventEnvelope) -> Handled;
}

/// Map a [`Transience`]-classified error to the offset action every simple
/// consumer on the backbone shares (§4) — the preferred entry point: the
/// classification comes from the error's own trait impl, so a call site can't
/// pass the wrong boolean for the type in hand. See [`handled_for`] for the
/// raw-verdict form (composite conditions a single error type can't express).
pub fn handled(err: impl Transience + std::fmt::Display, consumer: &str) -> Handled {
    handled_for(err.is_transient(), err, consumer)
}

/// Map an error's transient/permanent classification to the offset action every
/// simple consumer on the backbone shares (§4): a transient fault (a downstream
/// store/cache/broker blip) is logged and retried, leaving the offset for
/// redelivery — the handler must be idempotent, since a redelivery re-runs it; a
/// permanent one (a parse/encoding bug that fails identically on every retry) is
/// logged and skipped so it can't wedge the stream.
///
/// Callers with a [`Transience`]-implementing error should prefer [`handled`];
/// this raw form exists for verdicts computed from more than one source. It only
/// owns the shared "log + pick the `Handled` variant" shape, so every consumer's
/// failure log looks the same and a consumer can't drift on the retry-vs-skip
/// decision itself. `consumer` names the caller in the log line (mirrors
/// [`run_consumer`]'s own `name` field) so multiple consumers in one process
/// stay distinguishable.
pub fn handled_for(is_transient: bool, err: impl std::fmt::Display, consumer: &str) -> Handled {
    if is_transient {
        tracing::warn!(
            consumer,
            error = %err,
            "transient fault; leaving offset to retry"
        );
        Handled::Retry
    } else {
        tracing::error!(
            consumer,
            error = %err,
            "permanent fault; skipping record so it cannot wedge the stream"
        );
        Handled::Commit
    }
}

/// Drive `handler` over `topics` until shutdown or a fatal subscribe error — the
/// resilient, at-least-once consume loop shared by every simple stream consumer.
///
/// The loop owns the invariant mechanics so no service re-implements them: it
/// subscribes to the explicit `topics` (a closed, schema-derived list fails loudly
/// on drift, unlike a `mev.events.*` regex), prefers a pending shutdown over a ready
/// message (`biased` select), **skips poison** (a record with no payload or
/// undecodable bytes is committed-not-handled so it can't wedge the stream), and
/// continues the producer's distributed trace by adopting the record headers as the
/// handler span's parent (§19). The per-record [`Handled`] verdict then maps to the
/// offset action: `Commit` advances it, `Retry` backs off `retry_backoff`
/// (cancellably) and leaves it for redelivery, `Stop` returns without committing.
///
/// `name` labels the span + logs so multiple consumers in one process stay
/// distinguishable. Manual commit (`enable.auto.commit=false`) on the passed
/// consumer is what ties the offset to the handler's verdict — the caller builds the
/// consumer with the group/offset-reset it wants.
pub async fn run_consumer(
    consumer: StreamConsumer,
    topics: &[&str],
    name: &str,
    retry_backoff: Duration,
    handler: impl EventHandler,
    shutdown: &CancellationToken,
) -> Result<()> {
    consumer
        .subscribe(topics)
        .with_context(|| format!("{name}: subscribing to {topics:?}"))?;
    tracing::info!(
        consumer = name,
        topics = topics.len(),
        "consumer subscribed"
    );

    loop {
        let msg = tokio::select! {
            // Prefer shutdown so a pending cancel wins over a ready message.
            biased;
            () = shutdown.cancelled() => {
                tracing::info!(consumer = name, "consumer stopping");
                return Ok(());
            }
            received = consumer.recv() => match received {
                Ok(msg) => msg,
                Err(err) => {
                    // Transport-level error (broker blip); log and keep going.
                    tracing::error!(consumer = name, error = %err, "Kafka receive error");
                    continue;
                }
            },
        };

        // Poison (no payload / undecodable / future schema version) can never be
        // handled — commit to skip it so one bad record can't wedge the stream.
        let Some(envelope) = decode(&msg, name) else {
            commit(&consumer, &msg, name);
            continue;
        };

        // Continue the producer's trace as this record's handling span parent (§19).
        let span = tracing::info_span!(
            "consume_record",
            consumer = name,
            topic = msg.topic(),
            partition = msg.partition(),
            offset = msg.offset(),
        );
        propagation::set_parent_from_headers(&span, &header_carrier(&msg));

        match handler.handle(envelope).instrument(span).await {
            Handled::Commit => commit(&consumer, &msg, name),
            Handled::Retry => {
                tracing::warn!(
                    consumer = name,
                    "transient fault; leaving offset, backing off"
                );
                tokio::select! {
                    () = shutdown.cancelled() => return Ok(()),
                    () = tokio::time::sleep(retry_backoff) => {}
                }
            }
            Handled::Stop => {
                tracing::info!(
                    consumer = name,
                    "consumer stopping (record left for redelivery)"
                );
                return Ok(());
            }
        }
    }
}

/// Decode one record into an [`EventEnvelope`], or `None` for poison (no payload or
/// undecodable bytes — `from_json_slice` also rejects future schema versions, §2),
/// logged so a skipped record is visible.
fn decode(msg: &BorrowedMessage<'_>, name: &str) -> Option<EventEnvelope> {
    let Some(payload) = msg.payload() else {
        tracing::error!(consumer = name, "record has no payload; skipping");
        return None;
    };
    match EventEnvelope::from_json_slice(payload) {
        Ok(envelope) => Some(envelope),
        Err(err) => {
            tracing::error!(consumer = name, error = %err, "undecodable event; skipping");
            None
        }
    }
}

/// Advance the offset for a handled record; a commit failure is logged, not fatal
/// (the broker redelivers an uncommitted record).
fn commit(consumer: &StreamConsumer, msg: &BorrowedMessage<'_>, name: &str) {
    if let Err(err) = consumer.commit_message(msg, CommitMode::Async) {
        tracing::error!(consumer = name, error = %err, "offset commit failed");
    }
}

/// Lift a record's headers into a [`HeaderCarrier`] (UTF-8 string values only, as
/// W3C `traceparent`/`tracestate` are), so a consumer can adopt the producer's trace
/// context (§19). The consume-side counterpart to [`trace_headers`]; shared so every
/// consumer (including detection's bespoke loop) reconstructs the carrier identically.
pub fn header_carrier(msg: &BorrowedMessage<'_>) -> HeaderCarrier {
    let mut map = std::collections::HashMap::new();
    if let Some(headers) = msg.headers() {
        for header in headers.iter() {
            if let Some(value) = header.value {
                if let Ok(value) = std::str::from_utf8(value) {
                    map.insert(header.key.to_owned(), value.to_owned());
                }
            }
        }
    }
    HeaderCarrier::from_map(map)
}

/// Serialize the current span's W3C trace context into Kafka record headers, so
/// the consumer adopts it as the parent span and the trace continues unbroken
/// across the broker (§19). The produce-side counterpart to [`header_carrier`].
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

    /// `handled_for` maps the caller's transient/permanent verdict straight to
    /// the matching `Handled` variant — the one behavior every consumer
    /// depends on, regardless of what error type or message it passes in.
    #[test]
    fn handled_for_maps_transient_to_retry_and_permanent_to_commit() {
        assert_eq!(
            handled_for(true, "broker blip", "test-consumer"),
            Handled::Retry
        );
        assert_eq!(
            handled_for(false, "malformed row", "test-consumer"),
            Handled::Commit
        );
    }

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
