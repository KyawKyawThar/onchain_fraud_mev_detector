//! Kafka ingest: the second write path into the store (§4). Subscribes to every
//! domain-event topic, deserializes each envelope, and appends it — continuing
//! the producer's distributed trace across the broker boundary.
//!
//! Delivery is at-least-once: the source offset is committed only *after* a
//! successful append, so a crash re-delivers rather than drops (the audit log
//! must never lose an event). A malformed message is the one thing we commit
//! *without* storing — logged loudly and skipped, so one poison record can't
//! wedge the whole stream. A real dead-letter topic is a follow-up.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use events::{EventEnvelope, TOPIC_PREFIX};
use rdkafka::consumer::{CommitMode, Consumer, StreamConsumer};
use rdkafka::message::{BorrowedMessage, Headers};
use rdkafka::{ClientConfig, Message};
use telemetry::propagation::{self, HeaderCarrier};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::config::KafkaConfig;
use crate::store::EventStore;

/// Back-off before retrying after a transient storage failure, so a ClickHouse
/// blip doesn't hot-loop the consumer.
const RETRY_BACKOFF: Duration = Duration::from_secs(1);

/// Build the consumer. Manual offset commit (`enable.auto.commit=false`) is what
/// lets us tie the commit to a successful append; `earliest` means a fresh group
/// back-fills the store from the start of retained history.
pub fn build_consumer(cfg: &KafkaConfig) -> Result<StreamConsumer> {
    ClientConfig::new()
        .set("bootstrap.servers", &cfg.brokers)
        .set("group.id", &cfg.group_id)
        .set("enable.auto.commit", "false")
        .set("auto.offset.reset", "earliest")
        .create()
        .context("creating Kafka consumer")
}

/// Subscribe to all `mev.events.*` topics and append every event until
/// `shutdown` is cancelled. Returns `Ok(())` on a clean shutdown — it finishes
/// the in-flight message and commits before exiting — or `Err` on a fatal
/// subscribe error.
pub async fn run(
    consumer: StreamConsumer,
    store: EventStore,
    shutdown: CancellationToken,
) -> Result<()> {
    // A topic starting with `^` is a subscription regex in librdkafka, so this
    // one rule picks up every per-event-type topic, including ones created after
    // we start.
    let pattern = format!("^{}\\..+", TOPIC_PREFIX.replace('.', "\\."));
    consumer
        .subscribe(&[pattern.as_str()])
        .with_context(|| format!("subscribing to {pattern}"))?;
    tracing::info!(pattern, "event-store consumer subscribed");

    loop {
        let msg = tokio::select! {
            // Prefer shutdown so a pending cancel wins over a ready message.
            biased;
            () = shutdown.cancelled() => {
                tracing::info!("event-store consumer stopping");
                return Ok(());
            }
            received = consumer.recv() => match received {
                Ok(msg) => msg,
                Err(err) => {
                    // Transport-level error (e.g. broker blip); log and keep going.
                    tracing::error!(error = %err, "Kafka receive error");
                    continue;
                }
            },
        };

        // Continue the producer's trace: rebuild the carrier from record headers
        // and adopt it as the processing span's parent.
        let span = tracing::info_span!(
            "consume_event",
            topic = msg.topic(),
            partition = msg.partition(),
            offset = msg.offset(),
        );
        propagation::set_parent_from_headers(&span, &header_carrier(&msg));

        match handle_message(&store, &msg).instrument(span).await {
            Ok(()) => {
                // Durably stored — safe to advance the offset.
                if let Err(err) = consumer.commit_message(&msg, CommitMode::Async) {
                    tracing::error!(error = %err, "offset commit failed after append");
                }
            }
            Err(HandleError::Permanent(err)) => {
                // Won't succeed on retry: commit to skip it so one poison record
                // can't wedge the stream.
                tracing::error!(error = %err, "skipping unprocessable event (committed, not stored)");
                if let Err(err) = consumer.commit_message(&msg, CommitMode::Async) {
                    tracing::error!(error = %err, "offset commit failed for skipped message");
                }
            }
            Err(HandleError::Transient(err)) => {
                // Storage blip — do NOT commit; back off (cancellably) and let
                // redelivery retry.
                tracing::error!(error = %err, "append failed; will retry on redelivery");
                tokio::select! {
                    () = shutdown.cancelled() => return Ok(()),
                    () = tokio::time::sleep(RETRY_BACKOFF) => {}
                }
            }
        }
    }
}

/// Why processing one message failed — the variant decides whether we commit
/// (skip) or leave the offset for redelivery.
enum HandleError {
    /// Will never succeed for this input (bad bytes, unsupported version,
    /// encode bug). Skip it.
    Permanent(anyhow::Error),
    /// Could succeed later (storage unreachable). Retry — don't commit.
    Transient(anyhow::Error),
}

/// Deserialize one record and append it.
async fn handle_message(store: &EventStore, msg: &BorrowedMessage<'_>) -> Result<(), HandleError> {
    let payload = msg
        .payload()
        .ok_or_else(|| HandleError::Permanent(anyhow!("record has no payload")))?;

    // `from_json_slice` also rejects future schema versions (§2).
    let envelope = EventEnvelope::from_json_slice(payload)
        .map_err(|err| HandleError::Permanent(anyhow::Error::new(err)))?;

    // The typed StoreError says whether a retry could ever help.
    store
        .append_batch(std::slice::from_ref(&envelope))
        .await
        .map_err(|err| {
            if err.is_transient() {
                HandleError::Transient(err.into())
            } else {
                HandleError::Permanent(err.into())
            }
        })?;

    tracing::debug!(
        event_type = envelope.event_type(),
        "appended event from Kafka"
    );
    Ok(())
}

/// Lift the record's headers into a [`HeaderCarrier`] (UTF-8 string values only,
/// which is what W3C `traceparent`/`tracestate` are).
fn header_carrier(msg: &BorrowedMessage<'_>) -> HeaderCarrier {
    let mut map = HashMap::new();
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
