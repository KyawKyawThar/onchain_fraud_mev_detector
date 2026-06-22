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
use rdkafka::admin::{AdminClient, AdminOptions, NewTopic, TopicReplication};
use rdkafka::consumer::{CommitMode, Consumer, StreamConsumer};
use rdkafka::error::RDKafkaErrorCode;
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

/// How long to wait for the admin *request* round-trip during provisioning.
const ADMIN_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the controller may take to create a topic and propagate it across
/// the cluster before replying. Distinct from [`ADMIN_TIMEOUT`] (the client-side
/// request wait): without this set, the broker can ack the request *before* the
/// topic is fully created, so `ensure_topics` returning would not actually mean
/// the topics are usable — which the explicit subscription in [`run`] relies on.
const ADMIN_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

/// The desired state for one Kafka topic — *policy*, decided purely from the
/// schema + config, with no broker I/O. Splitting this out from the apply step
/// ([`ensure_topics`]) makes the interesting decisions (one topic per event
/// type, with what partitions/replication/retention) unit-testable without a
/// running broker; only the thin apply shell needs Docker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicSpec {
    pub name: String,
    pub partitions: i32,
    pub replication: i32,
    pub retention_ms: i64,
}

/// The full topology the event-store owns (§20): one [`TopicSpec`] per domain
/// event type (`mev.events.<EventType>`), all carrying the same
/// partition/replication/retention from `cfg`. Driven by [`events::all_topics`],
/// so adding an event variant adds its topic here automatically — the topology
/// can never drift from the schema.
pub fn desired_topics(cfg: &KafkaConfig) -> Vec<TopicSpec> {
    events::all_topics()
        .map(|name| TopicSpec {
            name,
            partitions: cfg.topic_partitions,
            replication: cfg.topic_replication,
            retention_ms: cfg.retention_ms,
        })
        .collect()
}

/// Declare the per-event-type topics ([`desired_topics`]) up front, so the
/// topology is explicit and version-controlled instead of being conjured lazily
/// by broker auto-create — which is off in production and would otherwise mint
/// topics with whatever partition count *and unbounded retention* the broker
/// happens to default to. Chain is the message key (§20), so events for one
/// chain keep their order on a single partition.
///
/// Idempotent and safe to run on every boot: a topic that already exists is
/// reported and skipped. It is deliberately *not* a reconciler — it never grows
/// or shrinks the partitions of an existing topic (that reshuffles key→partition
/// assignment and breaks per-chain ordering), nor does it alter the retention of
/// one already created; both must be separate, deliberate operations.
pub async fn ensure_topics(cfg: &KafkaConfig) -> Result<()> {
    let admin: AdminClient<_> = ClientConfig::new()
        .set("bootstrap.servers", &cfg.brokers)
        .create()
        .context("creating Kafka admin client")?;

    let specs = desired_topics(cfg);
    // `NewTopic::set` borrows its value `&str`, so the retention strings must
    // outlive the `NewTopic`s — materialize them alongside the specs.
    let retentions: Vec<String> = specs.iter().map(|s| s.retention_ms.to_string()).collect();
    let new_topics: Vec<NewTopic> = specs
        .iter()
        .zip(&retentions)
        .map(|(spec, retention)| {
            NewTopic::new(
                &spec.name,
                spec.partitions,
                TopicReplication::Fixed(spec.replication),
            )
            // Bound the wire (§2/§4): the event store, not Kafka, is the record.
            .set("retention.ms", retention)
            .set("cleanup.policy", "delete")
        })
        .collect();

    let opts = AdminOptions::new()
        .request_timeout(Some(ADMIN_TIMEOUT))
        .operation_timeout(Some(ADMIN_OPERATION_TIMEOUT));
    let results = admin
        .create_topics(&new_topics, &opts)
        .await
        .context("requesting Kafka topic creation")?;

    // Don't bail on the first failure: report every bad topic so one boot shows
    // the whole picture (e.g. replication > broker count fails *all* of them).
    let mut created = 0usize;
    let mut failures = Vec::new();
    for result in results {
        match result {
            Ok(name) => {
                created += 1;
                tracing::info!(topic = %name, "provisioned Kafka topic");
            }
            Err((name, RDKafkaErrorCode::TopicAlreadyExists)) => {
                tracing::debug!(topic = %name, "Kafka topic already exists; left as-is");
            }
            Err((name, code)) => {
                tracing::error!(topic = %name, ?code, "failed to provision Kafka topic");
                failures.push(format!("{name} ({code:?})"));
            }
        }
    }
    if !failures.is_empty() {
        return Err(anyhow!(
            "failed to provision {} Kafka topic(s): {}",
            failures.len(),
            failures.join(", ")
        ));
    }

    tracing::info!(
        total = specs.len(),
        created,
        partitions = cfg.topic_partitions,
        replication = cfg.topic_replication,
        retention_ms = cfg.retention_ms,
        "Kafka topic provisioning complete"
    );
    Ok(())
}

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

/// Subscribe to the per-event-type topics and append every event until
/// `shutdown` is cancelled. Returns `Ok(())` on a clean shutdown — it finishes
/// the in-flight message and commits before exiting — or `Err` on a fatal
/// subscribe error.
///
/// Subscribes to the *explicit* schema-derived topic list ([`events::all_topics`]),
/// the same source [`ensure_topics`] provisions from — not a `mev.events.*`
/// regex. The set is closed and known at compile time, so an explicit list fails
/// loudly on drift (a renamed/missing topic) instead of a regex silently
/// matching nothing; the boot path provisions the topics first, so they exist by
/// the time we subscribe.
pub async fn run(
    consumer: StreamConsumer,
    store: EventStore,
    shutdown: CancellationToken,
) -> Result<()> {
    let topics: Vec<String> = events::all_topics().collect();
    let topic_refs: Vec<&str> = topics.iter().map(String::as_str).collect();
    consumer
        .subscribe(&topic_refs)
        .with_context(|| format!("subscribing to {} {TOPIC_PREFIX}.* topics", topics.len()))?;
    tracing::info!(topics = topics.len(), "event-store consumer subscribed");

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

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> KafkaConfig {
        KafkaConfig {
            brokers: "localhost:9092".to_owned(),
            group_id: "test".to_owned(),
            topic_partitions: 6,
            topic_replication: 3,
            retention_ms: 86_400_000,
        }
    }

    #[test]
    fn desired_topics_is_one_per_event_type_from_the_schema() {
        let topics = desired_topics(&cfg());
        // Exactly the schema's topic set — same source the consumer subscribes to.
        let names: Vec<&str> = topics.iter().map(|t| t.name.as_str()).collect();
        let from_schema: Vec<String> = events::all_topics().collect();
        assert_eq!(
            names,
            from_schema.iter().map(String::as_str).collect::<Vec<_>>()
        );
        assert!(names.contains(&"mev.events.BlockAssembled"));
    }

    #[test]
    fn desired_topics_stamps_every_topic_with_the_configured_topology() {
        let cfg = cfg();
        // Every topic carries the same partition/replication/retention policy —
        // no topic silently inherits a broker default.
        for spec in desired_topics(&cfg) {
            assert_eq!(spec.partitions, cfg.topic_partitions);
            assert_eq!(spec.replication, cfg.topic_replication);
            assert_eq!(spec.retention_ms, cfg.retention_ms);
        }
    }
}
