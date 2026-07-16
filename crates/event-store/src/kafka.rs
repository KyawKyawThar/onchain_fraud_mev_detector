//! Kafka ingest: the second write path into the store (§4). Subscribes to every
//! domain-event topic, deserializes each envelope, and appends it — continuing
//! the producer's distributed trace across the broker boundary.
//!
//! Delivery is at-least-once: the source offset is committed only *after* a
//! successful append, so a crash re-delivers rather than drops (the audit log
//! must never lose an event). A malformed message is the one thing we commit
//! *without* storing — logged loudly and skipped, so one poison record can't
//! wedge the whole stream. A real dead-letter topic is a follow-up.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use event_bus::{run_consumer, EventHandler, Handled, Transience};
use events::{EventEnvelope, TOPIC_PREFIX};
use rdkafka::admin::{AdminClient, AdminOptions, NewTopic, TopicReplication};
use rdkafka::consumer::StreamConsumer;
use rdkafka::error::RDKafkaErrorCode;
use rdkafka::ClientConfig;
use tokio_util::sync::CancellationToken;

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
/// `shutdown` is cancelled, via the shared [`event_bus::run_consumer`] loop — the
/// store supplies only its per-event decision ([`Ingest`]).
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
    tracing::info!(
        topics = topics.len(),
        "event-store ingesting {TOPIC_PREFIX}.* topics"
    );
    run_consumer(
        consumer,
        &topic_refs,
        "event-store",
        RETRY_BACKOFF,
        Ingest { store },
        &shutdown,
    )
    .await
}

/// The store's per-record decision: append the event, mapping the typed store
/// outcome onto the offset action. A successful append or a *permanent* fault
/// (bad input the append will always reject) commits — one poison record can't
/// wedge the stream (the audit log records what it can and moves on) — while a
/// *transient* fault (storage unreachable) retries without committing. Decode
/// poison is skipped by the driver before it reaches here.
struct Ingest {
    store: EventStore,
}

#[async_trait]
impl EventHandler for Ingest {
    async fn handle(&self, envelope: EventEnvelope) -> Handled {
        match self
            .store
            .append_batch(std::slice::from_ref(&envelope))
            .await
        {
            Ok(()) => {
                tracing::debug!(
                    event_type = envelope.event_type(),
                    "appended event from Kafka"
                );
                Handled::Commit
            }
            Err(err) if err.is_transient() => {
                tracing::error!(error = %err, "append failed; will retry on redelivery");
                Handled::Retry
            }
            Err(err) => {
                tracing::error!(error = %err, "skipping unprocessable event (committed, not stored)");
                Handled::Commit
            }
        }
    }
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
