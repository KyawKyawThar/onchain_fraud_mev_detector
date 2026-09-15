//! Kafka ingest: the second write path into the store (§4). Subscribes to every
//! domain-event topic, deserializes each envelope, and appends it — continuing
//! the producer's distributed trace across the broker boundary.
//!
//! **Batched.** Built on the shared micro-batching loop
//! (`event_bus::batch`), not the per-record one. Every ClickHouse insert is an
//! on-disk part, and the capacity plan puts day-one ingest at ~77 events/s and
//! the horizon at well over a thousand: one insert per event is a part per
//! event, which ClickHouse first throttles and then refuses. Records accumulate
//! to [`crate::config`]'s bounds (rows or wait, whichever first), flush as one
//! insert, and only then commit their offsets.
//!
//! **Delivery is at-least-once and the write is idempotent.** A crash between
//! flush and commit redelivers the batch; the insert's deduplication token and
//! the table's `ReplacingMergeTree` key make that a no-op (see
//! [`EventStore::append_rows`]).
//!
//! **Evidence is never dropped by this loop.** Two different failures, two
//! different answers:
//!
//! * An envelope that cannot be *encoded* can never be stored. It is rejected in
//!   `accept`, parked alone on `mev.dlq.event-store` with its bytes intact, and
//!   committed — one bad record cannot wedge the stream, and it is replayable.
//! * A *flush* that fails is always retried ([`IngestFlushError`] is transient
//!   whatever the cause). The shared loop drops a batch on a permanent flush
//!   error so a sink cannot wedge, and for a usage rollup that is right. For the
//!   system of record it would mean committing offsets past events that were
//!   never stored. So a flush that can never succeed wedges ingest instead, and
//!   the wedge pages: `EventStoreAppendErrorsHigh`, and consumer lag.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use event_bus::batch::{run_batch_consumer, Accepted, BatchConfig, BatchHandler};
use event_bus::dlq::DeadLetterQueue;
use event_bus::lag::{build_reporting_consumer, LagReporting};
use event_bus::Transience;
use events::{EventEnvelope, TOPIC_PREFIX};
use rdkafka::admin::{AdminClient, AdminOptions, NewTopic, TopicReplication};
use rdkafka::consumer::StreamConsumer;
use rdkafka::error::RDKafkaErrorCode;
use rdkafka::ClientConfig;
use tokio_util::sync::CancellationToken;

use crate::config::KafkaConfig;
use crate::store::{EventRow, EventStore, StoreError};

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
/// happens to default to. Chain-keyed records land on their chain's registered
/// slot (`events::partitioning`), so a chain's events keep their order on one
/// partition.
///
/// Idempotent and safe to run on every boot: a topic that already exists is
/// reported and skipped. It is deliberately *not* a reconciler — it never grows
/// or shrinks the partitions of an existing topic (growing re-maps every
/// business key, and shrinking is impossible), nor does it alter the retention
/// of one already created; both must be separate, deliberate operations.
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

/// Build the consumer through the shared lag-reporting constructor (§19) —
/// manual offset commit ties the commit to a successful flush; `earliest`
/// means a fresh group back-fills the store from the start of retained history.
pub fn build_consumer(cfg: &KafkaConfig) -> Result<StreamConsumer<LagReporting>> {
    build_reporting_consumer(&cfg.brokers, &cfg.group_id, "event-store")
}

/// Subscribe to the per-event-type topics and append every event until
/// `shutdown` is cancelled, via the shared batching loop — the store supplies
/// only its two decisions ([`Ingest`]).
///
/// Subscribes to the *explicit* schema-derived topic list ([`events::all_topics`]),
/// the same source [`ensure_topics`] provisions from — not a `mev.events.*`
/// regex. The set is closed and known at compile time, so an explicit list fails
/// loudly on drift (a renamed/missing topic) instead of a regex silently
/// matching nothing; the boot path provisions the topics first, so they exist by
/// the time we subscribe.
pub async fn run(
    consumer: StreamConsumer<LagReporting>,
    store: EventStore,
    batch: BatchConfig,
    dlq: Option<&DeadLetterQueue>,
    shutdown: CancellationToken,
) -> Result<()> {
    let topics: Vec<String> = events::all_topics().collect();
    let topic_refs: Vec<&str> = topics.iter().map(String::as_str).collect();
    tracing::info!(
        topics = topics.len(),
        max_rows = batch.max_items,
        max_wait_ms = batch.max_wait.as_millis() as u64,
        "event-store ingesting {TOPIC_PREFIX}.* topics"
    );
    run_batch_consumer(
        consumer,
        &topic_refs,
        "event-store",
        batch,
        Ingest { store },
        dlq,
        &shutdown,
    )
    .await
}

/// A failed flush of the event-store ingest. **Always transient** — see the
/// module docs: the system of record retries a flush until it lands or the
/// process stops, and never commits past events it did not store.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct IngestFlushError(#[from] StoreError);

impl Transience for IngestFlushError {
    fn is_transient(&self) -> bool {
        true
    }
}

/// The store's decisions for the batching loop: per record, encode the row (an
/// unencodable envelope is a permanent skip → DLQ); per batch, one idempotent
/// insert.
struct Ingest {
    store: EventStore,
}

#[async_trait]
impl BatchHandler for Ingest {
    type Item = EventRow;
    type FlushError = IngestFlushError;

    fn accept(&self, envelope: EventEnvelope) -> Accepted<EventRow> {
        match EventRow::try_from(&envelope) {
            Ok(row) => Accepted::Item(row),
            Err(err) => {
                crate::metrics::record_ingest_rejected(envelope.event_type());
                Accepted::Skip {
                    error: format!(
                        "encoding {} {} for the event store: {err}",
                        envelope.event_type(),
                        envelope.event_id
                    ),
                }
            }
        }
    }

    async fn flush(&self, rows: &[EventRow]) -> Result<(), IngestFlushError> {
        self.store.append_rows(rows).await?;
        tracing::debug!(rows = rows.len(), "event-store batch flushed");
        Ok(())
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

    /// The property the whole ingest design rests on: the batch loop drops a
    /// batch only on a *permanent* flush error, and this one never is — even
    /// when the store's own classification would say so.
    #[test]
    fn a_flush_failure_is_never_permanent_so_no_batch_of_evidence_is_dropped() {
        let encode = StoreError::Encode(serde_json::from_str::<()>("not json").unwrap_err());
        assert!(!encode.is_transient(), "the store calls this permanent");
        assert!(IngestFlushError::from(encode).is_transient());
    }
}
