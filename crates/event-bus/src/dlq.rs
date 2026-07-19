//! Dead-letter queue: where a consumer parks a record it can never process,
//! instead of a counter bump and a log line being the only trace of it.
//!
//! Skip-and-count keeps a poison record from wedging a stream, but it is a
//! black hole: the bytes are gone, so a misrouted producer bug can't be
//! inspected after the fact and a wrongly-skipped record can't be replayed.
//! A [`DeadLetterQueue`] preserves the *original* record bytes on a
//! per-consumer topic (`mev.dlq.<consumer>`), with the skip reason and the
//! source coordinates in headers, so ops can inspect (`kafka-console-consumer`
//! on the DLQ topic) and — once the producer bug is fixed — replay by
//! re-producing onto the source topic.
//!
//! Publishing is **best-effort by design**: the DLQ is an observability aid,
//! not a second delivery guarantee, and a consumer must never stall its stream
//! because the DLQ partition is unavailable. A failed DLQ publish is logged
//! and counted ([`DLQ_FAILED_TOTAL`]) — alert on it — and the record is then
//! skipped exactly as it would have been without a DLQ.
//!
//! Shared here (not per-consumer) so every stream on the backbone parks its
//! poison the same way; consumers adopt it as they are touched — the batch
//! loop ([`crate::batch`]) takes it as a constructor argument, `run_consumer`
//! callers can wire it the same way when they migrate.

use std::time::Duration;

use anyhow::{Context, Result};
use rdkafka::admin::{AdminClient, AdminOptions, NewTopic, TopicReplication};
use rdkafka::error::RDKafkaErrorCode;
use rdkafka::message::{BorrowedMessage, Header, Headers, OwnedHeaders};
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::{ClientConfig, Message};

/// Counter (labeled by `consumer`): records parked on the DLQ. A non-zero rate
/// means some producer is publishing records its consumer can never process —
/// investigate the parked records, don't just watch the number grow.
pub const DLQ_PUBLISHED_TOTAL: &str = "dlq_published_total";
/// Counter (labeled by `consumer`): DLQ publishes that themselves failed — the
/// record was skipped *without* being preserved. Any non-zero rate deserves an
/// alert: the safety net has a hole.
pub const DLQ_FAILED_TOTAL: &str = "dlq_failed_total";

/// Topic namespace for dead letters — deliberately outside `mev.events.*` so
/// the event-store's schema-derived subscription can never accidentally ingest
/// parked poison as domain events.
pub const DLQ_TOPIC_PREFIX: &str = "mev.dlq";

/// Default DLQ retention when `KAFKA_RETENTION_MS` is unset: 7 days — long
/// enough to investigate and replay after a weekend incident.
pub const DEFAULT_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

/// How long to wait for the admin round-trips when provisioning the topic.
const ADMIN_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a DLQ produce may take before it is abandoned (best-effort — see
/// the module docs).
const SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// A consumer's dead-letter topic: provisioned at boot, published to on skip.
pub struct DeadLetterQueue {
    producer: FutureProducer,
    topic: String,
    consumer: String,
}

impl DeadLetterQueue {
    /// The DLQ topic for `consumer_name`: `mev.dlq.<consumer_name>`.
    pub fn topic_for(consumer_name: &str) -> String {
        format!("{DLQ_TOPIC_PREFIX}.{consumer_name}")
    }

    /// [`Self::ensure`] with the topology read from the two backbone-wide env
    /// knobs — `KAFKA_TOPIC_REPLICATION` (default 1) and `KAFKA_RETENTION_MS`
    /// (default 7 days), the same names event-store provisions the backbone
    /// with. A deliberate, narrow exception to services-read-their-own-env:
    /// these knobs describe the *cluster*, not the service, so every consumer
    /// resolving them here keeps the DLQ topology uniform (§20) without seven
    /// configs growing the same two fields.
    pub async fn ensure_from_env(brokers: &str, consumer_name: &str) -> Result<Self> {
        let replication = telemetry::env::parse_or("KAFKA_TOPIC_REPLICATION", 1)?;
        let retention_ms = telemetry::env::parse_or("KAFKA_RETENTION_MS", DEFAULT_RETENTION_MS)?;
        Self::ensure(brokers, consumer_name, replication, retention_ms).await
    }

    /// Provision the consumer's DLQ topic (idempotent — an existing topic is
    /// left as-is, mirroring event-store's `ensure_topics` discipline) and
    /// build the producer. One partition: dead letters are rare by definition
    /// and have no ordering contract; `replication`/`retention_ms` follow the
    /// caller's backbone topology so the parked records survive as long as the
    /// stream they fell out of.
    pub async fn ensure(
        brokers: &str,
        consumer_name: &str,
        replication: i32,
        retention_ms: i64,
    ) -> Result<Self> {
        let topic = Self::topic_for(consumer_name);

        let admin: AdminClient<_> = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .create()
            .context("creating Kafka admin client for the DLQ")?;
        let retention = retention_ms.to_string();
        let new_topic = NewTopic::new(&topic, 1, TopicReplication::Fixed(replication))
            .set("retention.ms", &retention)
            .set("cleanup.policy", "delete");
        let opts = AdminOptions::new()
            .request_timeout(Some(ADMIN_TIMEOUT))
            .operation_timeout(Some(ADMIN_TIMEOUT));
        let results = admin
            .create_topics(&[new_topic], &opts)
            .await
            .context("requesting DLQ topic creation")?;
        for result in results {
            match result {
                Ok(name) => tracing::info!(topic = %name, "provisioned DLQ topic"),
                Err((name, RDKafkaErrorCode::TopicAlreadyExists)) => {
                    tracing::debug!(topic = %name, "DLQ topic already exists; left as-is");
                }
                Err((name, code)) => {
                    anyhow::bail!("failed to provision DLQ topic {name}: {code:?}");
                }
            }
        }

        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("acks", "all")
            .set("message.timeout.ms", "5000")
            .create()
            .context("creating DLQ producer")?;

        Ok(Self {
            producer,
            topic,
            consumer: consumer_name.to_owned(),
        })
    }

    /// Park one source record, byte-for-byte, with the skip reason and source
    /// coordinates as `dlq.*` headers (original headers are carried over, so
    /// the producer's trace context survives onto the parked copy). Best-effort:
    /// a failure is logged + counted, never returned — the caller's skip
    /// decision stands either way.
    pub async fn publish(&self, source: &BorrowedMessage<'_>, error: &str) {
        let mut headers = OwnedHeaders::new();
        if let Some(original) = source.headers() {
            for header in original.iter() {
                headers = headers.insert(header);
            }
        }
        let partition = source.partition().to_string();
        let offset = source.offset().to_string();
        for (key, value) in [
            ("dlq.error", error),
            ("dlq.consumer", &self.consumer),
            ("dlq.source.topic", source.topic()),
            ("dlq.source.partition", &partition),
            ("dlq.source.offset", &offset),
        ] {
            headers = headers.insert(Header {
                key,
                value: Some(value),
            });
        }

        let mut record: FutureRecord<'_, [u8], [u8]> =
            FutureRecord::to(&self.topic).headers(headers);
        if let Some(payload) = source.payload() {
            record = record.payload(payload);
        }
        if let Some(key) = source.key() {
            record = record.key(key);
        }

        match self.producer.send(record, SEND_TIMEOUT).await {
            Ok(_) => {
                metrics::counter!(DLQ_PUBLISHED_TOTAL, "consumer" => self.consumer.clone())
                    .increment(1);
                tracing::warn!(
                    consumer = %self.consumer,
                    source_topic = source.topic(),
                    source_partition = source.partition(),
                    source_offset = source.offset(),
                    error,
                    "record parked on the DLQ"
                );
            }
            Err((err, _msg)) => {
                metrics::counter!(DLQ_FAILED_TOTAL, "consumer" => self.consumer.clone())
                    .increment(1);
                tracing::error!(
                    consumer = %self.consumer,
                    error = %err,
                    skip_reason = error,
                    "DLQ publish failed; record skipped WITHOUT being preserved"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dlq_topics_live_outside_the_domain_event_namespace() {
        let topic = DeadLetterQueue::topic_for("usage");
        assert_eq!(topic, "mev.dlq.usage");
        // The event-store subscribes to the schema-derived `mev.events.*` set;
        // a dead letter must never be ingestible as a domain event.
        assert!(!topic.starts_with(events::TOPIC_PREFIX));
    }
}
