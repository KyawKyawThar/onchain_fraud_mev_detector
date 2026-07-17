//! Kafka ingest: the sink's only ingress (§13 — "Emits: nothing"). Subscribes
//! to the single `mev.events.UsageRecorded` topic — every metering producer
//! (api today; notification/ingestion as Sprint-12 t2 wires them) publishes
//! onto the same topic, so new sources are new producers, not new consumer
//! wiring — and lands each envelope as one `usage_events` row.
//!
//! Built on the shared **batching** consume loop (`event_bus::batch`), not the
//! per-record one: ClickHouse turns every insert into an on-disk part, so a
//! sink that inserts per record hits `TOO_MANY_PARTS` long before CPU matters.
//! Records accumulate to [`crate::config::BatchConfig`]-bounded batches (rows
//! or wait, whichever first), flush as one RowBinary insert, and only then
//! commit their offsets. Delivery stays at-least-once — a crash between flush
//! and commit redelivers the batch, and the redelivered duplicates converge
//! away under the table's ReplacingMergeTree key. A record that can never map
//! (a misrouted non-usage event) is parked on the `mev.dlq.usage` dead-letter
//! topic and committed with its batch — inspectable and replayable, never a
//! wedge. Consumer lag is exported per partition via the shared
//! `event_bus::lag` context (`kafka_consumer_lag`), the keeping-up signal to
//! alert on.

use anyhow::Result;
use async_trait::async_trait;
use event_bus::batch::{run_batch_consumer, Accepted, BatchHandler};
use event_bus::dlq::DeadLetterQueue;
use event_bus::lag::{build_reporting_consumer, LagReporting};
use events::topic_for;
use rdkafka::consumer::StreamConsumer;
use tokio_util::sync::CancellationToken;

use crate::config::KafkaConfig;
use crate::store::{StoreError, UsageRow, UsageStore};

/// Counter (labeled by `event_type`): usage rows written to ClickHouse — the
/// landed side a §13 reconciliation checks the producers'
/// `usage_events_recorded_total` against.
pub const USAGE_ROWS_INGESTED_TOTAL: &str = "usage_rows_ingested_total";
/// Counter: messages on the topic that could never map to a usage row
/// (misrouted event type) — parked on the DLQ, not stored. Any non-zero rate
/// means a producer is publishing the wrong events onto the metering topic;
/// alert, then inspect `mev.dlq.usage`.
pub const USAGE_ROWS_SKIPPED_TOTAL: &str = "usage_rows_skipped_total";

/// The one topic this sink drains. Derived through [`events::topic_for`], the
/// same helper the producers' [`events::EventEnvelope::topic`] uses, so the
/// two sides can't drift.
pub fn topic() -> String {
    topic_for("UsageRecorded")
}

/// Build the consumer: the shared lag-reporting shape (manual commit,
/// `earliest` reset — a fresh group back-fills from retained history; the
/// event store holds the full record beyond that).
pub fn build_consumer(cfg: &KafkaConfig) -> Result<StreamConsumer<LagReporting>> {
    build_reporting_consumer(&cfg.brokers, &cfg.group_id, "usage")
}

/// Subscribe to [`topic`] and sink every event until `shutdown` is cancelled,
/// via the shared batching loop — the sink supplies only its two decisions
/// ([`Sink`]): map an envelope to its row, and write a batch of rows.
pub async fn run(
    consumer: StreamConsumer<LagReporting>,
    store: UsageStore,
    batch: event_bus::batch::BatchConfig,
    dlq: Option<&DeadLetterQueue>,
    shutdown: CancellationToken,
) -> Result<()> {
    let topic = topic();
    tracing::info!(topic = %topic, "usage sink ingesting");
    run_batch_consumer(
        consumer,
        &[topic.as_str()],
        "usage",
        batch,
        Sink { store },
        dlq,
        &shutdown,
    )
    .await
}

/// The sink's decisions for the batching loop: per record, map the envelope to
/// its row (a non-usage event is a permanent skip → DLQ); per batch, one
/// RowBinary insert, with the ingested counters bumped only after the insert
/// succeeds (the counter is the *landed* side of the §13 reconciliation, so it
/// must not count rows a failed flush never landed).
struct Sink {
    store: UsageStore,
}

#[async_trait]
impl BatchHandler for Sink {
    type Item = UsageRow;
    type FlushError = StoreError;

    fn accept(&self, envelope: events::EventEnvelope) -> Accepted<UsageRow> {
        match UsageRow::try_from(&envelope) {
            Ok(row) => Accepted::Item(row),
            Err(err) => {
                metrics::counter!(USAGE_ROWS_SKIPPED_TOTAL).increment(1);
                Accepted::Skip {
                    error: err.to_string(),
                }
            }
        }
    }

    async fn flush(&self, rows: &[UsageRow]) -> Result<(), StoreError> {
        self.store.insert_batch(rows).await?;
        for row in rows {
            metrics::counter!(USAGE_ROWS_INGESTED_TOTAL, "event_type" => row.event_type.clone())
                .increment(1);
        }
        tracing::debug!(rows = rows.len(), "usage batch flushed");
        Ok(())
    }
}
