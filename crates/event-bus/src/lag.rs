//! Consumer-lag reporting: the "is this consumer keeping up" signal (§19),
//! exported as a gauge instead of living only inside librdkafka.
//!
//! Skipped records and flush counters say what a consumer *did*; lag says what
//! it hasn't gotten to yet — the metric ops actually pages on (an ingest that
//! silently falls hours behind looks healthy on every throughput counter).
//! librdkafka already computes per-partition lag; [`LagReporting`] is the thin
//! [`ClientContext`] that surfaces it through the shared `metrics` facade on
//! every statistics tick.
//!
//! Wire it by building the consumer through [`build_reporting_consumer`] and
//! running it through the (generic) consume loops. Consumers built the old way
//! keep working — this is opt-in per consumer, adopted as each is touched.

use std::time::Duration;

use anyhow::{Context, Result};
use rdkafka::consumer::{ConsumerContext, StreamConsumer};
use rdkafka::{ClientConfig, ClientContext, Statistics};

/// Gauge (labeled by `consumer`, `topic`, `partition`): how many records this
/// consumer group is behind the partition high watermark. Alert on sustained
/// growth — a healthy consumer's lag oscillates near zero.
pub const CONSUMER_LAG_GAUGE: &str = "kafka_consumer_lag";

/// How often librdkafka emits statistics (and therefore how often the gauge
/// updates). Coarse on purpose: lag is a trend signal, not a per-record one.
const STATS_INTERVAL: Duration = Duration::from_secs(15);

/// A consumer context that publishes per-partition lag on every statistics
/// callback. `consumer` labels the series so several consumers in one process
/// stay distinguishable (the same convention as the consume loops' `name`).
pub struct LagReporting {
    consumer: String,
}

impl LagReporting {
    pub fn new(consumer: &str) -> Self {
        Self {
            consumer: consumer.to_owned(),
        }
    }
}

impl ClientContext for LagReporting {
    fn stats(&self, statistics: Statistics) {
        for (topic, stats) in &statistics.topics {
            for (partition, p) in &stats.partitions {
                // -1 is librdkafka's "unknown / internal UA partition" marker;
                // publishing it would render as a phantom negative lag.
                if *partition < 0 || p.consumer_lag < 0 {
                    continue;
                }
                metrics::gauge!(
                    CONSUMER_LAG_GAUGE,
                    "consumer" => self.consumer.clone(),
                    "topic" => topic.clone(),
                    "partition" => partition.to_string(),
                )
                .set(p.consumer_lag as f64);
            }
        }
    }
}

impl ConsumerContext for LagReporting {}

/// Build a manual-commit, `earliest`-reset stream consumer with lag reporting
/// attached — the standard consumer shape every sink on the backbone uses
/// (see event-store's `build_consumer`), plus the statistics tick that feeds
/// [`CONSUMER_LAG_GAUGE`].
pub fn build_reporting_consumer(
    brokers: &str,
    group_id: &str,
    consumer_name: &str,
) -> Result<StreamConsumer<LagReporting>> {
    ClientConfig::new()
        .set("bootstrap.servers", brokers)
        .set("group.id", group_id)
        .set("enable.auto.commit", "false")
        .set("auto.offset.reset", "earliest")
        .set(
            "statistics.interval.ms",
            STATS_INTERVAL.as_millis().to_string(),
        )
        .create_with_context(LagReporting::new(consumer_name))
        .context("creating Kafka consumer with lag reporting")
}
