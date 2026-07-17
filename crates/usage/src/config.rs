//! Configuration, resolved once from the environment at startup.
//!
//! The single place this service reads env (the event-store discipline, via
//! the shared [`telemetry::env`] helpers): everything downstream takes an
//! explicit [`Config`] so the rest of the service stays pure and testable.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use event_bus::batch::BatchConfig;
use secrecy::SecretString;
use telemetry::env::{parse_or, required};

/// Default rows-per-flush ceiling. Sized for ClickHouse's parts economics
/// (one insert = one part; the official guidance is few, large inserts) while
/// keeping a bounded memory footprint per consumer.
const DEFAULT_BATCH_MAX_ROWS: usize = 5_000;
/// Default wait ceiling before a partial batch flushes — bounds end-to-end
/// metering latency on a quiet stream, and caps insert frequency (~1/s) on a
/// busy one.
const DEFAULT_BATCH_MAX_WAIT_MS: u64 = 1_000;
/// Back-off between retries of a transiently-failed flush.
const RETRY_BACKOFF: Duration = Duration::from_secs(1);
/// Ceiling on the final drain-flush at shutdown (the server crate's
/// FLUSH_GRACE posture: a store that is down at shutdown can't hang exit).
const SHUTDOWN_FLUSH_GRACE: Duration = Duration::from_secs(5);

/// Milliseconds in 7 days — the default DLQ retention, matching the backbone
/// topics' default so parked records survive as long as the stream they fell
/// out of.
const DEFAULT_DLQ_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

/// All runtime configuration for the usage service.
///
/// Secret-bearing fields are [`SecretString`], so `Debug` redacts them and an
/// explicit `expose_secret()` is required at every use site.
#[derive(Debug, Clone)]
pub struct Config {
    pub clickhouse: ClickhouseConfig,
    pub kafka: KafkaConfig,
    /// How the sink sizes and paces its ClickHouse flushes.
    pub batch: BatchConfig,
    /// Address the Prometheus `/metrics` exporter binds to (§19).
    pub metrics_addr: SocketAddr,
}

/// How to reach ClickHouse. Shares the physical instance (and the
/// `CLICKHOUSE_*` env) with the other analytical stores in the dev stack, but
/// owns its tables and migration bookkeeping outright (§14: no shared tables).
#[derive(Debug, Clone)]
pub struct ClickhouseConfig {
    /// HTTP-interface base URL, e.g. `http://127.0.0.1:8123` (no creds, no db).
    pub url: String,
    pub user: String,
    pub password: SecretString,
    pub database: String,
}

/// How to reach Kafka, which consumer group to join, and the shape of this
/// consumer's dead-letter topic. No backbone-topology fields: the one topic
/// this sink drains (`mev.events.UsageRecorded`) is provisioned by
/// event-store's `ensure_topics` (§20) — this service subscribes, it never
/// declares. The DLQ topic (`mev.dlq.usage`) is the exception: it is this
/// consumer's own, so this consumer provisions it (idempotently, at boot),
/// reusing the backbone's replication/retention knobs so the parked records
/// live on the same footing as the stream they fell out of.
#[derive(Debug, Clone)]
pub struct KafkaConfig {
    /// Comma-separated bootstrap brokers (`localhost:9092`).
    pub brokers: String,
    /// Consumer-group id — restarts resume from committed offsets.
    pub group_id: String,
    /// Replication factor for the DLQ topic (`KAFKA_TOPIC_REPLICATION`, the
    /// same knob event-store provisions the backbone with).
    pub dlq_replication: i32,
    /// Retention for the DLQ topic in milliseconds (`KAFKA_RETENTION_MS`).
    pub dlq_retention_ms: i64,
}

impl Config {
    /// Resolve config from the process environment, erroring on anything missing
    /// or malformed (fail fast at boot rather than at first record).
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            clickhouse: ClickhouseConfig {
                url: required("CLICKHOUSE_HTTP_URL")?,
                user: required("CLICKHOUSE_USER")?,
                password: SecretString::from(required("CLICKHOUSE_PASSWORD")?),
                database: required("CLICKHOUSE_DB")?,
            },
            kafka: KafkaConfig {
                brokers: required("KAFKA_BROKERS")?,
                group_id: required("USAGE_KAFKA_GROUP")?,
                dlq_replication: parse_or("KAFKA_TOPIC_REPLICATION", 1)?,
                dlq_retention_ms: parse_or("KAFKA_RETENTION_MS", DEFAULT_DLQ_RETENTION_MS)?,
            },
            batch: BatchConfig {
                max_items: parse_or("USAGE_BATCH_MAX_ROWS", DEFAULT_BATCH_MAX_ROWS)?,
                max_wait: Duration::from_millis(parse_or(
                    "USAGE_BATCH_MAX_WAIT_MS",
                    DEFAULT_BATCH_MAX_WAIT_MS,
                )?),
                retry_backoff: RETRY_BACKOFF,
                shutdown_flush_grace: SHUTDOWN_FLUSH_GRACE,
            },
            metrics_addr: parse_or("USAGE_METRICS_ADDR", "0.0.0.0:9109".parse()?)?,
        })
    }
}
