//! Configuration, resolved once from the environment at startup.
//!
//! This is the single place the service reads env (mirroring how the
//! `telemetry` crate keeps env access in one spot). Everything downstream takes
//! an explicit [`Config`] so the rest of the service stays pure and testable.

use std::net::SocketAddr;

use anyhow::{bail, Context, Result};
use secrecy::SecretString;
use telemetry::env::{parse_or as env_parse, required as env};

/// All runtime configuration for the event-store service.
///
/// Secret-bearing fields are [`SecretString`], so `Debug` redacts them and an
/// explicit `expose_secret()` is required at every use site — a stray
/// `tracing::debug!(?config)` can never leak the password or token.
#[derive(Debug, Clone)]
pub struct Config {
    pub clickhouse: ClickhouseConfig,
    pub kafka: KafkaConfig,
    /// Address the internal HTTP append API binds to.
    pub http_addr: SocketAddr,
    /// Shared secret a caller must present (`Authorization: Bearer …`) to append.
    /// Internal service-to-service auth, distinct from the public §11 JWT.
    pub write_token: SecretString,
    /// Address the Prometheus `/metrics` endpoint binds to (§19 — append
    /// latency/throughput/errors). Defaults to `0.0.0.0:9102`.
    pub metrics_addr: SocketAddr,
    /// How long an event must live (engineering conventions §18).
    ///
    /// Resolved from the shared `RETENTION_*` variables rather than a
    /// service-prefixed pair, because the copilot resolves the *same* policy
    /// from the *same* names: a deployment that could set them differently per
    /// service would have split one decision into two, which is the failure
    /// this policy exists to prevent. Enforced on the `events` table's TTL at
    /// boot ([`crate::retention`]).
    ///
    /// A **set** and not a single policy: ClickHouse's TTL is a property of the
    /// table, so with more than one artifact policy in play the only legal
    /// window for `events` is the widest of them
    /// ([`retention::PolicySet::widest_evidence_days`]). One policy today; the
    /// type is what stops that from being an assumption baked into the call
    /// site the day a second jurisdiction arrives.
    pub retention: ::retention::PolicySet,
    /// Chain stamped on the §18 governance facts this service publishes
    /// (`RetentionPolicyChanged`).
    ///
    /// A **partition key, not a routing key**: the event store is chain-
    /// agnostic and holds every chain's events, but an envelope needs a key and
    /// a platform-wide fact has no natural one. Same stance as the copilot's
    /// `COPILOT_CHAIN`. Read from the deployment-wide `CHAIN_ID`.
    pub chain: events::primitives::Chain,
    /// How the Kafka ingest batches its appends (`EVENT_STORE_BATCH_MAX_ROWS`,
    /// `EVENT_STORE_BATCH_MAX_WAIT_MS`). The capacity plan's insert-rate gate
    /// reads the same two values from the deployed config map.
    pub ingest: event_bus::batch::BatchConfig,
    /// Hot/cold storage tiering for the `events` table, when the deployment
    /// has a tiered storage policy (`EVENT_STORE_STORAGE_POLICY`,
    /// `EVENT_STORE_COLD_VOLUME`, `EVENT_STORE_COLD_AFTER_DAYS` — all three or
    /// none). `None` leaves the table on the server's default policy.
    pub tiering: Option<crate::tiering::TieringConfig>,
}

/// How to reach ClickHouse. The `clickhouse` crate wants a credential-free base
/// URL plus user/password/database set separately, so we keep them apart.
#[derive(Debug, Clone)]
pub struct ClickhouseConfig {
    /// HTTP-interface base URL, e.g. `http://127.0.0.1:8123` (no creds, no db).
    pub url: String,
    pub user: String,
    pub password: SecretString,
    pub database: String,
}

/// How to reach Kafka, which consumer group to join, and the topology to
/// provision (§20).
#[derive(Debug, Clone)]
pub struct KafkaConfig {
    /// Comma-separated bootstrap brokers (`localhost:9092`).
    pub brokers: String,
    /// Consumer-group id — restarts resume from committed offsets.
    pub group_id: String,
    /// Partitions per topic when provisioning (§20). Chain is the message key,
    /// so every event for a given chain lands on the same partition (per-chain
    /// ordering is preserved); the count is the parallelism/capacity ceiling
    /// across chains, not a 1:1 map to chains. Defaults to 3 (matches the local
    /// broker's `KAFKA_NUM_PARTITIONS`).
    pub topic_partitions: i32,
    /// Replication factor per topic. 1 for the single-broker local/dev stack;
    /// raise in production. Defaults to 1.
    pub topic_replication: i32,
    /// Retention for every provisioned topic, in milliseconds (§2/§4 — Kafka is
    /// *the wire, not the record*, so retention is bounded; the permanent record
    /// is ClickHouse). Declared on the topic so it can't silently inherit a
    /// broker default of "infinite". Must be positive — an unbounded wire is a
    /// second, accidental system of record. Defaults to 7 days.
    pub retention_ms: i64,
}

impl Config {
    /// Resolve config from the process environment, erroring on anything missing
    /// or malformed (fail fast at boot rather than at first request).
    pub fn from_env() -> Result<Self> {
        let http_addr = format!("{}:{}", env("EVENT_STORE_HOST")?, env("EVENT_STORE_PORT")?)
            .parse()
            .context("EVENT_STORE_HOST:EVENT_STORE_PORT is not a valid socket address")?;

        Ok(Self {
            clickhouse: ClickhouseConfig {
                url: env("CLICKHOUSE_HTTP_URL")?,
                user: env("CLICKHOUSE_USER")?,
                password: SecretString::from(env("CLICKHOUSE_PASSWORD")?),
                database: env("CLICKHOUSE_DB")?,
            },
            kafka: kafka_from_env()?,
            http_addr,
            write_token: SecretString::from(env("EVENT_STORE_WRITE_TOKEN")?),
            metrics_addr: env_parse(
                "EVENT_STORE_METRICS_ADDR",
                SocketAddr::from(([0, 0, 0, 0], 9102)),
            )?,
            retention: ::retention::PolicySet::uniform(::retention::Policy::from_env()?),
            chain: events::primitives::Chain(env_parse(
                "CHAIN_ID",
                events::primitives::Chain::ETHEREUM.0,
            )?),
            ingest: ingest_config(
                env_parse("EVENT_STORE_BATCH_MAX_ROWS", DEFAULT_BATCH_MAX_ROWS)?,
                env_parse("EVENT_STORE_BATCH_MAX_WAIT_MS", DEFAULT_BATCH_MAX_WAIT_MS)?,
            )?,
            tiering: tiering_from_env()?,
        })
    }
}

/// Default rows per ingest insert.
pub const DEFAULT_BATCH_MAX_ROWS: usize = 10_000;
/// Default ceiling on how long a record waits for its batch, in milliseconds.
pub const DEFAULT_BATCH_MAX_WAIT_MS: u64 = 1_000;

/// Validate the ingest batch bounds.
///
/// The wait is what bounds inserts per second on a quiet stream (one flush per
/// wait per consumer at most), so it has a floor; the row count bounds memory
/// per batch, so it has a ceiling. Both ends are ones the capacity plan's
/// insert-rate gate assumes.
pub fn ingest_config(max_rows: usize, max_wait_ms: u64) -> Result<event_bus::batch::BatchConfig> {
    if !(1..=100_000).contains(&max_rows) {
        bail!("EVENT_STORE_BATCH_MAX_ROWS must be 1..=100000, got {max_rows}");
    }
    if !(100..=60_000).contains(&max_wait_ms) {
        bail!(
            "EVENT_STORE_BATCH_MAX_WAIT_MS must be 100..=60000 — below 100ms a quiet stream \
             inserts faster than ClickHouse merges parts; got {max_wait_ms}"
        );
    }
    Ok(event_bus::batch::BatchConfig {
        max_items: max_rows,
        max_wait: std::time::Duration::from_millis(max_wait_ms),
        retry_backoff: std::time::Duration::from_secs(1),
        shutdown_flush_grace: std::time::Duration::from_secs(10),
    })
}

/// Resolve the optional tiering triple: all three variables, or none.
fn tiering_from_env() -> Result<Option<crate::tiering::TieringConfig>> {
    let optional = |key: &str| std::env::var(key).ok().filter(|v| !v.trim().is_empty());
    match (
        optional("EVENT_STORE_STORAGE_POLICY"),
        optional("EVENT_STORE_COLD_VOLUME"),
        optional("EVENT_STORE_COLD_AFTER_DAYS"),
    ) {
        (None, None, None) => Ok(None),
        (Some(policy), Some(volume), Some(days)) => {
            let days: u32 = days
                .parse()
                .context("EVENT_STORE_COLD_AFTER_DAYS must be a whole number of days")?;
            Ok(Some(crate::tiering::TieringConfig::new(
                policy, volume, days,
            )?))
        }
        _ => bail!(
            "storage tiering needs EVENT_STORE_STORAGE_POLICY, EVENT_STORE_COLD_VOLUME and \
             EVENT_STORE_COLD_AFTER_DAYS together — a partial set would leave the table half \
             configured"
        ),
    }
}

/// Partitions per topic when none is configured. Sized for the capacity plan's
/// horizon, not today: a topic's count can only grow, growing it re-maps every
/// business key, and chain keys occupy registered slots
/// (`events::partitioning`) that stay put only while the count exceeds them.
/// Twelve leaves room for ten more chains and a consumer group of twelve.
pub const DEFAULT_TOPIC_PARTITIONS: i32 = 12;

/// Number of milliseconds in 7 days — the default Kafka topic retention.
const DEFAULT_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

/// Resolve and *validate* the Kafka topology config. The counts feed straight
/// into broker topic creation, where a non-positive value fails with an opaque
/// librdkafka error; catching it here keeps the "fail fast with a clear message
/// at boot" contract the rest of this module holds.
fn kafka_from_env() -> Result<KafkaConfig> {
    let topic_partitions = env_parse("KAFKA_TOPIC_PARTITIONS", DEFAULT_TOPIC_PARTITIONS)?;
    let topic_replication = env_parse("KAFKA_TOPIC_REPLICATION", 1)?;
    let retention_ms = env_parse("KAFKA_RETENTION_MS", DEFAULT_RETENTION_MS)?;

    if topic_partitions < 1 {
        bail!("KAFKA_TOPIC_PARTITIONS must be >= 1, got {topic_partitions}");
    }
    if topic_replication < 1 {
        bail!("KAFKA_TOPIC_REPLICATION must be >= 1, got {topic_replication}");
    }
    // -1 (infinite) is deliberately rejected: Kafka is the wire, not the record.
    if retention_ms < 1 {
        bail!("KAFKA_RETENTION_MS must be >= 1 (the event wire is bounded, not infinite), got {retention_ms}");
    }

    Ok(KafkaConfig {
        brokers: env("KAFKA_BROKERS")?,
        group_id: env("EVENT_STORE_KAFKA_GROUP")?,
        topic_partitions,
        topic_replication,
        retention_ms,
    })
}
