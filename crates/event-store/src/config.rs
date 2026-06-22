//! Configuration, resolved once from the environment at startup.
//!
//! This is the single place the service reads env (mirroring how the
//! `telemetry` crate keeps env access in one spot). Everything downstream takes
//! an explicit [`Config`] so the rest of the service stays pure and testable.

use std::net::SocketAddr;

use anyhow::{bail, Context, Result};
use secrecy::SecretString;

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
        })
    }
}

/// Number of milliseconds in 7 days — the default Kafka topic retention.
const DEFAULT_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

/// Resolve and *validate* the Kafka topology config. The counts feed straight
/// into broker topic creation, where a non-positive value fails with an opaque
/// librdkafka error; catching it here keeps the "fail fast with a clear message
/// at boot" contract the rest of this module holds.
fn kafka_from_env() -> Result<KafkaConfig> {
    let topic_partitions = env_parse("KAFKA_TOPIC_PARTITIONS", 3)?;
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

/// Read a required env var, with the variable name in the error so a missing
/// value is self-explanatory in the boot log.
fn env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing required env var {key}"))
}

/// Read an *optional* env var parsed into `T`, falling back to `default` when
/// unset. Unlike [`env`], a missing value is fine (these have safe defaults);
/// only a present-but-unparseable value is an error — caught at boot, not at
/// first use.
fn env_parse<T>(key: &str, default: T) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match std::env::var(key) {
        Ok(raw) => raw.parse().map_err(|err| {
            anyhow::anyhow!(
                "env var {key} is not a valid {}: {err}",
                std::any::type_name::<T>()
            )
        }),
        Err(_) => Ok(default),
    }
}
