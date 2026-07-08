//! Configuration, resolved once from the environment at startup — the single
//! place this service reads env (mirroring `simulation`, `detection`,
//! `event-store`). Everything downstream takes an explicit [`Config`] so the
//! rest of the service stays pure and testable.

use std::time::Duration;

use anyhow::Result;
use secrecy::SecretString;

/// All runtime configuration for the intelligence service (§8, §14): the three
/// data stores (Postgres system of record, Redis hot cache, ClickHouse
/// adjacency graph) plus the t4 attribution consumer's Kafka settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// Postgres connection URL (`postgres://…`) for labels/entities/
    /// attribution/sanctions (§14). Secret — the URL embeds the password, so
    /// `Debug` redacts it and the use site must `expose_secret()`. Migrations
    /// are applied out-of-band by sqlx-cli (`just migrate-*`), not at boot.
    pub postgres_url: SecretString,
    pub redis: RedisConfig,
    pub clickhouse: ClickhouseConfig,
    pub kafka: KafkaConfig,
}

/// How to reach Kafka for the `attribute` consumer (Sprint 7 t4): the
/// broker list, and the consumer group whose committed offsets a restart
/// resumes from.
#[derive(Debug, Clone)]
pub struct KafkaConfig {
    /// Comma-separated bootstrap brokers (`localhost:9092`).
    pub brokers: String,
    /// Consumer-group id for the `PreliminaryAlertCreated`/`IncidentCreated`
    /// attribution consumer — restarts resume from committed offsets.
    pub group_id: String,
}

/// How to reach Redis and how long cached entries live. The full URL is secret
/// (`redis://:password@host:port/db` embeds the password), so `Debug` redacts
/// it and the use site must `expose_secret()`.
#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub url: SecretString,
    /// TTL for hot-cache entries (§8: TTL-backed, evicted on update). The TTL
    /// is the *staleness backstop* — correctness comes from explicit eviction.
    pub cache_ttl: Duration,
}

/// How to reach ClickHouse. Same split as the event store / simulation
/// projection: credential-free base URL, user/password/database separate, the
/// password behind [`SecretString`].
#[derive(Debug, Clone)]
pub struct ClickhouseConfig {
    /// HTTP-interface base URL, e.g. `http://127.0.0.1:8123` (no creds, no db).
    pub url: String,
    pub user: String,
    pub password: SecretString,
    pub database: String,
}

impl Config {
    /// Resolve from the environment, erroring on anything missing or malformed
    /// (fail fast at boot rather than at the first event).
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            postgres_url: SecretString::from(env("DATABASE_URL")?),
            redis: RedisConfig {
                url: SecretString::from(env("REDIS_URL")?),
                cache_ttl: Duration::from_secs(env_parse("INTEL_CACHE_TTL_SECS", 300u64)?),
            },
            clickhouse: ClickhouseConfig {
                url: env("CLICKHOUSE_HTTP_URL")?,
                user: env("CLICKHOUSE_USER")?,
                password: SecretString::from(env("CLICKHOUSE_PASSWORD")?),
                database: env("CLICKHOUSE_DB")?,
            },
            kafka: KafkaConfig {
                brokers: env("KAFKA_BROKERS")?,
                group_id: env_or("INTELLIGENCE_KAFKA_GROUP", "intelligence-attribution"),
            },
        })
    }
}

/// Read a required env var, with the variable name in the error.
fn env(key: &str) -> Result<String> {
    std::env::var(key).map_err(|_| anyhow::anyhow!("missing required env var {key}"))
}

/// Read an optional env var, falling back to a static default.
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

/// Read an *optional* env var parsed into `T`, falling back to `default` when
/// unset. A present-but-unparseable value is an error, caught at boot.
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
