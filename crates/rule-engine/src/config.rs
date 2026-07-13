//! Configuration, resolved once from the environment at startup — the single
//! place this service reads env (mirroring `intelligence`/`server`).
//! Everything downstream takes an explicit [`Config`] so the rest of the
//! service stays pure and testable.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use secrecy::SecretString;

use crate::webhook::WebhookConfig;

/// How often the periodic backstop refresh reloads the enabled rule set when
/// `RULE_REFRESH_SECS` is unset. `RuleCreated` events refresh immediately;
/// this catches disable/delete, which have no events of their own yet.
const DEFAULT_REFRESH_SECS: u64 = 30;

/// Capacity of the temporal-fires channel when `RULE_FIRES_CAPACITY` is
/// unset — a full channel backpressures the workers (§6), which backpressures
/// the consumer.
const DEFAULT_FIRES_CAPACITY: usize = 1024;

/// Hot-cache read TTL fallback, mirroring intelligence's own default.
const DEFAULT_CACHE_TTL_SECS: u64 = 300;

/// All runtime configuration for the §9 rule-engine service.
#[derive(Debug, Clone)]
pub struct Config {
    /// Postgres: the `rules` table (this service's own, §14) and the
    /// intelligence tables the enrichment adapter reads.
    pub database_url: SecretString,
    /// Redis: temporal window state (t3) + the intelligence hot cache.
    pub redis_url: SecretString,
    pub kafka: KafkaConfig,
    /// Periodic rule-set refresh interval (see [`DEFAULT_REFRESH_SECS`]).
    pub refresh_interval: Duration,
    /// Temporal-fires channel capacity (see [`DEFAULT_FIRES_CAPACITY`]).
    pub fires_capacity: usize,
    /// Intelligence hot-cache TTL for scores this service repopulates.
    pub cache_ttl: Duration,
    /// Webhook delivery policy (t5): per-attempt timeout, bounded retries.
    pub webhook: WebhookConfig,
    /// Address the Prometheus `/metrics` endpoint binds to (§19).
    pub metrics_addr: SocketAddr,
}

/// How to reach Kafka.
#[derive(Debug, Clone)]
pub struct KafkaConfig {
    /// Comma-separated bootstrap brokers (`localhost:9092`).
    pub brokers: String,
    /// Consumer-group id — its own group, so offsets advance independently of
    /// every other consumer on the backbone.
    pub group_id: String,
}

impl Config {
    /// Resolve from the environment, erroring on anything missing or
    /// malformed (fail fast at boot rather than at first event).
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            database_url: SecretString::from(env("DATABASE_URL")?),
            redis_url: SecretString::from(env("REDIS_URL")?),
            kafka: KafkaConfig {
                brokers: env("KAFKA_BROKERS")?,
                group_id: env("RULE_ENGINE_KAFKA_GROUP")?,
            },
            refresh_interval: Duration::from_secs(env_parse(
                "RULE_REFRESH_SECS",
                DEFAULT_REFRESH_SECS,
            )?),
            fires_capacity: env_parse("RULE_FIRES_CAPACITY", DEFAULT_FIRES_CAPACITY)?.max(1),
            cache_ttl: Duration::from_secs(env_parse(
                "INTEL_CACHE_TTL_SECS",
                DEFAULT_CACHE_TTL_SECS,
            )?),
            webhook: {
                let defaults = WebhookConfig::default();
                WebhookConfig {
                    timeout: Duration::from_secs(env_parse(
                        "RULE_WEBHOOK_TIMEOUT_SECS",
                        defaults.timeout.as_secs(),
                    )?),
                    attempts: env_parse("RULE_WEBHOOK_ATTEMPTS", defaults.attempts)?.max(1),
                    retry_backoff: Duration::from_millis(env_parse(
                        "RULE_WEBHOOK_RETRY_BACKOFF_MS",
                        u64::try_from(defaults.retry_backoff.as_millis()).unwrap_or(500),
                    )?),
                }
            },
            metrics_addr: env_parse(
                "RULE_ENGINE_METRICS_ADDR",
                SocketAddr::from(([0, 0, 0, 0], 9107)),
            )?,
        })
    }
}

/// Read a required env var, with the variable name in the error so a missing
/// value is self-explanatory in the boot log.
fn env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing required env var {key}"))
}

/// Read an *optional* env var parsed into `T`, falling back to `default` when
/// unset; a present-but-unparseable value is a boot error.
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
