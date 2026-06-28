//! Configuration, resolved once from the environment at startup — the single
//! place this service reads env (mirroring `ingestion`, `event-store` and
//! `telemetry`). Everything downstream takes an explicit [`Config`] so the rest of
//! the service stays pure and testable.

use std::net::SocketAddr;

use anyhow::{bail, Result};
use events::primitives::Chain;

/// All runtime configuration for the detection service.
#[derive(Debug, Clone)]
pub struct Config {
    /// Which chain this instance detects on (§5 — one instance per chain; the
    /// detection events it emits are keyed by this chain).
    pub chain: Chain,
    pub kafka: KafkaConfig,
    /// Capacity of the bounded consumer→scheduler work channel (§17). The number of
    /// decoded-but-not-yet-detected blocks buffered before the consumer stops
    /// pulling — the backpressure depth. Defaults to 256.
    pub work_buffer: usize,
    /// Capacity of the bounded scheduler→committer channel — published-but-not-yet-
    /// committed blocks. Defaults to 256.
    pub commit_buffer: usize,
    /// Address the Prometheus `/metrics` endpoint binds to (§19 — per-detector
    /// hit/latency, plus future service metrics). Defaults to `0.0.0.0:9100`, so a
    /// scraper on the deploy network reaches it without extra config.
    pub metrics_addr: SocketAddr,
}

/// How to reach Kafka: the broker list, and the consumer group whose committed
/// offsets a restart resumes from.
#[derive(Debug, Clone)]
pub struct KafkaConfig {
    /// Comma-separated bootstrap brokers (`localhost:9092`).
    pub brokers: String,
    /// Consumer-group id — restarts resume from committed offsets.
    pub group_id: String,
}

impl Config {
    /// Resolve config from the process environment, erroring on anything missing or
    /// malformed (fail fast at boot rather than at first event).
    pub fn from_env() -> Result<Self> {
        let work_buffer = env_parse("DETECTION_WORK_BUFFER", 256usize)?;
        let commit_buffer = env_parse("DETECTION_COMMIT_BUFFER", 256usize)?;
        if work_buffer < 1 || commit_buffer < 1 {
            bail!("DETECTION_WORK_BUFFER and DETECTION_COMMIT_BUFFER must be >= 1");
        }
        Ok(Self {
            chain: Chain(env_parse("CHAIN_ID", 1u64)?),
            kafka: KafkaConfig {
                brokers: env("KAFKA_BROKERS")?,
                group_id: env_or("DETECTION_KAFKA_GROUP", "detection"),
            },
            work_buffer,
            commit_buffer,
            metrics_addr: env_parse(
                "DETECTION_METRICS_ADDR",
                SocketAddr::from(([0, 0, 0, 0], 9100)),
            )?,
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
