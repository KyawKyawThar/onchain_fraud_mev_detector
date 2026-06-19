//! Configuration, resolved once from the environment at startup.
//!
//! This is the single place the service reads env (mirroring how the
//! `telemetry` crate keeps env access in one spot). Everything downstream takes
//! an explicit [`Config`] so the rest of the service stays pure and testable.

use std::net::SocketAddr;

use anyhow::{Context, Result};
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

/// How to reach Kafka and which consumer group to join.
#[derive(Debug, Clone)]
pub struct KafkaConfig {
    /// Comma-separated bootstrap brokers (`localhost:9092`).
    pub brokers: String,
    /// Consumer-group id — restarts resume from committed offsets.
    pub group_id: String,
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
            kafka: KafkaConfig {
                brokers: env("KAFKA_BROKERS")?,
                group_id: env("EVENT_STORE_KAFKA_GROUP")?,
            },
            http_addr,
            write_token: SecretString::from(env("EVENT_STORE_WRITE_TOKEN")?),
        })
    }
}

/// Read a required env var, with the variable name in the error so a missing
/// value is self-explanatory in the boot log.
fn env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing required env var {key}"))
}
