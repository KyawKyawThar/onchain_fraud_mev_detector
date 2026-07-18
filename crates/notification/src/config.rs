//! Configuration, resolved once from the environment at startup — the
//! single place this service reads env (mirrors `rule_engine::config`).
//! Everything downstream takes an explicit [`Config`] so the rest of the
//! service stays pure and testable.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use secrecy::SecretString;
use telemetry::env::{parse_or as env_parse, required as env};

use crate::delivery::DeliveryConfig;
use crate::email_delivery::EmailConfig;

/// SMTP relay port when `SMTP_PORT` is unset — the standard STARTTLS
/// submission port.
const DEFAULT_SMTP_PORT: u16 = 587;

/// How often the periodic backstop refresh reloads the subscriber snapshot
/// (`crate::subscriber_cache`) when `NOTIFICATION_SUBSCRIBER_REFRESH_SECS` is
/// unset — mirrors `rule_engine::config`'s `DEFAULT_REFRESH_SECS`. There is
/// no `SubscriberCreated`-style immediate-refresh trigger yet (no
/// subscriber-management API in this pass), so this interval is the only
/// thing bounding how stale the routing snapshot gets.
const DEFAULT_SUBSCRIBER_REFRESH_SECS: u64 = 30;

/// All runtime configuration for the §11 notification service.
#[derive(Debug, Clone)]
pub struct Config {
    /// Postgres: subscribers, the delivery/dedup ledger, the incident↔alert
    /// correlation index (§14, this service's own tables).
    pub database_url: SecretString,
    pub kafka: KafkaConfig,
    /// Shared retry/timeout policy for every HTTP-based channel
    /// (webhook/Slack/PagerDuty) and email.
    pub delivery: DeliveryConfig,
    pub smtp: EmailConfig,
    /// Periodic subscriber-snapshot refresh interval (see
    /// [`DEFAULT_SUBSCRIBER_REFRESH_SECS`]).
    pub subscriber_refresh_interval: Duration,
    /// Address the Prometheus `/metrics` endpoint binds to (§19).
    pub metrics_addr: SocketAddr,
}

/// How to reach Kafka.
#[derive(Debug, Clone)]
pub struct KafkaConfig {
    /// Comma-separated bootstrap brokers (`localhost:9092`).
    pub brokers: String,
    /// Consumer-group id — its own group, so offsets advance independently
    /// of every other consumer on the backbone.
    pub group_id: String,
}

impl Config {
    /// Resolve from the environment, erroring on anything missing or
    /// malformed (fail fast at boot rather than at first event).
    pub fn from_env() -> Result<Self> {
        let delivery_defaults = DeliveryConfig::default();
        Ok(Self {
            database_url: SecretString::from(env("DATABASE_URL")?),
            kafka: KafkaConfig {
                brokers: env("KAFKA_BROKERS")?,
                group_id: env("NOTIFICATION_KAFKA_GROUP")?,
            },
            delivery: DeliveryConfig {
                timeout: Duration::from_secs(env_parse(
                    "NOTIFICATION_DELIVERY_TIMEOUT_SECS",
                    delivery_defaults.timeout.as_secs(),
                )?),
                attempts: env_parse("NOTIFICATION_DELIVERY_ATTEMPTS", delivery_defaults.attempts)?
                    .max(1),
                retry_backoff: Duration::from_millis(env_parse(
                    "NOTIFICATION_DELIVERY_RETRY_BACKOFF_MS",
                    u64::try_from(delivery_defaults.retry_backoff.as_millis()).unwrap_or(500),
                )?),
            },
            smtp: EmailConfig {
                host: env("SMTP_HOST")?,
                port: env_parse("SMTP_PORT", DEFAULT_SMTP_PORT)?,
                username: env("SMTP_USERNAME")?,
                password: SecretString::from(env("SMTP_PASSWORD")?),
                from: env("SMTP_FROM")?,
            },
            subscriber_refresh_interval: Duration::from_secs(env_parse(
                "NOTIFICATION_SUBSCRIBER_REFRESH_SECS",
                DEFAULT_SUBSCRIBER_REFRESH_SECS,
            )?),
            metrics_addr: env_parse(
                "NOTIFICATION_METRICS_ADDR",
                SocketAddr::from(([0, 0, 0, 0], 9110)),
            )?,
        })
    }
}
