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
    /// §16.4 (Sprint 16 task 4): the opt-in predictive-events consumer —
    /// disabled unless a deployment explicitly turns it on (see
    /// [`PredictiveConfig`]'s docs).
    pub predictive: PredictiveConfig,
    /// Shared retry/timeout policy for every HTTP-based channel
    /// (webhook/Slack/PagerDuty) and email.
    pub delivery: DeliveryConfig,
    pub smtp: EmailConfig,
    /// Periodic subscriber-snapshot refresh interval (see
    /// [`DEFAULT_SUBSCRIBER_REFRESH_SECS`]).
    pub subscriber_refresh_interval: Duration,
    /// Address the Prometheus `/metrics` endpoint binds to (§19).
    pub metrics_addr: SocketAddr,
    /// The §19 feedback loop's minting settings (readiness Epic E). `None`
    /// when `FEEDBACK_GRANT_SECRET` or `FEEDBACK_LINK_BASE` is unset: a
    /// deployment that does not want the loop delivers alerts with no way to
    /// answer them, which is a choice rather than a fault — and one the
    /// `alert_feedback_solicitation_enabled` gauge states explicitly.
    pub feedback: Option<FeedbackConfig>,
}

/// Resolve the §19 feedback loop's minting settings, or `None` when this
/// deployment does not run the loop.
///
/// **The secret decides.** No `FEEDBACK_GRANT_SECRET` means the loop is off —
/// with a warning when a link base is configured anyway, because that is the
/// shape of a rollout where the key was forgotten in the secrets manager, and
/// it must degrade the loop rather than keep the pod from starting: the link
/// base rides in the shared `app-config`, so every cluster has one.
///
/// A secret **without** a link base is refused at boot. That combination can
/// only come from an operator who deliberately configured the secret, and a
/// grant nobody can spend is a loop that looks enabled and silently is not.
fn feedback_config() -> Result<Option<FeedbackConfig>> {
    let secret = std::env::var("FEEDBACK_GRANT_SECRET")
        .ok()
        .filter(|s| !s.is_empty());
    let link_base = std::env::var("FEEDBACK_LINK_BASE")
        .ok()
        .filter(|s| !s.is_empty());
    match (secret, link_base) {
        (None, None) => Ok(None),
        (None, Some(_)) => {
            tracing::warn!(
                "FEEDBACK_LINK_BASE is set but FEEDBACK_GRANT_SECRET is not: the feedback \
                 loop is disabled and alerts will carry no feedback link"
            );
            Ok(None)
        }
        (Some(_), None) => anyhow::bail!(
            "FEEDBACK_GRANT_SECRET is set but FEEDBACK_LINK_BASE is not: grants would be \
             minted for a link nothing serves"
        ),
        (Some(grant_secret), Some(link_base)) => Ok(Some(FeedbackConfig {
            grant_secret: SecretString::from(grant_secret),
            link_base,
            solicit_permille: env_parse("FEEDBACK_SOLICIT_PERMILLE", 50u32)?,
            grant_ttl: Duration::from_secs(
                u64::from(env_parse("FEEDBACK_GRANT_TTL_DAYS", 30u32)?) * 86_400,
            ),
        })),
    }
}

/// What the delivery path needs to mint a feedback capability.
#[derive(Debug, Clone)]
pub struct FeedbackConfig {
    /// Shared with the API service, which holds the verifying half. Not
    /// `JWT_SECRET`: one secret for identity and another for capabilities is
    /// what stops either being spent as the other.
    pub grant_secret: SecretString,
    /// Base URL of the surface that renders the feedback form, e.g.
    /// `https://app.example.com`.
    pub link_base: String,
    /// How many incidents in a thousand the platform *asks* about, rather than
    /// waiting to be told. The solicited cohort is the only one whose rate can
    /// back a published claim, and it costs a line in an email.
    pub solicit_permille: u32,
    /// How long a feedback link stays usable. Past this a link in an old email
    /// is refused — a capability, not a standing permission.
    pub grant_ttl: Duration,
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

/// §16.4 (Sprint 16 task 4): the predictive-events consumer is opt-in — a
/// deployment with no risk desk configured runs the incident-stream consumer
/// only, and `NOTIFICATION_PREDICTIVE_ENABLED` (default `false`) is the one
/// switch that turns the second task on. Its own [`KafkaConfig::group_id`]
/// keeps its offsets, lag, and DLQ entirely independent of the incident
/// stream's consumer group (§16.4's "no coupling to the incident stream") —
/// `main.rs` only builds/spawns the second consumer task when `enabled`.
#[derive(Debug, Clone)]
pub struct PredictiveConfig {
    pub enabled: bool,
    pub group_id: String,
}

impl Config {
    /// Resolve from the environment, erroring on anything missing or
    /// malformed (fail fast at boot rather than at first event).
    pub fn from_env() -> Result<Self> {
        let delivery_defaults = DeliveryConfig::default();
        let kafka_group_id = env("NOTIFICATION_KAFKA_GROUP")?;
        Ok(Self {
            database_url: SecretString::from(env("DATABASE_URL")?),
            kafka: KafkaConfig {
                brokers: env("KAFKA_BROKERS")?,
                group_id: kafka_group_id.clone(),
            },
            predictive: PredictiveConfig {
                enabled: env_parse("NOTIFICATION_PREDICTIVE_ENABLED", false)?,
                group_id: env_parse(
                    "NOTIFICATION_PREDICTIVE_KAFKA_GROUP",
                    format!("{kafka_group_id}-predictive"),
                )?,
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
            feedback: feedback_config()?,
            metrics_addr: env_parse(
                "NOTIFICATION_METRICS_ADDR",
                SocketAddr::from(([0, 0, 0, 0], 9110)),
            )?,
        })
    }
}
