//! Configuration, resolved once from the environment at startup — the single
//! place this service reads env (mirrors `event-store`/`intelligence`/
//! `simulation`). Everything downstream takes an explicit [`Config`] so the
//! rest of the service stays pure and testable.

use std::net::SocketAddr;

use anyhow::{bail, Context, Result};
use secrecy::SecretString;

/// Broadcast channel capacity for `WS /v1/stream` when `WS_ALERT_CHANNEL_CAPACITY`
/// is unset (§11).
const DEFAULT_ALERT_CHANNEL_CAPACITY: usize = 1024;

/// All runtime configuration for the public §11 API service: where to bind,
/// where to reach the three internal services it fronts, and the JWT
/// verification settings that gate every `/v1` route.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address the public HTTP API binds to.
    pub http_addr: SocketAddr,
    /// Base URL of event-store's internal read API (`GET /v1/audit/incident/{id}`).
    pub event_store_url: String,
    /// Base URL of simulation-projection's internal read API (`GET /v1/incidents`).
    pub simulation_url: String,
    /// `http://host:port` of intelligence's `IntelligenceRead` gRPC server.
    pub intelligence_grpc_addr: String,
    pub jwt: JwtConfig,
    /// Kafka settings for the `/v1/stream` WebSocket's consumer (§11).
    pub kafka: KafkaConfig,
    /// Capacity of the broadcast channel `WS /v1/stream` fans alerts out
    /// through (§11) — how many alerts a slow client can fall behind by
    /// before it starts missing them (further sends surface as
    /// `RecvError::Lagged`, which `stream::stream_socket` handles by
    /// dropping the backlog, not the connection). Defaults to
    /// [`DEFAULT_ALERT_CHANNEL_CAPACITY`].
    pub alert_channel_capacity: usize,
}

/// How to reach Kafka for the `WS /v1/stream` consumer (§11) — it subscribes to
/// the three lifecycle topics (`PreliminaryAlertCreated`/`IncidentCreated`/
/// `IncidentRetracted`) that event-store's `ensure_topics` already provisions,
/// so this service only ever reads.
#[derive(Debug, Clone)]
pub struct KafkaConfig {
    /// Comma-separated bootstrap brokers (`localhost:9092`).
    pub brokers: String,
    /// Consumer-group id — restarts resume from committed offsets. Distinct
    /// from event-store's group so the two consumers advance independently.
    pub group_id: String,
}

/// JWT bearer verification settings (§11). No issuance here — see `src/auth.rs`.
#[derive(Clone)]
pub struct JwtConfig {
    /// HMAC signing secret. Secret — `Debug` redacts it.
    pub secret: SecretString,
    /// Expected `iss` claim; a token from anywhere else is rejected.
    pub issuer: String,
}

impl std::fmt::Debug for JwtConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtConfig")
            .field("secret", &"[redacted]")
            .field("issuer", &self.issuer)
            .finish()
    }
}

impl Config {
    /// Resolve config from the process environment, erroring on anything missing
    /// or malformed (fail fast at boot rather than at first request).
    pub fn from_env() -> Result<Self> {
        let http_addr = format!("{}:{}", env("SERVER_HOST")?, env("SERVER_PORT")?)
            .parse()
            .context("SERVER_HOST:SERVER_PORT is not a valid socket address")?;

        Ok(Self {
            http_addr,
            event_store_url: env("EVENT_STORE_URL")?,
            simulation_url: env("SIMULATION_URL")?,
            intelligence_grpc_addr: env("INTELLIGENCE_GRPC_ADDR")?,
            jwt: JwtConfig {
                secret: SecretString::from(env("JWT_SECRET")?),
                issuer: env("JWT_ISSUER")?,
            },
            kafka: KafkaConfig {
                brokers: env("KAFKA_BROKERS")?,
                group_id: env("SERVER_KAFKA_GROUP")?,
            },
            alert_channel_capacity: alert_channel_capacity()?,
        })
    }
}

/// Resolve and validate `WS_ALERT_CHANNEL_CAPACITY`. A non-positive value
/// would panic inside `tokio::sync::broadcast::channel`; catching it here
/// keeps the "fail fast with a clear message at boot" contract the rest of
/// this module holds, same as event-store's Kafka topology validation.
fn alert_channel_capacity() -> Result<usize> {
    let capacity = env_parse("WS_ALERT_CHANNEL_CAPACITY", DEFAULT_ALERT_CHANNEL_CAPACITY)?;
    if capacity < 1 {
        bail!("WS_ALERT_CHANNEL_CAPACITY must be >= 1, got {capacity}");
    }
    Ok(capacity)
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
