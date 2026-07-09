//! Configuration, resolved once from the environment at startup — the single
//! place this service reads env (mirrors `event-store`/`intelligence`/
//! `simulation`). Everything downstream takes an explicit [`Config`] so the
//! rest of the service stays pure and testable.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use secrecy::SecretString;

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
        })
    }
}

/// Read a required env var, with the variable name in the error so a missing
/// value is self-explanatory in the boot log.
fn env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing required env var {key}"))
}
