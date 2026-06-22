//! Configuration, resolved once from the environment at startup — the single
//! place this service reads env (mirroring `event-store` and `telemetry`).
//! Everything downstream takes an explicit [`Config`] so the rest of the
//! service stays pure and testable.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use events::primitives::Chain;
use url::Url;

use crate::source::circuit::BreakerConfig;

/// All runtime configuration for the ingestion service.
#[derive(Debug, Clone)]
pub struct Config {
    /// Which chain this instance ingests (§5 — one instance per chain; chain is
    /// the partition key on every event it emits).
    pub chain: Chain,
    /// Depth (blocks below the tip) at which a block is treated as final and
    /// can no longer be reorged (§15). Used by tasks 2–4; carried here so the
    /// whole service reads env in one place.
    pub finalization_depth: u64,
    pub rpc: RpcPoolConfig,
}

/// The RPC failover pool's configuration (§5, adapter #3).
#[derive(Debug, Clone)]
pub struct RpcPoolConfig {
    /// Endpoints in preference order; the pool tries them first-to-last.
    pub endpoints: Vec<Url>,
    /// How often the head poller asks for the chain tip.
    pub poll_interval: Duration,
    /// How often the active health probe sweeps every endpoint.
    pub health_interval: Duration,
    /// Per-call ceiling; a slower endpoint is failed over (counts as a failure).
    pub request_timeout: Duration,
    pub breaker: BreakerConfig,
}

impl Config {
    /// Resolve config from the process environment, erroring on anything missing
    /// or malformed (fail fast at boot rather than at first request).
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            chain: Chain(env_parse("CHAIN_ID", 1u64)?),
            finalization_depth: env_parse("FINALIZATION_DEPTH", 64u64)?,
            rpc: rpc_from_env()?,
        })
    }
}

fn rpc_from_env() -> Result<RpcPoolConfig> {
    let endpoints = parse_endpoints(&env("ETH_RPC_URLS")?)?;

    let breaker = BreakerConfig {
        failure_threshold: env_parse("RPC_BREAKER_FAILURE_THRESHOLD", 5u32)?,
        open_cooldown: Duration::from_millis(env_parse("RPC_BREAKER_OPEN_COOLDOWN_MS", 30_000u64)?),
        success_threshold: env_parse("RPC_BREAKER_SUCCESS_THRESHOLD", 1u32)?,
    };
    if breaker.failure_threshold < 1 {
        bail!("RPC_BREAKER_FAILURE_THRESHOLD must be >= 1");
    }
    if breaker.success_threshold < 1 {
        bail!("RPC_BREAKER_SUCCESS_THRESHOLD must be >= 1");
    }

    Ok(RpcPoolConfig {
        endpoints,
        poll_interval: Duration::from_millis(env_parse("RPC_POLL_INTERVAL_MS", 2_000u64)?),
        health_interval: Duration::from_millis(env_parse("RPC_HEALTH_INTERVAL_MS", 10_000u64)?),
        request_timeout: Duration::from_millis(env_parse("RPC_REQUEST_TIMEOUT_MS", 5_000u64)?),
        breaker,
    })
}

/// Parse a comma-separated `ETH_RPC_URLS` into validated [`Url`]s, rejecting an
/// empty list (a pool with no endpoints can never serve a request — fail fast).
fn parse_endpoints(raw: &str) -> Result<Vec<Url>> {
    let endpoints = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            Url::parse(s).with_context(|| format!("ETH_RPC_URLS contains an invalid URL: {s}"))
        })
        .collect::<Result<Vec<_>>>()?;

    if endpoints.is_empty() {
        bail!("ETH_RPC_URLS is empty; the RPC failover pool needs at least one endpoint");
    }
    Ok(endpoints)
}

/// Read a required env var, with the variable name in the error.
fn env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing required env var {key}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_trims_a_comma_separated_endpoint_list() {
        let urls = parse_endpoints(" http://a.example , http://b.example/key ").unwrap();
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0].as_str(), "http://a.example/");
        assert_eq!(urls[1].as_str(), "http://b.example/key");
    }

    #[test]
    fn rejects_an_empty_endpoint_list() {
        assert!(parse_endpoints("").is_err());
        assert!(parse_endpoints("  ,  ").is_err());
    }

    #[test]
    fn rejects_a_malformed_url() {
        assert!(parse_endpoints("http://ok.example,not a url").is_err());
    }
}
