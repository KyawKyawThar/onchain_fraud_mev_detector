//! Configuration, resolved once from the environment at startup — the single
//! place this service reads env (mirroring `event-store` and `telemetry`).
//! Everything downstream takes an explicit [`Config`] so the rest of the
//! service stays pure and testable.

use std::net::SocketAddr;
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
    /// How often the pipeline polls the source's `finalized` tag to advance
    /// finality and emit `BlockFinalized` (§5, §15). Coarser than the head poll —
    /// finality moves at most once per epoch (~6.4 min on Ethereum).
    pub finalize_interval: Duration,
    pub rpc: RpcPoolConfig,
    pub kafka: KafkaConfig,
    /// Address the Prometheus `/metrics` endpoint binds to (§19 — ingestion lag,
    /// assembly latency, reorg depth/frequency). Defaults to `0.0.0.0:9103`, a
    /// slot distinct from detection's `9100`/`9101` (base) and event-store's
    /// `9102` (§20 standardized port table).
    pub metrics_addr: SocketAddr,
}

/// How to reach Kafka for *producing* chain events (§20). The ingestion service
/// is the first producer in the system; the event-store owns topic provisioning,
/// so this is just the broker list — the topic name is derived per event from
/// the schema ([`events::EventEnvelope::topic`]).
#[derive(Debug, Clone)]
pub struct KafkaConfig {
    /// Comma-separated bootstrap brokers (`localhost:9092`).
    pub brokers: String,
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
        let chain = Chain(env_parse("CHAIN_ID", 1u64)?);
        Ok(Self {
            chain,
            finalization_depth: resolve_finalization_depth(
                chain,
                env_parse_opt::<u64>("FINALIZATION_DEPTH")?,
            )?,
            finalize_interval: Duration::from_millis(env_parse("FINALIZE_INTERVAL_MS", 12_000u64)?),
            rpc: rpc_from_env()?,
            kafka: KafkaConfig {
                brokers: env("KAFKA_BROKERS")?,
            },
            metrics_addr: env_parse(
                "INGESTION_METRICS_ADDR",
                SocketAddr::from(([0, 0, 0, 0], 9103)),
            )?,
        })
    }
}

/// Pick the finalization depth: an explicit `FINALIZATION_DEPTH` always wins;
/// otherwise the chain's default ([`Chain::default_finalization_depth`] —
/// Ethereum 64, Base 1024). A chain with no default and no explicit depth is a
/// boot error — guessing Ethereum's 64 for an unknown L2 would prune blocks
/// the source still considers reorgable (§15).
fn resolve_finalization_depth(chain: Chain, explicit: Option<u64>) -> Result<u64> {
    if let Some(depth) = explicit {
        if depth < 1 {
            bail!("FINALIZATION_DEPTH must be >= 1");
        }
        return Ok(depth);
    }
    chain.default_finalization_depth().ok_or_else(|| {
        anyhow::anyhow!(
            "chain {chain} has no default finalization depth; set FINALIZATION_DEPTH explicitly"
        )
    })
}

fn rpc_from_env() -> Result<RpcPoolConfig> {
    // `RPC_URLS` is the chain-neutral name (a Base instance's endpoints aren't
    // "ETH"); `ETH_RPC_URLS` stays as the fallback existing deployments set.
    let raw = match std::env::var("RPC_URLS") {
        Ok(raw) => raw,
        Err(_) => env("ETH_RPC_URLS").context("set RPC_URLS (or legacy ETH_RPC_URLS)")?,
    };
    let endpoints = parse_endpoints(&raw)?;

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

/// Parse a comma-separated `RPC_URLS`/`ETH_RPC_URLS` into validated [`Url`]s,
/// rejecting an empty list (a pool with no endpoints can never serve a
/// request — fail fast).
fn parse_endpoints(raw: &str) -> Result<Vec<Url>> {
    let endpoints = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| Url::parse(s).with_context(|| format!("RPC_URLS contains an invalid URL: {s}")))
        .collect::<Result<Vec<_>>>()?;

    if endpoints.is_empty() {
        bail!("RPC_URLS is empty; the RPC failover pool needs at least one endpoint");
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

/// Read an *optional* env var parsed into `T`, `None` when unset. A
/// present-but-unparseable value is an error, caught at boot.
fn env_parse_opt<T>(key: &str) -> Result<Option<T>>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match std::env::var(key) {
        Ok(raw) => raw.parse().map(Some).map_err(|err| {
            anyhow::anyhow!(
                "env var {key} is not a valid {}: {err}",
                std::any::type_name::<T>()
            )
        }),
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_finalization_depth_wins_over_the_chain_default() {
        assert_eq!(
            resolve_finalization_depth(Chain::ETHEREUM, Some(128)).unwrap(),
            128
        );
        assert_eq!(
            resolve_finalization_depth(Chain::BASE, Some(2048)).unwrap(),
            2048
        );
    }

    #[test]
    fn known_chains_fall_back_to_their_default_depth() {
        assert_eq!(
            resolve_finalization_depth(Chain::ETHEREUM, None).unwrap(),
            64
        );
        assert_eq!(resolve_finalization_depth(Chain::BASE, None).unwrap(), 1024);
    }

    #[test]
    fn unknown_chain_without_explicit_depth_is_a_boot_error() {
        assert!(resolve_finalization_depth(Chain(424242), None).is_err());
        assert_eq!(
            resolve_finalization_depth(Chain(424242), Some(300)).unwrap(),
            300
        );
    }

    #[test]
    fn zero_explicit_depth_is_rejected() {
        assert!(resolve_finalization_depth(Chain::ETHEREUM, Some(0)).is_err());
    }

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
