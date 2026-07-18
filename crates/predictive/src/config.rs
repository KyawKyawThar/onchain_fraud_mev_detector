//! Configuration, resolved once from the environment at startup — mirrors
//! `ingestion::config`'s shape and its `env`/`env_parse` helpers.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use events::primitives::Chain;
use url::Url;

/// All runtime configuration for the predictive pipeline service.
#[derive(Debug, Clone)]
pub struct Config {
    /// Which chain this instance predicts over (mirrors ingestion — one
    /// instance per chain, §16).
    pub chain: Chain,
    /// The single mempool RPC endpoint (§16 — no failover pool; see
    /// `source` module docs).
    pub mempool_rpc_url: Url,
    /// How often the mempool source polls `eth_getFilterChanges`.
    pub poll_interval: Duration,
    /// `http://host:port` for intelligence's `IntelligenceRead` gRPC service.
    pub intelligence_grpc_addr: String,
    /// Max distinct tx hashes remembered for dedup (the mempool re-announces
    /// the same pending tx across polls); oldest is evicted past this.
    pub dedup_capacity: usize,
    pub kafka: KafkaConfig,
    pub metrics_addr: SocketAddr,
}

/// How to reach Kafka for *producing* `PredictedAlert` (§16, §20).
#[derive(Debug, Clone)]
pub struct KafkaConfig {
    /// Comma-separated bootstrap brokers (`localhost:9092`).
    pub brokers: String,
}

impl Config {
    /// Resolve config from the process environment, erroring on anything
    /// missing or malformed (fail fast at boot rather than at first request).
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            chain: Chain(env_parse("CHAIN_ID", 1u64)?),
            mempool_rpc_url: Url::parse(&env("MEMPOOL_RPC_URL")?)
                .context("MEMPOOL_RPC_URL is not a valid URL")?,
            poll_interval: Duration::from_millis(env_parse("MEMPOOL_POLL_INTERVAL_MS", 500u64)?),
            intelligence_grpc_addr: env("INTELLIGENCE_GRPC_ADDR")?,
            dedup_capacity: env_parse("MEMPOOL_DEDUP_CAPACITY", 50_000usize)?,
            kafka: KafkaConfig {
                brokers: env("KAFKA_BROKERS")?,
            },
            metrics_addr: env_parse("METRICS_ADDR", "0.0.0.0:9465".to_string())?
                .parse()
                .context("METRICS_ADDR is not a valid socket address")?,
        })
    }
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
    fn env_parse_falls_back_to_default_when_unset() {
        assert_eq!(env_parse::<u64>("PREDICTIVE_TEST_UNSET_VAR", 7).unwrap(), 7);
    }
}
