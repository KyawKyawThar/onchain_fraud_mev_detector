//! Configuration, resolved once from the environment at startup — mirrors
//! `ingestion::config`'s shape and its `env`/`env_parse` helpers.

use std::net::SocketAddr;
use std::time::Duration;

use alloy_primitives::Address;
use anyhow::{Context, Result};
use detector_api::Bps;
use events::primitives::Chain;
use url::Url;

use crate::position::{LiquidationThresholds, Protocol};

/// Fallback trailing window (in blocks) for the position tracker's reorg
/// snapshot store when the chain has no known [`Chain::default_finalization_depth`]
/// — an explicit, generous default rather than refusing to boot (unlike
/// ingestion's `FINALIZATION_DEPTH`, an unrecognized chain here degrades to a
/// deep-but-bounded window instead of being a hard boot error, since a
/// too-small window only means "a very old reorg silently under-rewinds",
/// not a wrong balance on the hot path).
const DEFAULT_POSITION_WINDOW_BLOCKS: u32 = 256;

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
    pub position_tracker: PositionTrackerConfig,
}

/// How to reach Kafka for *producing* `PredictedAlert` (§16, §20).
#[derive(Debug, Clone)]
pub struct KafkaConfig {
    /// Comma-separated bootstrap brokers (`localhost:9092`).
    pub brokers: String,
}

/// Configuration for the lending position tracker (§16.1, Sprint 16 task 1).
#[derive(Debug, Clone)]
pub struct PositionTrackerConfig {
    /// RPC endpoint `eth_getLogs` is queried against. Defaults to
    /// [`Config::mempool_rpc_url`] (the same node commonly serves both) so an
    /// existing deployment needn't add a second required env var.
    pub rpc_url: Url,
    /// The Aave `Pool` proxy / Compound `CToken` market contracts to fetch
    /// logs for. Empty means the tracker is wired but inert (no addresses
    /// configured yet) rather than a boot error — see `position_source`'s
    /// empty-address short-circuit.
    pub contract_addresses: Vec<Address>,
    /// Kafka consumer group for the `BlockCanonicalized`/`BlockReverted`
    /// subscription.
    pub consumer_group: String,
    /// Trailing blocks of position-book snapshots retained for reorg rollback
    /// (§15) — sized to the chain's reorg depth, not an analytical window; see
    /// `position` module docs.
    pub window_blocks: u32,
    pub liquidation_thresholds: LiquidationThresholds,
}

impl Config {
    /// Resolve config from the process environment, erroring on anything
    /// missing or malformed (fail fast at boot rather than at first request).
    pub fn from_env() -> Result<Self> {
        let chain = Chain(env_parse("CHAIN_ID", 1u64)?);
        let mempool_rpc_url =
            Url::parse(&env("MEMPOOL_RPC_URL")?).context("MEMPOOL_RPC_URL is not a valid URL")?;

        let lending_rpc_url = match std::env::var("LENDING_RPC_URL") {
            Ok(raw) => Url::parse(&raw).context("LENDING_RPC_URL is not a valid URL")?,
            Err(_) => mempool_rpc_url.clone(),
        };
        let default_window_blocks = chain
            .default_finalization_depth()
            .and_then(|depth| u32::try_from(depth).ok())
            .unwrap_or(DEFAULT_POSITION_WINDOW_BLOCKS);

        Ok(Self {
            chain,
            mempool_rpc_url,
            poll_interval: Duration::from_millis(env_parse("MEMPOOL_POLL_INTERVAL_MS", 500u64)?),
            intelligence_grpc_addr: env("INTELLIGENCE_GRPC_ADDR")?,
            dedup_capacity: env_parse("MEMPOOL_DEDUP_CAPACITY", 50_000usize)?,
            kafka: KafkaConfig {
                brokers: env("KAFKA_BROKERS")?,
            },
            metrics_addr: env_parse("METRICS_ADDR", "0.0.0.0:9465".to_string())?
                .parse()
                .context("METRICS_ADDR is not a valid socket address")?,
            position_tracker: PositionTrackerConfig {
                rpc_url: lending_rpc_url,
                contract_addresses: env_addr_list("LENDING_CONTRACT_ADDRESSES")?,
                consumer_group: env_parse(
                    "POSITION_CONSUMER_GROUP",
                    "predictive-position-tracker".to_string(),
                )?,
                window_blocks: env_parse("POSITION_WINDOW_BLOCKS", default_window_blocks)?,
                // Env-var fallbacks are `LiquidationThresholds::default()`'s own
                // figures, not re-hardcoded literals — one source of truth for
                // the documented default (position.rs) and the config fallback.
                liquidation_thresholds: LiquidationThresholds::new(
                    Bps::new(env_parse(
                        "AAVE_LIQUIDATION_THRESHOLD_BPS",
                        LiquidationThresholds::default()
                            .for_protocol(Protocol::Aave)
                            .get(),
                    )?),
                    Bps::new(env_parse(
                        "COMPOUND_LIQUIDATION_THRESHOLD_BPS",
                        LiquidationThresholds::default()
                            .for_protocol(Protocol::Compound)
                            .get(),
                    )?),
                ),
            },
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

/// A comma-separated list of `0x…` addresses, e.g. `LENDING_CONTRACT_ADDRESSES`
/// — unset means no contracts configured (`vec![]`), not an error; see
/// [`PositionTrackerConfig::contract_addresses`]. The parse itself is the pure
/// [`parse_addr_list`], kept separate from the env read so it's testable
/// without mutating process environment (this workspace forbids `unsafe`,
/// which `std::env::set_var` now requires).
fn env_addr_list(key: &str) -> Result<Vec<Address>> {
    match std::env::var(key) {
        Ok(raw) => parse_addr_list(&raw).with_context(|| format!("env var {key} is invalid")),
        Err(_) => Ok(Vec::new()),
    }
}

/// Parse a comma-separated list of `0x…` addresses, trimming whitespace and
/// skipping empty entries (so a trailing comma or stray spaces don't error).
fn parse_addr_list(raw: &str) -> Result<Vec<Address>> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<Address>()
                .with_context(|| format!("invalid address: {s:?}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_parse_falls_back_to_default_when_unset() {
        assert_eq!(env_parse::<u64>("PREDICTIVE_TEST_UNSET_VAR", 7).unwrap(), 7);
    }

    #[test]
    fn env_addr_list_is_empty_when_unset() {
        assert_eq!(
            env_addr_list("PREDICTIVE_TEST_UNSET_ADDR_LIST").unwrap(),
            Vec::<Address>::new()
        );
    }

    #[test]
    fn parse_addr_list_trims_and_skips_empty_entries() {
        let parsed = parse_addr_list(
            " 0x1111111111111111111111111111111111111111 ,0x2222222222222222222222222222222222222222,",
        )
        .unwrap();
        assert_eq!(
            parsed,
            vec![Address::repeat_byte(0x11), Address::repeat_byte(0x22)]
        );
    }

    #[test]
    fn parse_addr_list_rejects_a_malformed_address() {
        assert!(parse_addr_list("not-an-address").is_err());
    }

    #[test]
    fn parse_addr_list_of_an_empty_string_is_empty() {
        assert_eq!(parse_addr_list("").unwrap(), Vec::<Address>::new());
    }
}
