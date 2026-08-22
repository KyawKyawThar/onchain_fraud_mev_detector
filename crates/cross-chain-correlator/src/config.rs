//! Configuration, resolved once from the environment at startup — mirrors
//! `predictive::config`'s shape and its `env`/`env_parse` helpers.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use chrono::TimeDelta;
use events::primitives::Chain;

use crate::buffer::DEFAULT_CANDIDATE_LEG_CAPACITY;
use crate::leg::BridgeOrPair;

/// Default per-bridge/pair window: how long an unmatched candidate leg stays
/// buffered before aging out (§24). Generous relative to typical bridge
/// finality/fill times, small enough that a real attack's two legs (minutes
/// apart, not hours) are still both in-window when task 2's join runs.
const DEFAULT_LEG_WINDOW_SECS: i64 = 600;

/// Default bound on a correlation actor's inbound channel (§17 backpressure).
const DEFAULT_ACTOR_CHANNEL_CAPACITY: usize = 1024;

/// All runtime configuration for the cross-chain correlator.
#[derive(Debug, Clone)]
pub struct Config {
    /// The chains this instance correlates across — §24's whole premise
    /// needs at least two, but a single-chain roster is accepted (and
    /// logged) rather than a boot error, so a partial rollout (one chain
    /// live, more to come) still boots and correlates nothing rather than
    /// refusing to start.
    pub chains: Vec<Chain>,
    /// The bridge/pair roster: one [`crate::actor::CorrelationActor`] is
    /// spawned per entry (§17). Empty means the correlator is wired but
    /// inert — no actors, every leg dropped by the router — the same
    /// "configured but empty is not a boot error" convention
    /// `predictive::config::PositionTrackerConfig::contract_addresses` uses.
    pub bridges_or_pairs: Vec<BridgeOrPair>,
    pub kafka: KafkaConfig,
    /// Prefix for each chain's dedicated consumer group id (see
    /// [`Config::consumer_group_for`]).
    pub consumer_group_prefix: String,
    /// How long an unmatched candidate leg stays buffered (§24).
    pub leg_window: TimeDelta,
    /// Hard cap on legs retained per bridge/pair (the memory-DoS backstop,
    /// see `crate::buffer` module docs).
    pub leg_buffer_capacity: usize,
    /// Bound on a correlation actor's inbound channel (§17).
    pub actor_channel_capacity: usize,
    pub metrics_addr: SocketAddr,
}

/// How to reach Kafka — shared by every chain's consumer and the (currently
/// unused, task-2) producer side (§20).
#[derive(Debug, Clone)]
pub struct KafkaConfig {
    /// Comma-separated bootstrap brokers (`localhost:9092`).
    pub brokers: String,
}

impl Config {
    /// Resolve config from the process environment, erroring on anything
    /// missing or malformed (fail fast at boot rather than at first record).
    pub fn from_env() -> Result<Self> {
        let chains = env_chain_list("CROSS_CHAIN_CHAINS")?;
        if chains.is_empty() {
            anyhow::bail!(
                "CROSS_CHAIN_CHAINS must list at least one chain id (comma-separated) — \
                 there is nothing to correlate across zero chains"
            );
        }

        let bridges_or_pairs = env_bridge_list("CROSS_CHAIN_BRIDGES_OR_PAIRS")?;
        if bridges_or_pairs.is_empty() {
            tracing::warn!(
                "CROSS_CHAIN_BRIDGES_OR_PAIRS is unset/empty; the correlator will boot but \
                 every candidate leg will be dropped (no correlation actor configured)"
            );
        }
        if chains.len() < 2 {
            tracing::warn!(
                chains = chains.len(),
                "cross-chain correlation needs at least two chains to find anything — \
                 booting anyway with a partial roster"
            );
        }

        Ok(Self {
            chains,
            bridges_or_pairs,
            kafka: KafkaConfig {
                brokers: env("KAFKA_BROKERS")?,
            },
            consumer_group_prefix: env_parse(
                "CROSS_CHAIN_CONSUMER_GROUP_PREFIX",
                "cross-chain-correlator".to_string(),
            )?,
            leg_window: TimeDelta::seconds(env_parse(
                "CROSS_CHAIN_LEG_WINDOW_SECS",
                DEFAULT_LEG_WINDOW_SECS,
            )?),
            leg_buffer_capacity: env_parse(
                "CROSS_CHAIN_LEG_BUFFER_CAPACITY",
                DEFAULT_CANDIDATE_LEG_CAPACITY,
            )?,
            actor_channel_capacity: env_parse(
                "CROSS_CHAIN_ACTOR_CHANNEL_CAPACITY",
                DEFAULT_ACTOR_CHANNEL_CAPACITY,
            )?,
            metrics_addr: env_parse("CROSS_CHAIN_METRICS_ADDR", "0.0.0.0:9114".to_string())?
                .parse()
                .context("CROSS_CHAIN_METRICS_ADDR is not a valid socket address")?,
        })
    }

    /// This chain's dedicated Kafka consumer group id — unique per chain so
    /// each chain's [`crate::chain_consumer::ChainConsumer`] is the sole
    /// member of its own group (see that module's docs for why every chain
    /// needs its own group rather than sharing one).
    pub fn consumer_group_for(&self, chain: Chain) -> String {
        format!("{}-chain-{}", self.consumer_group_prefix, chain.id())
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

/// A comma-separated list of chain ids (`CROSS_CHAIN_CHAINS=1,8453`); unset
/// means no chains configured (`vec![]`) — [`Config::from_env`] turns that
/// into a boot error itself, so the parse stays a plain "empty is valid"
/// building block, testable without mutating process environment.
fn env_chain_list(key: &str) -> Result<Vec<Chain>> {
    match std::env::var(key) {
        Ok(raw) => parse_chain_list(&raw).with_context(|| format!("env var {key} is invalid")),
        Err(_) => Ok(Vec::new()),
    }
}

fn parse_chain_list(raw: &str) -> Result<Vec<Chain>> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<u64>()
                .map(Chain)
                .with_context(|| format!("invalid chain id: {s:?}"))
        })
        .collect()
}

/// A comma-separated list of bridge/pair identifiers
/// (`CROSS_CHAIN_BRIDGES_OR_PAIRS=usdc-eth-base,weth-eth-arb`); unset means
/// none configured (`vec![]`), not an error — see
/// [`Config::bridges_or_pairs`].
fn env_bridge_list(key: &str) -> Result<Vec<BridgeOrPair>> {
    match std::env::var(key) {
        Ok(raw) => Ok(parse_bridge_list(&raw)),
        Err(_) => Ok(Vec::new()),
    }
}

fn parse_bridge_list(raw: &str) -> Vec<BridgeOrPair> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| BridgeOrPair(s.to_owned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_parse_falls_back_to_default_when_unset() {
        assert_eq!(
            env_parse::<u64>("CROSS_CHAIN_TEST_UNSET_VAR", 7).unwrap(),
            7
        );
    }

    #[test]
    fn parse_chain_list_trims_and_skips_empty_entries() {
        assert_eq!(
            parse_chain_list(" 1 ,8453,").unwrap(),
            vec![Chain::ETHEREUM, Chain::BASE]
        );
    }

    #[test]
    fn parse_chain_list_rejects_a_non_numeric_entry() {
        assert!(parse_chain_list("1,not-a-chain-id").is_err());
    }

    #[test]
    fn parse_chain_list_of_an_empty_string_is_empty() {
        assert_eq!(parse_chain_list("").unwrap(), Vec::<Chain>::new());
    }

    #[test]
    fn parse_bridge_list_trims_and_skips_empty_entries() {
        assert_eq!(
            parse_bridge_list(" usdc-eth-base ,weth-eth-arb,"),
            vec![
                BridgeOrPair("usdc-eth-base".to_owned()),
                BridgeOrPair("weth-eth-arb".to_owned()),
            ]
        );
    }

    #[test]
    fn consumer_group_for_is_unique_per_chain() {
        let cfg = Config {
            chains: vec![Chain::ETHEREUM, Chain::BASE],
            bridges_or_pairs: vec![],
            kafka: KafkaConfig {
                brokers: "localhost:9092".into(),
            },
            consumer_group_prefix: "cross-chain-correlator".into(),
            leg_window: TimeDelta::seconds(DEFAULT_LEG_WINDOW_SECS),
            leg_buffer_capacity: DEFAULT_CANDIDATE_LEG_CAPACITY,
            actor_channel_capacity: DEFAULT_ACTOR_CHANNEL_CAPACITY,
            metrics_addr: "0.0.0.0:9114".parse().unwrap(),
        };
        assert_eq!(
            cfg.consumer_group_for(Chain::ETHEREUM),
            "cross-chain-correlator-chain-1"
        );
        assert_eq!(
            cfg.consumer_group_for(Chain::BASE),
            "cross-chain-correlator-chain-8453"
        );
    }
}
