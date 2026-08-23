//! Configuration, resolved once from the environment at startup — mirrors
//! `predictive::config`'s shape and its `env`/`env_parse` helpers.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::TimeDelta;
use events::primitives::Chain;

use crate::buffer::DEFAULT_CANDIDATE_LEG_CAPACITY;
use crate::changelog::{
    DEFAULT_REPLAY_TIMEOUT, DEFAULT_RETENTION_MS as DEFAULT_CHANGELOG_RETENTION_MS,
};
use crate::finality::{DEFAULT_FINDING_CAPACITY, DEFAULT_FINDING_RETENTION_SECS};
use crate::finding_changelog::{
    DEFAULT_FINDING_CHANGELOG_RETENTION_MS,
    DEFAULT_REPLAY_TIMEOUT as DEFAULT_FINDING_CHANGELOG_REPLAY_TIMEOUT,
};
use crate::leg::BridgeOrPair;

/// Default per-bridge/pair window: how long an unmatched candidate leg stays
/// buffered before aging out (§24). Generous relative to typical bridge
/// finality/fill times, small enough that a real attack's two legs (minutes
/// apart, not hours) are still both in-window when task 2's join runs.
const DEFAULT_LEG_WINDOW_SECS: i64 = 600;

/// Default bound on a correlation actor's inbound channel (§17 backpressure).
const DEFAULT_ACTOR_CHANNEL_CAPACITY: usize = 1024;

/// Default bound on [`Config`]'s per-chain redelivery dedup set (production
/// hardening) — generous relative to any sane `DetectorTriggered` rate over
/// the redelivery windows Kafka at-least-once semantics actually produce
/// (a rebalance/crash-restart replaying a recent, not day-old, span of
/// offsets), mirrors `predictive::main::SeenTxs`'s dedup capacity role.
const DEFAULT_DEDUP_CAPACITY: usize = 100_000;

/// All runtime configuration for the cross-chain correlator.
#[derive(Debug, Clone)]
pub struct Config {
    /// The chains this instance correlates across — §24's whole premise
    /// needs at least two, but a single-chain roster is accepted (and
    /// logged) rather than a boot error, so a partial rollout (one chain
    /// live, more to come) still boots and correlates nothing rather than
    /// refusing to start.
    pub chains: Vec<Chain>,
    /// The full declared bridge/pair roster (§17). When [`Self::replica_count`]
    /// is 1 (the default), every entry gets an actor on this instance. When
    /// sharded across multiple replicas, use [`Self::owned_bridges_or_pairs`]
    /// to get just this replica's share — every replica still needs the full
    /// roster in scope so it can compute ownership for legs it sees but
    /// doesn't keep. Empty means the correlator is wired but inert — no
    /// actors, every leg dropped by the router — the same "configured but
    /// empty is not a boot error" convention
    /// `predictive::config::PositionTrackerConfig::contract_addresses` uses.
    pub bridges_or_pairs: Vec<BridgeOrPair>,
    /// Detector ids whose `DetectorTriggered`s are candidate bridge-deposit
    /// legs (Sprint 17 task 2, [`crate::leg::EvidenceLegExtractor`]) —
    /// which detector spots which behaviour is a deployment fact, not
    /// something this crate hard-codes. Empty means none configured; the
    /// extractor then never recognizes a bridge-deposit leg, same
    /// "configured but empty is not a boot error" convention as
    /// [`Config::bridges_or_pairs`].
    pub bridge_deposit_detector_ids: HashSet<String>,
    /// Detector ids whose triggers are candidate large-swap legs — the fill
    /// side of a bridge match or either side of a cross-chain arb cycle.
    pub large_swap_detector_ids: HashSet<String>,
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
    /// Bound on each [`crate::chain_consumer::ChainConsumer`]'s redelivery
    /// dedup set (production hardening) — see
    /// [`crate::chain_consumer::ChainConsumer`]'s module docs for why a
    /// Kafka at-least-once redelivery needs one at all.
    pub dedup_capacity: usize,
    /// This instance's position in a horizontally-sharded bridge/pair roster
    /// (production hardening, §17) — `0`-based, must be `< replica_count`.
    /// See [`BridgeOrPair::owned_by`].
    pub replica_index: u32,
    /// Total replicas the bridge/pair roster is sharded across. `1` (the
    /// default) means no sharding: every replica — i.e. this single
    /// instance — owns every configured bridge/pair, and
    /// [`Config::consumer_group_for`] keeps its pre-sharding group-name
    /// contract so upgrading an existing single-replica deployment never
    /// resets its Kafka offsets.
    pub replica_count: u32,
    /// Retention for the leg-buffer changelog topic (`crate::changelog`,
    /// production hardening) — see that module's docs for why this is
    /// deliberately much shorter than `event_bus::dlq`'s retention default.
    pub changelog_retention_ms: i64,
    /// Deadline for the leg-buffer changelog replay at boot
    /// (`crate::changelog::replay`) before continuing with whatever warm
    /// start it managed.
    pub changelog_replay_timeout: Duration,
    /// How long [`crate::finality::FindingFinalityTracker`] retains a
    /// finding awaiting finality before its retention-window safety valve
    /// drops it (§15, Sprint 17 task 3) — see that module's "bounded memory"
    /// docs.
    pub finding_retention: TimeDelta,
    /// Hard cap on findings [`crate::finality::FindingFinalityTracker`]
    /// tracks awaiting finality (the memory-DoS backstop).
    pub finding_capacity: usize,
    /// Retention for the finding-finality changelog topic
    /// (`crate::finding_changelog`, production hardening) — must stay
    /// comfortably longer than [`Self::finding_retention`], or a restart's
    /// replay can miss the `Recorded` fact for a finding that would
    /// otherwise still legitimately be tracked (see
    /// [`crate::finding_changelog::DEFAULT_FINDING_CHANGELOG_RETENTION_MS`]'s
    /// docs); [`Self::from_env`] warns if this invariant doesn't hold.
    pub finding_changelog_retention_ms: i64,
    /// Deadline for the finding-finality changelog replay at boot
    /// (`crate::finding_changelog::replay`) before continuing with whatever
    /// warm start it managed.
    pub finding_changelog_replay_timeout: Duration,
    pub metrics_addr: SocketAddr,
}

/// How to reach Kafka — shared by every chain's consumer and the producer
/// side (findings + the leg-buffer changelog, §20).
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

        let replica_count: u32 = env_parse("CROSS_CHAIN_REPLICA_COUNT", 1u32)?.max(1);
        let replica_index: u32 = env_parse("CROSS_CHAIN_REPLICA_INDEX", 0u32)?;
        if replica_index >= replica_count {
            anyhow::bail!(
                "CROSS_CHAIN_REPLICA_INDEX ({replica_index}) must be less than \
                 CROSS_CHAIN_REPLICA_COUNT ({replica_count})"
            );
        }

        let finding_retention_secs: i64 = env_parse(
            "CROSS_CHAIN_FINDING_RETENTION_SECS",
            DEFAULT_FINDING_RETENTION_SECS,
        )?;
        let finding_changelog_retention_ms: i64 = env_parse(
            "CROSS_CHAIN_FINDING_CHANGELOG_RETENTION_MS",
            DEFAULT_FINDING_CHANGELOG_RETENTION_MS,
        )?;
        if finding_changelog_retention_ms < finding_retention_secs * 1_000 {
            tracing::warn!(
                finding_retention_secs,
                finding_changelog_retention_ms,
                "CROSS_CHAIN_FINDING_CHANGELOG_RETENTION_MS is shorter than \
                 CROSS_CHAIN_FINDING_RETENTION_SECS — a restart's changelog replay can miss \
                 the `Recorded` fact for a finding that would otherwise still legitimately be \
                 tracked; set the changelog retention comfortably longer"
            );
        }

        Ok(Self {
            chains,
            bridges_or_pairs,
            bridge_deposit_detector_ids: env_string_set("CROSS_CHAIN_BRIDGE_DEPOSIT_DETECTOR_IDS"),
            large_swap_detector_ids: env_string_set("CROSS_CHAIN_LARGE_SWAP_DETECTOR_IDS"),
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
            dedup_capacity: env_parse("CROSS_CHAIN_DEDUP_CAPACITY", DEFAULT_DEDUP_CAPACITY)?,
            replica_index,
            replica_count,
            changelog_retention_ms: env_parse(
                "CROSS_CHAIN_CHANGELOG_RETENTION_MS",
                DEFAULT_CHANGELOG_RETENTION_MS,
            )?,
            changelog_replay_timeout: Duration::from_secs(env_parse(
                "CROSS_CHAIN_CHANGELOG_REPLAY_TIMEOUT_SECS",
                DEFAULT_REPLAY_TIMEOUT.as_secs(),
            )?),
            finding_retention: TimeDelta::seconds(finding_retention_secs),
            finding_capacity: env_parse("CROSS_CHAIN_FINDING_CAPACITY", DEFAULT_FINDING_CAPACITY)?,
            finding_changelog_retention_ms,
            finding_changelog_replay_timeout: Duration::from_secs(env_parse(
                "CROSS_CHAIN_FINDING_CHANGELOG_REPLAY_TIMEOUT_SECS",
                DEFAULT_FINDING_CHANGELOG_REPLAY_TIMEOUT.as_secs(),
            )?),
            metrics_addr: env_parse("CROSS_CHAIN_METRICS_ADDR", "0.0.0.0:9114".to_string())?
                .parse()
                .context("CROSS_CHAIN_METRICS_ADDR is not a valid socket address")?,
        })
    }

    /// This replica's share of [`Self::bridges_or_pairs`] (production
    /// hardening, §17) — the roster [`crate::actor::CorrelationActor`]s
    /// actually get spawned for. With the default `replica_count = 1` this
    /// is the whole roster, unchanged from pre-sharding behaviour.
    pub fn owned_bridges_or_pairs(&self) -> Vec<BridgeOrPair> {
        self.bridges_or_pairs
            .iter()
            .filter(|b| b.owned_by(self.replica_index, self.replica_count))
            .cloned()
            .collect()
    }

    /// This chain's dedicated Kafka consumer group id — unique per chain so
    /// each chain's [`crate::chain_consumer::ChainConsumer`] is the sole
    /// member of its own group (see that module's docs for why every chain
    /// needs its own group rather than sharing one), and — once
    /// [`Self::replica_count`] is greater than 1 — unique *per replica* too,
    /// since every replica must independently see each chain's *entire*
    /// stream to compute leg ownership for itself (see
    /// [`Self::owned_bridges_or_pairs`]'s docs and the crate's top-level
    /// "Production hardening" section). The single-replica group name is
    /// deliberately left unchanged from before sharding existed: an
    /// existing deployment upgrading in place must not have its consumer
    /// group renamed out from under it, which Kafka would treat as a brand
    /// new group and reset offsets.
    pub fn consumer_group_for(&self, chain: Chain) -> String {
        if self.replica_count <= 1 {
            format!("{}-chain-{}", self.consumer_group_prefix, chain.id())
        } else {
            format!(
                "{}-r{}-chain-{}",
                self.consumer_group_prefix,
                self.replica_index,
                chain.id()
            )
        }
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

/// A comma-separated set of detector ids
/// (`CROSS_CHAIN_BRIDGE_DEPOSIT_DETECTOR_IDS=bridge-watch`); unset or empty
/// means none configured — never a boot error, mirroring
/// [`env_bridge_list`].
fn env_string_set(key: &str) -> HashSet<String> {
    std::env::var(key)
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            chains: vec![Chain::ETHEREUM, Chain::BASE],
            bridges_or_pairs: vec![],
            bridge_deposit_detector_ids: HashSet::new(),
            large_swap_detector_ids: HashSet::new(),
            kafka: KafkaConfig {
                brokers: "localhost:9092".into(),
            },
            consumer_group_prefix: "cross-chain-correlator".into(),
            leg_window: TimeDelta::seconds(DEFAULT_LEG_WINDOW_SECS),
            leg_buffer_capacity: DEFAULT_CANDIDATE_LEG_CAPACITY,
            actor_channel_capacity: DEFAULT_ACTOR_CHANNEL_CAPACITY,
            dedup_capacity: DEFAULT_DEDUP_CAPACITY,
            replica_index: 0,
            replica_count: 1,
            changelog_retention_ms: DEFAULT_CHANGELOG_RETENTION_MS,
            changelog_replay_timeout: DEFAULT_REPLAY_TIMEOUT,
            finding_retention: TimeDelta::seconds(DEFAULT_FINDING_RETENTION_SECS),
            finding_capacity: DEFAULT_FINDING_CAPACITY,
            finding_changelog_retention_ms: DEFAULT_FINDING_CHANGELOG_RETENTION_MS,
            finding_changelog_replay_timeout: DEFAULT_FINDING_CHANGELOG_REPLAY_TIMEOUT,
            metrics_addr: "0.0.0.0:9114".parse().unwrap(),
        }
    }

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
    fn env_string_set_is_empty_when_unset() {
        assert_eq!(
            env_string_set("CROSS_CHAIN_TEST_UNSET_DETECTOR_IDS"),
            HashSet::new()
        );
    }

    #[test]
    fn consumer_group_for_is_unique_per_chain() {
        let cfg = test_config();
        assert_eq!(
            cfg.consumer_group_for(Chain::ETHEREUM),
            "cross-chain-correlator-chain-1"
        );
        assert_eq!(
            cfg.consumer_group_for(Chain::BASE),
            "cross-chain-correlator-chain-8453"
        );
    }

    #[test]
    fn a_single_replica_keeps_the_pre_sharding_group_name() {
        // Upgrading an existing single-replica deployment must not rename
        // its consumer group (Kafka would treat that as a brand new group
        // and reset offsets) — see `consumer_group_for`'s docs.
        let cfg = test_config();
        assert!(!cfg.consumer_group_for(Chain::ETHEREUM).contains("-r0-"));
    }

    #[test]
    fn sharded_replicas_get_distinct_per_replica_group_names() {
        let mut a = test_config();
        a.replica_count = 3;
        a.replica_index = 0;
        let mut b = test_config();
        b.replica_count = 3;
        b.replica_index = 1;

        let group_a = a.consumer_group_for(Chain::ETHEREUM);
        let group_b = b.consumer_group_for(Chain::ETHEREUM);
        assert_ne!(group_a, group_b);
        assert!(group_a.contains("-r0-"));
        assert!(group_b.contains("-r1-"));
    }

    #[test]
    fn owned_bridges_or_pairs_is_the_whole_roster_at_replica_count_one() {
        let mut cfg = test_config();
        cfg.bridges_or_pairs = vec![
            BridgeOrPair("a".into()),
            BridgeOrPair("b".into()),
            BridgeOrPair("c".into()),
        ];
        assert_eq!(cfg.owned_bridges_or_pairs(), cfg.bridges_or_pairs);
    }

    #[test]
    fn owned_bridges_or_pairs_partitions_the_roster_across_replicas() {
        let roster: Vec<BridgeOrPair> =
            (0..20).map(|i| BridgeOrPair(format!("pair-{i}"))).collect();
        let replica_count = 4;
        let mut union = Vec::new();
        for replica_index in 0..replica_count {
            let mut cfg = test_config();
            cfg.bridges_or_pairs = roster.clone();
            cfg.replica_count = replica_count;
            cfg.replica_index = replica_index;
            union.extend(cfg.owned_bridges_or_pairs());
        }
        union.sort();
        let mut expected = roster.clone();
        expected.sort();
        assert_eq!(
            union, expected,
            "every bridge/pair must be owned exactly once"
        );
    }
}
