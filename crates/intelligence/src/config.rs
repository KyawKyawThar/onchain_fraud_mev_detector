//! Configuration, resolved once from the environment at startup — the single
//! place this service reads env (mirroring `simulation`, `detection`,
//! `event-store`). Everything downstream takes an explicit [`Config`] so the
//! rest of the service stays pure and testable.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use secrecy::SecretString;
use url::Url;

use crate::production_source::RelayEndpoint;

/// All runtime configuration for the intelligence service (§8, §14): the three
/// data stores (Postgres system of record, Redis hot cache, ClickHouse
/// adjacency graph) plus the t4 attribution consumer's Kafka settings and the
/// `grpc` subcommand's bind address (§11).
#[derive(Debug, Clone)]
pub struct Config {
    /// Postgres connection URL (`postgres://…`) for labels/entities/
    /// attribution/sanctions (§14). Secret — the URL embeds the password, so
    /// `Debug` redacts it and the use site must `expose_secret()`. Migrations
    /// are applied out-of-band by sqlx-cli (`just migrate-*`), not at boot.
    pub postgres_url: SecretString,
    pub redis: RedisConfig,
    pub clickhouse: ClickhouseConfig,
    pub kafka: KafkaConfig,
    /// Address the `IntelligenceRead` gRPC server (`grpc` subcommand) binds
    /// to — read only by that run mode.
    pub grpc_addr: SocketAddr,
    /// Optional Prometheus `/metrics` bind address (`INTELLIGENCE_METRICS_ADDR`).
    /// `None` disables the exporter — the §19 counters (e.g. the block-
    /// production relay hit/miss the builder/relay dashboard renders) become
    /// no-ops. Set it in the long-running consumer run modes.
    pub metrics_addr: Option<SocketAddr>,
    /// §10 block-production pipeline settings — read only by the
    /// `block-production` run mode.
    pub block_production: BlockProductionConfig,
    /// Base bounds for the §8.2/§11 entity-graph hop query — read only by the
    /// `grpc` run mode. `max_hops` here is the per-request default; the
    /// operator-tunable knobs are `degree_cap` and `max_nodes`.
    pub graph_limits: crate::graph::GraphLimits,
    /// §20.3 behavior-embedding settings — read by the `embedding` run mode
    /// and the `embed` inspection command.
    pub embedding: EmbeddingConfig,
    /// §20.3 behavioral-similarity search settings — read only by the `grpc`
    /// run mode.
    pub similarity: SimilarityConfig,
    /// §20.3 clustering-signal settings — read by the `link-signal` run mode
    /// and the `link-candidates`/`link-decide` operator commands.
    pub link_signal: LinkSignalConfig,
}

/// Settings for the §20.3 clustering signal (Sprint 19 t3).
#[derive(Debug, Clone)]
pub struct LinkSignalConfig {
    /// Consumer-group id — its own group, like every other consumer in this
    /// service, so the signal is independently deployable and its lag is
    /// separately visible.
    pub group_id: String,
    /// Gates and bounds for the pass, including the proposal-shaping policy.
    pub policy: crate::link_signal::LinkSignalPolicy,
}

/// Settings for the §20.3 similarity search (Sprint 19 t2).
#[derive(Debug, Clone)]
pub struct SimilarityConfig {
    /// The one schema version comparisons are served under
    /// (`INTEL_SIMILARITY_VERSION`), defaulting to the roster's newest. A
    /// score only means something inside a single feature space, so cutting
    /// the read over to a v2 is this deliberate config change — never a
    /// per-request choice. An unknown version is a boot error, the same
    /// typed-miss stance `embedder_for` takes.
    pub version: Option<String>,
    /// Search bounds.
    pub limits: crate::similarity::SimilarityLimits,
    /// Population-baseline snapshot bounds (refresh cadence + the age past
    /// which a baseline is refused rather than served).
    pub baseline: crate::baseline_cache::BaselineCacheConfig,
    /// Concurrent similarity searches allowed in-process — the bulkhead that
    /// keeps this expensive read from degrading the p50-critical screening
    /// path it shares a service and a ClickHouse with. Beyond it, requests are
    /// shed (`RESOURCE_EXHAUSTED`), never queued.
    pub max_concurrent: usize,
}

/// Settings for the §20.3 behavior-embedding job (Sprint 19 t1).
#[derive(Debug, Clone)]
pub struct EmbeddingConfig {
    /// The one chain whose adjacency graph this instance embeds
    /// (`INTEL_EMBEDDING_CHAIN_ID`, default 1 = Ethereum). Observations are
    /// chain-scoped even though labels and entities are not, so a two-chain
    /// deployment runs two instances rather than one that guesses.
    pub chain: events::primitives::Chain,
    /// Consumer-group id for the invalidation consumer — its own group, like
    /// `score`/`reorg`/`block-production`, so it is independently deployable
    /// and its lag is separately visible.
    pub group_id: String,
    /// The schema versions to compute, newest-first in the roster. Empty means
    /// "the default (newest) version"; naming two is how a v2 rollout runs
    /// both side by side (`INTEL_EMBEDDING_VERSIONS`, comma-separated). An
    /// unknown version is a boot error, never a silent fallback.
    pub versions: Vec<String>,
    /// Bounds for the compute core.
    pub limits: crate::embedding_job::EmbeddingLimits,
    /// Bounds for the schedule, including this replica's keyspace shard.
    pub sweep: crate::embedding_sweep::SweepLimits,
}

/// Settings for the `block-production` consumer (§10, Sprint 11 t1).
#[derive(Debug, Clone)]
pub struct BlockProductionConfig {
    /// The one chain this pipeline attributes (`INTEL_PRODUCTION_CHAIN_ID`,
    /// default 1 = Ethereum). PBS/MEV-Boost is an Ethereum-mainnet mechanism
    /// and `rpc_url` reads exactly one chain, so events from any other chain
    /// on the shared topics (Sprint 13 t2 — e.g. Base) are commit-skipped
    /// rather than wedging the consumer on an unknown block hash.
    pub chain: events::primitives::Chain,
    /// HTTP RPC endpoint for full-block reads (`INTEL_ETH_RPC_URL`). Optional
    /// at parse time — required (checked) only when the `block-production`
    /// subcommand actually runs, so every other run mode boots without it.
    pub rpc_url: Option<Url>,
    /// The MEV-Boost relays to ask for delivered-payload bid traces
    /// (`MEV_RELAY_ENDPOINTS`, comma-separated `name=url` pairs; a bare URL
    /// names itself by host). Empty is legal — the pipeline still records
    /// header facts, with no relay attribution (§10: the relay landscape is
    /// configuration, never code).
    pub relays: Vec<RelayEndpoint>,
    /// Per-relay-call ceiling — a hung relay is skipped, not waited out.
    pub relay_timeout: Duration,
    /// Consumer-group id for the block-production consumer — its own group
    /// (like `attribute`/`score`/`reorg`), independently deployable.
    pub group_id: String,
}

/// How to reach Kafka for the `attribute` and `score` consumers (Sprint 7 t4,
/// Sprint 8 t2): the broker list, and each consumer's own group whose
/// committed offsets a restart resumes from.
#[derive(Debug, Clone)]
pub struct KafkaConfig {
    /// Comma-separated bootstrap brokers (`localhost:9092`).
    pub brokers: String,
    /// Consumer-group id for the `PreliminaryAlertCreated`/`IncidentCreated`
    /// attribution consumer — restarts resume from committed offsets.
    pub group_id: String,
    /// Consumer-group id for the risk-score cache-invalidation consumer
    /// ([`crate::risk_scorer`], §8.3) — a separate group from `group_id` since
    /// it's an independently deployable/scalable process reading a disjoint
    /// (mostly self-produced) set of topics.
    pub risk_group_id: String,
    /// Consumer-group id for the reorg-rollback consumer ([`crate::reorg`],
    /// §15) — its own group since it reads a disjoint topic
    /// (`IncidentRetracted`) and is independently deployable/scalable, like
    /// `score`/`attribute`.
    pub reorg_group_id: String,
    /// Consumer-group id for the Sprint 17 t4 cross-chain attribution
    /// consumer ([`crate::cross_chain_attribution`], §8/§24) — its own group
    /// since it reads a disjoint topic pair (`BridgeMevDetected`/
    /// `CrossChainMevDetected`) and is independently deployable/scalable,
    /// like `score`/`attribute`/`reorg`.
    pub cross_chain_group_id: String,
}

/// How to reach Redis and how long cached entries live. The full URL is secret
/// (`redis://:password@host:port/db` embeds the password), so `Debug` redacts
/// it and the use site must `expose_secret()`.
#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub url: SecretString,
    /// TTL for hot-cache entries (§8: TTL-backed, evicted on update). The TTL
    /// is the *staleness backstop* — correctness comes from explicit eviction.
    pub cache_ttl: Duration,
}

/// How to reach ClickHouse. Same split as the event store / simulation
/// projection: credential-free base URL, user/password/database separate, the
/// password behind [`SecretString`].
#[derive(Debug, Clone)]
pub struct ClickhouseConfig {
    /// HTTP-interface base URL, e.g. `http://127.0.0.1:8123` (no creds, no db).
    pub url: String,
    pub user: String,
    pub password: SecretString,
    pub database: String,
}

impl Config {
    /// Resolve from the environment, erroring on anything missing or malformed
    /// (fail fast at boot rather than at the first event).
    pub fn from_env() -> Result<Self> {
        let grpc_addr = format!(
            "{}:{}",
            env("INTELLIGENCE_GRPC_HOST")?,
            env("INTELLIGENCE_GRPC_PORT")?
        )
        .parse()
        .context("INTELLIGENCE_GRPC_HOST:INTELLIGENCE_GRPC_PORT is not a valid socket address")?;

        let metrics_addr = match std::env::var("INTELLIGENCE_METRICS_ADDR") {
            Ok(raw) => Some(
                raw.parse()
                    .context("INTELLIGENCE_METRICS_ADDR is not a valid socket address")?,
            ),
            Err(_) => None,
        };

        let defaults = crate::embedding_job::EmbeddingLimits::default();
        let sweep_defaults = crate::embedding_sweep::SweepLimits::default();
        let similarity_defaults = crate::similarity::SimilarityLimits::default();
        let baseline_defaults = crate::baseline_cache::BaselineCacheConfig::default();
        let link_defaults = crate::link_signal::LinkSignalPolicy::default();

        Ok(Self {
            postgres_url: SecretString::from(env("DATABASE_URL")?),
            redis: RedisConfig {
                url: SecretString::from(env("REDIS_URL")?),
                cache_ttl: Duration::from_secs(env_parse("INTEL_CACHE_TTL_SECS", 300u64)?),
            },
            clickhouse: ClickhouseConfig {
                url: env("CLICKHOUSE_HTTP_URL")?,
                user: env("CLICKHOUSE_USER")?,
                password: SecretString::from(env("CLICKHOUSE_PASSWORD")?),
                database: env("CLICKHOUSE_DB")?,
            },
            kafka: KafkaConfig {
                brokers: env("KAFKA_BROKERS")?,
                group_id: env_or("INTELLIGENCE_KAFKA_GROUP", "intelligence-attribution"),
                risk_group_id: env_or("INTELLIGENCE_RISK_KAFKA_GROUP", "intelligence-risk-scoring"),
                reorg_group_id: env_or("INTELLIGENCE_REORG_KAFKA_GROUP", "intelligence-reorg"),
                cross_chain_group_id: env_or(
                    "INTELLIGENCE_CROSS_CHAIN_KAFKA_GROUP",
                    "intelligence-cross-chain-attribution",
                ),
            },
            grpc_addr,
            metrics_addr,
            block_production: BlockProductionConfig {
                rpc_url: match std::env::var("INTEL_ETH_RPC_URL") {
                    Ok(raw) => Some(
                        raw.parse()
                            .context("INTEL_ETH_RPC_URL is not a valid URL")?,
                    ),
                    Err(_) => None,
                },
                chain: events::primitives::Chain(env_parse("INTEL_PRODUCTION_CHAIN_ID", 1u64)?),
                relays: parse_relay_endpoints(
                    &std::env::var("MEV_RELAY_ENDPOINTS").unwrap_or_default(),
                )?,
                relay_timeout: Duration::from_millis(env_parse("MEV_RELAY_TIMEOUT_MS", 5_000u64)?),
                group_id: env_or(
                    "INTELLIGENCE_PRODUCTION_KAFKA_GROUP",
                    "intelligence-block-production",
                ),
            },
            embedding: EmbeddingConfig {
                chain: events::primitives::Chain(env_parse("INTEL_EMBEDDING_CHAIN_ID", 1u64)?),
                group_id: env_or(
                    "INTELLIGENCE_EMBEDDING_KAFKA_GROUP",
                    "intelligence-embedding",
                ),
                versions: std::env::var("INTEL_EMBEDDING_VERSIONS")
                    .unwrap_or_default()
                    .split(',')
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(str::to_owned)
                    .collect(),
                limits: crate::embedding_job::EmbeddingLimits {
                    history_cap: env_parse("INTEL_EMBEDDING_HISTORY_CAP", defaults.history_cap)?,
                    batch_size: env_parse("INTEL_EMBEDDING_BATCH_SIZE", defaults.batch_size)?,
                    page_concurrency: env_parse(
                        "INTEL_EMBEDDING_PAGE_CONCURRENCY",
                        defaults.page_concurrency,
                    )?,
                    refresh_interval: Duration::from_secs(env_parse(
                        "INTEL_EMBEDDING_REFRESH_INTERVAL_SECS",
                        defaults.refresh_interval.as_secs(),
                    )?),
                },
                sweep: crate::embedding_sweep::SweepLimits {
                    interval: Duration::from_secs(env_parse(
                        "INTEL_EMBEDDING_SWEEP_INTERVAL_SECS",
                        sweep_defaults.interval.as_secs(),
                    )?),
                    lookback: Duration::from_secs(env_parse(
                        "INTEL_EMBEDDING_SWEEP_LOOKBACK_SECS",
                        sweep_defaults.lookback.as_secs(),
                    )?),
                    page_size: env_parse(
                        "INTEL_EMBEDDING_SWEEP_PAGE_SIZE",
                        sweep_defaults.page_size,
                    )?,
                    budget: env_parse("INTEL_EMBEDDING_SWEEP_BUDGET", sweep_defaults.budget)?,
                    // Parsed, not validated: an index at or past the total
                    // would select nothing at all, so a mistyped shard is a
                    // refused boot rather than a replica that silently embeds
                    // no addresses.
                    shard: crate::adjacency::Shard::new(
                        env_parse("INTEL_EMBEDDING_SHARD_INDEX", 0u32)?,
                        env_parse("INTEL_EMBEDDING_SHARD_TOTAL", 1u32)?,
                    )
                    .context("INTEL_EMBEDDING_SHARD_INDEX/INTEL_EMBEDDING_SHARD_TOTAL")?,
                },
            },
            similarity: SimilarityConfig {
                version: std::env::var("INTEL_SIMILARITY_VERSION")
                    .ok()
                    .map(|raw| raw.trim().to_owned())
                    .filter(|raw| !raw.is_empty()),
                limits: crate::similarity::SimilarityLimits {
                    max_results: env_parse(
                        "INTEL_SIMILARITY_MAX_RESULTS",
                        similarity_defaults.max_results,
                    )?,
                    default_results: env_parse(
                        "INTEL_SIMILARITY_DEFAULT_RESULTS",
                        similarity_defaults.default_results,
                    )?,
                    // The recall knob: stage 1 shortlists in raw cosine space
                    // and stage 2 re-ranks in standardized space, so this is
                    // how much slack a neighbour gets to survive a metric it
                    // is not scored by. Raise it if
                    // `intelligence_similarity_approximate_total` is a large
                    // share of served searches.
                    candidate_multiplier: env_parse(
                        "INTEL_SIMILARITY_CANDIDATE_MULTIPLIER",
                        similarity_defaults.candidate_multiplier,
                    )?,
                    max_candidates: env_parse(
                        "INTEL_SIMILARITY_MAX_CANDIDATES",
                        similarity_defaults.max_candidates,
                    )?,
                    // `0` disables the materialized read model — every search
                    // runs live. An explicit off switch matters: this is a
                    // cache in front of a correctness-sensitive ranking, and
                    // "turn it off" must not require a redeploy of new code.
                    cache_max_age: match env_parse(
                        "INTEL_SIMILARITY_CACHE_MAX_AGE_SECS",
                        similarity_defaults
                            .cache_max_age
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                    )? {
                        0 => None,
                        secs => Some(Duration::from_secs(secs)),
                    },
                },
                baseline: crate::baseline_cache::BaselineCacheConfig {
                    refresh_interval: Duration::from_secs(env_parse(
                        "INTEL_SIMILARITY_BASELINE_REFRESH_SECS",
                        baseline_defaults.refresh_interval.as_secs(),
                    )?),
                    max_age: Duration::from_secs(env_parse(
                        "INTEL_SIMILARITY_BASELINE_MAX_AGE_SECS",
                        baseline_defaults.max_age.as_secs(),
                    )?),
                },
                max_concurrent: env_parse("INTEL_SIMILARITY_MAX_CONCURRENT", 32usize)?,
            },
            link_signal: LinkSignalConfig {
                group_id: env_or(
                    "INTELLIGENCE_LINK_SIGNAL_KAFKA_GROUP",
                    "intelligence-link-signal",
                ),
                policy: crate::link_signal::LinkSignalPolicy {
                    // The cost gate. Off means every clustered address is
                    // searched too — the merge-candidate mode — which an
                    // operator should turn on deliberately after looking at
                    // what the default already costs.
                    scope: env_parse("INTEL_LINK_SIGNAL_SCOPE", link_defaults.scope)?,
                    neighbors: env_parse("INTEL_LINK_SIGNAL_NEIGHBORS", link_defaults.neighbors)?,
                    proposal: crate::link_candidate::SignalPolicy {
                        // Parsed as the raw scalar the operator types, then
                        // wrapped — the newtypes deliberately have no
                        // `FromStr`, so a config value can never bypass the
                        // constructor that bounds it.
                        min_similarity: crate::similarity::Similarity::new(env_parse(
                            "INTEL_LINK_MIN_SIMILARITY",
                            f64::from(link_defaults.proposal.min_similarity.get()),
                        )?),
                        max_per_subject: env_parse(
                            "INTEL_LINK_MAX_PER_SUBJECT",
                            link_defaults.proposal.max_per_subject,
                        )?,
                        // Tunable *downward* in practice: §8.1's ladder is the
                        // reason this exists, and raising it past the
                        // entity-derived 0.5 band would make a behavioral
                        // guess outrank a graph fact.
                        confidence_ceiling: events::primitives::Confidence::new(env_parse(
                            "INTEL_LINK_CONFIDENCE_CEILING",
                            link_defaults.proposal.confidence_ceiling.get(),
                        )?),
                        truncated_discount: env_parse(
                            "INTEL_LINK_TRUNCATED_DISCOUNT",
                            link_defaults.proposal.truncated_discount,
                        )?,
                    },
                },
            },
            graph_limits: crate::graph::GraphLimits {
                degree_cap: env_parse(
                    "INTELLIGENCE_GRAPH_DEGREE_CAP",
                    crate::graph::GraphLimits::default().degree_cap,
                )?,
                max_nodes: env_parse(
                    "INTELLIGENCE_GRAPH_MAX_NODES",
                    crate::graph::GraphLimits::default().max_nodes,
                )?,
                max_hops: crate::graph::GraphLimits::DEFAULT_HOPS,
            },
        })
    }
}

/// Parse `MEV_RELAY_ENDPOINTS`: comma-separated entries, each `name=url` or a
/// bare `url` (which names itself by its host). Empty input is an empty list;
/// a malformed entry is a boot error, not a silently-dropped relay.
pub fn parse_relay_endpoints(raw: &str) -> Result<Vec<RelayEndpoint>> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let (name, url_raw) = match entry.split_once('=') {
                Some((name, url_raw)) => (Some(name.trim()), url_raw.trim()),
                None => (None, entry),
            };
            let url: Url = url_raw
                .parse()
                .with_context(|| format!("MEV_RELAY_ENDPOINTS entry {entry:?}: bad URL"))?;
            let name = match name {
                Some(name) if !name.is_empty() => name.to_owned(),
                _ => url
                    .host_str()
                    .with_context(|| format!("MEV_RELAY_ENDPOINTS entry {entry:?}: URL has no host to name the relay by"))?
                    .to_owned(),
            };
            Ok(RelayEndpoint { name, url })
        })
        .collect()
}

/// Read a required env var, with the variable name in the error.
fn env(key: &str) -> Result<String> {
    std::env::var(key).map_err(|_| anyhow::anyhow!("missing required env var {key}"))
}

/// Read an optional env var, falling back to a static default.
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
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
    fn relay_endpoints_parse_named_and_bare_entries() {
        let relays = parse_relay_endpoints(
            "flashbots=https://boost-relay.flashbots.net, https://relay.ultrasound.money",
        )
        .expect("well-formed");
        assert_eq!(relays.len(), 2);
        assert_eq!(relays[0].name, "flashbots");
        assert_eq!(relays[0].url.as_str(), "https://boost-relay.flashbots.net/");
        // A bare URL names itself by host.
        assert_eq!(relays[1].name, "relay.ultrasound.money");
    }

    #[test]
    fn relay_endpoints_empty_input_is_an_empty_list() {
        assert!(parse_relay_endpoints("").expect("legal").is_empty());
        assert!(parse_relay_endpoints(" , ").expect("legal").is_empty());
    }

    #[test]
    fn relay_endpoints_reject_a_malformed_url() {
        assert!(parse_relay_endpoints("flashbots=not a url").is_err());
    }
}
