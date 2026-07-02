//! Configuration, resolved once from the environment at startup — the single
//! place this service reads env (mirroring `detection`, `ingestion`,
//! `event-store`). Everything downstream takes an explicit [`Config`] so the rest
//! of the service stays pure and testable.

use anyhow::{Context, Result};
use events::primitives::Chain;
use secrecy::SecretString;

use crate::simulator::{MinProfit, SimLimits};

/// All runtime configuration for the simulation service (§7) — shared by both
/// binaries: the `simulation` dispatcher (Sprint 5 t1) and the `simulation-worker`
/// pool (t3). Each binary reads the fields it needs.
#[derive(Debug, Clone)]
pub struct Config {
    /// Which chain this instance dispatches for (§5 — one instance per chain). The
    /// chain is stamped onto every `SimulationJob` so the worker knows which
    /// fork/RPC to simulate against.
    pub chain: Chain,
    pub kafka: KafkaConfig,
    pub rabbitmq: RabbitConfig,
    /// Worker-pool tuning — read by `simulation-worker`, ignored by the dispatcher.
    pub worker: WorkerConfig,
}

/// Tuning for the revm worker pool (§7, §17). Competing-consumer concurrency
/// (`workers` × `prefetch`), the rayon pool size revm runs on, and the confirmation
/// threshold.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Unacked jobs each consumer holds (`basic_qos` prefetch). Bounds in-flight
    /// work per consumer — the backpressure knob (§17).
    pub prefetch: u16,
    /// In-process competing consumers (each its own consume channel). Horizontal
    /// scale is more *replicas* (§20); this is per-replica concurrency.
    pub workers: usize,
    /// rayon pool threads revm runs on. `0` = rayon's default (one per core) — the
    /// usual choice, since revm CPU is the bottleneck §20 scales hardest.
    pub pool_threads: usize,
    /// Minimum attacker profit to *confirm* an alert into an incident; below it the
    /// simulation retracts. A validated newtype so a bad threshold fails at boot.
    pub min_profit: MinProfit,
    /// Gas/step caps bounding hostile honeypot bytecode in the revm engine (§7
    /// hardening).
    pub sim_limits: SimLimits,
    /// How many `(block, tx_set)` outcomes the [`CachingSimulator`](crate::cache)
    /// memoizes before FIFO-evicting. `0` disables the cache.
    pub cache_capacity: usize,
}

/// How to reach Kafka: the broker list, and the consumer group whose committed
/// offsets a restart resumes from.
#[derive(Debug, Clone)]
pub struct KafkaConfig {
    /// Comma-separated bootstrap brokers (`localhost:9092`).
    pub brokers: String,
    /// Consumer-group id for the dispatcher's `PreliminaryAlertCreated` consumer —
    /// restarts resume from committed offsets.
    pub group_id: String,
    /// Consumer-group id for the service-side reorg (retraction) consumer that reacts
    /// to `BlockReverted` by emitting `IncidentRetracted` (§15). A distinct group so it
    /// tracks the `BlockReverted` topic independently of the alert stream.
    pub reorg_group_id: String,
}

/// How to reach RabbitMQ, plus the names of the `sim.jobs` topology the dispatcher
/// declares at boot (§7, §20): the work queue, its dead-letter exchange, and the
/// dead-letter queue bound behind it.
#[derive(Debug, Clone)]
pub struct RabbitConfig {
    /// Full AMQP URI (`amqp://user:pass@host:5672/vhost`).
    pub url: String,
    /// The `sim.jobs` work queue (§7); the routing key on the default exchange.
    /// Declared as a durable **quorum** queue (replicated for HA, §20).
    pub queue: String,
    /// The dead-letter exchange `sim.jobs.dlx` (§7, §20). A job that exceeds
    /// [`delivery_limit`](Self::delivery_limit) redeliveries is routed here instead
    /// of looping forever — operators get a quarantine, not an outage.
    pub dlx: String,
    /// The queue bound behind [`dlx`](Self::dlx) where dead-lettered jobs land for
    /// inspection. Without it, dead-lettered messages would be dropped unrouted.
    pub dead_letter_queue: String,
    /// Quorum-queue redelivery cap (`x-delivery-limit`): after this many failed
    /// deliveries a job dead-letters to [`dlx`](Self::dlx). This is the native
    /// "fails N times → DLX" mechanism (§7) — a quorum-queue feature a classic
    /// queue lacks.
    pub delivery_limit: i64,
}

/// Configuration for the `simulation-projection` binary (Sprint 6 t5) — the incident/
/// job persistence consumer. Deliberately **separate** from [`Config`]: the projection
/// is a Kafka→Postgres/ClickHouse consumer and needs neither RabbitMQ nor the revm
/// worker tuning, so requiring `RABBITMQ_URL` etc. would be wrong. Each binary reads only
/// the env it needs (§ the crate's config discipline).
#[derive(Debug, Clone)]
pub struct ProjectionConfig {
    /// Comma-separated Kafka bootstrap brokers — the result-path event source.
    pub kafka_brokers: String,
    /// Consumer-group id; restarts resume from committed offsets.
    pub group_id: String,
    /// Postgres connection URL (`postgres://…`) for the mutable read model (§14).
    pub postgres_url: String,
    /// ClickHouse connection for the append-only analytics projection (§14).
    pub clickhouse: ClickhouseConfig,
}

/// How to reach ClickHouse. The `clickhouse` crate wants a credential-free base URL plus
/// user/password/database set separately, so they are kept apart (mirrors event-store).
/// The password is [`SecretString`] so `Debug` redacts it and an explicit
/// `expose_secret()` is required at the use site.
#[derive(Debug, Clone)]
pub struct ClickhouseConfig {
    /// HTTP-interface base URL, e.g. `http://127.0.0.1:8123` (no creds, no db).
    pub url: String,
    pub user: String,
    pub password: SecretString,
    pub database: String,
}

impl ProjectionConfig {
    /// Resolve from the environment, erroring on anything missing (fail fast at boot).
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            kafka_brokers: env("KAFKA_BROKERS")?,
            group_id: env_or("SIMULATION_PROJECTION_KAFKA_GROUP", "simulation-projection"),
            postgres_url: env("DATABASE_URL")?,
            clickhouse: ClickhouseConfig {
                url: env("CLICKHOUSE_HTTP_URL")?,
                user: env("CLICKHOUSE_USER")?,
                password: SecretString::from(env("CLICKHOUSE_PASSWORD")?),
                database: env("CLICKHOUSE_DB")?,
            },
        })
    }
}

impl Config {
    /// Resolve config from the process environment, erroring on anything missing or
    /// malformed (fail fast at boot rather than at first alert).
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            chain: Chain(env_parse("CHAIN_ID", 1u64)?),
            kafka: KafkaConfig {
                brokers: env("KAFKA_BROKERS")?,
                group_id: env_or("SIMULATION_KAFKA_GROUP", "simulation"),
                reorg_group_id: env_or("SIMULATION_REORG_KAFKA_GROUP", "simulation-reorg"),
            },
            rabbitmq: RabbitConfig {
                url: env("RABBITMQ_URL")?,
                queue: env_or("RABBITMQ_SIM_QUEUE", "sim.jobs"),
                dlx: env_or("RABBITMQ_SIM_DLX", "sim.jobs.dlx"),
                dead_letter_queue: env_or("RABBITMQ_SIM_DLQ", "sim.jobs.dlq"),
                delivery_limit: env_parse("RABBITMQ_SIM_DELIVERY_LIMIT", 5i64)?,
            },
            worker: WorkerConfig {
                prefetch: env_parse("RABBITMQ_PREFETCH", 16u16)?,
                workers: env_parse("SIMULATION_WORKERS", 4usize)?,
                pool_threads: env_parse("SIMULATION_POOL_THREADS", 0usize)?,
                min_profit: MinProfit::try_new(env_parse("SIMULATION_MIN_PROFIT_ETH", 0.05f64)?)
                    .context("SIMULATION_MIN_PROFIT_ETH")?,
                sim_limits: SimLimits {
                    per_tx_gas: env_parse(
                        "SIMULATION_PER_TX_GAS",
                        SimLimits::default().per_tx_gas,
                    )?,
                    bundle_gas_budget: env_parse(
                        "SIMULATION_BUNDLE_GAS_BUDGET",
                        SimLimits::default().bundle_gas_budget,
                    )?,
                },
                cache_capacity: env_parse("SIMULATION_CACHE_CAPACITY", 1024usize)?,
            },
        })
    }
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
