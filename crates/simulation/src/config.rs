//! Configuration, resolved once from the environment at startup — the single
//! place this service reads env (mirroring `detection`, `ingestion`,
//! `event-store`). Everything downstream takes an explicit [`Config`] so the rest
//! of the service stays pure and testable.

use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroUsize};
use std::time::Duration;

use anyhow::{Context, Result};
use events::primitives::Chain;
use secrecy::SecretString;

use crate::result::EthUsdPrice;
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
    /// Address the `simulation` dispatcher's Prometheus `/metrics` endpoint binds
    /// to (§19). Defaults to `0.0.0.0:9105` — distinct from `worker_metrics_addr`
    /// so both binaries can run on one host in local dev without colliding.
    pub metrics_addr: SocketAddr,
    /// Address the `simulation-worker` binary's Prometheus `/metrics` endpoint
    /// binds to (§19 — simulation confirmation rate, job latency). Defaults to
    /// `0.0.0.0:9106`.
    pub worker_metrics_addr: SocketAddr,
}

/// Tuning for the revm worker pool (§7, §17). Competing-consumer concurrency
/// (`workers` × `prefetch`), the rayon pool size revm runs on, and the confirmation
/// threshold.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Competing consumers × their prefetch window: the replica's backpressure
    /// bound, and the autoscaler's per-replica unit.
    pub capacity: JobCapacity,
    /// Wall-clock budget for one job's resolve + simulate. Past it the job is
    /// requeued (a transient outcome: wall time depends on load). The pod's
    /// termination grace period is derived from it (`tests/grace_period.rs`).
    pub job_deadline: Duration,
    /// rayon pool threads revm runs on. `0` = rayon's default (one per core) — the
    /// usual choice, since revm CPU is the bottleneck §20 scales hardest.
    pub pool_threads: usize,
    /// Minimum attacker profit to *confirm* an alert into an incident; below it the
    /// simulation retracts. A validated newtype so a bad threshold fails at boot.
    pub min_profit: MinProfit,
    /// ETH→USD reference price for restamping a confirmed incident's scoring
    /// triple onto the USD bands (§7 — see [`crate::result`]). A coarse operator
    /// knob (a real price feed is deferred), validated so a bad price fails at boot.
    pub eth_usd_price: EthUsdPrice,
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
    /// `x-max-length-bytes` on `sim.jobs`, with `x-overflow: reject-publish`. At
    /// the bound the broker nacks the dispatcher's publish, the dispatcher leaves
    /// the alert uncommitted on Kafka, and the backlog lands in Kafka lag (durable,
    /// replayable, already alerting) instead of broker memory. Queue arguments are
    /// immutable: changing this on a live broker fails the declaration at boot
    /// (topology drift is refused loudly, see [`crate::topology`]).
    pub max_length_bytes: u64,
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
    /// Secret — the URL embeds the password, so `Debug` redacts it and the use
    /// site must `expose_secret()` (same treatment as the ClickHouse password).
    pub postgres_url: SecretString,
    /// ClickHouse connection for the append-only analytics projection (§14).
    pub clickhouse: ClickhouseConfig,
    /// Address the internal `GET /v1/incidents` read API (§11) binds to.
    pub http_addr: SocketAddr,
    /// Address the Prometheus `/metrics` endpoint binds to (§19). Defaults to
    /// `0.0.0.0:9111`.
    pub metrics_addr: SocketAddr,
    /// How often the scheduled §25 exposure-report push (`crate::exposure_report`,
    /// Sprint 15 t5) cycles over every opted-in monitored wallet. Defaults to
    /// 24h — a customer's report cadence, not a tuning knob operators need to
    /// touch often, so a coarse env override is enough.
    pub exposure_report_interval: Duration,
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
        let http_addr = format!(
            "{}:{}",
            env("SIMULATION_PROJECTION_HTTP_HOST")?,
            env("SIMULATION_PROJECTION_HTTP_PORT")?
        )
        .parse()
        .context(
            "SIMULATION_PROJECTION_HTTP_HOST:SIMULATION_PROJECTION_HTTP_PORT is not a valid socket address",
        )?;

        Ok(Self {
            kafka_brokers: env("KAFKA_BROKERS")?,
            group_id: env_or("SIMULATION_PROJECTION_KAFKA_GROUP", "simulation-projection"),
            postgres_url: SecretString::from(env("DATABASE_URL")?),
            clickhouse: ClickhouseConfig {
                url: env("CLICKHOUSE_HTTP_URL")?,
                user: env("CLICKHOUSE_USER")?,
                password: SecretString::from(env("CLICKHOUSE_PASSWORD")?),
                database: env("CLICKHOUSE_DB")?,
            },
            http_addr,
            metrics_addr: env_parse(
                "SIMULATION_PROJECTION_METRICS_ADDR",
                SocketAddr::from(([0, 0, 0, 0], 9111)),
            )?,
            exposure_report_interval: Duration::from_secs(env_parse(
                "EXPOSURE_REPORT_INTERVAL_SECS",
                86_400u64,
            )?),
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
                max_length_bytes: max_length_bytes(env_parse(
                    "RABBITMQ_SIM_MAX_LENGTH_BYTES",
                    DEFAULT_SIM_MAX_LENGTH_BYTES,
                )?)?,
            },
            worker: WorkerConfig {
                capacity: JobCapacity::try_new(
                    env_parse("SIMULATION_WORKERS", 4usize)?,
                    env_parse("RABBITMQ_PREFETCH", 16u16)?,
                )?,
                job_deadline: job_deadline(env_parse(
                    "SIMULATION_JOB_DEADLINE_SECS",
                    crate::worker::DEFAULT_JOB_DEADLINE.as_secs(),
                )?)?,
                pool_threads: env_parse("SIMULATION_POOL_THREADS", 0usize)?,
                min_profit: MinProfit::try_new(env_parse("SIMULATION_MIN_PROFIT_ETH", 0.05f64)?)
                    .context("SIMULATION_MIN_PROFIT_ETH")?,
                eth_usd_price: EthUsdPrice::try_new(env_parse(
                    "SIMULATION_ETH_USD_PRICE",
                    3_000.0f64,
                )?)
                .context("SIMULATION_ETH_USD_PRICE")?,
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
            metrics_addr: env_parse(
                "SIMULATION_METRICS_ADDR",
                SocketAddr::from(([0, 0, 0, 0], 9105)),
            )?,
            worker_metrics_addr: env_parse(
                "SIMULATION_WORKER_METRICS_ADDR",
                SocketAddr::from(([0, 0, 0, 0], 9106)),
            )?,
        })
    }
}

/// Jobs one worker replica holds at once: `workers` competing consumers, each
/// with a `prefetch` window of unacked jobs.
///
/// One value for two readers by construction. The consumer's `basic_qos` reads
/// [`prefetch`](Self::prefetch), and the autoscaler's unit
/// (`simulation_worker_job_capacity`) reads [`jobs`](Self::jobs); neither can
/// be retuned without the other following.
///
/// Zero in either factor is refused at boot, because both zeros fail silently
/// somewhere else. A prefetch of 0 is AMQP for *unlimited*: a consumer that
/// takes the whole queue into memory. A capacity of 0 makes the autoscaling rule
/// divide by zero, +Inf demand, and the HPA jumps to maxReplicas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobCapacity {
    workers: NonZeroUsize,
    prefetch: NonZeroU16,
}

impl JobCapacity {
    pub fn try_new(workers: usize, prefetch: u16) -> Result<Self> {
        let workers = NonZeroUsize::new(workers).context(
            "SIMULATION_WORKERS must be >= 1: a replica with no consumers holds nothing",
        )?;
        let prefetch = NonZeroU16::new(prefetch).context(
            "RABBITMQ_PREFETCH must be >= 1: a prefetch of 0 is AMQP for unlimited, \
             which lets one consumer take the whole queue",
        )?;
        workers
            .get()
            .checked_mul(usize::from(prefetch.get()))
            .context("SIMULATION_WORKERS x RABBITMQ_PREFETCH overflows")?;
        Ok(Self { workers, prefetch })
    }

    /// In-process competing consumers. Horizontal scale is more replicas (§20).
    pub fn workers(self) -> usize {
        self.workers.get()
    }

    /// Unacked jobs each consumer holds (`basic_qos`).
    pub fn prefetch(self) -> u16 {
        self.prefetch.get()
    }

    /// Jobs the replica holds in total. Never zero.
    pub fn jobs(self) -> usize {
        self.workers.get() * usize::from(self.prefetch.get())
    }
}

/// `sim.jobs` byte bound when `RABBITMQ_SIM_MAX_LENGTH_BYTES` is unset: 100 MiB.
///
/// Sized so the work queue can never be what trips the broker's memory alarm,
/// which blocks every publisher on the node, not just this one. The broker pod
/// is limited to 1 GiB (`deploy/k8s/base/infra/rabbitmq.yaml`), and 100 MiB is a
/// small fraction of that. A `SimulationJob` body is a few hundred bytes, so
/// the bound is on the order of 250k jobs: hundreds of times the whole worker
/// pool's in-flight capacity at maxReplicas, so it is reached only when the
/// autoscaler is already pinned.
pub const DEFAULT_SIM_MAX_LENGTH_BYTES: u64 = 100 * 1024 * 1024;

fn max_length_bytes(bytes: u64) -> Result<u64> {
    anyhow::ensure!(
        bytes > 0,
        "RABBITMQ_SIM_MAX_LENGTH_BYTES must be >= 1: 0 would reject every job"
    );
    Ok(bytes)
}

fn job_deadline(secs: u64) -> Result<Duration> {
    anyhow::ensure!(
        secs > 0,
        "SIMULATION_JOB_DEADLINE_SECS must be >= 1: 0 would requeue every job"
    );
    Ok(Duration::from_secs(secs))
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
mod job_capacity_tests {
    use super::*;

    #[test]
    fn capacity_is_workers_times_prefetch() {
        let c = JobCapacity::try_new(4, 16).unwrap();
        assert_eq!((c.workers(), c.prefetch(), c.jobs()), (4, 16, 64));
    }

    #[test]
    fn a_zero_prefetch_is_refused_because_amqp_reads_it_as_unlimited() {
        let err = JobCapacity::try_new(4, 0).unwrap_err().to_string();
        assert!(err.contains("unlimited"), "{err}");
    }

    #[test]
    fn zero_workers_is_refused() {
        assert!(JobCapacity::try_new(0, 16).is_err());
    }

    #[test]
    fn zero_bounds_are_refused() {
        assert!(max_length_bytes(0).is_err());
        assert!(job_deadline(0).is_err());
        assert_eq!(job_deadline(45).unwrap(), Duration::from_secs(45));
    }
}
