//! Configuration, resolved once from the environment at startup — the single
//! place this service reads env (mirroring `detection`, `ingestion`,
//! `event-store`). Everything downstream takes an explicit [`Config`] so the rest
//! of the service stays pure and testable.

use anyhow::Result;
use events::primitives::Chain;

/// All runtime configuration for the simulation dispatcher (§7, Sprint 5 t1).
#[derive(Debug, Clone)]
pub struct Config {
    /// Which chain this instance dispatches for (§5 — one instance per chain). The
    /// chain is stamped onto every `SimulationJob` so the worker knows which
    /// fork/RPC to simulate against.
    pub chain: Chain,
    pub kafka: KafkaConfig,
    pub rabbitmq: RabbitConfig,
}

/// How to reach Kafka: the broker list, and the consumer group whose committed
/// offsets a restart resumes from.
#[derive(Debug, Clone)]
pub struct KafkaConfig {
    /// Comma-separated bootstrap brokers (`localhost:9092`).
    pub brokers: String,
    /// Consumer-group id — restarts resume from committed offsets.
    pub group_id: String,
}

/// How to reach RabbitMQ: the AMQP URL and the work-queue name the dispatcher
/// publishes commands to.
#[derive(Debug, Clone)]
pub struct RabbitConfig {
    /// Full AMQP URI (`amqp://user:pass@host:5672/vhost`).
    pub url: String,
    /// The `sim.jobs` work queue (§7); the routing key on the default exchange.
    pub queue: String,
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
            },
            rabbitmq: RabbitConfig {
                url: env("RABBITMQ_URL")?,
                queue: env_or("RABBITMQ_SIM_QUEUE", "sim.jobs"),
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
