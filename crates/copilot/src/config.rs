//! Configuration, resolved once from the environment at startup — the single
//! place this service reads env (§9, mirrors `notification::config`).
//! Everything downstream takes an explicit [`Config`], so the rest of the
//! service stays pure and testable.
//!
//! The LLM half is not re-declared here: `llm::LlmConfig::from_env` owns the
//! seam's own knobs (model, timeouts, retry, breaker, bulkhead, cache), and a
//! second copy of them would drift. What this crate adds is the *queue's*
//! shape, plus the one cross-check neither side can make alone —
//! [`Config::validate`] on the lease-versus-call-budget margin.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use events::primitives::Chain;
use llm::LlmConfig;
use secrecy::SecretString;
use telemetry::env::{parse_or as env_parse, required as env};

use crate::worker::{CallBudget, PoolConfig};

/// Backstop poll interval when `COPILOT_POLL_INTERVAL_SECS` is unset. The
/// consumer's wake covers this pod's own enqueues, so this only has to be
/// small enough to pick up another pod's work and expired leases promptly.
const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;

/// Default lease. Sized from [`Config::call_budget`] against the shipped LLM
/// defaults (1020s worst case) with slack, not from a round number: a lease
/// that expires mid-call lets a second pod claim a job that is still running
/// and both pay (see [`crate::worker::CallBudget`]).
const DEFAULT_LEASE_SECS: u64 = 1200;

/// Default claims per draft before it is retired as failed.
const DEFAULT_MAX_ATTEMPTS: i32 = 3;

/// Default worker concurrency — §20's "small pool". Concurrency here
/// multiplies by the replica count before it reaches a provider limit that is
/// org-wide, so the default is deliberately timid.
const DEFAULT_CONCURRENCY: usize = 2;

/// All runtime configuration for the §20.4 copilot service.
#[derive(Debug, Clone)]
pub struct Config {
    /// Postgres: the draft queue, the drafts, approval state, and the
    /// cross-pod completion cache (§14, this service's own table).
    pub database_url: SecretString,
    pub kafka: KafkaConfig,
    /// event-store's root URL — the audit stream is read over its internal
    /// HTTP API, never by joining its store (§14).
    pub event_store_url: String,
    /// Per-request timeout for that read.
    pub event_store_timeout: Duration,
    /// The LLM seam's own configuration.
    pub llm: LlmConfig,
    /// Chain stamped on the `UsageRecorded` facts the metering decorator
    /// publishes. The copilot is not per-chain — it drafts for whatever
    /// incident arrives — so this is a deployment label, not a routing key.
    pub chain: Chain,
    pub pool: PoolConfig,
    /// Address the Prometheus `/metrics` endpoint binds to (§19).
    pub metrics_addr: SocketAddr,
}

/// How to reach Kafka.
#[derive(Debug, Clone)]
pub struct KafkaConfig {
    /// Comma-separated bootstrap brokers (`localhost:9092`).
    pub brokers: String,
    /// Consumer-group id — its own group, so offsets advance independently of
    /// every other consumer on the backbone.
    pub group_id: String,
}

impl Config {
    /// Resolve from the environment, erroring on anything missing or
    /// malformed (fail fast at boot rather than at the first incident).
    pub fn from_env() -> Result<Self> {
        let llm = LlmConfig::from_env().context("reading the LLM seam's configuration")?;
        let config = Self {
            database_url: SecretString::from(env("DATABASE_URL")?),
            kafka: KafkaConfig {
                brokers: env("KAFKA_BROKERS")?,
                group_id: env_parse("COPILOT_KAFKA_GROUP", "copilot".to_owned())?,
            },
            event_store_url: env("COPILOT_EVENT_STORE_URL")?,
            event_store_timeout: Duration::from_secs(env_parse(
                "COPILOT_EVENT_STORE_TIMEOUT_SECS",
                crate::audit::DEFAULT_REQUEST_TIMEOUT.as_secs(),
            )?),
            chain: Chain(env_parse("COPILOT_CHAIN", Chain::ETHEREUM.0)?),
            pool: PoolConfig {
                concurrency: env_parse("COPILOT_WORKER_CONCURRENCY", DEFAULT_CONCURRENCY)?.max(1),
                poll_interval: Duration::from_secs(
                    env_parse("COPILOT_POLL_INTERVAL_SECS", DEFAULT_POLL_INTERVAL_SECS)?.max(1),
                ),
                lease: Duration::from_secs(env_parse("COPILOT_LEASE_SECS", DEFAULT_LEASE_SECS)?),
                max_attempts: env_parse("COPILOT_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS)?.max(1),
                max_audit_events: env_parse(
                    "COPILOT_MAX_AUDIT_EVENTS",
                    crate::audit::DEFAULT_MAX_EVENTS,
                )?
                .max(1),
            },
            metrics_addr: env_parse(
                "COPILOT_METRICS_ADDR",
                SocketAddr::from(([0, 0, 0, 0], 9113)),
            )?,
            llm,
        };
        config.validate()?;
        Ok(config)
    }

    /// The wall-clock one claimed job can occupy, assembled from the knobs
    /// two different crates own — which is exactly why it lives here: neither
    /// `llm` (which knows its retry budget but not that a lease exists) nor
    /// `worker` (which knows about leases but reads no env) can compute it
    /// alone.
    pub fn call_budget(&self) -> CallBudget {
        // A full audit read is bounded by its per-request timeout times the
        // pages the ceiling allows, since the reader follows cursors to
        // exhaustion.
        let pages = self
            .pool
            .max_audit_events
            .div_ceil(crate::audit::DEFAULT_PAGE_SIZE as usize)
            .max(1);
        CallBudget {
            audit: self
                .event_store_timeout
                .saturating_mul(u32::try_from(pages).unwrap_or(u32::MAX)),
            attempts: self.llm.max_attempts,
            timeout: self.llm.timeout,
            // The seam sleeps *between* attempts, and that sleep is bounded
            // by whichever of the two ceilings is larger.
            gap: self.llm.retry_backoff_max.max(self.llm.retry_after_cap),
        }
    }

    /// The one cross-cutting check: a lease must outlast the worst-case job.
    /// A shorter lease lets a second pod reclaim a job that is still running,
    /// and both pay for the same narrative — a failure that shows up as a
    /// doubled bill and two documents, never as an error.
    pub fn validate(&self) -> Result<()> {
        let budget = self.call_budget();
        anyhow::ensure!(
            crate::worker::lease_covers_call(self.pool.lease, budget),
            "COPILOT_LEASE_SECS ({}s) is shorter than the worst-case job ({}s = {}s reading \
             the audit stream + {} attempts x {}s + {} backoff gaps x {}s) — a lease that \
             expires mid-call lets a second pod reclaim the job and pay for the same draft \
             twice. Raise COPILOT_LEASE_SECS, or lower LLM_MAX_ATTEMPTS / LLM_TIMEOUT_SECS / \
             LLM_RETRY_BACKOFF_MAX_MS / LLM_RETRY_AFTER_CAP_SECS / COPILOT_MAX_AUDIT_EVENTS.",
            self.pool.lease.as_secs(),
            budget.worst_case().as_secs(),
            budget.audit.as_secs(),
            budget.attempts,
            budget.timeout.as_secs(),
            budget.attempts.saturating_sub(1),
            budget.gap.as_secs(),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(lease: Duration, timeout: Duration, attempts: u32) -> Config {
        let mut llm = LlmConfig::for_test("http://localhost:0");
        llm.timeout = timeout;
        llm.max_attempts = attempts;
        llm.retry_backoff_max = Duration::from_secs(30);
        llm.retry_after_cap = Duration::from_secs(30);
        Config {
            database_url: SecretString::from("postgres://test"),
            kafka: KafkaConfig {
                brokers: "localhost:9092".into(),
                group_id: "copilot".into(),
            },
            event_store_url: "http://event-store:8080".into(),
            event_store_timeout: Duration::from_secs(30),
            llm,
            chain: Chain::ETHEREUM,
            pool: PoolConfig {
                lease,
                ..PoolConfig::default()
            },
            metrics_addr: SocketAddr::from(([0, 0, 0, 0], 9113)),
        }
    }

    #[test]
    fn a_lease_that_cannot_cover_a_call_is_refused_at_boot() {
        let err = config(Duration::from_secs(60), Duration::from_secs(300), 3)
            .validate()
            .expect_err("must refuse");
        assert!(err.to_string().contains("COPILOT_LEASE_SECS"), "{err}");
    }

    #[test]
    fn the_default_lease_covers_the_default_call_budget() {
        // Guards the shipped numbers against each other: this is the test
        // that would have caught the original 900s lease, which was 60s
        // short of the real worst case because it counted only
        // `attempts x timeout` and not the sleeps between attempts.
        config(
            Duration::from_secs(DEFAULT_LEASE_SECS),
            Duration::from_secs(300),
            3,
        )
        .validate()
        .expect("the shipped defaults are self-consistent");
    }

    #[test]
    fn the_budget_counts_every_hop_the_lease_has_to_cover() {
        let budget = config(
            Duration::from_secs(DEFAULT_LEASE_SECS),
            Duration::from_secs(300),
            3,
        )
        .call_budget();
        assert_eq!(budget.audit, Duration::from_secs(60), "2 pages x 30s");
        assert_eq!(budget.gap, Duration::from_secs(30));
        assert_eq!(budget.worst_case(), Duration::from_secs(1020));
    }
}
