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

use crate::backfill::BackfillConfig;
use crate::grounding::{GroundingPolicy, DEFAULT_MIN_CITED_RATIO};
use crate::grounding_audit::{DEFAULT_CONCURRENCY as DEFAULT_AUDIT_CONCURRENCY, MAX_CONCURRENCY};
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

/// Default lease for a draft handed to the Batch API. Longer than the API's
/// own 24-hour deadline, because the lease has to cover the job *and* the poll
/// that lands its results.
const DEFAULT_BATCH_LEASE_SECS: u64 = 25 * 60 * 60;

/// Default gap between batch status polls. Minutes, not seconds: a batch takes
/// an hour or more, and polling it faster spends rate limit on nothing.
const DEFAULT_BATCH_POLL_SECS: u64 = 60;

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
    /// How strictly a landed narrative is held to its citations (§20.4).
    pub grounding: GroundingPolicy,
    /// The Batch API backfill's pacing (the `backfill` subcommand).
    pub backfill: BackfillConfig,
    /// Audit-stream reads the `audit` sweep keeps in flight (§20.4 t5).
    ///
    /// Deployment shape, so it is resolved here and not from a CLI flag: the
    /// CronJob that actually runs the sweep passes `args: ["audit"]` and
    /// configures everything else through the environment. The sweep's *scope*
    /// (`--since`, `--limit`) stays on the command line, because that is a
    /// property of one run rather than of the deployment.
    pub audit_concurrency: usize,
    /// Address the Prometheus `/metrics` endpoint binds to (§19).
    pub metrics_addr: SocketAddr,
    /// The draft review API, when a deployment serves one. `None` (the
    /// default) serves nothing — the API is opt-in the way `HEALTH_ADDR` is,
    /// so a dev run does not silently expose an approval endpoint.
    pub http: Option<HttpConfig>,
}

/// The review API's listener and its verdict gate.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub addr: SocketAddr,
    /// How a reviewer's JWT is verified (§11, the shared `auth` crate). The
    /// token's `sub` becomes the reviewer recorded on the draft, so this is
    /// what makes "who approved this narrative" an authenticated fact rather
    /// than a request field. Required whenever the API is served.
    pub jwt: auth::JwtConfig,
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
            grounding: GroundingPolicy {
                min_cited_ratio: env_parse("COPILOT_MIN_CITED_RATIO", DEFAULT_MIN_CITED_RATIO)?,
                // Not configurable, deliberately: a citation that does not
                // resolve is a fabricated reference, and there is no
                // deployment for which accepting one is the right answer.
                reject_unknown: true,
                enforced: env_parse("COPILOT_REQUIRE_GROUNDING", true)?,
            },
            backfill: BackfillConfig {
                batch_size: env_parse("COPILOT_BATCH_SIZE", crate::backfill::DEFAULT_BATCH_SIZE)?
                    .max(1),
                lease: Duration::from_secs(env_parse(
                    "COPILOT_BATCH_LEASE_SECS",
                    DEFAULT_BATCH_LEASE_SECS,
                )?),
                poll_interval: Duration::from_secs(
                    env_parse("COPILOT_BATCH_POLL_SECS", DEFAULT_BATCH_POLL_SECS)?.max(1),
                ),
                max_attempts: env_parse("COPILOT_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS)?.max(1),
                max_audit_events: env_parse(
                    "COPILOT_MAX_AUDIT_EVENTS",
                    crate::audit::DEFAULT_MAX_EVENTS,
                )?
                .max(1),
                page_size: env_parse(
                    "COPILOT_BACKFILL_PAGE_SIZE",
                    crate::backfill::DEFAULT_PAGE_SIZE,
                )?
                .max(1),
            },
            audit_concurrency: env_parse("COPILOT_AUDIT_CONCURRENCY", DEFAULT_AUDIT_CONCURRENCY)?,
            metrics_addr: env_parse(
                "COPILOT_METRICS_ADDR",
                SocketAddr::from(([0, 0, 0, 0], 9113)),
            )?,
            http: http_from_env()?,
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

    /// The review API's state, if this deployment serves one.
    pub fn http(&self) -> Option<&HttpConfig> {
        self.http.as_ref()
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
        anyhow::ensure!(
            (0.0..=1.0).contains(&self.grounding.min_cited_ratio),
            "COPILOT_MIN_CITED_RATIO ({}) must be a share between 0 and 1",
            self.grounding.min_cited_ratio,
        );
        anyhow::ensure!(
            (1..=MAX_CONCURRENCY).contains(&self.audit_concurrency),
            "COPILOT_AUDIT_CONCURRENCY ({}) must be between 1 and {MAX_CONCURRENCY} — it is a \
             bulkhead on event-store's read path, not a throughput dial, and 0 would leave the \
             audit hanging on a stream that never yields",
            self.audit_concurrency,
        );
        // The Batch API's own deadline is 24 hours. A lease that expires
        // before it lets a second run claim a draft the provider is still
        // working on, and the platform pays for both.
        anyhow::ensure!(
            self.backfill.lease >= Duration::from_secs(24 * 60 * 60),
            "COPILOT_BATCH_LEASE_SECS ({}s) is shorter than the Batch API's own 24h deadline — \
             a backfill draft whose lease expires while the batch is still running would be \
             claimed and submitted a second time, paying twice for one narrative",
            self.backfill.lease.as_secs(),
        );
        Ok(())
    }
}

/// The review API's config, or `None` when `COPILOT_HTTP_ADDR` is unset.
///
/// The token is required the moment the address is set — fail at boot rather
/// than serve an ungated approval endpoint.
fn http_from_env() -> Result<Option<HttpConfig>> {
    let Some(addr) = std::env::var("COPILOT_HTTP_ADDR")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(None);
    };
    let addr: SocketAddr = addr
        .parse()
        .with_context(|| format!("env var COPILOT_HTTP_ADDR ({addr})"))?;
    let secret = env("JWT_SECRET").context(
        "COPILOT_HTTP_ADDR is set, so JWT_SECRET/JWT_ISSUER are required — the approve/reject \
         routes are what let a machine-written SAR narrative leave the platform (§20.4), and \
         the token's subject is the reviewer recorded against that decision. They are not \
         served unauthenticated",
    )?;
    let issuer =
        env("JWT_ISSUER").context("COPILOT_HTTP_ADDR is set, so JWT_ISSUER is required")?;
    Ok(Some(HttpConfig {
        addr,
        jwt: auth::JwtConfig {
            secret: SecretString::from(secret),
            issuer,
        },
    }))
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
            grounding: GroundingPolicy::default(),
            backfill: BackfillConfig::default(),
            audit_concurrency: DEFAULT_AUDIT_CONCURRENCY,
            metrics_addr: SocketAddr::from(([0, 0, 0, 0], 9113)),
            http: None,
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

    /// The batch lease has to outlast the provider's own deadline, or a
    /// running job is claimed and submitted twice.
    #[test]
    fn a_batch_lease_shorter_than_the_api_deadline_is_refused_at_boot() {
        let mut config = config(
            Duration::from_secs(DEFAULT_LEASE_SECS),
            Duration::from_secs(300),
            3,
        );
        config.backfill.lease = Duration::from_secs(60 * 60);
        let err = config.validate().expect_err("must refuse");
        assert!(
            err.to_string().contains("COPILOT_BATCH_LEASE_SECS"),
            "{err}"
        );

        config.backfill.lease = Duration::from_secs(DEFAULT_BATCH_LEASE_SECS);
        config.validate().expect("the shipped default covers it");
    }

    /// The bulkhead is a bounded range, both ends: `0` is a sweep that hangs,
    /// and a fat-fingered large value is event-store falling over.
    #[test]
    fn an_out_of_range_audit_concurrency_is_refused_at_boot() {
        let mut config = config(
            Duration::from_secs(DEFAULT_LEASE_SECS),
            Duration::from_secs(300),
            3,
        );
        for bad in [0, MAX_CONCURRENCY + 1] {
            config.audit_concurrency = bad;
            let err = config.validate().expect_err("must refuse {bad}");
            assert!(
                err.to_string().contains("COPILOT_AUDIT_CONCURRENCY"),
                "{err}"
            );
        }
        config.audit_concurrency = DEFAULT_AUDIT_CONCURRENCY;
        config.validate().expect("the shipped default is in range");
    }

    #[test]
    fn a_nonsensical_grounding_threshold_is_refused_at_boot() {
        let mut config = config(
            Duration::from_secs(DEFAULT_LEASE_SECS),
            Duration::from_secs(300),
            3,
        );
        config.grounding.min_cited_ratio = 1.5;
        let err = config.validate().expect_err("must refuse");
        assert!(err.to_string().contains("COPILOT_MIN_CITED_RATIO"), "{err}");
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
