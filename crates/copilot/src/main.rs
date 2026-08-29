//! Copilot service binary (§20.4, Sprint 20 t2) — two long-running halves in
//! one process: a thin `IncidentCreated` consumer that records draft jobs, and
//! a worker pool that drains them through the LLM seam.
//!
//! Subcommands, mirroring the other service binaries:
//!   - `run` (default; also the no-arg run) — both halves above.
//!   - `ping` — probe Postgres (the copilot schema) *and* the model
//!     credential, so a misconfigured deployment fails fast and visibly.
//!
//! ## Why both halves share a process
//!
//! They are independently scalable in principle, and deliberately not split:
//! the queue is the coupling, and it is durable. A pod that runs only the
//! consumer would still need the pool's config to size its leases, and a pod
//! that runs only the pool would still need the consumer's Kafka group for
//! its DLQ. Two deployments would double the operational surface to solve a
//! problem — one half saturating before the other — that §20's "small pool"
//! sizing says will not arise.
//!
//! ## Boot is fail-fast, including the credential
//!
//! `LlmStack::build_verified` costs no tokens and turns a typo'd
//! `ANTHROPIC_API_KEY` into a refused rollout instead of a 3am surprise on
//! the first incident of the day. The prompt registry links here too
//! (link-or-fail), and the lease/call-budget margin is checked in
//! `Config::from_env`.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use copilot::audit::{AuditSource, HttpAuditSource};
use copilot::cache::PgCompletionCache;
use copilot::config::Config;
use copilot::consumer::{build_consumer, CopilotConsumer};
use copilot::draft::{DraftGenerator, NarrativeDrafter};
use copilot::store::PgDraftStore;
use copilot::worker::{DraftWorkerPool, GeneratorRegistry};
use event_bus::{EventSink, KafkaEventSink};
use llm::{LlmClient, LlmStack};
use secrecy::ExposeSecret;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

const USAGE: &str = "expected `run` (also the no-arg default) or `ping`";

/// Back-off before the consume loop retries a transiently-failed record.
const RETRY_BACKOFF: Duration = Duration::from_secs(1);

#[tokio::main]
async fn main() -> Result<()> {
    // Hold the guard for the lifetime of `main` so spans flush on exit (§19).
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env("copilot"))?;
    let cfg = Config::from_env()?;

    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("run") | None => run(&cfg).await,
        Some("ping") => ping(&cfg).await,
        Some(other) => bail!("unknown argument {other:?}; {USAGE}"),
    }
}

/// Probe both dependencies this service cannot start without.
async fn ping(cfg: &Config) -> Result<()> {
    let pool = db::connect(cfg.database_url.expose_secret()).await?;
    PgDraftStore::new(pool)
        .ping()
        .await
        .context("Postgres copilot schema probe failed")?;
    println!("ok: postgres (copilot schema) reachable");

    // The model half of the probe: a `GET /v1/models/{id}`, which costs no
    // tokens and answers the only question a deployment gets wrong quietly.
    llm::AnthropicClient::new(cfg.llm.clone())?
        .verify_credentials()
        .await
        .context("Anthropic credential/model probe failed")?;
    println!("ok: llm credential and model `{}` reachable", cfg.llm.model);
    Ok(())
}

async fn run(cfg: &Config) -> Result<()> {
    telemetry::metrics::init(cfg.metrics_addr).context("starting the metrics exporter")?;
    tracing::info!(
        schema_version = events::SCHEMA_VERSION,
        model = %cfg.llm.model,
        concurrency = cfg.pool.concurrency,
        "copilot starting"
    );

    let shutdown = CancellationToken::new();
    // K8s probes (§20): /livez immediately; /readyz flips on once boot wiring
    // completes below. Opt-in via HEALTH_ADDR — unset (dev) serves nothing.
    let health = telemetry::health::HealthState::new();
    telemetry::health::spawn_from_env(health.clone(), shutdown.clone())
        .await
        .context("starting the health endpoints")?;
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_signal().await;
            tracing::info!("shutdown signal received");
            shutdown.cancel();
        }
    });

    // ── Prompt artifacts (link-or-fail, §20.4) ─────────────────────
    let prompts = copilot::prompts::registry().context("linking the prompt artifacts")?;
    for prompt in prompts.iter() {
        tracing::info!(
            prompt = %prompt.id(),
            digest = %prompt.digest().short(),
            "prompt linked"
        );
    }

    // ── Store (fail-fast) ──────────────────────────────────────────
    // One store, handed out as four narrow views below (`copilot::store`):
    // the consumer can only enqueue, the pool can only lease and report, the
    // cache adapter can only read and land a completion. Nothing here can
    // approve a draft — that is a human's, over an API this binary does not
    // yet serve.
    let pool = db::connect(cfg.database_url.expose_secret()).await?;
    let store = Arc::new(PgDraftStore::new(pool));
    store
        .ping()
        .await
        .context("copilot schema not reachable — run `just migrate-up`?")?;

    // ── The LLM stack, with the drafts table as its cross-pod cache ─
    // `with_cache` is the seam's store-backed override (§20.4): a
    // process-local cache cannot survive the rebalance/rolling-update
    // redeliveries that actually happen here.
    let sink: Arc<dyn EventSink> =
        Arc::new(KafkaEventSink::new(&cfg.kafka.brokers).context("building the Kafka producer")?);
    let cache = Arc::new(PgCompletionCache::new(store.clone()));
    let client: Arc<dyn LlmClient> = LlmStack::new(
        cfg.llm.clone(),
        Arc::clone(&sink),
        cfg.chain,
        shutdown.clone(),
    )
    .with_cache(cache)
    .build_verified()
    .await
    .context("assembling and verifying the LLM stack")?;

    // ── The audit-stream reader (§14: an HTTP client, not a store edge) ─
    let http = reqwest::Client::builder()
        .timeout(cfg.event_store_timeout)
        .build()
        .context("building the event-store HTTP client")?;
    let audit: Arc<dyn AuditSource> =
        Arc::new(HttpAuditSource::new(http, cfg.event_store_url.clone()));

    // ── The worker pool (the slow half) ─────────────────────────────
    // Link-or-fail, and the roster is load-bearing beyond wiring: its kinds
    // become the claim filter, so this pod can only ever lease work it can
    // finish. Adding a generator here is what makes a new draft kind
    // claimable at all.
    let generators = Arc::new(
        GeneratorRegistry::link(vec![
            Arc::new(NarrativeDrafter::new()) as Arc<dyn DraftGenerator>
        ])
        .context("linking the draft generators")?,
    );
    tracing::info!(kinds = ?generators.kinds(), "draft generators linked");

    let wake = Arc::new(Notify::new());
    let pool_task = tokio::spawn(
        DraftWorkerPool::new(store.clone(), audit, client, generators, cfg.pool)
            .run(Arc::clone(&wake), shutdown.clone()),
    );

    // ── The consumer (the fast half) ────────────────────────────────
    let consumer_handle = build_consumer(&cfg.kafka.brokers, &cfg.kafka.group_id)?;
    // The uniform poison policy (§20): parked-not-lost, provisioned fail-fast.
    let dlq = event_bus::dlq::DeadLetterQueue::ensure_from_env(&cfg.kafka.brokers, "copilot")
        .await
        .context("provisioning the copilot DLQ topic")?;

    let consumer = CopilotConsumer::new(store.clone(), wake);
    health.set_ready(true);
    let result = consumer
        .run(consumer_handle, RETRY_BACKOFF, Some(&dlq), &shutdown)
        .await;

    // The pool drains in-flight calls before exiting — an answer already paid
    // for is worth the drain window (see `copilot::worker`).
    shutdown.cancel();
    if let Err(err) = pool_task.await {
        tracing::error!(error = %err, "draft worker pool task panicked");
    }
    tracing::info!("copilot shut down");
    result
}

/// Resolve when the process receives Ctrl+C or (on Unix) SIGTERM.
async fn wait_for_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
