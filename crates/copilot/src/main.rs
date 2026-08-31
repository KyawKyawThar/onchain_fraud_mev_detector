//! Copilot service binary (§20.4, Sprint 20 t2) — two long-running halves in
//! one process: a thin `IncidentCreated` consumer that records draft jobs, and
//! a worker pool that drains them through the LLM seam.
//!
//! Subcommands, mirroring the other service binaries:
//!   - `run` (default; also the no-arg run) — the consumer and the pool, plus
//!     the outbox flusher and (when `COPILOT_HTTP_ADDR` is set) the HTTP
//!     surface: the review API where a human approves a narrative, and
//!     `POST /v1/rules/draft` where a customer asks for a rule in plain
//!     English (§20.4 t4).
//!   - `backfill [--from RFC3339] [--to RFC3339]` — §20.4's historical
//!     backfill through the Batch API at half price. A job, not a service:
//!     bounded window, safe to re-run, safe to interrupt.
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
use chrono::{DateTime, Utc};
use copilot::audit::{AuditSource, HttpAuditSource, IncidentSource};
use copilot::backfill::BackfillRunner;
use copilot::cache::PgCompletionCache;
use copilot::capability::DraftCapability;
use copilot::config::{Config, HttpConfig};
use copilot::consumer::{build_consumer, CopilotConsumer};
use copilot::draft::NarrativeDrafter;
use copilot::grounding_audit::{AuditConfig, GroundingAuditor, Outcome};
use copilot::rule_draft::RuleDrafter;
use copilot::store::PgDraftStore;
use copilot::worker::{DraftWorkerPool, GeneratorRegistry};
use event_bus::{EventSink, KafkaEventSink};
use llm::batch::{AnthropicBatchClient, BatchClient, MeteredBatchClient};
use llm::{LlmClient, LlmStack};
use secrecy::ExposeSecret;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

const USAGE: &str = "expected `run` (also the no-arg default), `backfill [--from RFC3339] \
                     [--to RFC3339]`, `audit [--limit N] [--json]`, `prompts`, or `ping`";

/// How often the outbox flusher drains pending announcements.
const OUTBOX_INTERVAL: Duration = Duration::from_secs(5);

/// Facts published by the batch metering decorator carry this purpose label —
/// the same string as the draft kind and the prompt artifact's id, so a
/// backfill's spend lines up with the live path's in one query (§13).
const BACKFILL_PURPOSE: &str = "incident_narrative";

/// Back-off before the consume loop retries a transiently-failed record.
const RETRY_BACKOFF: Duration = Duration::from_secs(1);

#[tokio::main]
async fn main() -> Result<()> {
    // The scope is load-bearing: the telemetry guard flushes spans when it
    // drops, and `audit` reports its result as an **exit code**. Calling
    // `process::exit` while the guard was still alive would skip that flush,
    // so the code is carried out of the scope and the process exits after it.
    let exit_code = {
        let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env("copilot"))?;
        dispatch().await?
    };
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

/// Run the requested subcommand, returning the process exit code.
///
/// `Ok(0)` for everything except the audit sweep, whose whole purpose is to be
/// runnable by something that reads exit codes (a CronJob, a pipeline).
async fn dispatch() -> Result<i32> {
    let mut args = std::env::args().skip(1);
    let command = args.next();

    // Before the config: printing which instructions this binary carries must
    // work in a checkout, in CI and on a pod, and none of those three has the
    // same environment. `just prompt-manifest` redirects this into the
    // checked-in manifest (engineering conventions §16).
    if command.as_deref() == Some("prompts") {
        print!("{}", copilot::prompts::manifest());
        return Ok(0);
    }

    let cfg = Config::from_env()?;
    match command.as_deref() {
        Some("run") | None => run(&cfg).await.map(|()| 0),
        Some("backfill") => backfill(&cfg, args.collect()).await.map(|()| 0),
        Some("audit") => audit(&cfg, args.collect()).await,
        Some("ping") => ping(&cfg).await.map(|()| 0),
        Some(other) => bail!("unknown argument {other:?}; {USAGE}"),
    }
}

/// `copilot backfill [--from RFC3339] [--to RFC3339]` — §20.4's historical
/// narrative backfill, through the Batch API at half price.
///
/// A subcommand and not a background task inside `run`, because it is a *job*:
/// it has a window, it finishes, and an operator decides when the archive is
/// worth drafting. Running it inside the service would make an expensive,
/// bounded piece of work into an unbounded one nobody can schedule. Safe to
/// re-run and safe to interrupt — the enqueue is idempotent per incident and
/// an outstanding batch is resumed from the store rather than re-submitted
/// (see `copilot::backfill`).
async fn backfill(cfg: &Config, args: Vec<String>) -> Result<()> {
    let (from, to) = parse_window(&args)?;
    telemetry::metrics::init(cfg.metrics_addr).context("starting the metrics exporter")?;

    let shutdown = CancellationToken::new();
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_signal().await;
            tracing::info!("shutdown signal received; the running batch is left for the next run");
            shutdown.cancel();
        }
    });

    let pool = db::connect(cfg.database_url.expose_secret()).await?;
    let store = Arc::new(PgDraftStore::new(pool).with_grounding(cfg.grounding));
    store.ping().await.context("copilot schema not reachable")?;

    let sink: Arc<dyn EventSink> =
        Arc::new(KafkaEventSink::new(&cfg.kafka.brokers).context("building the Kafka producer")?);

    // Metered like every other call path (§13), against the **batch** SKUs:
    // batched tokens bill at half rate, and a fact that cannot be priced is
    // not metering.
    let batch: Arc<dyn BatchClient> = Arc::new(MeteredBatchClient::new(
        AnthropicBatchClient::new(cfg.llm.clone()).context("building the batch client")?,
        Arc::clone(&sink),
        cfg.chain,
        RETRY_BACKOFF,
        shutdown.clone(),
        BACKFILL_PURPOSE,
    ));

    let http = reqwest::Client::builder()
        .timeout(cfg.event_store_timeout)
        .build()
        .context("building the event-store HTTP client")?;
    let source = Arc::new(HttpAuditSource::new(http, cfg.event_store_url.clone()));

    let runner = BackfillRunner::new(
        store.clone(),
        store.clone(),
        Arc::clone(&source) as Arc<dyn IncidentSource>,
        Arc::clone(&source) as Arc<dyn AuditSource>,
        Arc::new(NarrativeDrafter::new()),
        batch,
        cfg.backfill,
    );

    tracing::info!(
        ?from,
        ?to,
        batch_size = cfg.backfill.batch_size,
        "backfill starting"
    );
    let report = runner.run(from, to, &shutdown).await?;
    println!(
        "backfill: scanned {} incidents, enqueued {}, submitted {} in {} batch(es), landed {}",
        report.scanned, report.enqueued, report.submitted, report.batches, report.landed
    );
    // The announcements this run produced are already durable — each landing
    // wrote its envelope into `copilot_outbox` in the same transaction. The
    // service's flusher publishes them on its next tick, on exactly the same
    // path a live draft's announcement takes.
    Ok(())
}

/// `copilot audit [--limit N] [--since RFC3339] [--max-findings N]` — the
/// §20.4 governance sweep (Sprint 20 t5).
///
/// Re-resolves every landed narrative's citations against event-store, and
/// **exits non-zero when a stored draft makes a claim that does not hold**.
/// The exit code is the deliverable: this is meant to run in a CronJob, in a
/// pipeline, or by hand before an audit, and all three read exit codes rather
/// than scraping a process that has already gone.
///
///   0 — clean: everything examined resolves.
///   1 — findings: a draft cites what the store does not have, or a row
///       disagrees with its own text, or a `ready` draft never went through the
///       citation boundary at all.
///   2 — inconclusive: drafts were examined and none could be verified (an
///       unreachable event-store, or an archive whose retention has overtaken
///       its narratives). Deliberately not 0: an audit that proved nothing must
///       not exit like one that proved everything.
async fn audit(cfg: &Config, args: Vec<String>) -> Result<i32> {
    let options = parse_audit_options(&args)?;

    let shutdown = CancellationToken::new();
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_signal().await;
            tracing::info!("shutdown signal received; the audit will report what it has");
            shutdown.cancel();
        }
    });

    let pool = db::connect(cfg.database_url.expose_secret()).await?;
    // No `.with_grounding` here, deliberately: that policy configures the
    // *landing* write path, and this sweep only reads. Passing it would read
    // as though the audit re-applies the cited-ratio threshold, which it does
    // not — it checks whether citations resolve, which is a different question
    // and is not configurable.
    let store = Arc::new(PgDraftStore::new(pool));
    store.ping().await.context("copilot schema not reachable")?;

    let http = reqwest::Client::builder()
        .timeout(cfg.event_store_timeout)
        .build()
        .context("building the event-store HTTP client")?;
    let events = Arc::new(HttpAuditSource::new(http, cfg.event_store_url.clone()));

    let config = AuditConfig {
        max_audit_events: cfg.pool.max_audit_events,
        concurrency: cfg.audit_concurrency,
        ..options
    };
    let report = GroundingAuditor::new(store, events, config)
        .run(&shutdown)
        .await
        .context("the grounding audit could not read the draft store")?;

    println!("{report}");
    // An exit code rather than an `Err`: these are *results*, not failures of
    // the command, and rendering a finding as an anyhow chain would bury the
    // report under a backtrace-shaped error message.
    Ok(match report.outcome() {
        Outcome::Clean => 0,
        Outcome::Findings => 1,
        Outcome::Inconclusive => 2,
    })
}

/// `--limit`, `--since`, `--max-findings` for the audit sweep.
fn parse_audit_options(args: &[String]) -> Result<AuditConfig> {
    let mut config = AuditConfig::default();
    let mut index = 0usize;
    while index < args.len() {
        let flag = args[index].as_str();
        let raw = || -> Result<&String> {
            args.get(index + 1)
                .with_context(|| format!("{flag} needs a value"))
        };
        match flag {
            "--limit" => {
                config.max_drafts = raw()?
                    .parse()
                    .with_context(|| format!("--limit {:?} is not a count", raw()))?
            }
            "--max-findings" => {
                config.max_findings = raw()?
                    .parse()
                    .with_context(|| format!("--max-findings {:?} is not a count", raw()))?
            }
            "--since" => {
                config.since = Some(
                    DateTime::parse_from_rfc3339(raw()?)
                        .with_context(|| format!("--since {:?} is not RFC 3339", raw()))?
                        .with_timezone(&Utc),
                )
            }
            other => bail!("unknown audit argument {other:?}; {USAGE}"),
        }
        index += 2;
    }
    Ok(config)
}

/// The half-open window a backfill run covers. Both ends optional: no window
/// means the whole archive, which is the usual first run.
type Window = (Option<DateTime<Utc>>, Option<DateTime<Utc>>);

/// `--from`/`--to` as RFC 3339 instants.
fn parse_window(args: &[String]) -> Result<Window> {
    let mut from = None;
    let mut to = None;
    let mut index = 0usize;
    while index < args.len() {
        let flag = args[index].as_str();
        let value = || -> Result<DateTime<Utc>> {
            let raw = args
                .get(index + 1)
                .with_context(|| format!("{flag} needs an RFC 3339 timestamp"))?;
            Ok(DateTime::parse_from_rfc3339(raw)
                .with_context(|| format!("{flag} {raw:?} is not RFC 3339"))?
                .with_timezone(&Utc))
        };
        match flag {
            "--from" => from = Some(value()?),
            "--to" => to = Some(value()?),
            other => bail!("unknown backfill argument {other:?}; {USAGE}"),
        }
        index += 2;
    }
    if let (Some(from), Some(to)) = (from, to) {
        anyhow::ensure!(from < to, "--from must be before --to");
    }
    Ok((from, to))
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
    // The grounding policy lives on the store because every path that lands
    // an answer must apply exactly one (§20.4 — see `copilot::store::land`).
    let store = Arc::new(PgDraftStore::new(pool).with_grounding(cfg.grounding));
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
            Arc::new(NarrativeDrafter::new().with_grounding(cfg.grounding))
                as Arc<dyn DraftCapability>,
            // §20.4 t4. Registering it here is what makes `rule_draft` rows
            // claimable at all — the roster's kinds *are* the claim filter, so
            // a pod that does not link this one leaves them for a pod that
            // does rather than leasing work it cannot finish.
            Arc::new(RuleDrafter::new()),
        ])
        .context("linking the draft generators")?,
    );
    tracing::info!(kinds = ?generators.kinds(), "draft generators linked");

    let wake = Arc::new(Notify::new());
    let pool_task = tokio::spawn(
        DraftWorkerPool::new(store.clone(), audit, client, generators, cfg.pool)
            .run(Arc::clone(&wake), shutdown.clone()),
    );

    // ── The outbox flusher (§20.4) ──────────────────────────────────
    // The landing transaction writes the `IncidentNarrativeDrafted` envelope
    // beside the draft row; this publishes it. The split is what makes the
    // dual write safe — a crash between commit and publish loses nothing,
    // because the row is still pending (see `copilot::outbox`).
    let outbox_task = tokio::spawn(copilot::outbox::run_flusher(
        store.clone(),
        Arc::clone(&sink),
        OUTBOX_INTERVAL,
        shutdown.clone(),
    ));

    // ── The review API (§20.4's approval boundary) ──────────────────
    // Opt-in: unset `COPILOT_HTTP_ADDR` serves nothing, so a dev run does not
    // quietly expose an endpoint that can approve a SAR narrative.
    let http_task = match cfg.http() {
        Some(http) => Some(
            serve_reviews(
                http,
                store.clone(),
                Arc::clone(&wake),
                cfg.chain,
                shutdown.clone(),
            )
            .await?,
        ),
        None => {
            tracing::info!("COPILOT_HTTP_ADDR unset — the draft review API is not served");
            None
        }
    };

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
    if let Err(err) = outbox_task.await {
        tracing::error!(error = %err, "outbox flusher task panicked");
    }
    if let Some(http_task) = http_task {
        if let Err(err) = http_task.await {
            tracing::error!(error = %err, "review API task panicked");
        }
    }
    tracing::info!("copilot shut down");
    result
}

/// Bind and serve the draft review API, returning its task handle.
///
/// Bound *before* readiness flips, so a pod that cannot take the port fails
/// the rollout rather than passing its probes with no way to approve anything.
async fn serve_reviews(
    http: &HttpConfig,
    store: Arc<PgDraftStore>,
    wake: Arc<Notify>,
    chain: events::primitives::Chain,
    shutdown: CancellationToken,
) -> Result<tokio::task::JoinHandle<()>> {
    let listener = tokio::net::TcpListener::bind(http.addr)
        .await
        .with_context(|| format!("binding the review API on {}", http.addr))?;
    tracing::info!(
        addr = %http.addr,
        "draft review API listening (Swagger UI at /swagger-ui)"
    );
    // The same store, handed out as two narrow views: a reviewer's read/verdict
    // surface and the enqueue the drafting route needs. Neither can claim a
    // job, call the model, or land an answer.
    let router = copilot::http::router(copilot::http::AppState {
        store: store.clone(),
        queue: store,
        wake,
        chain,
        jwt: http.jwt.clone(),
    });
    Ok(tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, router)
            .with_graceful_shutdown(async move { shutdown.cancelled().await })
            .await
        {
            tracing::error!(error = %err, "review API server failed");
        }
    }))
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
