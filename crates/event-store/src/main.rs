//! Event-store service binary (§4) — the immutable system of record.
//!
//! A thin shell over the [`event_store`] library: two ingress paths feed one
//! append-only ClickHouse store —
//!   1. the internal HTTP append API ([`event_store::http`]), and
//!   2. the Kafka consumer ([`event_store::kafka`]) that drains every
//!      domain-event topic.
//!
//! Boot order: stand up observability, resolve config, connect ClickHouse and
//! apply migrations, then run the Kafka consumer and the HTTP server together
//! until a shutdown signal arrives. One [`CancellationToken`] coordinates the
//! stop: a SIGTERM/Ctrl+C — or a fatal consumer error — cancels it, the HTTP
//! server drains, and the consumer finishes its in-flight message and commits.
//!
//! Run modes (first CLI arg):
//!   - *(none)* — run the service (the default).
//!   - `migrate up` / `migrate down` / `migrate info` — drive ClickHouse
//!     migrations explicitly and exit (the boot path always runs `up` too).
//!   - `provision-topics` — declare the per-event-type Kafka topics (§20) and
//!     exit (the boot path always provisions too; this is for ops/CI).
//!   - `retention` / `retention apply [--i-understand-this-deletes-evidence]` —
//!     plan or reconcile the `events` table's regulatory evidence window
//!     (engineering conventions §18). The boot path reconciles too, but takes
//!     no `DestructiveIntent` and therefore *cannot* narrow a window, bind an
//!     existing archive, or overwrite a clause it could not parse.

use anyhow::{bail, Context, Result};
use chrono::Utc;
use clickhouse::Client;
use event_store::retention::Reconciliation;
use event_store::{config, http, kafka, migrate, retention, store};
// The shared crate, not this binary's `event_store::retention` module — the
// `use` above binds that name, so the witness is reached by absolute path.
use ::retention::DestructiveIntent;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<()> {
    // Hold the guard for the lifetime of `main` so spans flush on exit (§19).
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env("event-store"))?;
    let cfg = config::Config::from_env()?;

    // The binary owns the ClickHouse client; the migration runner and the store
    // share it, but neither owns the connection lifecycle.
    let client = store::build_client(&cfg.clickhouse);

    // First positional arg selects the run mode; no arg runs the service.
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => serve(cfg, client).await,
        Some("migrate") => {
            migrate::MIGRATOR
                .cli(&client, args.next().as_deref())
                .await
        }
        Some("provision-topics") => {
            kafka::ensure_topics(&cfg.kafka).await?;
            println!("✅ provision-topics: Kafka topics ensured");
            Ok(())
        }
        Some("retention") => retention_cli(&cfg, &client, args.collect()).await,
        Some(other) => bail!(
            "unknown argument {other:?}; expected `migrate up|down|info`, `provision-topics`, `retention [apply [--i-understand-this-deletes-evidence]]`, or no args to run the service"
        ),
    }
}

/// Run the service: apply pending migrations, then the Kafka consumer and HTTP
/// server together until shutdown.
async fn serve(cfg: config::Config, client: Client) -> Result<()> {
    telemetry::metrics::init(cfg.metrics_addr).context("starting the metrics exporter")?;

    // Bring the schema up to date before accepting any writes.
    migrate::MIGRATOR
        .run(&client)
        .await
        .context("running ClickHouse migrations")?;
    tracing::info!(
        schema_version = events::SCHEMA_VERSION,
        "event-store schema ready"
    );

    // The evidence half of the regulatory retention policy (engineering
    // conventions §18). After the migrations, because the migration is what
    // guarantees a floor and this is what raises it to whatever the deployment
    // decided; before accepting writes, because a store whose retention this
    // build cannot vouch for should not be taking evidence.
    reconcile_retention(&client, &cfg).await?;

    let store = store::EventStore::new(client);
    let shutdown = CancellationToken::new();
    // K8s probes (§20): /livez immediately; /readyz flips on once boot wiring
    // completes below. Opt-in via HEALTH_ADDR — unset (dev) serves nothing.
    let health = telemetry::health::HealthState::new();
    telemetry::health::spawn_from_env(health.clone(), shutdown.clone())
        .await
        .context("starting the health endpoints")?;

    // Translate OS signals into a cancel.
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_signal().await;
            tracing::info!("shutdown signal received");
            shutdown.cancel();
        }
    });

    // Declare the per-event-type topics (§20) before subscribing, so the
    // topology exists explicitly rather than relying on broker auto-create.
    // Idempotent — a no-op once the topics are there.
    kafka::ensure_topics(&cfg.kafka)
        .await
        .context("provisioning Kafka topics")?;

    // ── Kafka ingest (background task) ────────────────────────────────
    // A fatal consumer error cancels the token too, so the whole service stops
    // and the orchestrator restarts it (fail fast) rather than silently running
    // HTTP-only with no ingest.
    let consumer = kafka::build_consumer(&cfg.kafka)?;
    // The uniform poison policy (§20): parked-not-lost. Provisioned at boot,
    // fail-fast, like the backbone topics above.
    let dlq = event_bus::dlq::DeadLetterQueue::ensure_from_env(&cfg.kafka.brokers, "event-store")
        .await
        .context("provisioning the event-store DLQ topic")?;
    let consumer_task = tokio::spawn({
        let store = store.clone();
        let shutdown = shutdown.clone();
        async move {
            let result = kafka::run(consumer, store, Some(&dlq), shutdown.clone()).await;
            if let Err(ref err) = result {
                tracing::error!(error = %err, "Kafka consumer failed; initiating shutdown");
                shutdown.cancel();
            }
            result
        }
    });

    // ── HTTP append API ───────────────────────────────────────────────
    let state = http::AppState {
        store,
        write_token: cfg.write_token.clone(),
    };
    let listener = tokio::net::TcpListener::bind(cfg.http_addr)
        .await
        .with_context(|| format!("binding HTTP listener on {}", cfg.http_addr))?;
    tracing::info!(addr = %cfg.http_addr, "event-store HTTP API listening");
    health.set_ready(true);

    axum::serve(listener, http::router(state))
        .with_graceful_shutdown({
            let shutdown = shutdown.clone();
            async move { shutdown.cancelled().await }
        })
        .await
        .context("HTTP server error")?;

    // The server has drained — wait for the consumer to finish and surface a
    // fatal error as a non-zero exit.
    let consumer_result = consumer_task.await.context("consumer task panicked")?;
    tracing::info!("event-store shut down");
    consumer_result.context("Kafka consumer exited with error")
}

/// Bring the `events` table's TTL in line with the configured policy at boot.
///
/// Calls [`retention::reconcile_safe`], which takes **no**
/// [`DestructiveIntent`] — so this function cannot narrow a window, impose a
/// first bound over an existing archive, or overwrite a TTL clause it failed to
/// parse. Those come back as `RefusedDestructive` and the service does not
/// start, which is the correct outcome: a store whose retention this build
/// cannot vouch for should not be accepting evidence.
///
/// There is no `unreachable!` here any more. The previous shape returned a
/// value carrying variants this path could never receive, and the compiler had
/// to be told so by hand — a sign the signature was wrong rather than the
/// caller careless.
async fn reconcile_retention(client: &Client, cfg: &config::Config) -> Result<()> {
    let desired = cfg.retention.widest_evidence_days();
    event_store::metrics::set_evidence_retention_days(desired);

    let decision =
        retention::reconcile_safe(client, &cfg.clickhouse.database, &cfg.retention, Utc::now())
            .await
            .context(
                "reconciling the events table's retention window — the service will not accept \
         evidence it cannot state a retention policy for",
            )?;

    match &decision {
        Reconciliation::Unchanged { days } => tracing::info!(
            evidence_days = days,
            policy = %cfg.retention,
            "events retention already matches the policy"
        ),
        Reconciliation::Extend(extension) => tracing::warn!(
            from_days = extension.from,
            to_days = extension.to,
            policy = %cfg.retention,
            "widened the events table's retention window"
        ),
        Reconciliation::Bind(bound) => tracing::warn!(
            to_days = bound.to,
            policy = %cfg.retention,
            "bound the events table's retention; it held nothing older than the window"
        ),
        // `reconcile_safe` returns these as errors, propagated by the `?` above.
        Reconciliation::Shorten(_) | Reconciliation::Refuse { .. } => {}
    }

    announce_policy_change(cfg, &decision, retention::APPLIED_BY_BOOT).await;
    Ok(())
}

/// Publish `RetentionPolicyChanged` (engineering conventions §18) when a run
/// actually moved the window.
///
/// Best-effort and never fatal. The TTL is already written by the time this
/// runs, so failing boot here would refuse to start a service whose store is
/// correct — and the operator would then have no way to start it at all. The
/// error log is the fallback, and it says plainly that the audit trail is
/// missing a record rather than that something did not happen.
///
/// A one-shot producer rather than a long-lived one: this fires on a policy
/// change, which is a handful of times in a store's life.
async fn announce_policy_change(cfg: &config::Config, decision: &Reconciliation, applied_by: &str) {
    let Some(envelope) =
        retention::policy_change_announcement(decision, applied_by, Utc::now(), cfg.chain)
    else {
        return;
    };

    match event_bus::KafkaEventSink::new(&cfg.kafka.brokers) {
        Ok(sink) => match event_bus::EventSink::publish(&sink, envelope).await {
            Ok(()) => tracing::info!(
                applied_by,
                "announced the retention policy change to the audit trail"
            ),
            Err(err) => tracing::error!(
                error = %err,
                applied_by,
                "the events table's retention window changed but RetentionPolicyChanged could \
                 not be published — the audit trail is missing the record of a governance change"
            ),
        },
        Err(err) => tracing::error!(
            error = %err,
            "the retention window changed but no producer could be built to announce it"
        ),
    }
}

/// `event-store retention [apply [--i-understand-this-deletes-evidence]]`.
///
/// The no-arg form is a **plan**: it prints the policy, what the store actually
/// holds, and what applying would do — the question a runbook asks and the one a
/// config map cannot answer. `apply` carries it out; the long flag mints the
/// [`DestructiveIntent`] that the narrowing and archive-binding paths demand.
///
/// The flag is deliberately unpleasant to type. It is the only thing in this
/// binary that can delete five years of regulatory evidence, and a `-f` would
/// make it look like every other force flag in the world.
async fn retention_cli(cfg: &config::Config, client: &Client, args: Vec<String>) -> Result<()> {
    const DESTRUCTIVE_FLAG: &str = "--i-understand-this-deletes-evidence";

    let mut apply = false;
    let mut destructive = false;
    for arg in &args {
        match arg.as_str() {
            "apply" => apply = true,
            DESTRUCTIVE_FLAG => destructive = true,
            other => {
                bail!("unknown argument {other:?}; expected `apply [{DESTRUCTIVE_FLAG}]`")
            }
        }
    }
    if destructive && !apply {
        bail!("{DESTRUCTIVE_FLAG} only means something with `apply`");
    }

    let policies = &cfg.retention;
    let database = &cfg.clickhouse.database;
    let now = Utc::now();

    // The plan is printed on both paths, so `apply` never does something the
    // dry run would not have described.
    let observed = retention::observe(client, database).await?;
    let decision = retention::plan(&observed, policies);
    println!("policy: {policies}");
    println!("store:  {observed}");
    println!("plan:   {decision}");

    // The one extra read, on the one plan that needs it.
    if let Reconciliation::Bind(bound) = &decision {
        match bound.assess(retention::oldest_event(client).await?, now) {
            retention::BindAssessment::Safe(_) => {
                println!("        the table holds nothing older than the window — safe");
            }
            retention::BindAssessment::WouldDestroy { oldest, cutoff, .. } => println!(
                "        the oldest event is {}, before the window's start {} — \
                 applying DELETES everything in between",
                oldest.to_rfc3339(),
                cutoff.to_rfc3339()
            ),
        }
    }

    if !apply {
        if decision.is_fatal() {
            println!("        `retention apply {DESTRUCTIVE_FLAG}` would carry this out");
        }
        return Ok(());
    }

    let applied = if destructive {
        // The single call site that mints the witness in this binary.
        retention::reconcile_with_intent(
            client,
            database,
            policies,
            now,
            DestructiveIntent::from_operator_flag(),
        )
        .await?
    } else {
        retention::reconcile_safe(client, database, policies, now).await?
    };

    announce_policy_change(cfg, &applied, retention::APPLIED_BY_OPERATOR).await;
    println!("✅ retention: applied — {applied}");
    Ok(())
}

/// Resolve when the process receives Ctrl+C or (on Unix) SIGTERM — the signals a
/// container runtime sends to ask for a graceful stop.
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
