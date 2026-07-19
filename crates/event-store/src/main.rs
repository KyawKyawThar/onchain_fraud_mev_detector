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

use anyhow::{bail, Context, Result};
use clickhouse::Client;
use event_store::{config, http, kafka, migrate, store};
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
        Some(other) => bail!(
            "unknown argument {other:?}; expected `migrate up|down|info`, `provision-topics`, or no args to run the service"
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
