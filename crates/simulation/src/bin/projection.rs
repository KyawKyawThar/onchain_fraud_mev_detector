//! Simulation incident/job **persistence** binary (§7, §14, Sprint 6 t5) — the
//! `simulation-projection` consumer.
//!
//! A separate binary from the dispatcher + worker because it is a Kafka projection, not a
//! revm worker: it consumes the result-path events, folds them through the pure
//! [`IncidentProjection`](simulation::projection), and write-throughs to Postgres (the
//! mutable in-flight-job + confirmed-incident read model) and ClickHouse (the append-only
//! incident-analytics firehose). It scales/deploys independently and holds no revm/RabbitMQ
//! dependency.
//!
//! Boot: stand up observability, resolve config, connect Postgres + ClickHouse and apply the
//! ClickHouse analytics migration (Postgres migrations are applied out-of-band by sqlx-cli /
//! `just migrate-*`), then drain the result topics until a shutdown signal.
//!
//! Run modes (first CLI arg):
//!   - *(none)* — run the consumer (the default).
//!   - `migrate up` / `migrate down` / `migrate info` — drive the ClickHouse analytics
//!     migrations explicitly and exit (the boot path always runs `up` too). Mirrors the
//!     event-store `migrate` subcommand + the sqlx/Postgres `just migrate-*` recipes.

use anyhow::{bail, Context, Result};
use clickhouse::Client;
use event_bus::PUBLISH_BACKOFF;
use secrecy::ExposeSecret;
use simulation::ch_migrate;
use simulation::config::ProjectionConfig;
use simulation::http;
use simulation::projection_consumer::{build_consumer, ProjectionConsumer};
use simulation::store::{build_clickhouse_client, ClickhouseAnalytics, PgIncidentStore};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<()> {
    // Hold the guard for the lifetime of `main` so spans flush on exit (§19).
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env(
        "simulation-projection",
    ))?;
    let cfg = ProjectionConfig::from_env()?;

    // The binary owns the ClickHouse client; the migration runner and the analytics store
    // share it, but neither owns the connection lifecycle.
    let client = build_clickhouse_client(&cfg.clickhouse);

    // First positional arg selects the run mode; no arg runs the consumer.
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => run(cfg, client).await,
        Some("migrate") => {
            ch_migrate::MIGRATOR
                .cli(&client, args.next().as_deref())
                .await
        }
        Some(other) => bail!(
            "unknown argument {other:?}; expected `migrate up|down|info`, or no args to run the consumer"
        ),
    }
}

/// Run the consumer: apply pending ClickHouse migrations, connect the stores, then drain the
/// result topics until shutdown.
async fn run(cfg: ProjectionConfig, client: Client) -> Result<()> {
    telemetry::metrics::init(cfg.metrics_addr).context("starting the metrics exporter")?;

    tracing::info!(
        group = %cfg.group_id,
        "starting simulation incident/job projection consumer"
    );

    // Bring the analytics schema up to date before writing (Postgres schema is applied by
    // sqlx-cli via `just migrate-*` / the migrate.yml workflow — the same split as the
    // event store: schema is an operational step, distinct from running the service).
    ch_migrate::MIGRATOR
        .run(&client)
        .await
        .context("running ClickHouse analytics migrations")?;

    // Connect the two stores; a bad URL / unreachable database fails fast here at boot.
    let pool = db::connect(cfg.postgres_url.expose_secret())
        .await
        .context("connecting to Postgres")?;
    let pg_store = PgIncidentStore::new(pool);
    let store = Arc::new(pg_store.clone());
    let analytics = ClickhouseAnalytics::new(client);
    analytics
        .ping()
        .await
        .context("probing ClickHouse analytics store")?;
    let analytics = Arc::new(analytics);

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

    // ── Kafka result-path projection (background task) ───────────────
    // A fatal consumer error cancels the token too, so the HTTP server drains
    // rather than serving reads against a process that stopped ingesting
    // (mirrors event-store's `serve()`).
    let consumer = build_consumer(&cfg.kafka_brokers, &cfg.group_id)
        .context("building the result-path Kafka consumer")?;
    // The uniform poison policy (§20): parked-not-lost, provisioned fail-fast.
    let dlq =
        event_bus::dlq::DeadLetterQueue::ensure_from_env(&cfg.kafka_brokers, "sim-projection")
            .await
            .context("provisioning the projection DLQ topic")?;
    let consumer_task = tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            let result = ProjectionConsumer::new(store, analytics)
                .run(consumer, PUBLISH_BACKOFF, Some(&dlq), &shutdown)
                .await;
            if let Err(ref err) = result {
                tracing::error!(error = %err, "projection consumer failed; initiating shutdown");
                shutdown.cancel();
            }
            result
        }
    });

    // ── Internal read API (§11 `/v1/incidents`) ───────────────────────
    let http_state = http::AppState {
        store: Arc::new(pg_store.clone()),
        pg: pg_store,
    };
    let listener = tokio::net::TcpListener::bind(cfg.http_addr)
        .await
        .with_context(|| format!("binding HTTP listener on {}", cfg.http_addr))?;
    tracing::info!(addr = %cfg.http_addr, "simulation-projection HTTP API listening");
    health.set_ready(true);

    axum::serve(listener, http::router(http_state))
        .with_graceful_shutdown({
            let shutdown = shutdown.clone();
            async move { shutdown.cancelled().await }
        })
        .await
        .context("HTTP server error")?;

    let consumer_result = consumer_task.await.context("consumer task panicked")?;
    tracing::info!("simulation projection consumer shut down");
    consumer_result.context("projection consumer exited with error")
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
