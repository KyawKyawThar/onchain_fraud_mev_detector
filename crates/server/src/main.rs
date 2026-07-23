//! The public §11 API service — the JWT-gated front door onto three internal
//! services: `intelligence` (gRPC, risk/labels), `event-store` and
//! `simulation-projection` (their existing internal HTTP read endpoints,
//! proxied) — plus its own Kafka consumer feeding `WS /v1/stream`'s live
//! alert lifecycle.
//!
//! Boot: observability, resolve config, build the outbound clients (a lazy
//! gRPC channel to intelligence, a `reqwest::Client` for the two HTTP
//! proxies, a broadcast channel + Kafka consumer for the WS stream, and a
//! Kafka producer publishing every metered call as `UsageRecorded`, §13), then
//! serve until a shutdown signal — the same `CancellationToken` +
//! graceful-drain shape every other service in this workspace uses. A fatal
//! consumer error cancels the token too (mirrors event-store), so the whole
//! service stops rather than silently running HTTP-only with a dead stream.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use event_bus::{EventSink, KafkaEventSink, PUBLISH_BACKOFF};
use rule_engine::store::PgRuleStore;
use secrecy::ExposeSecret;
use server::config::Config;
use server::http::{self, AppState};
use server::intelligence_client::IntelligenceClient;
use server::policy_store::PgPolicyStore;
use server::stream;
use server::usage::{self, UsageRecorder};
use tokio_util::sync::CancellationToken;

/// How long boot waits for the eager intelligence dial before falling back
/// to a lazy channel — bounds startup, never blocks it on a peer.
const INTELLIGENCE_DIAL_TIMEOUT: Duration = Duration::from_secs(2);

#[tokio::main]
async fn main() -> Result<()> {
    // Hold the guard for the lifetime of `main` so spans flush on exit (§19).
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env("server"))?;
    let cfg = Config::from_env()?;

    // Inside the Tokio runtime: the exporter spawns its `/metrics` listener here.
    // Serves this service's §13 usage counters (and future service metrics, §19).
    telemetry::metrics::init(cfg.metrics_addr).context("starting the metrics exporter")?;

    tracing::info!(schema_version = events::SCHEMA_VERSION, "server starting");

    // Warm (bounded) rather than lazy: the first screening call after boot
    // shouldn't pay the connection handshake out of its p50 < 100ms budget.
    // A dial failure falls back to lazy with a warn — never a boot-order
    // coupling on intelligence being up first.
    let intelligence = IntelligenceClient::connect_warm(
        cfg.intelligence_grpc_addr.clone(),
        INTELLIGENCE_DIAL_TIMEOUT,
    )
    .await
    .context("building the intelligence gRPC channel")?
    .with_screening_deadline(cfg.screening_deadline);
    let http_client = reqwest::Client::builder()
        .build()
        .context("building the outbound HTTP client")?;
    let (alerts_tx, _) = tokio::sync::broadcast::channel(cfg.alert_channel_capacity);
    let (usage_recorder, usage_rx) = UsageRecorder::channel(cfg.usage_channel_capacity);

    // ── Rule store (§9, Sprint 9 t4) ───────────────────────────────────
    // `POST /v1/rules` writes through the rule-engine crate's customer-
    // isolated store; probe it at boot so a missing migration fails here.
    let pg_pool = db::connect(cfg.database_url.expose_secret())
        .await
        .context("connecting Postgres for the rule store")?;
    let rule_store = PgRuleStore::new(pg_pool.clone());
    rule_store
        .ping()
        .await
        .context("rules schema not reachable — run `just migrate-up`?")?;

    // ── Decision-policy store (§11, Sprint 14 t2) ──────────────────────
    // `POST /v1/address/{addr}/screen` resolves a named policy through this
    // (customer-authored ones only — the built-in catalog is server code,
    // never a row); shares the same pool, same fail-fast-at-boot posture.
    let policy_store = PgPolicyStore::new(pg_pool);
    policy_store
        .ping()
        .await
        .context("screening_policies schema not reachable — run `just migrate-up`?")?;

    // The one Kafka producer this service holds: usage metering (§13) and the
    // `RuleCreated` announcement (§9) share it.
    let sink: Arc<dyn EventSink> =
        Arc::new(KafkaEventSink::new(&cfg.kafka.brokers).context("building the Kafka producer")?);

    let state = AppState {
        intelligence,
        http_client,
        event_store_url: cfg.event_store_url.clone(),
        simulation_url: cfg.simulation_url.clone(),
        jwt: cfg.jwt.clone(),
        alerts: alerts_tx.clone(),
        usage: usage_recorder,
        rules: Arc::new(rule_store),
        events: sink.clone(),
        policies: Arc::new(policy_store),
    };

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

    // ── UsageRecorded publisher (§13, background task) ─────────────────
    // The topic is provisioned by event-store's `ensure_topics` like every
    // other.
    let usage_task = tokio::spawn(usage::run(
        sink,
        usage_rx,
        PUBLISH_BACKOFF,
        shutdown.clone(),
    ));

    // ── WS /v1/stream ingest (background task) ────────────────────────
    let stream_consumer =
        stream::build_consumer(&cfg.kafka).context("building the Kafka consumer for /v1/stream")?;
    let stream_task = tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            let result = stream::run(stream_consumer, alerts_tx, shutdown.clone()).await;
            if let Err(ref err) = result {
                tracing::error!(error = %err, "/v1/stream Kafka consumer failed; initiating shutdown");
                shutdown.cancel();
            }
            result
        }
    });

    let listener = tokio::net::TcpListener::bind(cfg.http_addr)
        .await
        .with_context(|| format!("binding HTTP listener on {}", cfg.http_addr))?;
    tracing::info!(addr = %cfg.http_addr, "server HTTP API listening");
    health.set_ready(true);

    axum::serve(listener, http::router(state))
        .with_graceful_shutdown({
            let shutdown = shutdown.clone();
            async move { shutdown.cancelled().await }
        })
        .await
        .context("HTTP server error")?;

    // The server has drained — wait for the background tasks to finish and
    // surface a fatal error as a non-zero exit.
    usage_task.await.context("usage publisher task panicked")?;
    let stream_result = stream_task
        .await
        .context("/v1/stream consumer task panicked")?;
    tracing::info!("server shut down");
    stream_result.context("/v1/stream Kafka consumer exited with error")
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
