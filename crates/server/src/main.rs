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

use anyhow::{Context, Result};
use event_bus::{EventSink, KafkaEventSink, PUBLISH_BACKOFF};
use server::config::Config;
use server::http::{self, AppState};
use server::intelligence_client::IntelligenceClient;
use server::stream;
use server::usage::{self, UsageRecorder};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<()> {
    // Hold the guard for the lifetime of `main` so spans flush on exit (§19).
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env("server"))?;
    let cfg = Config::from_env()?;

    // Inside the Tokio runtime: the exporter spawns its `/metrics` listener here.
    // Serves this service's §13 usage counters (and future service metrics, §19).
    telemetry::metrics::init(cfg.metrics_addr).context("starting the metrics exporter")?;

    tracing::info!(schema_version = events::SCHEMA_VERSION, "server starting");

    let intelligence = IntelligenceClient::connect_lazy(cfg.intelligence_grpc_addr.clone())
        .context("building the intelligence gRPC channel")?;
    let http_client = reqwest::Client::builder()
        .build()
        .context("building the outbound HTTP client")?;
    let (alerts_tx, _) = tokio::sync::broadcast::channel(cfg.alert_channel_capacity);
    let (usage_recorder, usage_rx) = UsageRecorder::channel(cfg.usage_channel_capacity);

    let state = AppState {
        intelligence,
        http_client,
        event_store_url: cfg.event_store_url.clone(),
        simulation_url: cfg.simulation_url.clone(),
        jwt: cfg.jwt.clone(),
        alerts: alerts_tx.clone(),
        usage: usage_recorder,
    };

    let shutdown = CancellationToken::new();
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_signal().await;
            tracing::info!("shutdown signal received");
            shutdown.cancel();
        }
    });

    // ── UsageRecorded publisher (§13, background task) ─────────────────
    // The one place this service *produces* onto the backbone; the topic is
    // provisioned by event-store's `ensure_topics` like every other.
    let usage_sink: Arc<dyn EventSink> = Arc::new(
        KafkaEventSink::new(&cfg.kafka.brokers)
            .context("building the Kafka producer for usage metering")?,
    );
    let usage_task = tokio::spawn(usage::run(
        usage_sink,
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
