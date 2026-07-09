//! The public §11 API service — the JWT-gated front door onto three internal
//! services: `intelligence` (gRPC, risk/labels), `event-store` and
//! `simulation-projection` (their existing internal HTTP read endpoints,
//! proxied).
//!
//! Boot: observability, resolve config, build the outbound clients (a lazy
//! gRPC channel to intelligence, a `reqwest::Client` for the two HTTP
//! proxies), then serve until a shutdown signal — the same
//! `CancellationToken` + graceful-drain shape every other service in this
//! workspace uses.

use anyhow::{Context, Result};
use server::config::Config;
use server::http::{self, AppState};
use server::intelligence_client::IntelligenceClient;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<()> {
    // Hold the guard for the lifetime of `main` so spans flush on exit (§19).
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env("server"))?;
    let cfg = Config::from_env()?;

    tracing::info!(schema_version = events::SCHEMA_VERSION, "server starting");

    let intelligence = IntelligenceClient::connect_lazy(cfg.intelligence_grpc_addr.clone())
        .context("building the intelligence gRPC channel")?;
    let http_client = reqwest::Client::builder()
        .build()
        .context("building the outbound HTTP client")?;

    let state = AppState {
        intelligence,
        http_client,
        event_store_url: cfg.event_store_url.clone(),
        simulation_url: cfg.simulation_url.clone(),
        jwt: cfg.jwt.clone(),
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

    let listener = tokio::net::TcpListener::bind(cfg.http_addr)
        .await
        .with_context(|| format!("binding HTTP listener on {}", cfg.http_addr))?;
    tracing::info!(addr = %cfg.http_addr, "server HTTP API listening");

    axum::serve(listener, http::router(state))
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
        .context("HTTP server error")?;

    tracing::info!("server shut down");
    Ok(())
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
