//! Ingestion service binary (§5).
//!
//! This task (Sprint 2 #1) delivers the **source adapter layer**: it stands up
//! the RPC failover pool, verifies the configured endpoints are on the right
//! chain, then runs three cooperating tasks until a shutdown signal —
//!   1. an active health probe sweeping every endpoint on an interval,
//!   2. the head poller streaming new [`ChainHead`]s off the pool, and
//!   3. a consumer that, for now, logs each head.
//!
//! That consumer is the seam for tasks 2–4: the reorg-aware block tree replaces
//! the logging loop and turns heads into `RawBlockReceived`/`BlockAssembled`/…
//! events on Kafka. One [`CancellationToken`] coordinates a graceful stop.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use ingestion::config::{Config, RpcPoolConfig};
use ingestion::source::head_stream::run_head_poller;
use ingestion::source::rpc::RpcFailoverPool;
use ingestion::source::{ChainHead, ChainSource};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<()> {
    // Hold the guard for the lifetime of `main` so spans flush on exit (§19).
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env("ingestion"))?;
    let cfg = Config::from_env()?;
    run(cfg).await
}

async fn run(cfg: Config) -> Result<()> {
    let RpcPoolConfig {
        endpoints,
        poll_interval,
        health_interval,
        request_timeout,
        breaker,
    } = cfg.rpc.clone();

    tracing::info!(
        chain = cfg.chain.id(),
        endpoints = endpoints.len(),
        finalization_depth = cfg.finalization_depth,
        "starting ingestion source adapter (RPC failover pool)"
    );

    let pool = Arc::new(RpcFailoverPool::new(
        &endpoints,
        cfg.chain,
        request_timeout,
        breaker,
    ));

    // Fail fast on a wholly misconfigured pool: probe once at boot, and refuse
    // to start if *every* endpoint is on the wrong chain (never recoverable).
    // Endpoints merely unreachable are left to recover via the health loop.
    pool.health_check_once().await;
    if pool.all_quarantined() {
        bail!("every configured RPC endpoint is on the wrong chain (expected chain {}); check ETH_RPC_URLS / CHAIN_ID", cfg.chain.id());
    }

    let shutdown = CancellationToken::new();
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_signal().await;
            tracing::info!("shutdown signal received");
            shutdown.cancel();
        }
    });

    // ── Active health probe ───────────────────────────────────────────
    let health_task = tokio::spawn({
        let pool = pool.clone();
        let shutdown = shutdown.clone();
        async move {
            let mut ticker = tokio::time::interval(health_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => return,
                    _ = ticker.tick() => pool.health_check_once().await,
                }
                let routable = pool.routable_count(std::time::Instant::now());
                tracing::debug!(routable, total = endpoints.len(), "endpoint health swept");
            }
        }
    });

    // ── Head poller ───────────────────────────────────────────────────
    let (tx, mut rx) = mpsc::channel::<ChainHead>(1024);
    let source: Arc<dyn ChainSource> = pool;
    let poller_task = tokio::spawn(run_head_poller(source, poll_interval, tx, shutdown.clone()));

    // ── Head consumer (task 2+ replaces this with the block tree) ─────
    while let Some(head) = rx.recv().await {
        tracing::info!(
            number = head.number,
            hash = %head.hash,
            parent_hash = %head.parent_hash,
            timestamp = head.timestamp,
            "new head (→ task 3 will emit RawBlockReceived)"
        );
    }

    // The channel closed: the poller stopped (shutdown). Join the tasks.
    health_task.await.context("health task panicked")?;
    poller_task.await.context("head poller task panicked")?;
    tracing::info!("ingestion shut down");
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
