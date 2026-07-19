//! Ingestion service binary (§5).
//!
//! The service stands up the RPC failover pool, verifies the configured
//! endpoints are on the right chain, then runs four cooperating tasks until a
//! shutdown signal —
//!   1. an active health probe sweeping every endpoint on an interval,
//!   2. the head poller streaming new [`ChainHead`]s off the pool,
//!   3. the [`Pipeline`] that feeds those heads through the reorg-aware block
//!      tree and emits `RawBlockReceived`/`BlockAssembled`/`BlockCanonicalized`/
//!      `BlockReverted` onto Kafka (Sprint 2 tasks 3–4), and
//!   4. a finality ticker that polls the `finalized` tag and emits
//!      `BlockFinalized` for blocks that cross the line.
//!
//! One [`CancellationToken`] coordinates a graceful stop.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use ingestion::config::{Config, RpcPoolConfig};
use ingestion::pipeline::Pipeline;
use ingestion::publisher::KafkaEventSink;
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
    // Prometheus exporter (§19): one instance per chain, so the chain is a
    // global label on every series — the same convention detection/predictive
    // use, so a dashboard can filter/aggregate across chains cleanly.
    telemetry::metrics::init_labeled(cfg.metrics_addr, &[("chain", cfg.chain.metrics_label())])
        .context("starting the metrics exporter")?;

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
    let (tx, rx) = mpsc::channel::<ChainHead>(1024);
    let source: Arc<dyn ChainSource> = pool;
    let poller_task = tokio::spawn(run_head_poller(
        source.clone(),
        poll_interval,
        tx,
        shutdown.clone(),
    ));

    // ── Pipeline: heads → block tree → chain events on Kafka ──────────
    // Owns the block tree in one task (single writer): ingests each head and, on
    // a coarser tick, advances finality, until shutdown or the head stream closes.
    let sink =
        Arc::new(KafkaEventSink::new(&cfg.kafka.brokers).context("building Kafka producer")?);
    let pipeline = Pipeline::new(
        cfg.chain,
        source,
        sink,
        cfg.finalization_depth,
        shutdown.clone(),
    );
    let pipeline_task = tokio::spawn(pipeline.run(rx, cfg.finalize_interval));
    health.set_ready(true);

    // Join the tasks. The poller drops `tx` on shutdown, which ends the pipeline.
    health_task.await.context("health task panicked")?;
    poller_task.await.context("head poller task panicked")?;
    pipeline_task.await.context("pipeline task panicked")?;
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
