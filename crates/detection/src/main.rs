//! Detection service binary (§6, §17) — the fast path.
//!
//! Boot: stand up the detector roster and pair it with its model cards into one
//! [`DetectionPlan`] (fail-fast if any live detector is uncatalogued —
//! `link`-or-fail), then run three cooperating tasks until a shutdown signal —
//!   1. the Kafka **consumer**, decoding `BlockAssembled`/`BlockReverted` into work,
//!   2. the async **scheduler**, fanning each block's `Block` detectors out on rayon
//!      and rewinding cross-block state on a reorg, publishing the resulting
//!      `DetectorTriggered`/`PreliminaryAlertCreated` events, and
//!   3. the **committer**, advancing the consumer offset once a block is published.
//!
//! The three are wired by two bounded channels (work, commit) for inter-stage
//! backpressure (§17), and one [`CancellationToken`] coordinates a graceful stop.

use std::sync::Arc;

use anyhow::{Context, Result};
use detection::boot::link_builtin_roster;
use detection::config::Config;
use detection::model::{default_performance_store_path, load_performance_store, RolloutPolicy};
use detection::registry::register_cross_block_builtins;
use detection::scheduler::{
    build_consumer, run_committer, run_consumer, BlockEvent, Offsets, Scheduler,
};
use detection::{DetectorId, FeatureFlags};
use event_bus::KafkaEventSink;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<()> {
    // Hold the guard for the lifetime of `main` so spans flush on exit (§19).
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env("detection"))?;
    let cfg = Config::from_env()?;
    run(cfg).await
}

async fn run(cfg: Config) -> Result<()> {
    // Install the Prometheus exporter before any detection runs, so the
    // per-detector hit/latency series (§19) are exported from the first block.
    // Inside the Tokio runtime: the exporter spawns its `/metrics` listener here.
    // Every series this per-chain instance exports carries its chain (§19), so
    // two chains' instances aggregate and filter cleanly in PromQL.
    telemetry::metrics::init_labeled(cfg.metrics_addr, &[("chain", cfg.chain.metrics_label())])
        .context("starting the metrics exporter")?;

    // Roster (compile-time + runtime flags) paired with its model cards once at
    // boot — `link` fails fast if any live detector is uncatalogued, so the hot
    // path never has to fabricate a config_hash (the link-or-fail discipline).
    // Shared with the backtest harness via `detection::boot` — see its docs.
    let flags = FeatureFlags::all_enabled();

    // Staged rollout (§6, §18, Sprint 10 t4): the five detectors that landed this
    // sprint start `Shadow` — they run and are scored, but don't alert — until a
    // backtest/production comparison promotes them. Promote one by dropping its
    // `.shadow(...)` line here.
    let rollout = RolloutPolicy::new()
        .shadow(DetectorId::new("flashloan"))
        .shadow(DetectorId::new("liquidation"))
        .shadow(DetectorId::new("rugpull"))
        .shadow(DetectorId::new("wash-trading"))
        .shadow(DetectorId::new("address-poisoning"));

    // Measured precision/recall/hit_rate from the backtest harness (§18, Sprint 10
    // t4), committed at `crates/detection/model_performance.json`. A missing file
    // (no backtest has run yet) just leaves every card `Unmeasured`.
    let performance = load_performance_store(&default_performance_store_path())
        .context("loading measured detector performance")?;

    let plan = link_builtin_roster(&flags, &rollout, &performance)
        .context("linking the detector roster to its model cards")?;

    // The cross-block roster (wash-trading is the first `Scope::CrossBlock`
    // detector, §22 Sprint 10 t1). Each slot is paired with its resolved
    // `DetectorRef` here, the same link-time discipline as the `Block` plan; the
    // roster is empty in a build that links no cross-block detector feature.
    let cross_block = register_cross_block_builtins(&flags, &rollout, &performance);

    tracing::info!(
        chain = cfg.chain.id(),
        detectors = plan.len(),
        cross_block_detectors = cross_block.len(),
        "starting detection service"
    );

    let consumer = Arc::new(
        build_consumer(&cfg.kafka.brokers, &cfg.kafka.group_id)
            .context("building Kafka consumer")?,
    );
    let sink =
        Arc::new(KafkaEventSink::new(&cfg.kafka.brokers).context("building Kafka producer")?);

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

    // Bounded channels = inter-stage backpressure (§17).
    let (work_tx, work_rx) = mpsc::channel::<(Option<BlockEvent>, Offsets)>(cfg.work_buffer);
    let (done_tx, done_rx) = mpsc::channel::<Offsets>(cfg.commit_buffer);

    // The uniform poison policy (§20). Named by the (per-chain) consumer group
    // so two chains' detection instances never share a DLQ topic.
    let dlq =
        event_bus::dlq::DeadLetterQueue::ensure_from_env(&cfg.kafka.brokers, &cfg.kafka.group_id)
            .await
            .context("provisioning the detection DLQ topic")?;
    let consumer_task = tokio::spawn(run_consumer(
        consumer.clone(),
        cfg.chain,
        work_tx,
        Some(dlq),
        shutdown.clone(),
    ));
    let scheduler = Scheduler::new(
        cfg.chain,
        Arc::new(plan),
        cross_block,
        sink,
        shutdown.clone(),
    );
    let scheduler_task = tokio::spawn(scheduler.run(work_rx, done_tx));
    let committer_task = tokio::spawn(run_committer(consumer, done_rx));
    health.set_ready(true);

    // The consumer drops `work_tx` on shutdown, ending the scheduler, which drops
    // `done_tx`, ending the committer — a clean drain in dependency order.
    consumer_task.await.context("consumer task panicked")??;
    scheduler_task.await.context("scheduler task panicked")?;
    committer_task.await.context("committer task panicked")?;
    tracing::info!("detection shut down");
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
