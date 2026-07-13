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
use chrono::Utc;
use detection::config::Config;
use detection::emit::DetectionPlan;
use detection::model::{ConfigHash, ModelCard, ModelRegistry};
use detection::registry::{register_builtins, register_cross_block_builtins, Registry};
use detection::scheduler::{
    build_consumer, run_committer, run_consumer, BlockEvent, Offsets, Scheduler,
};
use detection::FeatureFlags;
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
    telemetry::metrics::init(cfg.metrics_addr).context("starting the metrics exporter")?;

    // Roster (compile-time + runtime flags) paired with its model cards once at
    // boot — `link` fails fast if any live detector is uncatalogued, so the hot
    // path never has to fabricate a config_hash (the link-or-fail discipline).
    let registry = register_builtins(&FeatureFlags::all_enabled());
    let models = catalogue(&registry);
    let plan = DetectionPlan::link(&registry, &models)
        .context("linking the detector roster to its model cards")?;

    // The cross-block roster (wash-trading is the first `Scope::CrossBlock`
    // detector, §22 Sprint 10 t1). Each slot is paired with its resolved
    // `DetectorRef` here, the same link-time discipline as the `Block` plan; the
    // roster is empty in a build that links no cross-block detector feature.
    let cross_block = register_cross_block_builtins(&FeatureFlags::all_enabled());

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
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_signal().await;
            tracing::info!("shutdown signal received");
            shutdown.cancel();
        }
    });

    // Bounded channels = inter-stage backpressure (§17).
    let (work_tx, work_rx) = mpsc::channel::<(BlockEvent, Offsets)>(cfg.work_buffer);
    let (done_tx, done_rx) = mpsc::channel::<Offsets>(cfg.commit_buffer);

    let consumer_task = tokio::spawn(run_consumer(consumer.clone(), work_tx, shutdown.clone()));
    let scheduler = Scheduler::new(
        cfg.chain,
        Arc::new(plan),
        cross_block,
        sink,
        shutdown.clone(),
    );
    let scheduler_task = tokio::spawn(scheduler.run(work_rx, done_tx));
    let committer_task = tokio::spawn(run_committer(consumer, done_rx));

    // The consumer drops `work_tx` on shutdown, ending the scheduler, which drops
    // `done_tx`, ending the committer — a clean drain in dependency order.
    consumer_task.await.context("consumer task panicked")??;
    scheduler_task.await.context("scheduler task panicked")?;
    committer_task.await.context("committer task panicked")?;
    tracing::info!("detection shut down");
    Ok(())
}

/// Catalogue every live detector into a [`ModelRegistry`] so the plan can `link`.
///
/// The `config_hash` here is derived from the detector's `(id, version)` as a
/// **boot placeholder** — detectors don't yet expose their serialized config for a
/// real [`ConfigHash::of`], and a fabricated-but-stable hash is enough to make the
/// link total. Computing the real config hash (the §18 reproducibility identifier)
/// is a model-registry follow-up, confined here so it doesn't leak into the lib.
fn catalogue(registry: &Registry) -> ModelRegistry {
    let mut builder = ModelRegistry::builder();
    for plugin in registry.detectors() {
        builder.record(ModelCard::for_plugin(
            plugin.as_ref(),
            ConfigHash::boot_placeholder(plugin.id(), plugin.version()),
            Utc::now(),
        ));
    }
    builder
        .build()
        .expect("one card per live detector — keys are unique by construction")
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
