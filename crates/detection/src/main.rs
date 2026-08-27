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
use detection::boot::link_roster;
use detection::config::Config;
use detection::model::{default_performance_store_path, load_performance_store, RolloutPolicy};
use detection::registry::{register_builtins_with, register_cross_block_builtins};
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

    // One optional subcommand, hand-matched rather than pulled through a CLI
    // framework — the binary has exactly one job and one pre-flight check, and
    // the topology of this workspace is wired by hand and greppable (§6).
    match std::env::args().nth(1).as_deref() {
        None => run(Config::from_env()?).await,
        Some("check-models") => check_models(std::env::args().nth(2)),
        Some(other) => anyhow::bail!(
            "unknown argument {other:?} — usage: `detection` | `detection check-models [path]`"
        ),
    }
}

/// Pre-flight the ML deployment (§20.2) and print the identity it will emit,
/// without joining a consumer group or touching Kafka.
///
/// This is the *same* code path boot takes — artifact digests, pinned-digest
/// check, feature-version skew, graph conformance, the probe inference, and the
/// baseline/schema pairing — so a bundle that passes here boots, and one that
/// fails here fails in CI instead of as a crashloop in a cluster. It also
/// prints the `config_hash` those weights will stamp onto every
/// `DetectorTriggered`, which is what an operator records when promoting a
/// model and what they paste into `expected_artifact` to pin it.
#[cfg(feature = "anomaly")]
fn check_models(path: Option<String>) -> Result<()> {
    use detection::model::ConfigHash;
    use detector_api::DetectorPlugin;

    let path = path
        .or_else(|| std::env::var(detection::ml::ANOMALY_CONFIG_ENV).ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no config given — pass a path or set {}",
                detection::ml::ANOMALY_CONFIG_ENV
            )
        })?;

    let detector = detection::ml::load_anomaly_detector(std::path::Path::new(&path))
        .with_context(|| format!("validating the ML deployment at {path}"))?;

    println!("ok: {path}");
    for slot in detector.models() {
        let d = slot.engine().descriptor();
        println!(
            "  {role:<10} model={id} artifact={artifact} feature_version={fv} \
granularity={g:?} inputs={n} baseline={baseline}",
            role = slot.role(),
            id = d.model_id(),
            artifact = d.artifact(),
            fv = d.feature_version(),
            g = d.granularity(),
            n = d.input_len(),
            baseline = slot.baseline().content_hash(),
        );
    }
    // The third component of the `(id, version, config_hash)` triple this
    // bundle will stamp on every event it produces (§6, §20.2).
    let config_hash = ConfigHash::boot_placeholder(
        anomaly_detector::AnomalyDetector::ID,
        anomaly_detector::AnomalyDetector::VERSION,
    )
    .with_model_artifact(
        &detector
            .model_digest()
            .expect("the ML detector always serves a model"),
    );
    println!(
        "  {} v{} config_hash={config_hash}",
        anomaly_detector::AnomalyDetector::ID,
        anomaly_detector::AnomalyDetector::VERSION,
    );
    Ok(())
}

#[cfg(not(feature = "anomaly"))]
fn check_models(_path: Option<String>) -> Result<()> {
    anyhow::bail!("this binary was built without the `anomaly` feature — nothing to check")
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

    // Staged rollout (§6, §18, Sprint 10 t4): a detector that hasn't earned its
    // place yet starts `Shadow` — it runs and is scored, and its
    // `DetectorTriggered` is recorded so backtests and metrics see it, but no
    // customer-facing alert is raised. Promote one by dropping its
    // `.shadow(...)` line here, once the backtest gate clears it.
    //
    // `anomaly` (§20.2) is on this list for the same reason as the rest, and
    // that sameness is deliberate: an ML detector walks Shadow → backtest gate
    // → Live like any heuristic change, with no special path around the gates.
    // It is also the detector where shadowing matters most — its evidence names
    // no known pattern, so a false positive is expensive to explain.
    let rollout = RolloutPolicy::new()
        .shadow(DetectorId::new("flashloan"))
        .shadow(DetectorId::new("liquidation"))
        .shadow(DetectorId::new("rugpull"))
        .shadow(DetectorId::new("wash-trading"))
        .shadow(DetectorId::new("address-poisoning"))
        .shadow(DetectorId::new("anomaly"));

    // Measured precision/recall/hit_rate from the backtest harness (§18, Sprint 10
    // t4), committed at `crates/detection/model_performance.json`. A missing file
    // (no backtest has run yet) just leaves every card `Unmeasured`.
    let performance = load_performance_store(&default_performance_store_path())
        .context("loading measured detector performance")?;

    // The ML detector is the one detector the *binary* constructs: its weights
    // and training-window baselines are mounted files, read here at boot,
    // link-or-fail (§20.2). Everything after this line treats it as an ordinary
    // plugin — flag-gated, catalogued, staged — which is why it goes through
    // `register_builtins_with` rather than a parallel path.
    let registry = register_builtins_with(&flags, ml_detectors()?);
    let plan = link_roster(&registry, &rollout, &performance)
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
    tracing::debug!(roster = ?registry, "linked detector roster");

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

/// The ML detector (§20.2), if this build links it *and* the deployment
/// configures one — empty otherwise, which is the default and leaves the
/// service behaving exactly as it did before ML landed.
#[cfg(feature = "anomaly")]
fn ml_detectors() -> Result<Vec<Arc<dyn detection::DetectorPlugin>>> {
    detection::ml::anomaly_detector_from_env().context("loading the ML detector (§20.2)")
}

#[cfg(not(feature = "anomaly"))]
fn ml_detectors() -> Result<Vec<Arc<dyn detection::DetectorPlugin>>> {
    // Say so rather than ignoring it: a deployment that mounted model artifacts
    // and set the variable, against a binary built without the feature, would
    // otherwise run happily with no ML detection and no clue why.
    if std::env::var_os("DETECTION_ANOMALY_CONFIG").is_some() {
        tracing::warn!(
            "DETECTION_ANOMALY_CONFIG is set but this binary was built without the \
             `anomaly` feature — the ML detector is not linked"
        );
    }
    Ok(Vec::new())
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
