//! Simulation dispatcher binary (§7, Sprint 5 t1) — the front half of the slow
//! path.
//!
//! Boot: connect the two publish seams (RabbitMQ for the `SimulationJob` command,
//! Kafka for the `SimulationRequested` audit event), build the
//! `PreliminaryAlertCreated` consumer, then run the [`Dispatcher`] until a shutdown
//! signal drains it. The worker pool that drains `sim.jobs` is a separate binary
//! (task 3).

use std::sync::Arc;

use anyhow::{Context, Result};
use event_bus::KafkaEventSink;
use simulation::config::Config;
use simulation::dispatcher::{build_consumer, Dispatcher};
use simulation::queue::RabbitJobSink;
use simulation::reorg::{self, EmptyIncidentIndex, ReorgConsumer};
use simulation::topology::declare_sim_topology;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<()> {
    // Hold the guard for the lifetime of `main` so spans flush on exit (§19).
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env("simulation"))?;
    let cfg = Config::from_env()?;
    run(cfg).await
}

async fn run(cfg: Config) -> Result<()> {
    telemetry::metrics::init_labeled(cfg.metrics_addr, &[("chain", cfg.chain.metrics_label())])
        .context("starting the metrics exporter")?;

    tracing::info!(
        chain = cfg.chain.id(),
        queue = %cfg.rabbitmq.queue,
        "starting simulation dispatcher"
    );

    // Declare the sim.jobs topology (durable quorum queue + DLX, §7/§20) once,
    // before anything publishes — the sink deliberately never declares, so the
    // queue must exist with the right arguments first. Fails fast at boot if the
    // declaration conflicts with an existing queue.
    declare_sim_topology(&cfg.rabbitmq.url, &cfg.rabbitmq)
        .await
        .context("declaring the RabbitMQ sim.jobs topology")?;

    // The two ends of the dispatch fan-out: the RabbitMQ command queue and the
    // Kafka audit stream. Both connect at boot so a misconfigured broker fails
    // fast rather than at the first alert.
    let job_sink = Arc::new(
        RabbitJobSink::connect(&cfg.rabbitmq.url, cfg.rabbitmq.queue.clone())
            .await
            .context("connecting the RabbitMQ job sink")?,
    );
    let event_sink =
        Arc::new(KafkaEventSink::new(&cfg.kafka.brokers).context("building Kafka producer")?);
    let consumer = build_consumer(&cfg.kafka.brokers, &cfg.kafka.group_id)
        .context("building Kafka consumer")?;

    // The service-side reorg consumer: react to `BlockReverted` by retracting incidents
    // from orphaned blocks (§15). Its own consumer group so it tracks `BlockReverted`
    // independently of the alert stream. The block→incident join is stubbed today
    // (`EmptyIncidentIndex`) — see `simulation::reorg`.
    let reorg_consumer = reorg::build_consumer(&cfg.kafka.brokers, &cfg.kafka.reorg_group_id)
        .context("building Kafka BlockReverted consumer")?;

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

    // Run the dispatcher and the reorg (retraction) consumer concurrently under one
    // shutdown. If either loop exits (graceful stop or a fatal subscribe error), cancel
    // the other so a single failure drains the whole process rather than leaving a half-
    // dead service.
    // The uniform poison policy (§20): parked-not-lost, provisioned fail-fast.
    // Each consumer owns its DLQ inside its spawned future.
    let dispatcher_dlq =
        event_bus::dlq::DeadLetterQueue::ensure_from_env(&cfg.kafka.brokers, "sim-dispatcher")
            .await
            .context("provisioning the dispatcher DLQ topic")?;
    let retractor_dlq =
        event_bus::dlq::DeadLetterQueue::ensure_from_env(&cfg.kafka.brokers, "sim-reorg-retractor")
            .await
            .context("provisioning the reorg-retractor DLQ topic")?;

    let mut dispatcher = tokio::spawn({
        let d = Dispatcher::new(job_sink, event_sink.clone(), shutdown.clone());
        async move { d.run(consumer, Some(&dispatcher_dlq)).await }
    });
    let mut retractor = tokio::spawn({
        let r = ReorgConsumer::new(Arc::new(EmptyIncidentIndex), event_sink, shutdown.clone());
        async move { r.run(reorg_consumer, Some(&retractor_dlq)).await }
    });
    health.set_ready(true);

    // Whichever loop finishes first, cancel the peer and await *only* it (re-awaiting
    // the already-finished handle would panic), so both drain before we exit.
    tokio::select! {
        res = &mut dispatcher => {
            log_task("dispatcher", res);
            shutdown.cancel();
            log_task("reorg consumer", retractor.await);
        }
        res = &mut retractor => {
            log_task("reorg consumer", res);
            shutdown.cancel();
            log_task("dispatcher", dispatcher.await);
        }
    }

    tracing::info!("simulation dispatcher shut down");
    Ok(())
}

/// Log how one of the concurrent service loops exited (a fatal loop error or a panicked
/// task is surfaced, not swallowed; awaiting an already-finished handle is a no-op).
fn log_task(name: &str, res: Result<Result<()>, tokio::task::JoinError>) {
    match res {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::error!(task = name, error = %err, "service loop exited with error")
        }
        Err(err) if err.is_cancelled() => {}
        Err(err) => tracing::error!(task = name, error = %err, "service task panicked"),
    }
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
