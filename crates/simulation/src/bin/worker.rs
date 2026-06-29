//! Simulation worker-pool binary (§7, §17, Sprint 5 t3) — the back half of the slow
//! path. Drains the RabbitMQ `sim.jobs` work queue with competing consumers, runs
//! revm on a shared rayon pool, and publishes each result back onto Kafka.
//!
//! Boot: declare the topology (idempotent — shared with the dispatcher), build the
//! revm engine + the (stubbed) resolver + the rayon pool + the Kafka result sink,
//! then spawn `SIMULATION_WORKERS` competing consumers — each its own consume
//! channel over the one queue — and drain until a shutdown signal. Scaling out is
//! more *replicas* of this binary (§20); the queue depth is the autoscaling signal.

use std::sync::Arc;

use anyhow::{Context, Result};
use event_bus::KafkaEventSink;
use simulation::config::Config;
use simulation::consumer::RabbitJobSource;
use simulation::resolver::UnresolvedJobResolver;
use simulation::simulator::RevmSimulator;
use simulation::topology::declare_sim_topology;
use simulation::worker::Worker;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<()> {
    // Hold the guard for the lifetime of `main` so spans flush on exit (§19).
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env("simulation-worker"))?;
    let cfg = Config::from_env()?;
    run(cfg).await
}

async fn run(cfg: Config) -> Result<()> {
    tracing::info!(
        chain = cfg.chain.id(),
        queue = %cfg.rabbitmq.queue,
        workers = cfg.worker.workers,
        prefetch = cfg.worker.prefetch,
        "starting simulation worker pool"
    );

    // Idempotent with the dispatcher's declaration — a worker may start first, so it
    // must not assume the queue exists. Re-declaring identical args is a no-op.
    declare_sim_topology(&cfg.rabbitmq.url, &cfg.rabbitmq)
        .await
        .context("declaring the RabbitMQ sim.jobs topology")?;

    // The shared seams: the revm engine, the (stubbed) resolver, the rayon pool
    // revm runs on, and the Kafka sink results re-enter the backbone through.
    let resolver = Arc::new(UnresolvedJobResolver);
    let simulator = Arc::new(RevmSimulator::new(cfg.worker.min_profit));
    let pool = Arc::new(build_pool(cfg.worker.pool_threads)?);
    let event_sink =
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

    let worker = Worker::new(resolver, simulator, pool, event_sink, shutdown.clone());

    // One competing consumer per worker slot: each opens its own consume channel
    // over the *same* queue, so the broker load-balances jobs across them.
    let mut handles = Vec::with_capacity(cfg.worker.workers);
    for slot in 0..cfg.worker.workers {
        let source =
            RabbitJobSource::connect(&cfg.rabbitmq.url, &cfg.rabbitmq.queue, cfg.worker.prefetch)
                .await
                .with_context(|| format!("connecting consumer slot {slot}"))?;
        let worker = worker.clone();
        handles.push(tokio::spawn(async move { worker.run(source).await }));
    }

    // Drain: wait for every consumer to finish (each returns when shutdown fires or
    // its source closes). The tasks run concurrently; awaiting them in turn just
    // collects each as it completes. A panicked/erroring task is logged, not swallowed.
    for handle in handles {
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::error!(error = %err, "worker exited with error"),
            Err(err) => tracing::error!(error = %err, "worker task panicked"),
        }
    }

    tracing::info!("simulation worker pool shut down");
    Ok(())
}

/// Build the rayon pool revm runs on. `0` threads = rayon's default (one per core),
/// the usual choice since revm CPU is the bottleneck (§20).
fn build_pool(threads: usize) -> Result<rayon::ThreadPool> {
    let mut builder = rayon::ThreadPoolBuilder::new().thread_name(|i| format!("revm-{i}"));
    if threads > 0 {
        builder = builder.num_threads(threads);
    }
    builder
        .build()
        .context("building the rayon simulation pool")
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
