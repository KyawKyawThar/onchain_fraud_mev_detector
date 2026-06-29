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
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<()> {
    // Hold the guard for the lifetime of `main` so spans flush on exit (§19).
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env("simulation"))?;
    let cfg = Config::from_env()?;
    run(cfg).await
}

async fn run(cfg: Config) -> Result<()> {
    tracing::info!(
        chain = cfg.chain.id(),
        queue = %cfg.rabbitmq.queue,
        "starting simulation dispatcher"
    );

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

    let shutdown = CancellationToken::new();
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_signal().await;
            tracing::info!("shutdown signal received");
            shutdown.cancel();
        }
    });

    Dispatcher::new(job_sink, event_sink, shutdown)
        .run(consumer)
        .await
        .context("dispatcher loop failed")?;

    tracing::info!("simulation dispatcher shut down");
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
