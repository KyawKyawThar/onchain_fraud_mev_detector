//! Usage-service binary (§13, Sprint 12 t1) — the metering sink.
//!
//! A thin shell over the [`usage`] library: one Kafka consumer drains
//! `mev.events.UsageRecorded` into the append-only ClickHouse `usage_events`
//! table until a shutdown signal arrives.
//!
//! Boot order: observability → config → connect ClickHouse and apply
//! migrations → metrics exporter → provision the `mev.dlq.usage` dead-letter
//! topic (this consumer's own; idempotent) → consume until SIGTERM/Ctrl+C.
//! The *source* topic is never provisioned here: it is part of the backbone
//! topology event-store's `ensure_topics` declares (§20) — this service
//! subscribes, it never declares.
//!
//! Run modes (first CLI arg), mirroring the other service binaries:
//!   - *(none)* / `run` — run the sink (the default).
//!   - `migrate up` / `migrate down` / `migrate info` — drive ClickHouse
//!     migrations explicitly and exit (the boot path always runs `up` too).
//!   - `ping` — probe ClickHouse, so a misconfigured deployment fails fast
//!     and visibly.

use anyhow::{bail, Context, Result};
use tokio_util::sync::CancellationToken;
use usage::{config, migrate, store};

const USAGE: &str = "expected `run` (also the no-arg default), `migrate up|down|info`, or `ping`";

#[tokio::main]
async fn main() -> Result<()> {
    // Hold the guard for the lifetime of `main` so spans flush on exit (§19).
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env("usage"))?;
    let cfg = config::Config::from_env()?;

    // The binary owns the ClickHouse client; the migration runner and the
    // store share it, but neither owns the connection lifecycle.
    let client = store::build_client(&cfg.clickhouse);

    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("run") | None => serve(cfg, client).await,
        Some("migrate") => migrate::MIGRATOR.cli(&client, args.next().as_deref()).await,
        Some("ping") => {
            store::UsageStore::new(client)
                .ping()
                .await
                .context("ClickHouse probe failed")?;
            println!("ok: clickhouse reachable");
            Ok(())
        }
        Some(other) => bail!("unknown argument {other:?}; {USAGE}"),
    }
}

/// Run the sink: apply pending migrations, then consume until shutdown.
async fn serve(cfg: config::Config, client: clickhouse::Client) -> Result<()> {
    // Bring the schema up to date before accepting any writes.
    migrate::MIGRATOR
        .run(&client)
        .await
        .context("running ClickHouse migrations")?;
    tracing::info!(
        schema_version = events::SCHEMA_VERSION,
        "usage schema ready"
    );

    telemetry::metrics::init(cfg.metrics_addr).context("starting the metrics exporter")?;

    let store = store::UsageStore::new(client);
    let shutdown = CancellationToken::new();

    // Translate OS signals into a cancel.
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_signal().await;
            tracing::info!("shutdown signal received");
            shutdown.cancel();
        }
    });

    // The consumer's own dead-letter topic: a record this sink can never
    // process is parked there (inspectable, replayable), not skip-and-forgot.
    let dlq = event_bus::dlq::DeadLetterQueue::ensure(
        &cfg.kafka.brokers,
        "usage",
        cfg.kafka.dlq_replication,
        cfg.kafka.dlq_retention_ms,
    )
    .await
    .context("provisioning the usage DLQ topic")?;

    let consumer = usage::kafka::build_consumer(&cfg.kafka)?;
    let result = usage::kafka::run(consumer, store, cfg.batch, Some(&dlq), shutdown).await;
    tracing::info!("usage service shut down");
    result.context("Kafka consumer exited with error")
}

/// Resolve when the process receives Ctrl+C or (on Unix) SIGTERM — the signals
/// a container runtime sends to ask for a graceful stop.
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
