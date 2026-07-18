//! Notification service binary (§11, Sprint 12 t4) — the long-running Kafka
//! consumer that routes `PreliminaryAlertCreated`/`IncidentCreated`/
//! `IncidentRetracted`/`IncidentFinalized`/`RuleAlertCreated`/`SanctionHit`
//! to severity-filtered subscribers over webhook/email/Slack/PagerDuty, with
//! retry/backoff, per-subscriber dedup, and delivery receipts.
//!
//! Subcommands, mirroring the other service binaries:
//!   - `run` (default; also the no-arg run) — the consumer described above.
//!   - `ping` — connect and probe Postgres (the notification schema), so a
//!     misconfigured deployment fails fast and visibly.
//!
//! No customer-facing subscriber-management HTTP API in this pass (a
//! deliberate scope cut, mirroring how rule-engine split its Postgres store
//! from its `POST /v1/rules` surface across separate tasks) — subscribers
//! are seeded directly against [`NotificationStore::create_subscriber`].

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use event_bus::{EventSink, KafkaEventSink};
use notification::config::Config;
use notification::consumer::{build_consumer, NotificationConsumer};
use notification::delivery::ChannelSink;
use notification::email_delivery::EmailDelivery;
use notification::http_delivery::HttpDelivery;
use notification::sink::MultiChannelSink;
use notification::store::{NotificationStore, PgNotificationStore};
use notification::subscriber_cache::{refresh_subscribers, SubscriberSetHandle};
use secrecy::ExposeSecret;
use tokio_util::sync::CancellationToken;

const USAGE: &str = "expected `run` (also the no-arg default) or `ping`";

/// Back-off before the consume loop retries a transiently-failed record.
const RETRY_BACKOFF: Duration = Duration::from_secs(1);

#[tokio::main]
async fn main() -> Result<()> {
    // Hold the guard for the lifetime of `main` so spans flush on exit (§19).
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env("notification"))?;
    let cfg = Config::from_env()?;

    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("run") | None => run(&cfg).await,
        Some("ping") => ping(&cfg).await,
        Some(other) => bail!("unknown argument {other:?}; {USAGE}"),
    }
}

/// Probe the store this service depends on — a misconfigured deployment
/// fails here, loudly, not at the first consumed event.
async fn ping(cfg: &Config) -> Result<()> {
    let pool = db::connect(cfg.database_url.expose_secret()).await?;
    PgNotificationStore::new(pool)
        .ping()
        .await
        .context("Postgres notification schema probe failed")?;
    println!("ok: postgres (notification schema) reachable");
    Ok(())
}

async fn run(cfg: &Config) -> Result<()> {
    telemetry::metrics::init(cfg.metrics_addr).context("starting the metrics exporter")?;
    tracing::info!(
        schema_version = events::SCHEMA_VERSION,
        "notification starting"
    );

    let shutdown = CancellationToken::new();
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_signal().await;
            tracing::info!("shutdown signal received");
            shutdown.cancel();
        }
    });

    // ── Store (fail-fast) ──────────────────────────────────────────
    let pool = db::connect(cfg.database_url.expose_secret()).await?;
    let store: Arc<dyn NotificationStore> = Arc::new(PgNotificationStore::new(pool.clone()));
    PgNotificationStore::new(pool)
        .ping()
        .await
        .context("notification schema not reachable — run `just migrate-up`?")?;

    // ── Subscriber snapshot (link-or-fail at boot; §17) ────────────
    // An unreachable store should fail the pod visibly at startup, not start
    // routing against an empty cache and silently drop every notice.
    let subscribers = Arc::new(SubscriberSetHandle::new(Vec::new()));
    refresh_subscribers(store.as_ref(), &subscribers)
        .await
        .context("loading the initial subscriber snapshot")?;

    // ── Delivery channels ───────────────────────────────────────────
    let http = HttpDelivery::new(cfg.delivery, shutdown.clone())
        .context("building the HTTP delivery client")?;
    let email = EmailDelivery::new(&cfg.smtp, cfg.delivery, shutdown.clone())
        .context("building the SMTP delivery client")?;
    let channels: Arc<dyn ChannelSink> = Arc::new(MultiChannelSink::new(http, email));

    // ── Periodic subscriber-snapshot refresh (the only trigger today —
    // no subscriber-management API/event exists yet to refresh on-demand) ──
    let refresh_task = tokio::spawn({
        let store = Arc::clone(&store);
        let subscribers = Arc::clone(&subscribers);
        let shutdown = shutdown.clone();
        let interval = cfg.subscriber_refresh_interval;
        async move {
            loop {
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => return,
                    () = tokio::time::sleep(interval) => {}
                }
                if let Err(err) = refresh_subscribers(store.as_ref(), &subscribers).await {
                    tracing::warn!(error = %err, "periodic subscriber refresh failed; keeping the current snapshot");
                }
            }
        }
    });

    // ── Emission (AlertDelivered usage facts) + the consume loop ───
    let sink: Arc<dyn EventSink> =
        Arc::new(KafkaEventSink::new(&cfg.kafka.brokers).context("building the Kafka producer")?);
    let consumer_handle = build_consumer(&cfg.kafka.brokers, &cfg.kafka.group_id)?;
    let engine = NotificationConsumer::new(store, channels, sink, subscribers, shutdown.clone());
    let result = engine.run(consumer_handle, RETRY_BACKOFF, &shutdown).await;

    shutdown.cancel();
    let _ = refresh_task.await;
    tracing::info!("notification shut down");
    result
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
