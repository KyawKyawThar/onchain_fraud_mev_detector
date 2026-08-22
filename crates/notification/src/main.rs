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
//!
//! §16.4 (Sprint 16 task 4) adds a second, **opt-in** consumer task —
//! `PredictedAlert`/`LiquidationRiskPredicted`/`LiquidationCascadeWarned`,
//! each already on its own topic (§2), routed to risk-desk subscribers
//! filtered on `AlertKind::Liquidation`. It only spawns when
//! `NOTIFICATION_PREDICTIVE_ENABLED=true` ([`Config::predictive`]), and runs
//! on its own consumer group/DLQ so a lagging or down predictive pipeline
//! can never stall the incident-stream consumer above.
//!
//! ## Predictive consumer supervision
//!
//! `event_bus::run_consumer`'s only *unsolicited* early exit is a failed
//! initial `consumer.subscribe(topics)` — a transport receive error just
//! logs and loops, and every other exit path is already shutdown-gated. So
//! the one real risk for a task nobody is watching is: broker unreachable
//! (or the topic not yet provisioned) at the exact moment this task boots,
//! and it dies once, silently, for the rest of the process's life — the
//! incident-stream consumer keeps running and nothing else would notice
//! short of reading logs. [`run_predictive_supervised`] closes that gap: a
//! retry-with-backoff loop around a fresh [`PredictiveConsumer`]/consumer
//! handle on every attempt (both are consumed by `run`, so they can't be
//! reused across retries), plus a `notification_predictive_consumer_up`
//! gauge (§19) so the gap between "the task should be running" and "it
//! actually is" is an alertable metric, not just a log line — `health.
//! set_ready(true)` alone doesn't reflect it, since K8s readiness here only
//! ever meant "boot wiring completed."

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use event_bus::dlq::DeadLetterQueue;
use event_bus::{EventSink, KafkaEventSink};
use notification::config::Config;
use notification::consumer::{
    build_consumer, build_predictive_consumer, NotificationConsumer, PredictiveConsumer,
    PREDICTIVE_CONSUMER_UP,
};
use notification::delivery::ChannelSink;
use notification::email_delivery::EmailDelivery;
use notification::http_delivery::HttpDelivery;
use notification::sink::MultiChannelSink;
use notification::store::{NotificationStore, PgNotificationStore};
use notification::subscriber_cache::{refresh_subscribers, SubscriberSetHandle};
use secrecy::ExposeSecret;
use tokio_util::sync::CancellationToken;

const USAGE: &str = "expected `run` (also the no-arg default) or `ping`";

/// Back-off before the consume loop retries a transiently-failed record —
/// also reused as the predictive supervisor's re-subscribe backoff (see the
/// module docs), so a flapping broker doesn't get hammered at a different
/// cadence than every other retry policy in this binary.
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
    // The uniform poison policy (§20): parked-not-lost, provisioned fail-fast.
    let dlq = event_bus::dlq::DeadLetterQueue::ensure_from_env(&cfg.kafka.brokers, "notification")
        .await
        .context("provisioning the notification DLQ topic")?;

    // ── §16.4 (Sprint 16 task 4): the opt-in predictive-events consumer —
    // a second, independent, *supervised* task sharing this binary's
    // store/channels/sink/subscriber snapshot (cheap `Arc` clones), but its
    // own Kafka consumer group and DLQ, so a lagging or down predictive
    // pipeline can never stall the incident-stream consumer below (see the
    // module docs).
    let predictive_task = if cfg.predictive.enabled {
        let predictive_dlq = event_bus::dlq::DeadLetterQueue::ensure_from_env(
            &cfg.kafka.brokers,
            "notification-predictive",
        )
        .await
        .context("provisioning the notification-predictive DLQ topic")?;
        let predictive_cfg = cfg.clone();
        let predictive_collaborators = (
            Arc::clone(&store),
            Arc::clone(&channels),
            Arc::clone(&sink),
            Arc::clone(&subscribers),
        );
        let predictive_shutdown = shutdown.clone();
        Some(tokio::spawn(async move {
            let (store, channels, sink, subscribers) = predictive_collaborators;
            run_predictive_supervised(
                &predictive_cfg,
                store,
                channels,
                sink,
                subscribers,
                &predictive_dlq,
                predictive_shutdown,
            )
            .await;
        }))
    } else {
        tracing::info!("predictive-events consumer disabled (NOTIFICATION_PREDICTIVE_ENABLED)");
        None
    };

    let engine = NotificationConsumer::new(store, channels, sink, subscribers, shutdown.clone());
    health.set_ready(true);
    let result = engine
        .run(consumer_handle, RETRY_BACKOFF, Some(&dlq), &shutdown)
        .await;

    shutdown.cancel();
    if let Some(task) = predictive_task {
        // `run_predictive_supervised` never returns `Err` — a subscribe
        // failure retries internally — so the only failure mode left here is
        // the task itself panicking.
        if let Err(err) = task.await {
            tracing::warn!(error = %err, "predictive consumer task panicked");
        }
    }
    let _ = refresh_task.await;
    tracing::info!("notification shut down");
    result
}

/// Run [`PredictiveConsumer`] until `shutdown` fires, retrying with
/// [`RETRY_BACKOFF`] on anything short of a clean shutdown-driven exit (see
/// the module docs for exactly what that covers) — a fresh consumer handle
/// and [`PredictiveConsumer`] every attempt, since both are consumed by
/// `run`. Sets [`PREDICTIVE_CONSUMER_UP`] for the duration of each attempt
/// so "the task is supposed to be running but isn't" is an alertable gauge,
/// not just a log line.
#[allow(clippy::too_many_arguments)]
async fn run_predictive_supervised(
    cfg: &Config,
    store: Arc<dyn NotificationStore>,
    channels: Arc<dyn ChannelSink>,
    sink: Arc<dyn EventSink>,
    subscribers: Arc<SubscriberSetHandle>,
    dlq: &DeadLetterQueue,
    shutdown: CancellationToken,
) {
    metrics::gauge!(PREDICTIVE_CONSUMER_UP).set(0.0);
    while !shutdown.is_cancelled() {
        let consumer_handle =
            match build_predictive_consumer(&cfg.kafka.brokers, &cfg.predictive.group_id) {
                Ok(handle) => handle,
                Err(err) => {
                    tracing::error!(
                        error = %err,
                        "failed to build the predictive Kafka consumer; retrying"
                    );
                    tokio::select! {
                        () = shutdown.cancelled() => break,
                        () = tokio::time::sleep(RETRY_BACKOFF) => continue,
                    }
                }
            };

        let engine = PredictiveConsumer::new(
            Arc::clone(&store),
            Arc::clone(&channels),
            Arc::clone(&sink),
            Arc::clone(&subscribers),
            shutdown.clone(),
        );

        metrics::gauge!(PREDICTIVE_CONSUMER_UP).set(1.0);
        let result = engine
            .run(consumer_handle, RETRY_BACKOFF, Some(dlq), &shutdown)
            .await;
        metrics::gauge!(PREDICTIVE_CONSUMER_UP).set(0.0);

        match result {
            // Only ever reached via a shutdown-gated path (see the module
            // docs) — nothing left to retry.
            Ok(()) => break,
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "predictive consumer exited unexpectedly; retrying after backoff"
                );
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(RETRY_BACKOFF) => {}
                }
            }
        }
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
