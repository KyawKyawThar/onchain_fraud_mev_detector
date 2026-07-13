//! Rule-engine service binary (§9, Sprint 9 t4) — the long-running Kafka
//! consumer that evaluates every customer's enabled rules over the enriched
//! event stream and emits `RuleTriggered`/`RuleAlertCreated` (§2).
//!
//! Boot: observability → config → fail-fast store probes → **link-or-fail**
//! rule compile (a malformed stored definition stops the boot with the rule
//! id in the error, the DetectionPlan discipline) → spawn the temporal pool,
//! the fire-drain task (separate from the consume loop — see `worker.rs`'s
//! deadlock note) and the periodic backstop refresh → drive the consumer
//! until a shutdown signal.
//!
//! Subcommands, mirroring the other service binaries:
//!   - `run` (default; also the no-arg run) — the consumer described above.
//!   - `ping` — connect and probe Postgres (rules schema) + Redis, so a
//!     misconfigured deployment fails fast and visibly.
//!
//! Action delivery goes through the `ActionSink` seam; production is
//! [`WebhookActionSink`] (t5) — webhook actions POST to the customer's
//! endpoint with bounded retry, the §12 channels log until Sprint 10 (the §2
//! events are published regardless — they are the durable output).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use event_bus::KafkaEventSink;
use intelligence::cache::RedisHotCache;
use intelligence::store::{PgIntelligenceStore, StoreSeams};
use rule_engine::compile::{CompiledRuleSet, RuleSetHandle};
use rule_engine::config::Config;
use rule_engine::consumer::{
    build_consumer, drain_fires, refresh_rules, EngineConsumer, FireEmitter,
};
use rule_engine::enrich::IntelligenceEnrichment;
use rule_engine::state_store::RedisTemporalStore;
use rule_engine::store::{PgRuleStore, RuleStore};
use rule_engine::webhook::WebhookActionSink;
use rule_engine::worker::{PoolConfig, TemporalPool};
use secrecy::ExposeSecret;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const USAGE: &str = "expected `run` (also the no-arg default) or `ping`";

/// Back-off before the consume loop retries a transiently-failed record.
const RETRY_BACKOFF: Duration = Duration::from_secs(1);

#[tokio::main]
async fn main() -> Result<()> {
    // Hold the guard for the lifetime of `main` so spans flush on exit (§19).
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env("rule-engine"))?;
    let cfg = Config::from_env()?;

    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("run") | None => run(&cfg).await,
        Some("ping") => ping(&cfg).await,
        Some(other) => bail!("unknown argument {other:?}; {USAGE}"),
    }
}

/// Probe every store this service depends on — a misconfigured deployment
/// fails here, loudly, not at the first consumed event.
async fn ping(cfg: &Config) -> Result<()> {
    let pool = db::connect(cfg.database_url.expose_secret()).await?;
    PgRuleStore::new(pool)
        .ping()
        .await
        .context("Postgres rules schema probe failed")?;
    RedisTemporalStore::connect(cfg.redis_url.expose_secret())
        .await
        .context("Redis probe failed")?;
    println!("ok: postgres (rules schema) + redis reachable");
    Ok(())
}

async fn run(cfg: &Config) -> Result<()> {
    telemetry::metrics::init(cfg.metrics_addr).context("starting the metrics exporter")?;
    tracing::info!(
        schema_version = events::SCHEMA_VERSION,
        "rule-engine starting"
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

    // ── Stores (fail-fast) ─────────────────────────────────────────
    let pool = db::connect(cfg.database_url.expose_secret()).await?;
    let store: Arc<dyn RuleStore> = Arc::new(PgRuleStore::new(pool.clone()));
    PgRuleStore::new(pool.clone())
        .ping()
        .await
        .context("rules schema not reachable — run `just migrate-up`?")?;

    // The enrichment adapter reads the intelligence stores/hot cache through
    // that crate's own seams — see `rule_engine::enrich`'s module docs.
    let intel = Arc::new(PgIntelligenceStore::new(pool));
    let cache = Arc::new(
        RedisHotCache::connect(cfg.redis_url.expose_secret(), cfg.cache_ttl)
            .await
            .map_err(|err| anyhow::anyhow!("connecting the intelligence hot cache: {err}"))?,
    );
    let enrichment = Arc::new(IntelligenceEnrichment::new(
        StoreSeams::single(intel),
        cache,
    ));

    let temporal_store = Arc::new(
        RedisTemporalStore::connect(cfg.redis_url.expose_secret())
            .await
            .map_err(|err| anyhow::anyhow!("connecting the temporal state store: {err}"))?,
    );

    // ── Compile the enabled set (link-or-fail at boot) ─────────────
    let enabled = store
        .enabled_rules()
        .await
        .context("loading the enabled rule set")?;
    let compiled = CompiledRuleSet::compile(&enabled).context("compiling the enabled rule set")?;
    tracing::info!(rules = compiled.len(), "rule set compiled");
    let rules = Arc::new(RuleSetHandle::new(compiled));

    // ── Emission + temporal pool + fire drain ──────────────────────
    let sink =
        Arc::new(KafkaEventSink::new(&cfg.kafka.brokers).context("building the Kafka producer")?);
    let actions = Arc::new(
        WebhookActionSink::new(cfg.webhook, shutdown.clone())
            .context("building the webhook delivery client")?,
    );
    let emitter = Arc::new(FireEmitter::new(sink, actions, shutdown.clone()));

    let (fires_tx, fires_rx) = mpsc::channel(cfg.fires_capacity);
    let pool = TemporalPool::spawn(
        PoolConfig::default(),
        Arc::clone(&rules),
        temporal_store,
        fires_tx,
        shutdown.clone(),
    );
    // Separate task, per the worker.rs deadlock note: never drain fires from
    // the task that steps/flushes.
    let drain_task = tokio::spawn(drain_fires(Arc::clone(&emitter), fires_rx));

    // ── Periodic backstop refresh (RuleCreated refreshes immediately) ──
    let refresh_task = tokio::spawn({
        let store = Arc::clone(&store);
        let rules = Arc::clone(&rules);
        let shutdown = shutdown.clone();
        let interval = cfg.refresh_interval;
        async move {
            loop {
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => return,
                    () = tokio::time::sleep(interval) => {}
                }
                if let Err(err) = refresh_rules(store.as_ref(), &rules).await {
                    tracing::warn!(error = %err, "periodic rule refresh failed; keeping the current set");
                }
            }
        }
    });

    // ── The consume loop ───────────────────────────────────────────
    let consumer = build_consumer(&cfg.kafka.brokers, &cfg.kafka.group_id)?;
    let engine = EngineConsumer::new(rules, store, enrichment, pool, emitter, shutdown.clone());
    let result = engine.run(consumer, RETRY_BACKOFF, &shutdown).await;

    // The consumer (and with it the pool + fire senders) is gone — the drain
    // task ends when the channel closes.
    shutdown.cancel();
    let _ = drain_task.await;
    let _ = refresh_task.await;
    tracing::info!("rule-engine shut down");
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
