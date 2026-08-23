//! Cross-chain correlator service binary (§17, §24, Sprint 17 t1) — boot: for
//! every configured bridge/pair, spawn its [`CorrelationActor`]; for every
//! configured chain, spawn a dedicated [`ChainConsumer`] task that filters to
//! that chain and routes any recognized candidate leg to its actor over the
//! shared [`LegRouter`]. See `lib.rs` for the module docs and this pass's
//! scope (the consumer/actor/buffer skeleton — leg recognition is task 2).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use cross_chain_correlator::actor::CorrelationActor;
use cross_chain_correlator::chain_consumer::{self, ChainConsumer};
use cross_chain_correlator::config::Config;
use cross_chain_correlator::leg::{BridgeOrPair, CandidateLeg, StubExtractor};
use cross_chain_correlator::router::LegRouter;
use event_bus::dlq::DeadLetterQueue;
use events::primitives::Chain;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Back-off before a chain consumer retries a transiently-failed record —
/// mirrors `notification`/`predictive`'s retry policy.
const RETRY_BACKOFF: Duration = Duration::from_secs(1);

#[tokio::main]
async fn main() -> Result<()> {
    // Hold the guard for the lifetime of `main` so spans flush on exit (§19).
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env(
        "cross-chain-correlator",
    ))?;
    let cfg = Config::from_env()?;
    run(cfg).await
}

async fn run(cfg: Config) -> Result<()> {
    telemetry::metrics::init(cfg.metrics_addr).context("starting the metrics exporter")?;
    tracing::info!(
        chains = cfg.chains.len(),
        bridges_or_pairs = cfg.bridges_or_pairs.len(),
        "starting cross-chain correlator"
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

    // ── One correlation actor per bridge/pair (§17) ─────────────────────
    let mut senders: HashMap<BridgeOrPair, mpsc::Sender<CandidateLeg>> = HashMap::new();
    let mut actor_tasks = Vec::new();
    for bridge_or_pair in &cfg.bridges_or_pairs {
        let (tx, rx) = mpsc::channel::<CandidateLeg>(cfg.actor_channel_capacity);
        senders.insert(bridge_or_pair.clone(), tx);
        let actor = CorrelationActor::new(
            bridge_or_pair.clone(),
            cfg.leg_window,
            cfg.leg_buffer_capacity,
        );
        actor_tasks.push(tokio::spawn(actor.run(rx, shutdown.clone())));
    }
    let router = Arc::new(LegRouter::new(senders));

    // ── One consumer per chain (§17), all feeding the shared router ────
    let mut consumer_tasks = Vec::new();
    for &chain in &cfg.chains {
        consumer_tasks.push(tokio::spawn(run_chain_consumer(
            chain,
            cfg.clone(),
            Arc::clone(&router),
            shutdown.clone(),
        )));
    }

    health.set_ready(true);

    for task in actor_tasks {
        task.await.context("correlation actor task panicked")?;
    }
    for task in consumer_tasks {
        task.await.context("chain consumer task panicked")??;
    }
    tracing::info!("cross-chain correlator shut down");
    Ok(())
}

/// Build and run one chain's [`ChainConsumer`] — its own Kafka consumer group
/// and DLQ (see `chain_consumer` module docs for why every chain needs its
/// own group), so a chain whose consumer can't subscribe (a broker blip at
/// exactly the wrong moment) doesn't take any other chain's task down with
/// it; each chain's own retry loop is `event_bus::run_consumer`'s internal
/// transient-fault handling, not a supervisor here (contrast
/// `notification`'s opt-in predictive consumer, which layers one because it
/// alone can die silently on a *subscribe* failure with nothing else
/// watching — every chain consumer here is joined and its `Err` surfaces the
/// same way).
async fn run_chain_consumer(
    chain: Chain,
    cfg: Config,
    router: Arc<LegRouter>,
    shutdown: CancellationToken,
) -> Result<()> {
    let group_id = cfg.consumer_group_for(chain);
    let dlq = DeadLetterQueue::ensure_from_env(&cfg.kafka.brokers, &group_id)
        .await
        .with_context(|| format!("provisioning the DLQ topic for chain {}", chain.id()))?;
    let consumer = chain_consumer::build_consumer(&cfg.kafka.brokers, &group_id)
        .with_context(|| format!("building the Kafka consumer for chain {}", chain.id()))?;
    // `StubExtractor` until Sprint 17 task 2 lands a real `LegExtractor` —
    // swapping it in is the only change this call site needs (see
    // `chain_consumer` module docs).
    let handler = ChainConsumer::new(chain, router, StubExtractor);
    handler
        .run(consumer, RETRY_BACKOFF, Some(&dlq), &shutdown)
        .await
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
