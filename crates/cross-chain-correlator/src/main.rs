//! Cross-chain correlator service binary (§17, §24, Sprint 17 t1+t2, plus
//! production hardening) — boot:
//!
//! 1. provision the leg-buffer changelog topic and replay it
//!    ([`changelog::replay`]) to warm-start every actor's buffer, then do the
//!    same for the finding-finality changelog ([`finding_changelog::replay`],
//!    §15, Sprint 17 task 3) to warm-start which findings were still
//!    awaiting finality;
//! 2. for every bridge/pair *this replica owns*
//!    ([`Config::owned_bridges_or_pairs`], production hardening's
//!    horizontal-sharding seam), spawn its [`CorrelationActor`] — sharing
//!    one Kafka producer for findings and one for the changelog across every
//!    actor;
//! 3. for every configured chain, spawn a dedicated [`ChainConsumer`] task
//!    that filters to that chain, dedupes Kafka redeliveries, and routes any
//!    leg [`EvidenceLegExtractor`] recognizes to its actor over the shared
//!    [`LegRouter`] (never blocking on a stalled actor — see `router`'s
//!    docs);
//! 4. spawn one [`FinalityConsumer`] task (§15, Sprint 17 task 3) sharing
//!    every actor's [`SharedFindingFinalityTracker`], broadcast-subscribed
//!    to `BlockReverted`/`BlockFinalized` so a reorg on any configured chain
//!    retracts whichever findings it orphaned — see `finality` module docs.
//!
//! See `lib.rs` for the full module map and the "Production hardening"
//! section.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use cross_chain_correlator::actor::CorrelationActor;
use cross_chain_correlator::chain_consumer::{self, ChainConsumer};
use cross_chain_correlator::changelog::{self, ChangelogSink, ChangelogWriter};
use cross_chain_correlator::config::Config;
use cross_chain_correlator::finality::{self, FinalityConsumer, SharedFindingFinalityTracker};
use cross_chain_correlator::finding_changelog::{
    self, FindingChangelogSink, FindingChangelogWriter,
};
use cross_chain_correlator::leg::{BridgeOrPair, CandidateLeg, EvidenceLegExtractor};
use cross_chain_correlator::router::LegRouter;
use event_bus::dlq::DeadLetterQueue;
use event_bus::{EventSink, KafkaEventSink, PUBLISH_BACKOFF};
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
    let owned_bridges_or_pairs = cfg.owned_bridges_or_pairs();
    tracing::info!(
        chains = cfg.chains.len(),
        bridges_or_pairs = cfg.bridges_or_pairs.len(),
        owned_bridges_or_pairs = owned_bridges_or_pairs.len(),
        replica_index = cfg.replica_index,
        replica_count = cfg.replica_count,
        "starting cross-chain correlator"
    );
    if cfg.replica_count > 1
        && !cfg.bridges_or_pairs.is_empty()
        && owned_bridges_or_pairs.is_empty()
    {
        tracing::warn!(
            replica_index = cfg.replica_index,
            replica_count = cfg.replica_count,
            "this replica owns zero of the configured bridges/pairs after sharding \
             (more replicas than bridges/pairs) — it will boot but correlate nothing"
        );
    }

    let sink: Arc<dyn EventSink> =
        Arc::new(KafkaEventSink::new(&cfg.kafka.brokers).context("building Kafka producer")?);

    // ── Leg-buffer changelog: provision + replay before anything else
    // starts consuming live legs, so a warm-started actor never processes a
    // live leg against a still-empty buffer while replay is in flight
    // (production hardening, `changelog` module docs) ─────────────────────
    let topic_replication = telemetry::env::parse_or("KAFKA_TOPIC_REPLICATION", 1)?;
    ChangelogWriter::ensure_topic(
        &cfg.kafka.brokers,
        topic_replication,
        cfg.changelog_retention_ms,
    )
    .await
    .context("provisioning the leg-changelog topic")?;
    let changelog: Arc<dyn ChangelogSink> = Arc::new(
        ChangelogWriter::new(&cfg.kafka.brokers).context("building the leg-changelog producer")?,
    );
    let mut replayed_state = changelog::replay(
        &cfg.kafka.brokers,
        &cfg.consumer_group_prefix,
        cfg.replica_index,
        cfg.changelog_replay_timeout,
    )
    .await
    .context("replaying the leg-changelog")?;

    // ── Finding-finality changelog: same provision-then-replay-before-live-
    // traffic discipline as the leg changelog above, for the same reason
    // (`crate::finding_changelog` module docs, Sprint 17 task 3) ───────────
    FindingChangelogWriter::ensure_topic(
        &cfg.kafka.brokers,
        topic_replication,
        cfg.finding_changelog_retention_ms,
    )
    .await
    .context("provisioning the finding-changelog topic")?;
    let finding_changelog_sink: Arc<dyn FindingChangelogSink> = Arc::new(
        FindingChangelogWriter::new(&cfg.kafka.brokers)
            .context("building the finding-changelog producer")?,
    );
    let replayed_finality_tracker = finding_changelog::replay(
        &cfg.kafka.brokers,
        &cfg.consumer_group_prefix,
        cfg.replica_index,
        cfg.finding_changelog_replay_timeout,
        cfg.finding_retention,
        cfg.finding_capacity,
    )
    .await
    .context("replaying the finding-changelog")?;

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

    // ── Cross-chain finality/reorg retraction (§15, Sprint 17 task 3):
    // shared by every actor below (writer via `record_finding`) and the one
    // finality consumer task spawned further down (writer via
    // `on_block_reverted`/`on_block_finalized`) — warm-started from the
    // finding-changelog replay above, see `finality`/`finding_changelog`
    // module docs ─────────────────────────────────────────────────────────
    let finality_tracker = SharedFindingFinalityTracker::from_tracker(
        replayed_finality_tracker,
        finding_changelog_sink,
        shutdown.clone(),
    );

    // ── One correlation actor per bridge/pair this replica owns (§17,
    // production hardening's horizontal-sharding seam) ─────────────────
    let mut senders: HashMap<BridgeOrPair, mpsc::Sender<CandidateLeg>> = HashMap::new();
    let mut actor_tasks = Vec::new();
    for bridge_or_pair in &owned_bridges_or_pairs {
        let (tx, rx) = mpsc::channel::<CandidateLeg>(cfg.actor_channel_capacity);
        senders.insert(bridge_or_pair.clone(), tx);
        let seed = replayed_state.remove(bridge_or_pair).unwrap_or_default();
        let actor = CorrelationActor::new_with_seed(
            bridge_or_pair.clone(),
            cfg.leg_window,
            cfg.leg_buffer_capacity,
            seed,
        );
        actor_tasks.push(tokio::spawn(actor.run(
            rx,
            Arc::clone(&sink),
            Arc::clone(&changelog),
            Arc::clone(&finality_tracker),
            PUBLISH_BACKOFF,
            shutdown.clone(),
        )));
    }
    if !replayed_state.is_empty() {
        tracing::warn!(
            unowned_bridges_or_pairs = replayed_state.len(),
            "leg-changelog replay found state for bridges/pairs this replica doesn't own \
             (a different replica's, or one removed from the roster) — discarding it"
        );
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

    // ── The one finality/reorg-retraction consumer (§15, Sprint 17 task 3):
    // a broadcast consumer, unique group per replica — every replica must
    // see every chain's `BlockReverted`/`BlockFinalized` (see `finality`
    // module docs) ───────────────────────────────────────────────────────
    let finality_group_id = format!(
        "{}-r{}-finality",
        cfg.consumer_group_prefix, cfg.replica_index
    );
    let finality_consumer =
        finality::build_broadcast_consumer(&cfg.kafka.brokers, &finality_group_id)
            .context("building the Kafka consumer for finality/reorg tracking")?;
    let finality_task = tokio::spawn(
        FinalityConsumer::new(finality_tracker, Arc::clone(&sink), shutdown.clone())
            .run(finality_consumer, RETRY_BACKOFF),
    );

    health.set_ready(true);

    for task in actor_tasks {
        task.await.context("correlation actor task panicked")?;
    }
    for task in consumer_tasks {
        task.await.context("chain consumer task panicked")??;
    }
    finality_task
        .await
        .context("finality consumer task panicked")?
        .context("finality consumer task failed")?;
    tracing::info!("cross-chain correlator shut down");
    Ok(())
}

/// Build and run one chain's [`ChainConsumer`] — its own Kafka consumer group
/// (per-replica too, once sharded — see
/// `Config::consumer_group_for`'s docs) and DLQ (see `chain_consumer` module
/// docs for why every chain needs its own group), so a chain whose consumer
/// can't subscribe (a broker blip at exactly the wrong moment) doesn't take
/// any other chain's task down with it; each chain's own retry loop is
/// `event_bus::run_consumer`'s internal transient-fault handling, not a
/// supervisor here (contrast `notification`'s opt-in predictive consumer,
/// which layers one because it alone can die silently on a *subscribe*
/// failure with nothing else watching — every chain consumer here is joined
/// and its `Err` surfaces the same way).
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
    let extractor = EvidenceLegExtractor::new(
        cfg.bridge_deposit_detector_ids.clone(),
        cfg.large_swap_detector_ids.clone(),
    );
    let handler = ChainConsumer::new(chain, router, extractor, cfg.dedup_capacity);
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
