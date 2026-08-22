//! Predictive pipeline service binary (§16) — `MempoolSource → decode →
//! predict-engine → PredictedAlert`, plus (§16.1, Sprint 16 task 1) a second,
//! independent lending position tracker, plus (§16.2, Sprint 16 task 2) a
//! third, independent cascade engine — all three sharing this binary.
//!
//! Boot: connect the single mempool RPC endpoint, the intelligence gRPC
//! client, and the Kafka producer, then run six cooperating tasks until a
//! shutdown signal —
//!   1. the mempool **poller**, forwarding pending transactions over a
//!      bounded channel (§17 backpressure),
//!   2. the mempool **consumer**, deduping by tx hash, decoding, scoring against
//!      intelligence's cached labels, and publishing `PredictedAlert`,
//!   3. the **position-tracker consumer**, folding `BlockCanonicalized`/
//!      `BlockReverted` into the tracked lending position book (§15) — its
//!      tracker is `Arc<Mutex<_>>`-shared with task 5 and task 6, below,
//!   4. the oracle **price poller**, forwarding genuine mark-price updates
//!      over a second bounded channel,
//!   5. the **cascade engine**, recomputing health factors off the shared
//!      position tracker on every price update and publishing
//!      `LiquidationRiskPredicted` for every worsening risk-band crossing,
//!      then walking the reflexivity model (§16.3) off the same tick and
//!      publishing `LiquidationCascadeWarned` when liquidating the at-risk
//!      set would itself pull more positions underwater — its engine is also
//!      `Arc<Mutex<_>>`-shared with task 6, and
//!   6. the internal read API (§16.4, [`predictive::http`]) — live
//!      position/risk reads and a cascade what-if simulator over the same
//!      shared tracker/engine, Swagger-documented for hand testing.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use alloy_primitives::{Address, B256};
use anyhow::{Context, Result};
use detector_api::TokenMeta;
use event_bus::{publish_resilient, EventSink, KafkaEventSink, PUBLISH_BACKOFF};
use events::predictive::{LiquidationCascadeWarned, LiquidationRiskPredicted, PredictedAlert};
use events::primitives::{Confidence, PredictionId};
use events::{DomainEvent, EventEnvelope};
use predictive::cascade::{CascadeEngine, RiskThresholds};
use predictive::config::Config;
use predictive::http::{self as predictive_http, AppState};
use predictive::intel_client::{IntelligenceClient, LabelLookup};
use predictive::position::PositionTracker;
use predictive::position_consumer::{self, PositionConsumer};
use predictive::position_source::RpcLendingLogSource;
use predictive::price_source::{run_price_poller, PriceSource, PriceTick, RpcPriceSource};
use predictive::reflexivity::{self, ReflexivityLimits, SteppedImpactModel};
use predictive::source::{run_mempool_poller, MempoolSource, PendingTx, RpcMempoolSource};
use predictive::{decode, metrics as predictive_metrics, predict};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<()> {
    // Hold the guard for the lifetime of `main` so spans flush on exit (§19).
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env("predictive"))?;
    let cfg = Config::from_env()?;
    run(cfg).await
}

async fn run(cfg: Config) -> Result<()> {
    // Every series this per-chain instance exports carries its chain (§19).
    telemetry::metrics::init_labeled(cfg.metrics_addr, &[("chain", cfg.chain.metrics_label())])
        .context("starting the metrics exporter")?;

    tracing::info!(
        chain = cfg.chain.id(),
        mempool_rpc = %cfg.mempool_rpc_url,
        "starting predictive pipeline service"
    );

    let source: Arc<dyn MempoolSource> =
        Arc::new(RpcMempoolSource::new(cfg.mempool_rpc_url.clone()));
    let intel: Arc<dyn LabelLookup> = Arc::new(
        IntelligenceClient::connect_lazy(cfg.intelligence_grpc_addr.clone())
            .context("connecting to intelligence gRPC")?,
    );
    let sink: Arc<dyn EventSink> =
        Arc::new(KafkaEventSink::new(&cfg.kafka.brokers).context("building Kafka producer")?);
    let cascade_sink = Arc::clone(&sink);

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

    // Bounded channel = inter-stage backpressure (§17): if scoring/publishing
    // falls behind the mempool's tx rate, the poller blocks on send rather
    // than buffering unboundedly.
    let (tx, rx) = mpsc::channel::<PendingTx>(1024);

    let poller_task = tokio::spawn(run_mempool_poller(
        source,
        cfg.poll_interval,
        tx,
        shutdown.clone(),
    ));
    let consumer_task = tokio::spawn(run_consumer(
        rx,
        intel,
        sink,
        cfg.chain,
        cfg.dedup_capacity,
        shutdown.clone(),
    ));

    let position_dlq = event_bus::dlq::DeadLetterQueue::ensure_from_env(
        &cfg.kafka.brokers,
        "predictive-position-tracker",
    )
    .await
    .context("provisioning the position-tracker DLQ topic")?;
    let position_kafka_consumer =
        position_consumer::build_consumer(&cfg.kafka.brokers, &cfg.position_tracker.consumer_group)
            .context("building the position-tracker Kafka consumer")?;
    let position_log_source = RpcLendingLogSource::new(
        cfg.position_tracker.rpc_url.clone(),
        cfg.position_tracker.contract_addresses.clone(),
    );
    // Shared with the cascade engine below — task 2's whole point is reading
    // this same tracked book (see module docs).
    let position_tracker = Arc::new(Mutex::new(PositionTracker::new(
        cfg.position_tracker.window_blocks,
        cfg.position_tracker.liquidation_thresholds,
    )));
    let position_consumer = PositionConsumer::new(
        cfg.chain,
        position_log_source,
        Arc::clone(&position_tracker),
    );
    let position_shutdown = shutdown.clone();
    let position_task = tokio::spawn(async move {
        position_consumer
            .run(
                position_kafka_consumer,
                PUBLISH_BACKOFF,
                Some(&position_dlq),
                &position_shutdown,
            )
            .await
    });

    // Sprint 16 task 2 (§16.2): the oracle price poller and the cascade
    // engine it feeds, over their own bounded channel (§17).
    let price_source: Arc<dyn PriceSource> = Arc::new(RpcPriceSource::new(
        cfg.cascade.rpc_url.clone(),
        cfg.cascade.feeds.clone(),
    ));
    let assets: Arc<HashMap<Address, TokenMeta>> = Arc::new(
        cfg.cascade
            .feeds
            .iter()
            .map(|feed| {
                (
                    feed.asset,
                    TokenMeta::new(feed.asset, None, feed.asset_decimals),
                )
            })
            .collect(),
    );
    let (price_tx, price_rx) = mpsc::channel::<PriceTick>(1024);
    let price_poller_task = tokio::spawn(run_price_poller(
        price_source,
        cfg.cascade.poll_interval,
        price_tx,
        shutdown.clone(),
    ));
    // Shared with task 6's read API below — `Arc<Mutex<_>>` mirrors the
    // position tracker's own sharing discipline (see module docs).
    let cascade_engine = Arc::new(Mutex::new(CascadeEngine::new(cfg.cascade.thresholds)));
    let cascade_task = tokio::spawn(run_cascade(
        price_rx,
        Arc::clone(&position_tracker),
        Arc::clone(&cascade_engine),
        CascadeParams {
            assets: Arc::clone(&assets),
            thresholds: cfg.cascade.thresholds,
            reflexivity_limits: cfg.cascade.reflexivity,
            price_impact_model: cfg.cascade.price_impact,
            chain: cfg.chain,
        },
        cascade_sink,
        shutdown.clone(),
    ));

    // Sprint 16 task 4 (§16.4): the internal read API, sharing the same
    // tracker/engine every other task reads/writes — never a second copy of
    // live state.
    let http_state = AppState {
        tracker: position_tracker,
        engine: cascade_engine,
        assets,
        thresholds: cfg.cascade.thresholds,
        reflexivity_limits: cfg.cascade.reflexivity,
        price_impact_model: cfg.cascade.price_impact,
    };
    let http_listener = tokio::net::TcpListener::bind(cfg.http_addr)
        .await
        .with_context(|| format!("binding predictive HTTP listener on {}", cfg.http_addr))?;
    tracing::info!(addr = %cfg.http_addr, "predictive read API listening");
    let http_shutdown = shutdown.clone();
    let http_task = tokio::spawn(async move {
        axum::serve(http_listener, predictive_http::router(http_state))
            .with_graceful_shutdown(async move { http_shutdown.cancelled().await })
            .await
    });

    health.set_ready(true);

    poller_task.await.context("mempool poller task panicked")?;
    consumer_task.await.context("consumer task panicked")?;
    position_task
        .await
        .context("position-tracker task panicked")??;
    price_poller_task
        .await
        .context("oracle price poller task panicked")?;
    cascade_task.await.context("cascade engine task panicked")?;
    http_task
        .await
        .context("HTTP server task panicked")?
        .context("HTTP server error")?;
    tracing::info!("predictive pipeline shut down");
    Ok(())
}

/// Drain pending transactions off `rx`: dedup by hash, decode, score against
/// intelligence's cached labels, and publish any resulting `PredictedAlert`.
/// Returns when `rx` closes (the poller stopped) or `shutdown` fires.
async fn run_consumer(
    mut rx: mpsc::Receiver<PendingTx>,
    intel: Arc<dyn LabelLookup>,
    sink: Arc<dyn EventSink>,
    chain: events::primitives::Chain,
    dedup_capacity: usize,
    shutdown: CancellationToken,
) {
    let mut seen = SeenTxs::new(dedup_capacity);

    loop {
        let pending = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                tracing::info!("predictive consumer shutting down");
                return;
            }
            pending = rx.recv() => match pending {
                Some(pending) => pending,
                None => {
                    tracing::info!("mempool source stopped; predictive consumer exiting");
                    return;
                }
            },
        };

        if !seen.insert(pending.hash) {
            continue; // already scored this tx on an earlier poll
        }

        let actions = decode::decode_tx(&pending);
        let Some(prediction) = predict::predict(&actions, intel.as_ref()).await else {
            continue;
        };

        let alert = PredictedAlert {
            prediction_id: PredictionId::new(),
            tx_hash: prediction.tx_hash,
            addresses: prediction.addresses,
            kind: prediction.kind,
            confidence: prediction.confidence,
            provisional: true,
        };
        let envelope = EventEnvelope::new(chain, DomainEvent::PredictedAlert(alert));
        publish_resilient(sink.as_ref(), envelope, PUBLISH_BACKOFF, &shutdown).await;
    }
}

/// [`run_cascade`]'s fixed (non-channel, non-shared-state) configuration,
/// grouped into one struct so the function stays under clippy's argument-count
/// lint rather than growing a ninth positional parameter.
struct CascadeParams {
    assets: Arc<HashMap<Address, TokenMeta>>,
    thresholds: RiskThresholds,
    reflexivity_limits: ReflexivityLimits,
    price_impact_model: SteppedImpactModel,
    chain: events::primitives::Chain,
}

/// Drain oracle price ticks off `rx`: fold each into the shared cascade
/// engine against the shared position tracker's current snapshot, publish a
/// `LiquidationRiskPredicted` for every worsening risk-band crossing, then
/// walk the reflexivity model (§16.3, Sprint 16 task 3) off the same tick and
/// publish a `LiquidationCascadeWarned` if it finds reflexive growth beyond
/// the plain at-risk set. Returns when `rx` closes (the price poller stopped)
/// or `shutdown` fires — mirrors [`run_consumer`]'s shape one channel-driven
/// stage over.
///
/// `engine` is `Arc<Mutex<_>>`-shared with the read API (§16.4) rather than
/// owned locally, so a live `GET /v1/positions` sees the exact price cache
/// this task just folded a tick into, never a second, potentially-stale copy.
async fn run_cascade(
    mut rx: mpsc::Receiver<PriceTick>,
    tracker: Arc<Mutex<PositionTracker>>,
    engine: Arc<Mutex<CascadeEngine>>,
    params: CascadeParams,
    sink: Arc<dyn EventSink>,
    shutdown: CancellationToken,
) {
    let CascadeParams {
        assets,
        thresholds,
        reflexivity_limits,
        price_impact_model,
        chain,
    } = params;

    loop {
        let tick = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                tracing::info!("cascade engine shutting down");
                return;
            }
            tick = rx.recv() => match tick {
                Some(tick) => tick,
                None => {
                    tracing::info!("oracle price source stopped; cascade engine exiting");
                    return;
                }
            },
        };

        // Clone the `Arc<PositionState>` snapshot out and drop the lock
        // immediately, rather than holding it for the O(open positions) cost
        // of `on_price_tick`/the reflexivity walk below — the position-tracker
        // consumer's writer (folding the next canonical block) must never
        // stall behind this reader's valuation pass.
        let snapshot = tracker.lock().unwrap().snapshot();
        let (worsened, outcome) = match &snapshot {
            Some(positions) => {
                // Held only for this synchronous mutate-then-read — no
                // `.await` inside — so a concurrent `GET /v1/positions`
                // never blocks longer than one tick's fold.
                let mut engine = engine.lock().unwrap();
                let worsened = engine.on_price_tick(tick, &assets, positions);
                // Reads the engine's price cache *after* folding this tick in,
                // so the walk reasons over the same real prices the worsening
                // pass above just computed against.
                let outcome = reflexivity::detect_cascade(
                    tick,
                    &assets,
                    engine.prices(),
                    positions,
                    &thresholds,
                    &reflexivity_limits,
                    &price_impact_model,
                );
                predictive_metrics::record_cascade_walk(&outcome);
                (worsened, outcome)
            }
            None => (Vec::new(), reflexivity::CascadeOutcome::default()),
        };

        for (key, assessment) in worsened {
            let alert = LiquidationRiskPredicted {
                prediction_id: PredictionId::new(),
                protocol: key.protocol,
                account: key.account,
                health_factor: assessment.health_factor,
                distance_pct: assessment.distance_pct,
                severity: assessment.severity,
                confidence: Confidence::CERTAIN,
                provisional: true,
            };
            let envelope = EventEnvelope::new(chain, DomainEvent::LiquidationRiskPredicted(alert));
            publish_resilient(sink.as_ref(), envelope, PUBLISH_BACKOFF, &shutdown).await;
        }

        let reflexivity::CascadeOutcome {
            warning,
            hub_capped,
        } = outcome;
        if let Some(warning) = warning {
            let alert = LiquidationCascadeWarned {
                prediction_id: PredictionId::new(),
                trigger_asset: warning.trigger_asset,
                trigger_price: warning.trigger_price,
                reflexive_depth: warning.reflexive_depth,
                accounts: warning.accounts,
                aggregate_at_risk_usd: warning.aggregate_at_risk_usd,
                hub_capped,
                confidence: Confidence::CERTAIN,
                provisional: true,
            };
            let envelope = EventEnvelope::new(chain, DomainEvent::LiquidationCascadeWarned(alert));
            publish_resilient(sink.as_ref(), envelope, PUBLISH_BACKOFF, &shutdown).await;
        }
    }
}

/// A capacity-bounded set of already-scored tx hashes: the mempool
/// re-announces the same pending transaction across multiple polls, and this
/// stops it from being decoded/scored/published more than once. Oldest entry
/// is evicted once `capacity` is reached (a FIFO ring, not an LRU — recency
/// of *insertion*, not of re-sight, is what bounds memory here).
struct SeenTxs {
    capacity: usize,
    set: HashSet<B256>,
    order: VecDeque<B256>,
}

impl SeenTxs {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            set: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// Record `hash` as seen. Returns `true` if it was newly inserted (not
    /// seen before), `false` if it was already present.
    fn insert(&mut self, hash: B256) -> bool {
        if !self.set.insert(hash) {
            return false;
        }
        self.order.push_back(hash);
        if self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.set.remove(&oldest);
            }
        }
        true
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seen_txs_dedups_and_evicts_oldest_past_capacity() {
        let mut seen = SeenTxs::new(2);
        let a = B256::repeat_byte(1);
        let b = B256::repeat_byte(2);
        let c = B256::repeat_byte(3);

        assert!(seen.insert(a));
        assert!(!seen.insert(a), "a duplicate insert must report false");
        assert!(seen.insert(b));
        assert!(seen.insert(c), "c pushes a out past capacity 2");
        assert!(seen.insert(a), "a was evicted, so it's new again");
    }
}
