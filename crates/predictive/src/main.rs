//! Predictive pipeline service binary (§16) — `MempoolSource → decode →
//! predict-engine → PredictedAlert`.
//!
//! Boot: connect the single mempool RPC endpoint, the intelligence gRPC
//! client, and the Kafka producer, then run two cooperating tasks until a
//! shutdown signal —
//!   1. the mempool **poller**, forwarding pending transactions over a
//!      bounded channel (§17 backpressure), and
//!   2. the **consumer**, deduping by tx hash, decoding, scoring against
//!      intelligence's cached labels, and publishing `PredictedAlert`.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use alloy_primitives::B256;
use anyhow::{Context, Result};
use event_bus::{publish_resilient, EventSink, KafkaEventSink, PUBLISH_BACKOFF};
use events::predictive::PredictedAlert;
use events::primitives::PredictionId;
use events::{DomainEvent, EventEnvelope};
use predictive::config::Config;
use predictive::intel_client::{IntelligenceClient, LabelLookup};
use predictive::source::{run_mempool_poller, MempoolSource, PendingTx, RpcMempoolSource};
use predictive::{decode, predict};
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
    telemetry::metrics::init(cfg.metrics_addr).context("starting the metrics exporter")?;

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

    let shutdown = CancellationToken::new();
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

    poller_task.await.context("mempool poller task panicked")?;
    consumer_task.await.context("consumer task panicked")?;
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
