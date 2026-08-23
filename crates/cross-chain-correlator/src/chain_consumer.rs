//! The per-chain consumer (§17, §24) — "one async consumer per chain's event
//! stream". Every configured chain gets one of these, each on its own Kafka
//! consumer group so it receives every partition of its subscribed topics
//! (Kafka isn't partitioned into per-chain *topics*, only per-chain
//! partitions within a shared topic, §20) and filters to its own chain — the
//! same foreign-chain-is-a-no-op discipline
//! `predictive::position_consumer`/`detection::scheduler` already use for a
//! single-chain deployment, just co-located here across chains in one
//! process because correlation is this crate's whole point (see the module
//! docs in `lib.rs`).
//!
//! Generic over [`LegExtractor`] (rather than calling
//! [`leg::extract_candidate_leg`](crate::leg) directly) so task 2's real
//! extractor plugs in at the `main.rs` wiring site without touching this
//! module, and so this module's own tests can exercise real routing against
//! a fake extractor instead of only ever proving "the stub routes nothing."
//!
//! **Redelivery dedup (production hardening).** Kafka's at-least-once
//! delivery means a crash/rebalance can redeliver a `DetectorTriggered`
//! this consumer already processed. Without a guard, a redelivered record
//! would extract and route the same leg a second time — potentially
//! completing (and republishing) the same correlated finding twice.
//! [`ChainConsumer`] tracks recently-seen [`EventEnvelope::event_id`]s (a
//! Kafka redelivery replays the identical envelope bytes, so its
//! `event_id` — minted once at produce time — is stable across the replay,
//! unlike a tx hash which multiple distinct events could legitimately
//! share) in a bounded FIFO ring, the same shape
//! `predictive::main::SeenTxs` uses for its mempool source.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use event_bus::dlq::DeadLetterQueue;
use event_bus::lag::{build_reporting_consumer, LagReporting};
use event_bus::{run_consumer, EventHandler, Handled};
use events::primitives::Chain;
use events::EventEnvelope;
use rdkafka::consumer::StreamConsumer;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::leg::LegExtractor;
use crate::router::LegRouter;

/// A capacity-bounded set of already-processed envelope ids — see the module
/// docs. Oldest entry is evicted once `capacity` is reached (a FIFO ring,
/// not an LRU — mirrors `predictive::main::SeenTxs` exactly).
struct SeenEnvelopes {
    capacity: usize,
    set: HashSet<Uuid>,
    order: VecDeque<Uuid>,
}

impl SeenEnvelopes {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            set: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// Record `id` as seen. Returns `true` if it was newly inserted (not
    /// seen before), `false` if it was already present (a redelivery).
    fn insert(&mut self, id: Uuid) -> bool {
        if !self.set.insert(id) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.set.remove(&oldest);
            }
        }
        true
    }
}

/// §24: "Consumed: the per-chain detection/chain event streams from every
/// monitored chain." `DetectorTriggered` is the only one of those already on
/// the bus with something to say about *observed on-chain activity worth
/// treating as a candidate leg* — `PreliminaryAlertCreated` is the scored
/// downstream fact, not the raw trigger. Sprint 17 task 2's
/// [`crate::leg::EvidenceLegExtractor`] extracts from exactly this event; a
/// future task can add `BlockCanonicalized`/`BlockReverted` alongside it if
/// leg extraction ends up needing chain-level context.
const CONSUMED_EVENT_TYPES: &[&str] = &["DetectorTriggered"];

pub fn consumed_topics() -> Vec<String> {
    events::topics_for(CONSUMED_EVENT_TYPES)
}

/// Build this chain's consumer. `group_id` must be unique per chain (see
/// [`crate::config::Config::consumer_group_for`]) so each chain's task is the
/// sole member of its own group and gets the *entire* subscribed topic's
/// partitions to filter, rather than splitting them with the other chains'
/// consumers.
pub fn build_consumer(brokers: &str, group_id: &str) -> Result<StreamConsumer<LagReporting>> {
    build_reporting_consumer(brokers, group_id, "cross-chain-correlator")
}

/// One chain's [`EventHandler`]: recognize a candidate leg via `E` and route
/// it to its bridge/pair's correlation actor.
pub struct ChainConsumer<E> {
    chain: Chain,
    router: Arc<LegRouter>,
    extractor: E,
    /// `Mutex`-guarded: `EventHandler::handle` takes `&self` (this consumer
    /// is driven by one task's own loop, but the trait bound requires
    /// `Send + Sync`), so interior mutability is how a single-owner mutable
    /// dedup set fits the shared-reference API — mirrors how
    /// `predictive::position::PositionTracker` and friends share mutable
    /// state behind a `Mutex` even when actual access is single-threaded in
    /// practice. Never held across an `.await`.
    seen: Mutex<SeenEnvelopes>,
}

impl<E: LegExtractor> ChainConsumer<E> {
    pub fn new(chain: Chain, router: Arc<LegRouter>, extractor: E, dedup_capacity: usize) -> Self {
        Self {
            chain,
            router,
            extractor,
            seen: Mutex::new(SeenEnvelopes::new(dedup_capacity)),
        }
    }

    async fn dispatch(&self, envelope: EventEnvelope) -> Handled {
        if envelope.chain != self.chain {
            // This chain's consumer group is assigned every partition of the
            // shared topic (see the module docs), so it sees other chains'
            // records too — not this task's leg to extract, but the offset
            // still advances.
            return Handled::Commit;
        }
        if !self.seen.lock().unwrap().insert(envelope.event_id) {
            // A Kafka redelivery of a record already extracted/routed (see
            // module docs) — commit and move on without doing it again.
            return Handled::Commit;
        }
        if let Some(candidate) = self.extractor.extract(&envelope) {
            self.router.route(candidate).await;
        }
        Handled::Commit
    }

    /// Drive this chain's consumer off Kafka until shutdown or a fatal
    /// subscribe error, via the shared [`run_consumer`] loop. Consumes
    /// `self`, mirroring `predictive::position_consumer::PositionConsumer::run`.
    pub async fn run(
        self,
        consumer: StreamConsumer<LagReporting>,
        retry_backoff: Duration,
        dlq: Option<&DeadLetterQueue>,
        shutdown: &CancellationToken,
    ) -> anyhow::Result<()> {
        let name = format!("cross-chain-correlator-chain-{}", self.chain.id());
        let topics = consumed_topics();
        let topic_refs: Vec<&str> = topics.iter().map(String::as_str).collect();
        run_consumer(
            consumer,
            &topic_refs,
            &name,
            retry_backoff,
            dlq,
            self,
            shutdown,
        )
        .await
    }
}

#[async_trait]
impl<E: LegExtractor> EventHandler for ChainConsumer<E> {
    async fn handle(&self, envelope: EventEnvelope) -> Handled {
        self.dispatch(envelope).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leg::{BridgeOrPair, CandidateLeg, LegKind, StubExtractor};
    use alloy_primitives::Address;
    use events::detection::DetectorTriggered;
    use events::primitives::{BlockRef, DetectorRef};
    use events::DomainEvent;
    use std::collections::HashMap;
    use tokio::sync::mpsc;

    fn a_detector_triggered(chain: Chain) -> EventEnvelope {
        EventEnvelope::new(
            chain,
            DomainEvent::DetectorTriggered(DetectorTriggered {
                detector: DetectorRef {
                    id: "sandwich".into(),
                    version: "1".into(),
                    config_hash: "deadbeef".into(),
                },
                block: BlockRef::new(1, Default::default()),
                txs: vec![],
                raw_confidence: events::primitives::Confidence::new(0.9),
                evidence: serde_json::json!({}),
            }),
        )
    }

    /// Always recognizes a leg for `bridge_or_pair`, regardless of the
    /// envelope — enough to prove `ChainConsumer`'s routing wiring end to
    /// end without waiting on the real (task 2) extractor.
    struct FakeExtractor {
        bridge_or_pair: BridgeOrPair,
    }

    impl LegExtractor for FakeExtractor {
        fn extract(&self, envelope: &EventEnvelope) -> Option<CandidateLeg> {
            Some(CandidateLeg {
                chain: envelope.chain,
                block: BlockRef::new(1, Default::default()),
                tx: Default::default(),
                kind: LegKind::LargeSwap,
                bridge_or_pair: self.bridge_or_pair.clone(),
                correlation_key: Address::ZERO,
                observed_at: envelope.occurred_at,
                confidence: events::primitives::Confidence::new(0.9),
                impact_usd: None,
            })
        }
    }

    #[tokio::test]
    async fn a_recognized_leg_on_a_matching_chain_is_routed() {
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        let (tx, mut rx) = mpsc::channel(1);
        let router = Arc::new(LegRouter::new(HashMap::from([(bridge.clone(), tx)])));
        let consumer = ChainConsumer::new(
            Chain::ETHEREUM,
            router,
            FakeExtractor {
                bridge_or_pair: bridge.clone(),
            },
            1024,
        );

        let handled = consumer
            .dispatch(a_detector_triggered(Chain::ETHEREUM))
            .await;
        assert_eq!(handled, Handled::Commit);

        let routed = rx
            .try_recv()
            .expect("a recognized leg on this chain must be routed");
        assert_eq!(routed.bridge_or_pair, bridge);
    }

    #[tokio::test]
    async fn a_redelivered_envelope_is_not_routed_twice() {
        // Kafka at-least-once: the identical envelope (same event_id) can
        // arrive twice. The second dispatch must commit without routing
        // another leg — see the module docs.
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        let (tx, mut rx) = mpsc::channel(4);
        let router = Arc::new(LegRouter::new(HashMap::from([(bridge.clone(), tx)])));
        let consumer = ChainConsumer::new(
            Chain::ETHEREUM,
            router,
            FakeExtractor {
                bridge_or_pair: bridge,
            },
            1024,
        );

        let envelope = a_detector_triggered(Chain::ETHEREUM);
        assert_eq!(consumer.dispatch(envelope.clone()).await, Handled::Commit);
        assert_eq!(consumer.dispatch(envelope).await, Handled::Commit);

        assert!(rx.try_recv().is_ok(), "the first dispatch must route a leg");
        assert!(
            rx.try_recv().is_err(),
            "the redelivered dispatch must not route a second leg"
        );
    }

    #[tokio::test]
    async fn a_foreign_chain_record_commits_without_routing_anything() {
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        let (tx, mut rx) = mpsc::channel(1);
        let router = Arc::new(LegRouter::new(HashMap::from([(bridge.clone(), tx)])));
        // Even an extractor that would always recognize a leg must never see
        // a foreign-chain record — the chain filter runs first.
        let consumer = ChainConsumer::new(
            Chain::ETHEREUM,
            router,
            FakeExtractor {
                bridge_or_pair: bridge,
            },
            1024,
        );

        let handled = consumer.dispatch(a_detector_triggered(Chain::BASE)).await;
        assert_eq!(handled, Handled::Commit);
        assert!(
            rx.try_recv().is_err(),
            "a foreign-chain record must not reach any correlation actor"
        );
    }

    #[tokio::test]
    async fn the_default_stub_extractor_routes_nothing() {
        // Pins today's production wiring (`main.rs` uses `StubExtractor`):
        // no leg shape exists yet, so nothing is routed even for a matching
        // chain — see `StubExtractor`'s docs for why.
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        let (tx, mut rx) = mpsc::channel(1);
        let router = Arc::new(LegRouter::new(HashMap::from([(bridge, tx)])));
        let consumer = ChainConsumer::new(Chain::ETHEREUM, router, StubExtractor, 1024);

        let handled = consumer
            .dispatch(a_detector_triggered(Chain::ETHEREUM))
            .await;
        assert_eq!(handled, Handled::Commit);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn consumed_topics_maps_to_the_schema_derived_topic() {
        assert_eq!(
            consumed_topics(),
            vec!["mev.events.DetectorTriggered".to_owned()]
        );
    }
}
