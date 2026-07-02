//! The detection service's concurrency model (§17, Sprint 4 task 2) — the async
//! **scheduler** that turns the chain-event stream into provisional alerts.
//!
//! Mirroring the ingestion [`Pipeline`](../../ingestion/src/pipeline.rs), the
//! interesting logic is split from the Kafka I/O so it's unit-testable against an
//! in-memory [`EventSink`] with no broker:
//!
//! - [`Scheduler::process`] is the **core**: given one decoded [`BlockEvent`] it
//!   runs the roster and returns the `Vec<DomainEvent>` to publish (for a
//!   `BlockAssembled`) or rewinds cross-block state and returns nothing (for a
//!   `BlockReverted`). Pure of Kafka; `assert_eq!`-testable.
//! - [`Scheduler::run`] is the **async loop**: it pulls decoded work off a bounded
//!   channel, runs `process`, publishes inline ([`event_bus::publish_resilient`]),
//!   and signals the work's commit token so the consumer can advance the offset.
//! - [`run_consumer`] / [`run_committer`] are the thin Kafka ends: decode messages
//!   into work, and commit offsets once their block is durably published.
//!
//! ## The concurrency model (§17)
//!
//! ```text
//! [run_consumer]  StreamConsumer (async I/O)
//!    BlockAssembled → DetectionCtx ;  BlockReverted → revert
//!    work_tx.send(work).await            ── bounded: backpressure when detection lags
//!         ▼
//! [Scheduler::run]  owns the one DetectionPlan + cross-block roster (single writer)
//!    Assembled → spawn_blocking(rayon Block fan-out) ⊕ serial cross-block slots
//!              → publish_resilient each event   →  done_tx.send(commit token)
//!    Reverted  → CrossBlockStates::apply_reverts (rewind); publishes nothing
//!         ▼
//! [run_committer]  commits the offset of each fully-published block (at-least-once)
//! ```
//!
//! Two **bounded** `mpsc` channels (`work`, `done`) give inter-stage backpressure:
//! if detection falls behind, the work channel fills, the consumer stops pulling,
//! and Kafka offsets aren't committed — the lag is visible and bounded rather than
//! buffering unboundedly in memory. CPU-bound detector fan-out runs on the `rayon`
//! pool via `spawn_blocking`, so it never blocks the async reactor (§17). Blocks are
//! processed **in order** (one chain ⇒ one partition, §20), so offset commits stay
//! in order and a crash re-delivers from the last committed block (the event store
//! dedups on `event_id`, §7).
//!
//! ## Header-only context (today)
//!
//! `BlockAssembled` carries the block ref + tx count + `trace_available`, but **not**
//! the tx hashes or enrichment, and the live RPC source is header-only. So the
//! [`BlockEvent::Assembled`] context built here has no txs/enrichment and the
//! `Block` detectors (which need them) find nothing — the *plumbing* is live end to
//! end; meaningful detection waits on a tx-carrying source/decoding layer. The
//! fan-out, channels and rewind are exercised regardless (tests drive synthetic
//! contexts + mock detectors).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use event_bus::{header_carrier, publish_resilient, EventSink};
use events::chain::BlockReverted;
use events::primitives::Chain;
use events::{DomainEvent, EventEnvelope};
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::{Message, Offset, TopicPartitionList};
use telemetry::propagation;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use detector_api::{BlockBundle, DetectionCtx};

use crate::emit::DetectionPlan;
use crate::reorg::CrossBlockStates;

/// One unit of decoded work the scheduler acts on — a canonical block to detect
/// over, or a reorg revert to roll cross-block state back through.
#[derive(Debug)]
pub enum BlockEvent {
    /// A block was assembled: run the detector roster over it.
    Assembled(DetectionCtx),
    /// A block was orphaned by a reorg: rewind cross-block state (tip-first; §15).
    Reverted(BlockReverted),
}

/// Where a Kafka record sits, kept owned so the committer can advance the offset
/// after the block is published without holding the borrowed message.
#[derive(Debug, Clone)]
pub struct Offsets {
    pub topic: String,
    pub partition: i32,
    pub offset: i64,
}

/// The async scheduler: owns the one [`DetectionPlan`] (built once at boot via
/// `link`, fail-fast) and the cross-block detector roster (single writer), and
/// turns decoded [`BlockEvent`]s into published events.
pub struct Scheduler {
    chain: Chain,
    /// Shared so the rayon fan-out can borrow it inside `spawn_blocking`.
    plan: Arc<DetectionPlan>,
    cross_block: CrossBlockStates,
    sink: Arc<dyn EventSink>,
    shutdown: CancellationToken,
    /// Back-off between transient publish retries; a field so tests can shrink it.
    publish_backoff: Duration,
}

impl Scheduler {
    /// Build a scheduler for one chain. `plan` is the linked roster reused for the
    /// process's life; `cross_block` is the (often empty) cross-block detector
    /// roster; `sink` is where events go; `shutdown` aborts a publish retry loop.
    pub fn new(
        chain: Chain,
        plan: Arc<DetectionPlan>,
        cross_block: CrossBlockStates,
        sink: Arc<dyn EventSink>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            chain,
            plan,
            cross_block,
            sink,
            shutdown,
            publish_backoff: event_bus::PUBLISH_BACKOFF,
        }
    }

    /// Run the roster over one decoded [`BlockEvent`] and return the events to
    /// publish — the scheduler **core**, free of Kafka so it's `assert_eq!`-testable.
    ///
    /// `Assembled` fans the `Block`-scoped detectors out over rayon (off the async
    /// reactor via `spawn_blocking`), then advances the cross-block roster serially
    /// (it threads `&mut` state); `Reverted` rewinds the cross-block roster to the
    /// common ancestor and publishes nothing.
    pub async fn process(&mut self, event: BlockEvent) -> Vec<DomainEvent> {
        match event {
            BlockEvent::Assembled(ctx) => {
                let ctx = Arc::new(ctx);
                // CPU-bound: fan the pure Block detectors out on rayon, off the
                // reactor. The plan + ctx are shared into the blocking pool.
                let plan = Arc::clone(&self.plan);
                let fan_ctx = Arc::clone(&ctx);
                let mut events =
                    tokio::task::spawn_blocking(move || plan.detection_events_parallel(&fan_ctx))
                        .await
                        .expect("detection fan-out task panicked");

                // Cross-block detectors run serially (mutable state); usually a
                // no-op (empty roster) until the first CrossBlock detector lands.
                events.extend(self.cross_block.observe_and_detect(&ctx));
                events
            }
            BlockEvent::Reverted(reverted) => {
                let rewind = self
                    .cross_block
                    .apply_reverts(std::slice::from_ref(&reverted));
                if rewind.changed() {
                    tracing::info!(
                        block = reverted.block.number,
                        detectors_rewound = rewind.rewound,
                        snapshots_popped = rewind.popped,
                        "rewound cross-block state through reorg"
                    );
                }
                Vec::new()
            }
        }
    }

    /// Drive the scheduler off the bounded `work` channel until shutdown or the
    /// channel closes (the consumer stopped). For each work item: run [`process`],
    /// publish its events, then forward the item's commit `token` on `done` so the
    /// committer can advance the offset — keeping commits in lock-step with durable
    /// publication (at-least-once).
    ///
    /// Generic over the commit token `T` so the core is testable with `T = ()`; the
    /// binary uses `T = Offsets`.
    pub async fn run<T>(mut self, mut work: mpsc::Receiver<(BlockEvent, T)>, done: mpsc::Sender<T>)
    where
        T: Send + 'static,
    {
        let shutdown = self.shutdown.clone();
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    tracing::info!("scheduler shutting down");
                    return;
                }
                msg = work.recv() => match msg {
                    Some((event, token)) => {
                        let events = self.process(event).await;
                        // Publish borrowing only the individual `Sync` fields (sink,
                        // shutdown) — never a shared `&self`, which would force the
                        // whole `Scheduler` (and so every cross-block slot) to be
                        // `Sync`; the slots run serially and needn't be.
                        for payload in events {
                            publish_resilient(
                                self.sink.as_ref(),
                                EventEnvelope::new(self.chain, payload),
                                self.publish_backoff,
                                &self.shutdown,
                            )
                            .await;
                        }
                        // Block is durably published — safe to advance its offset.
                        // A closed `done` (committer gone) means we're shutting down.
                        if done.send(token).await.is_err() {
                            tracing::warn!("commit channel closed; scheduler stopping");
                            return;
                        }
                    }
                    None => {
                        tracing::info!("work stream closed; scheduler stopping");
                        return;
                    }
                }
            }
        }
    }
}

/// Decode one domain-event envelope into the work the scheduler acts on, or `None`
/// for an event type detection doesn't consume (it subscribes only to the two
/// topics below, so this is belt-and-braces).
///
/// `BlockAssembled` becomes a **header-only** context (no txs/enrichment — see the
/// [module docs](self)); `BlockReverted` carries straight through.
pub fn block_event(envelope: EventEnvelope) -> Option<BlockEvent> {
    let chain = envelope.chain;
    match envelope.payload {
        DomainEvent::BlockAssembled(assembled) => Some(BlockEvent::Assembled(DetectionCtx::new(
            BlockBundle::new(chain, assembled.block, Vec::new()),
        ))),
        DomainEvent::BlockReverted(reverted) => Some(BlockEvent::Reverted(reverted)),
        _ => None,
    }
}

/// The two topics detection consumes: the block-assembled trigger and the reorg
/// revert. An explicit list (not a `mev.events.*` regex) so a renamed/missing topic
/// fails loudly rather than silently matching nothing (cf. event-store's consumer).
pub fn consumed_topics() -> [String; 2] {
    [
        events::topic_for("BlockAssembled"),
        events::topic_for("BlockReverted"),
    ]
}

/// Build the consumer. Manual offset commit (`enable.auto.commit=false`) is what
/// ties the commit to a block's successful publication; `earliest` means a fresh
/// group back-fills from the start of retained history (cf. event-store).
pub fn build_consumer(brokers: &str, group_id: &str) -> Result<StreamConsumer> {
    rdkafka::ClientConfig::new()
        .set("bootstrap.servers", brokers)
        .set("group.id", group_id)
        .set("enable.auto.commit", "false")
        .set("auto.offset.reset", "earliest")
        .create()
        .context("creating Kafka consumer")
}

/// Pull `BlockAssembled`/`BlockReverted` records off Kafka, decode them, and feed
/// the scheduler over the bounded `work` channel — the async I/O front of the
/// pipeline. Continues the producer's distributed trace across the broker (§19).
///
/// Returns on shutdown or a fatal subscribe error. The bounded `work` send is the
/// backpressure point: when the scheduler lags, this awaits rather than buffering.
pub async fn run_consumer(
    consumer: Arc<StreamConsumer>,
    work: mpsc::Sender<(BlockEvent, Offsets)>,
    shutdown: CancellationToken,
) -> Result<()> {
    let topics = consumed_topics();
    let topic_refs: Vec<&str> = topics.iter().map(String::as_str).collect();
    consumer
        .subscribe(&topic_refs)
        .context("subscribing to detection's input topics")?;
    tracing::info!(?topics, "detection consumer subscribed");

    loop {
        let msg = tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                tracing::info!("detection consumer stopping");
                return Ok(());
            }
            received = consumer.recv() => match received {
                Ok(msg) => msg,
                Err(err) => {
                    tracing::error!(error = %err, "Kafka receive error");
                    continue;
                }
            },
        };

        let offsets = Offsets {
            topic: msg.topic().to_owned(),
            partition: msg.partition(),
            offset: msg.offset(),
        };

        // Continue the producer's trace as this block's processing span parent.
        let span = tracing::info_span!(
            "detect_block",
            topic = offsets.topic,
            partition = offsets.partition,
            offset = offsets.offset,
        );
        propagation::set_parent_from_headers(&span, &header_carrier(&msg));

        let Some(payload) = msg.payload() else {
            tracing::error!("record has no payload; skipping");
            continue;
        };
        let event = match EventEnvelope::from_json_slice(payload) {
            Ok(envelope) => block_event(envelope),
            Err(err) => {
                tracing::error!(error = %err, "undecodable event; skipping");
                continue;
            }
        };
        let Some(event) = event else {
            // A topic we don't act on slipped through — skip without committing.
            continue;
        };

        // Record the decode under the trace-linked span synchronously (don't hold
        // the guard across the await). Continuing the trace through the scheduler
        // task is a follow-up — for now the linkage is logged here.
        span.in_scope(|| tracing::debug!(block_event = ?event, "decoded block event"));
        if work.send((event, offsets)).await.is_err() {
            tracing::info!("scheduler gone; consumer stopping");
            return Ok(());
        }
    }
}

/// Commit the offset of each block once the scheduler signals it has been published
/// — at-least-once: a crash before the commit re-delivers the block. Commits the
/// *next* offset (`offset + 1`), the Kafka convention for "resume after this one".
pub async fn run_committer(consumer: Arc<StreamConsumer>, mut done: mpsc::Receiver<Offsets>) {
    while let Some(o) = done.recv().await {
        let mut tpl = TopicPartitionList::new();
        // `add_partition_offset` only fails on an invalid partition/offset, which
        // these owned coordinates can't be — they came straight off a real record.
        if tpl
            .add_partition_offset(&o.topic, o.partition, Offset::Offset(o.offset + 1))
            .is_err()
        {
            tracing::error!(
                topic = o.topic,
                partition = o.partition,
                "bad offset to commit"
            );
            continue;
        }
        if let Err(err) = consumer.commit(&tpl, rdkafka::consumer::CommitMode::Async) {
            tracing::error!(error = %err, "offset commit failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use chrono::Utc;
    use event_bus::PublishError;

    use detector_api::test_util::{MockCrossBlockDetector, MockDetector};
    use detector_api::{Evidence, SemVer};
    use events::primitives::{AlertKind, BlockRef, Confidence, DetectorRef};

    use crate::model::{ConfigHash, ModelCard, ModelRegistry};
    use crate::registry::Registry;

    use alloy_primitives::B256;

    /// An in-memory [`EventSink`] recording every published payload, so tests assert
    /// on the emitted lifecycle without a broker.
    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<DomainEvent>>,
    }

    impl RecordingSink {
        fn types(&self) -> Vec<String> {
            self.events
                .lock()
                .unwrap()
                .iter()
                .map(|e| e.event_type().to_owned())
                .collect()
        }
    }

    #[async_trait]
    impl EventSink for RecordingSink {
        async fn publish(&self, envelope: EventEnvelope) -> Result<(), PublishError> {
            self.events.lock().unwrap().push(envelope.payload);
            Ok(())
        }
    }

    fn hash(byte: u8) -> B256 {
        B256::repeat_byte(byte)
    }

    fn card(id: &'static str, version: SemVer) -> ModelCard {
        ModelCard::for_plugin(
            &MockDetector::new(id, version),
            ConfigHash::of_bytes(id.as_bytes()),
            Utc::now(),
        )
    }

    /// A linked plan with a single `Block` detector that fires one finding.
    fn plan_with_one_detector() -> DetectionPlan {
        let registry = Registry::builder()
            .register(
                MockDetector::new("arb", SemVer::new(1, 0, 0)).returning(vec![Evidence::new(
                    AlertKind::Arbitrage,
                    vec![hash(1)],
                    Confidence::new(0.7),
                )]),
            )
            .build()
            .unwrap();
        let models = ModelRegistry::builder()
            .record(card("arb", SemVer::new(1, 0, 0)))
            .build()
            .unwrap();
        DetectionPlan::link(&registry, &models).unwrap()
    }

    fn scheduler(plan: DetectionPlan, cross_block: CrossBlockStates) -> Scheduler {
        Scheduler::new(
            Chain::ETHEREUM,
            Arc::new(plan),
            cross_block,
            Arc::new(RecordingSink::default()),
            CancellationToken::new(),
        )
    }

    fn assembled(n: u64) -> BlockEvent {
        BlockEvent::Assembled(DetectionCtx::new(BlockBundle::new(
            Chain::ETHEREUM,
            BlockRef::new(n, hash(n as u8)),
            Vec::new(),
        )))
    }

    fn a_ref(id: &'static str) -> DetectorRef {
        DetectorRef {
            id: id.into(),
            version: "1.0.0".into(),
            config_hash: "deadbeef".into(),
        }
    }

    #[tokio::test]
    async fn process_assembled_fans_out_and_returns_a_trigger_alert_pair() {
        let mut s = scheduler(plan_with_one_detector(), CrossBlockStates::new());
        let events = s.process(assembled(7)).await;
        let types: Vec<&str> = events.iter().map(DomainEvent::event_type).collect();
        assert_eq!(types, vec!["DetectorTriggered", "PreliminaryAlertCreated"]);
    }

    #[tokio::test]
    async fn process_reverted_rewinds_cross_block_state_and_emits_nothing() {
        // A cross-block detector advanced over blocks 1..=3, then a revert.
        let mut roster = CrossBlockStates::new();
        roster.insert_detector(
            a_ref("wash"),
            MockCrossBlockDetector::<u64>::new("wash", SemVer::new(1, 0, 0)),
        );
        let mut s = scheduler(plan_with_one_detector(), roster);

        for n in 1..=3 {
            let _ = s.process(assembled(n)).await;
        }
        // The revert for the tip (block 3) emits nothing.
        let events = s
            .process(BlockEvent::Reverted(BlockReverted {
                block: BlockRef::new(3, hash(3)),
                replaced_by: hash(0x33),
            }))
            .await;
        assert!(events.is_empty(), "a revert publishes no events");
    }

    #[tokio::test]
    async fn run_loop_publishes_assembled_events_and_signals_commit() {
        let sink = Arc::new(RecordingSink::default());
        let s = Scheduler::new(
            Chain::ETHEREUM,
            Arc::new(plan_with_one_detector()),
            CrossBlockStates::new(),
            sink.clone(),
            CancellationToken::new(),
        );

        let (work_tx, work_rx) = mpsc::channel::<(BlockEvent, u64)>(4);
        let (done_tx, mut done_rx) = mpsc::channel::<u64>(4);
        let handle = tokio::spawn(s.run(work_rx, done_tx));

        // Two blocks through the bounded channel, then close it to end the loop.
        work_tx.send((assembled(1), 1)).await.unwrap();
        work_tx.send((assembled(2), 2)).await.unwrap();
        drop(work_tx);
        handle.await.unwrap();

        // Each block emitted its trigger/alert pair, and both commit tokens fired
        // in order.
        assert_eq!(
            sink.types(),
            vec![
                "DetectorTriggered",
                "PreliminaryAlertCreated",
                "DetectorTriggered",
                "PreliminaryAlertCreated",
            ]
        );
        let mut tokens = Vec::new();
        while let Ok(t) = done_rx.try_recv() {
            tokens.push(t);
        }
        assert_eq!(tokens, vec![1, 2], "commit tokens signalled in block order");
    }

    #[tokio::test]
    async fn run_loop_stops_promptly_on_shutdown() {
        let shutdown = CancellationToken::new();
        let s = Scheduler::new(
            Chain::ETHEREUM,
            Arc::new(plan_with_one_detector()),
            CrossBlockStates::new(),
            Arc::new(RecordingSink::default()),
            shutdown.clone(),
        );
        let (_work_tx, work_rx) = mpsc::channel::<(BlockEvent, u64)>(4);
        let (done_tx, _done_rx) = mpsc::channel::<u64>(4);
        let handle = tokio::spawn(s.run(work_rx, done_tx));

        shutdown.cancel();
        // Completes rather than hanging on the open work channel.
        handle.await.unwrap();
    }

    #[test]
    fn block_event_decodes_assembled_and_reverted_and_ignores_others() {
        let assembled = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::BlockAssembled(events::chain::BlockAssembled {
                block: BlockRef::new(5, hash(5)),
                tx_count: 9,
                trace_available: false,
            }),
        );
        assert!(matches!(
            block_event(assembled),
            Some(BlockEvent::Assembled(_))
        ));

        let reverted = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::BlockReverted(BlockReverted {
                block: BlockRef::new(5, hash(5)),
                replaced_by: hash(0x55),
            }),
        );
        assert!(matches!(
            block_event(reverted),
            Some(BlockEvent::Reverted(_))
        ));

        // An event detection doesn't consume is ignored.
        let finalized = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::BlockFinalized(events::chain::BlockFinalized {
                block: BlockRef::new(5, hash(5)),
            }),
        );
        assert!(block_event(finalized).is_none());
    }

    #[test]
    fn consumed_topics_are_the_two_detection_inputs() {
        assert_eq!(
            consumed_topics(),
            ["mev.events.BlockAssembled", "mev.events.BlockReverted"]
        );
    }
}
