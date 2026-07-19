//! Reorg handling for the simulation service (§7, §15, Sprint 6 t4) — cancel
//! pending jobs and retract already-emitted incidents when their block is orphaned.
//!
//! `BlockReverted` is broadcast on Kafka to every service (§15); the simulation
//! service reacts on two fronts, and this module houses both, split pure-core /
//! effectful-shell like the rest of the crate:
//!
//! ```text
//! BlockReverted  (Kafka, domain event, one per orphaned block, tip-first)
//!    │
//!    ├─► retraction  (service side, in the dispatcher binary)
//!    │      IncidentIndex.incidents_in_block(block) → plan_retractions
//!    │      → publish IncidentRetracted back on Kafka (§15)          [ReorgConsumer]
//!    │
//!    └─► cancellation  (worker side, in each worker replica)
//!           SharedOrphanedBlocks.record(block)  — the "generation check" state
//!           → Worker::process skips a resolved job whose block is orphaned (§7)
//! ```
//!
//! ## Cancel pending jobs — the "generation check on the consumer" (§7)
//!
//! §7 gives two ways to cancel not-yet-started jobs for orphaned blocks:
//! `basic.reject` without requeue, or **a generation check on the consumer**. We take
//! the generation check: a `SimulationJob` deliberately carries no block
//! ([`crate::command`]), so there is nothing to reject *by block* on the queue — but a
//! worker learns the job's block the moment it *resolves* it ([`crate::resolver`]), and
//! at that point it consults an [`OrphanGuard`]: if the resolved block was orphaned, the
//! job is obsolete, so the worker drops it (acks, publishes nothing) instead of
//! simulating an orphaned block into a phantom incident. The orphaned-block set is fed
//! by each replica consuming `BlockReverted` itself (a broadcast — every worker must
//! know every revert, since any worker may pull any block's job), so the check is
//! process-local, which is exactly why the state lives behind a small object-safe seam.
//!
//! ## Retract already-emitted incidents (§15)
//!
//! An incident whose block is later orphaned must be withdrawn via `IncidentRetracted`
//! (§15). Finding *which* incidents a reverted block produced is a block→incident join,
//! and here we hit the same wall [`crate::resolver`] documents: the incident schema
//! carries no block (t2 locked "no schema change"), so the join needs the by-block
//! event-store read path that does not exist yet. So the join is a seam
//! ([`IncidentIndex`]) with a documented stub ([`EmptyIncidentIndex`], → retract
//! nothing), and everything downstream of it — the pure [`plan_retractions`] mapping and
//! the [`ReorgConsumer`] that publishes the results at-least-once — is complete and
//! tested. The plumbing is end-to-end; the live join lands with the same by-alert/
//! by-block query the resolver waits on. Retraction is idempotent (the incident
//! projection dedups a duplicate `IncidentRetracted`, §7), so the consumer commits its
//! offset only after publishing and a crash simply re-retracts.
//!
//! ## Bounded memory
//!
//! [`OrphanedBlocks`] is FIFO-bounded, the same discipline as [`crate::cache`] and the
//! projection's orphan buffer: a flood of `BlockReverted` events must not grow the set
//! without bound. Only blocks within reorg reach matter — a block orphaned long ago has
//! no pending jobs left — so evicting the oldest is the correct, safe policy.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use event_bus::dlq::DeadLetterQueue;
use event_bus::lag::{build_reporting_consumer, LagReporting};
use event_bus::{run_consumer, EventHandler, EventSink, Handled};
use events::chain::BlockReverted;
use events::primitives::{BlockRef, Chain, IncidentId};
use events::simulation::IncidentRetracted;
use events::{DomainEvent, EventEnvelope};
use rdkafka::consumer::StreamConsumer;
use revm::primitives::B256;
use tokio_util::sync::CancellationToken;

// ── Cancel pending jobs: the generation-check state ──────────────────────────

/// Default cap on distinct orphaned blocks [`OrphanedBlocks`] retains. A generation
/// check only cares about blocks recent enough to still have pending jobs — reorgs are
/// shallow and bounded by finality depth (§15) — so a few thousand covers the window
/// comfortably while capping the memory a `BlockReverted` flood could pin.
pub const DEFAULT_ORPHAN_BLOCK_CAPACITY: usize = 4_096;

/// The set of orphaned block hashes a worker checks a resolved job against — the §7
/// "generation check" state. Pure and lock-free so it is unit-testable directly;
/// [`SharedOrphanedBlocks`] wraps it for concurrent use across the consume/simulate
/// tasks.
///
/// Identity is the block **hash**, never the height: a reorg replaces the orphaned
/// block at height N with a *different* block at the same height, so a job for the
/// replacement (canonical) block must not be cancelled by its orphaned sibling's height.
///
/// FIFO-bounded ([`DEFAULT_ORPHAN_BLOCK_CAPACITY`]): at capacity the oldest orphaned
/// block is evicted. That is safe — a block old enough to fall off the back has no
/// not-yet-started jobs left to cancel — and bounds memory under a flood.
#[derive(Debug)]
pub struct OrphanedBlocks {
    capacity: usize,
    hashes: HashSet<B256>,
    /// Insertion order of `hashes`, for FIFO eviction.
    order: VecDeque<B256>,
}

impl Default for OrphanedBlocks {
    fn default() -> Self {
        Self::new()
    }
}

impl OrphanedBlocks {
    /// A fresh, empty set bounded to [`DEFAULT_ORPHAN_BLOCK_CAPACITY`].
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_ORPHAN_BLOCK_CAPACITY)
    }

    /// A fresh set bounded to `capacity` distinct orphaned blocks (`0` = unbounded — a
    /// deliberate opt-out for tests, never production).
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            hashes: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// Record a block as orphaned from a `BlockReverted` event. Returns whether it was
    /// newly recorded — a redelivered revert (the stream is at-least-once) is a no-op.
    /// Recording a new block evicts the oldest first when at capacity.
    pub fn record(&mut self, reverted: &BlockReverted) -> bool {
        let hash = reverted.block.hash;
        if !self.hashes.insert(hash) {
            return false;
        }
        self.order.push_back(hash);
        self.evict_to_fit();
        true
    }

    /// Whether `block` was orphaned by a reorg — the check a worker applies to a
    /// resolved job before simulating it (§7). Matches on hash, so the canonical block
    /// that replaced an orphan is *not* considered orphaned.
    pub fn is_orphaned(&self, block: &BlockRef) -> bool {
        self.hashes.contains(&block.hash)
    }

    /// How many distinct orphaned blocks are currently retained.
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Whether no blocks are currently recorded as orphaned.
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Drop oldest orphaned blocks until the set is within capacity (`0` = unbounded).
    fn evict_to_fit(&mut self) {
        if self.capacity == 0 {
            return;
        }
        while self.hashes.len() > self.capacity {
            match self.order.pop_front() {
                Some(oldest) => {
                    self.hashes.remove(&oldest);
                }
                None => break,
            }
        }
    }
}

/// The read side of the generation-check state a [`crate::worker::Worker`] holds:
/// "was this resolved block orphaned?". Object-safe so the worker takes
/// `Arc<dyn OrphanGuard>` and a test swaps in a canned answer (mirroring the
/// [`crate::resolver::JobResolver`] / [`crate::simulator::Simulator`] seams).
pub trait OrphanGuard: Send + Sync {
    /// Whether a job resolved to `block` should be cancelled because its block was
    /// orphaned by a reorg.
    fn is_orphaned(&self, block: &BlockRef) -> bool;
}

/// A guard that never cancels — the default when a worker is not wired to a
/// `BlockReverted` stream (e.g. unit tests of the happy path).
#[derive(Debug, Default, Clone, Copy)]
pub struct NeverOrphaned;

impl OrphanGuard for NeverOrphaned {
    fn is_orphaned(&self, _block: &BlockRef) -> bool {
        false
    }
}

/// Concurrent [`OrphanedBlocks`] shared between a worker's `BlockReverted` consume task
/// (the writer, via [`record`](Self::record)) and its simulate tasks (readers, via the
/// [`OrphanGuard`] impl). A `Mutex` is ample: reads are a hash lookup on the job path,
/// writes are rare (one per reverted block).
#[derive(Debug, Default)]
pub struct SharedOrphanedBlocks(Mutex<OrphanedBlocks>);

impl SharedOrphanedBlocks {
    /// Share a fresh, default-bounded set.
    pub fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(OrphanedBlocks::new())))
    }

    /// Record a reverted block. See [`OrphanedBlocks::record`].
    pub fn record(&self, reverted: &BlockReverted) -> bool {
        self.0
            .lock()
            .expect("orphaned-blocks lock poisoned")
            .record(reverted)
    }

    /// Distinct orphaned blocks currently retained — the gauge the shell exports (§19).
    pub fn len(&self) -> usize {
        self.0.lock().expect("orphaned-blocks lock poisoned").len()
    }

    /// Whether no blocks are currently recorded as orphaned.
    pub fn is_empty(&self) -> bool {
        self.0
            .lock()
            .expect("orphaned-blocks lock poisoned")
            .is_empty()
    }
}

impl OrphanGuard for SharedOrphanedBlocks {
    fn is_orphaned(&self, block: &BlockRef) -> bool {
        self.0
            .lock()
            .expect("orphaned-blocks lock poisoned")
            .is_orphaned(block)
    }
}

// ── Retract incidents: the pure mapping + the block→incident seam ────────────

/// The audit reason stamped on an `IncidentRetracted` when a block is orphaned, naming
/// the orphaned block and the block that replaced it so the withdrawal is explainable
/// straight off the event (§15).
pub fn retraction_reason(reverted: &BlockReverted) -> String {
    format!(
        "block {} ({:#x}) reverted by reorg, replaced by {:#x}",
        reverted.block.number, reverted.block.hash, reverted.replaced_by
    )
}

/// Map a reverted block plus the incidents it produced to the `IncidentRetracted`
/// events that withdraw them (§15). Pure — no Kafka, no store — so the retraction
/// decision is `assert_eq!`-testable like [`crate::result::events_for_outcome`].
///
/// The `incidents` come from the [`IncidentIndex`] block→incident join; the reason is
/// shared across the batch so every incident from one orphaned block carries the same
/// explanation.
pub fn plan_retractions(
    reverted: &BlockReverted,
    incidents: &[IncidentId],
) -> Vec<IncidentRetracted> {
    let reason = retraction_reason(reverted);
    incidents
        .iter()
        .map(|&incident_id| IncidentRetracted {
            incident_id,
            reason: reason.clone(),
        })
        .collect()
}

/// Why the block→incident join could not be resolved.
#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    /// A transient fault querying the index (store/event-store blip); the consumer
    /// leaves the offset so redelivery retries.
    #[error("transient fault resolving incidents for block: {0}")]
    Transient(String),
}

/// The block→incident join (§15): which confirmed incidents did an orphaned block
/// produce, so they can be retracted. Object-safe so the [`ReorgConsumer`] holds
/// `Arc<dyn IncidentIndex>` and a test swaps in a canned answer.
///
/// The production impl queries the event store / incident store for incidents whose
/// evidence transactions landed in `block` — the same by-block read path
/// [`crate::resolver`] is blocked on. Until it lands, [`EmptyIncidentIndex`] retracts
/// nothing (the honest no-op).
#[async_trait::async_trait]
pub trait IncidentIndex: Send + Sync {
    /// The incidents produced by transactions in `block`. `Ok(vec![])` means there is
    /// nothing to retract for this block.
    async fn incidents_in_block(&self, block: &BlockRef) -> Result<Vec<IncidentId>, IndexError>;
}

/// The deferred-production index: every block resolves to *no* incidents, so a reverted
/// block retracts nothing. See the module docs — this keeps the retraction path runnable
/// end-to-end (consume → plan → publish, all a no-op) until the by-block event-store
/// query lands, mirroring [`crate::resolver::UnresolvedJobResolver`].
#[derive(Debug, Default, Clone, Copy)]
pub struct EmptyIncidentIndex;

#[async_trait::async_trait]
impl IncidentIndex for EmptyIncidentIndex {
    async fn incidents_in_block(&self, _block: &BlockRef) -> Result<Vec<IncidentId>, IndexError> {
        Ok(Vec::new())
    }
}

// ── Retract incidents: the effectful shell (service side) ────────────────────

/// The one topic the reorg consumer subscribes to. An explicit name (not a
/// `mev.events.*` regex) so a renamed/missing topic fails loudly (cf. the dispatcher).
pub fn consumed_topic() -> String {
    events::topic_for("BlockReverted")
}

/// Build a `BlockReverted` consumer. Manual commit ties the offset to a revert being
/// fully handled; `earliest` means a fresh group processes retained reverts from the
/// start (cf. the dispatcher / event-store consumers).
pub fn build_consumer(brokers: &str, group_id: &str) -> Result<StreamConsumer<LagReporting>> {
    build_reporting_consumer(brokers, group_id, "reorg-retractor")
}

/// Build a **broadcast** `BlockReverted` consumer for the worker-side generation-check
/// tracker ([`run_revert_tracker`]). Unlike [`build_consumer`], every worker replica
/// must see *every* revert (any worker may pull any block's job), so the caller passes a
/// **unique-per-process** `group_id`; `latest` + auto-commit means a replica tracks live
/// reverts from start-up and never shares the stream with a sibling.
pub fn build_broadcast_consumer(brokers: &str, group_id: &str) -> Result<StreamConsumer> {
    rdkafka::ClientConfig::new()
        .set("bootstrap.servers", brokers)
        .set("group.id", group_id)
        .set("enable.auto.commit", "true")
        .set("auto.offset.reset", "latest")
        .create()
        .context("creating Kafka BlockReverted broadcast consumer")
}

/// The service-side reorg consumer: on each `BlockReverted`, look up the incidents the
/// orphaned block produced and publish an `IncidentRetracted` for each (§15). Mirrors
/// the [`Dispatcher`](crate::dispatcher::Dispatcher): the decision core ([`process`](Self::process))
/// is split from the shared [`event_bus::run_consumer`] loop, so it is testable with no broker.
pub struct ReorgConsumer {
    /// The block→incident join (stubbed today — see [`IncidentIndex`]).
    index: Arc<dyn IncidentIndex>,
    /// Where `IncidentRetracted` re-enters the backbone (keyed by incident id, §7 t2).
    event_sink: Arc<dyn EventSink>,
    shutdown: CancellationToken,
    /// Back-off between transient publish retries; a field so tests can shrink it.
    publish_backoff: Duration,
}

impl ReorgConsumer {
    /// Build a reorg consumer over the index and event sink. `shutdown` aborts the
    /// publish retry loops for a graceful drain.
    pub fn new(
        index: Arc<dyn IncidentIndex>,
        event_sink: Arc<dyn EventSink>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            index,
            event_sink,
            shutdown,
            publish_backoff: event_bus::PUBLISH_BACKOFF,
        }
    }

    /// Handle one reverted block — the **core**, free of the consume loop. Resolve the
    /// incidents it produced, then publish an `IncidentRetracted` for each. A transient
    /// index fault [`Retry`](Handled::Retry)s (leave the offset, redeliver); a publish
    /// interrupted by shutdown [`Stop`](Handled::Stop)s so nothing is silently lost.
    async fn process(&self, chain: Chain, reverted: &BlockReverted) -> Handled {
        let incidents = match self.index.incidents_in_block(&reverted.block).await {
            Ok(incidents) => incidents,
            Err(err) => {
                // Transient: leave the offset and let the broker redeliver — committing
                // here would silently skip retracting a reverted block.
                tracing::warn!(
                    error = %err,
                    block = reverted.block.number,
                    "resolving incidents for reverted block failed; will retry"
                );
                return Handled::Retry;
            }
        };

        if incidents.is_empty() {
            tracing::debug!(
                block = reverted.block.number,
                "no incidents to retract for reverted block"
            );
            return Handled::Commit;
        }

        for retracted in plan_retractions(reverted, &incidents) {
            tracing::info!(
                incident_id = %retracted.incident_id,
                block = reverted.block.number,
                "retracting incident from orphaned block"
            );
            event_bus::publish_resilient(
                self.event_sink.as_ref(),
                EventEnvelope::new(chain, DomainEvent::IncidentRetracted(retracted)),
                self.publish_backoff,
                &self.shutdown,
            )
            .await;
        }

        // If shutdown fired during a publish retry, some retraction may not be on the
        // wire — leave the offset so redelivery re-retracts (idempotent) rather than
        // committing past an un-retracted reorg.
        if self.shutdown.is_cancelled() {
            Handled::Stop
        } else {
            Handled::Commit
        }
    }

    /// Drive the consumer via the shared [`event_bus::run_consumer`] loop until shutdown
    /// or a fatal subscribe error — the reorg consumer supplies only its per-revert
    /// decision ([`EventHandler`]).
    pub async fn run(
        self,
        consumer: StreamConsumer<LagReporting>,
        dlq: Option<&DeadLetterQueue>,
    ) -> Result<()> {
        let topic = consumed_topic();
        let shutdown = self.shutdown.clone();
        let backoff = self.publish_backoff;
        run_consumer(
            consumer,
            &[topic.as_str()],
            "reorg-retractor",
            backoff,
            dlq,
            self,
            &shutdown,
        )
        .await
    }
}

#[async_trait::async_trait]
impl EventHandler for ReorgConsumer {
    /// Retract incidents for a `BlockReverted`; any other event type is a no-op.
    async fn handle(&self, envelope: EventEnvelope) -> Handled {
        let chain = envelope.chain;
        match envelope.payload {
            DomainEvent::BlockReverted(reverted) => self.process(chain, &reverted).await,
            other => {
                tracing::warn!(
                    event = other.event_type(),
                    "unexpected event on BlockReverted topic; skipping"
                );
                Handled::Commit
            }
        }
    }
}

// ── Cancel pending jobs: the effectful shell (worker side) ───────────────────

/// The worker-side generation-check tracker: records every `BlockReverted` into the
/// shared orphaned-block set so [`crate::worker::Worker`] cancels any resolved job for
/// an orphaned block (§7). An [`EventHandler`] like the retraction consumer, but it only
/// updates in-memory state — nothing is published, and it always commits.
struct RevertTracker(Arc<SharedOrphanedBlocks>);

#[async_trait::async_trait]
impl EventHandler for RevertTracker {
    async fn handle(&self, envelope: EventEnvelope) -> Handled {
        if let DomainEvent::BlockReverted(reverted) = envelope.payload {
            if self.0.record(&reverted) {
                tracing::info!(
                    block = reverted.block.number,
                    orphaned = self.0.len(),
                    "block orphaned; pending jobs for it will be cancelled"
                );
            }
        }
        Handled::Commit
    }
}

/// Drive the generation-check tracker off `BlockReverted` until shutdown, via the shared
/// [`event_bus::run_consumer`] loop.
///
/// Unlike the retraction consumer it needs its own **broadcast** group per replica (every
/// worker must see every revert, since any worker may pull any block's job) — the caller
/// builds the consumer with a unique group id + `latest` ([`build_broadcast_consumer`]).
/// Missing a revert during a restart gap is best-effort: the authoritative correction for
/// a reverted block is the offset-committed [`ReorgConsumer`] retraction, not this
/// defence-in-depth cancel.
pub async fn run_revert_tracker(
    consumer: StreamConsumer,
    orphaned: Arc<SharedOrphanedBlocks>,
    shutdown: CancellationToken,
) -> Result<()> {
    let topic = consumed_topic();
    run_consumer(
        consumer,
        &[topic.as_str()],
        "revert-tracker",
        event_bus::PUBLISH_BACKOFF,
        // Live-tail broadcast consumer: no DLQ — a skip here parks nothing the
        // backbone doesn't already durably own, once per worker replica.
        None,
        RevertTracker(orphaned),
        &shutdown,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use event_bus::PublishError;

    fn reverted(number: u64, hash: u8) -> BlockReverted {
        BlockReverted {
            block: BlockRef::new(number, B256::repeat_byte(hash)),
            replaced_by: B256::repeat_byte(hash.wrapping_add(1)),
        }
    }

    fn block(number: u64, hash: u8) -> BlockRef {
        BlockRef::new(number, B256::repeat_byte(hash))
    }

    // ── OrphanedBlocks: the generation-check state ───────────────────────────

    #[test]
    fn a_recorded_block_is_orphaned_by_hash_not_height() {
        let mut set = OrphanedBlocks::new();
        assert!(set.record(&reverted(100, 0xaa)));
        assert!(
            set.is_orphaned(&block(100, 0xaa)),
            "the orphaned block is cancelled"
        );
        // The canonical block that replaced it shares the height but not the hash — a
        // job for it must NOT be cancelled.
        assert!(
            !set.is_orphaned(&block(100, 0xbb)),
            "the replacement block at the same height is not orphaned"
        );
    }

    #[test]
    fn recording_a_revert_is_idempotent() {
        let mut set = OrphanedBlocks::new();
        assert!(set.record(&reverted(1, 0x01)), "first record is new");
        assert!(
            !set.record(&reverted(1, 0x01)),
            "a redelivered revert is a no-op"
        );
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn orphaned_blocks_are_fifo_bounded() {
        let mut set = OrphanedBlocks::with_capacity(2);
        set.record(&reverted(1, 0x01));
        set.record(&reverted(2, 0x02));
        set.record(&reverted(3, 0x03)); // evicts the oldest (0x01)
        assert_eq!(set.len(), 2, "capacity holds");
        assert!(!set.is_orphaned(&block(1, 0x01)), "oldest evicted");
        assert!(set.is_orphaned(&block(2, 0x02)));
        assert!(set.is_orphaned(&block(3, 0x03)));
    }

    #[test]
    fn shared_orphaned_blocks_reads_through_the_guard() {
        let shared = SharedOrphanedBlocks::new();
        assert!(!shared.is_orphaned(&block(5, 0x55)));
        shared.record(&reverted(5, 0x55));
        assert!(shared.is_orphaned(&block(5, 0x55)));
        assert_eq!(shared.len(), 1);
    }

    #[test]
    fn never_orphaned_guard_cancels_nothing() {
        assert!(!NeverOrphaned.is_orphaned(&block(1, 0x01)));
    }

    // ── plan_retractions: the pure retraction mapping ────────────────────────

    #[test]
    fn plan_retractions_makes_one_retraction_per_incident_with_a_shared_reason() {
        let rev = reverted(42, 0xab);
        let incidents = vec![IncidentId::new(), IncidentId::new()];
        let plan = plan_retractions(&rev, &incidents);

        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].incident_id, incidents[0]);
        assert_eq!(plan[1].incident_id, incidents[1]);
        let reason = retraction_reason(&rev);
        assert!(plan.iter().all(|r| r.reason == reason));
        assert!(
            reason.contains("42"),
            "reason names the reverted block height"
        );
    }

    #[test]
    fn plan_retractions_is_empty_when_no_incidents() {
        assert!(plan_retractions(&reverted(1, 0x01), &[]).is_empty());
    }

    // ── ReorgConsumer: the retraction shell ──────────────────────────────────

    /// An in-memory `EventSink` recording every published event.
    #[derive(Default)]
    struct RecordingEventSink {
        events: Mutex<Vec<DomainEvent>>,
    }

    #[async_trait::async_trait]
    impl EventSink for RecordingEventSink {
        async fn publish(&self, envelope: EventEnvelope) -> Result<(), PublishError> {
            self.events.lock().unwrap().push(envelope.payload);
            Ok(())
        }
    }

    /// An index returning a canned incident list.
    struct CannedIndex(Vec<IncidentId>);
    #[async_trait::async_trait]
    impl IncidentIndex for CannedIndex {
        async fn incidents_in_block(
            &self,
            _block: &BlockRef,
        ) -> Result<Vec<IncidentId>, IndexError> {
            Ok(self.0.clone())
        }
    }

    fn consumer(index: Arc<dyn IncidentIndex>, sink: Arc<dyn EventSink>) -> ReorgConsumer {
        let mut c = ReorgConsumer::new(index, sink, CancellationToken::new());
        c.publish_backoff = Duration::from_millis(1);
        c
    }

    #[tokio::test]
    async fn process_publishes_a_retraction_per_incident_and_commits() {
        let incidents = vec![IncidentId::new(), IncidentId::new()];
        let sink = Arc::new(RecordingEventSink::default());
        let c = consumer(Arc::new(CannedIndex(incidents.clone())), sink.clone());

        assert_eq!(
            c.process(Chain::ETHEREUM, &reverted(7, 0x07)).await,
            Handled::Commit
        );
        let emitted = sink.events.lock().unwrap();
        assert_eq!(emitted.len(), 2, "one IncidentRetracted per incident");
        for (event, expected) in emitted.iter().zip(&incidents) {
            match event {
                DomainEvent::IncidentRetracted(r) => assert_eq!(r.incident_id, *expected),
                other => panic!("expected IncidentRetracted, got {}", other.event_type()),
            }
        }
    }

    #[tokio::test]
    async fn process_commits_and_publishes_nothing_when_no_incidents() {
        let sink = Arc::new(RecordingEventSink::default());
        let c = consumer(Arc::new(EmptyIncidentIndex), sink.clone());
        assert_eq!(
            c.process(Chain::ETHEREUM, &reverted(1, 0x01)).await,
            Handled::Commit,
            "a reverted block with no incidents is a committable no-op"
        );
        assert!(sink.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn process_retries_on_a_transient_index_fault() {
        struct DeadIndex;
        #[async_trait::async_trait]
        impl IncidentIndex for DeadIndex {
            async fn incidents_in_block(
                &self,
                _block: &BlockRef,
            ) -> Result<Vec<IncidentId>, IndexError> {
                Err(IndexError::Transient("store down".into()))
            }
        }
        let sink = Arc::new(RecordingEventSink::default());
        let c = consumer(Arc::new(DeadIndex), sink.clone());
        assert_eq!(
            c.process(Chain::ETHEREUM, &reverted(1, 0x01)).await,
            Handled::Retry,
            "a transient join fault must leave the offset and redeliver, not skip the reorg"
        );
        assert!(sink.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn handle_retracts_only_for_block_reverted() {
        let incidents = vec![IncidentId::new()];
        let sink = Arc::new(RecordingEventSink::default());
        let c = consumer(Arc::new(CannedIndex(incidents)), sink.clone());

        // A non-revert event on the topic is a committable no-op.
        let other = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::BlockFinalized(events::chain::BlockFinalized {
                block: BlockRef::new(1, B256::ZERO),
            }),
        );
        assert_eq!(c.handle(other).await, Handled::Commit);
        assert!(sink.events.lock().unwrap().is_empty());

        // A BlockReverted drives a retraction.
        let env = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::BlockReverted(reverted(1, 0x01)),
        );
        assert_eq!(c.handle(env).await, Handled::Commit);
        assert_eq!(sink.events.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn revert_tracker_records_orphaned_blocks() {
        let orphaned = SharedOrphanedBlocks::new();
        let tracker = RevertTracker(orphaned.clone());

        let env = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::BlockReverted(reverted(9, 0x09)),
        );
        assert_eq!(tracker.handle(env).await, Handled::Commit);
        assert!(orphaned.is_orphaned(&block(9, 0x09)));

        // A non-revert event records nothing.
        let other = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::BlockFinalized(events::chain::BlockFinalized {
                block: BlockRef::new(1, B256::ZERO),
            }),
        );
        assert_eq!(tracker.handle(other).await, Handled::Commit);
        assert_eq!(orphaned.len(), 1);
    }

    #[test]
    fn consumed_topic_is_the_block_reverted_topic() {
        assert_eq!(consumed_topic(), "mev.events.BlockReverted");
    }
}
