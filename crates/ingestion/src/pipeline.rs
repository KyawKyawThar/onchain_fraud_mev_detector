//! The ingestion **pipeline** (§5, Sprint 2 tasks 3–4): turns the ordered head
//! stream into the chain lifecycle events on Kafka.
//!
//! It owns the single mutable [`BlockTree`] and is the one place that maps the
//! tree's pure [`AddOutcome`]/[`finalize`](BlockTree::finalize) decisions onto
//! [`events::chain`] events through an [`EventSink`]:
//!
//! | trigger                              | event(s) emitted                    |
//! |--------------------------------------|-------------------------------------|
//! | a head is first observed             | `RawBlockReceived`, `BlockAssembled`|
//! | the canonical tip moves             | `BlockCanonicalized` (ancestor-first) |
//! | a reorg orphans blocks               | `BlockReverted` (tip-first), then the canonicalize above |
//! | a block crosses the finality line    | `BlockFinalized` (ascending)        |
//!
//! ## Pure mapping vs. effectful publish
//!
//! Mirroring [`crate::tree`] (which is deliberately pure/synchronous), the
//! *decision* — which events an outcome produces, and in what order — lives in
//! free functions ([`observed_events`], [`canonical_events`]) that take plain
//! data and return a `Vec<DomainEvent>`. They are unit-tested with `assert_eq!`,
//! no runtime or mock sink. [`Pipeline`] is the thin effectful shell that feeds
//! the tree and ships those vectors.
//!
//! ## The source-driven reorg walk (task 4)
//!
//! The tree refuses a block whose parent it hasn't seen ([`AddOutcome::MissingParent`])
//! rather than storing it dangling. [`Pipeline::ingest`] resolves that: it
//! fetches the missing parent via [`ChainSource::head_by_hash`] and back-fills
//! bottom-up until the block links — the competing branch is back-filled as forks
//! until it reaches the tip's height, at which point the tree reports the whole
//! `reverted`/`canonicalized` swap in one outcome. A back-fill *fetch* failure
//! just skips the head; the next poll re-drives the walk and the blocks already
//! published return as `Duplicate`, so it self-heals.
//!
//! ## Delivery: at-least-once, never at-most-once
//!
//! Events are derived from in-memory tree state that has *already advanced* by
//! the time they're published, so a dropped publish can't be re-derived later —
//! it would be a permanent hole in the audit stream. [`Pipeline`] therefore
//! retries a transient publish failure (a broker blip) until it succeeds or
//! shutdown, over an envelope whose `event_id` is fixed across retries so the
//! downstream dedups the redelivery (§7). A *permanent* failure (an encode bug)
//! is logged and skipped — it can never succeed. Per chain, events keep the order
//! emitted here (Kafka keys by chain, §20); within a reorg, reverts precede
//! canonicalizations so a consumer rolls back before it rolls forward (§15). A
//! block already in the tree ([`AddOutcome::Duplicate`]) emits nothing.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use events::chain::{
    BlockAssembled, BlockCanonicalized, BlockFinalized, BlockReverted, RawBlockReceived,
};
use events::primitives::{BlockRef, Chain};
use events::{DomainEvent, EventEnvelope};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::publisher::{publish_resilient, EventSink, PUBLISH_BACKOFF};
use crate::source::{ChainHead, ChainSource};
use crate::tree::{AddOutcome, BlockTree, CanonicalUpdate};

/// Drives heads through the [`BlockTree`] and emits the resulting chain events.
pub struct Pipeline {
    chain: Chain,
    source: Arc<dyn ChainSource>,
    sink: Arc<dyn EventSink>,
    tree: BlockTree,
    /// Carried onto every [`BlockAssembled`]; a property of the source adapter
    /// (header-only RPC pool ⇒ `false`). Cached at construction so it isn't
    /// re-queried per block.
    trace_available: bool,
    /// Cancelled on shutdown, so a publish stuck retrying a downed broker can
    /// give up and let the service drain instead of blocking forever.
    shutdown: CancellationToken,
    /// Back-off between transient publish retries. A field (not the const
    /// directly) so tests can shrink it; production uses [`PUBLISH_BACKOFF`].
    publish_backoff: Duration,
    /// Optional **durable-progress watermark**: after a head's events are
    /// published, the new canonical tip is reported here. A push source (the
    /// reth ExEx) turns this into its "you may prune below N" acknowledgement, so
    /// the node never prunes a block whose `BlockAssembled` hasn't durably shipped
    /// — the ack trails the *publish* boundary, not the enqueue. `None` for the
    /// pull (RPC) path, which has no such contract. See [`Pipeline::report_progress_to`].
    progress: Option<mpsc::Sender<BlockRef>>,
    /// The last tip reported on `progress`, to suppress duplicate acks (the tip
    /// is unchanged across `Fork`/`Duplicate` ingests).
    last_progress: Option<BlockRef>,
}

impl Pipeline {
    /// Build a pipeline for one chain. `finalization_depth` bounds the in-memory
    /// tree (§15); `source` back-fills reorg ancestors and supplies the finalized
    /// tag; `sink` is where the events go; `shutdown` aborts a publish retry loop
    /// on a graceful stop.
    pub fn new(
        chain: Chain,
        source: Arc<dyn ChainSource>,
        sink: Arc<dyn EventSink>,
        finalization_depth: u64,
        shutdown: CancellationToken,
    ) -> Self {
        let trace_available = source.traces_available();
        Self {
            chain,
            source,
            sink,
            tree: BlockTree::new(finalization_depth),
            trace_available,
            shutdown,
            publish_backoff: PUBLISH_BACKOFF,
            progress: None,
            last_progress: None,
        }
    }

    /// Report the canonical tip on `tx` after each ingest whose events have been
    /// published — the **durable-progress watermark** (see the [`progress`] field).
    ///
    /// A push source acks pruning off this: it fires only once a head's
    /// `RawBlockReceived`/`BlockAssembled`/canonical events have gone through the
    /// (at-least-once) publish, so the ack can never outrun durability. Reporting
    /// uses a non-blocking send — the watermark is monotonic, so a dropped
    /// intermediate is superseded by the next tip and never lost.
    ///
    /// [`progress`]: Self::progress
    pub fn report_progress_to(&mut self, tx: mpsc::Sender<BlockRef>) {
        self.progress = Some(tx);
    }

    /// Own the pipeline in one task so the block tree has a single writer: ingest
    /// each head as it arrives and, on a coarser tick, advance finality. A
    /// per-head/-tick error is logged and the loop continues — one bad block must
    /// not tear down ingestion. Returns when shutdown is cancelled or the head
    /// stream closes (the poller stopped).
    ///
    /// Lives here, not in `main`, for symmetry with [`crate::source::head_stream::run_head_poller`]
    /// and so the loop is drivable from a test through a channel.
    pub async fn run(mut self, mut heads: mpsc::Receiver<ChainHead>, finalize_interval: Duration) {
        let shutdown = self.shutdown.clone();
        let mut finalize_ticker = tokio::time::interval(finalize_interval);
        finalize_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    tracing::info!("pipeline shutting down");
                    return;
                }
                head = heads.recv() => match head {
                    Some(head) => {
                        if let Err(err) = self.ingest(head).await {
                            tracing::error!(error = %err, number = head.number, "failed to ingest head; skipping");
                        }
                    }
                    None => {
                        tracing::info!("head stream closed; pipeline stopping");
                        return;
                    }
                },
                _ = finalize_ticker.tick() => {
                    if let Err(err) = self.tick_finalize().await {
                        tracing::error!(error = %err, "finality tick failed");
                    }
                }
            }
        }
    }

    /// Ingest one observed head: link it into the tree (back-filling missing
    /// ancestors), and emit the lifecycle events that follow.
    ///
    /// Back-fill is iterative (a stack), not recursive: a deep reorg can require
    /// fetching many ancestors, and the tree's finality floor bounds how far down
    /// it can go. Each iteration makes progress — it adds a block (pop) or pushes
    /// a strictly-lower-numbered parent to fetch first. The returned `Err` is a
    /// *source* failure (couldn't fetch a parent); publish failures don't surface
    /// here — they're retried internally (see [module docs](self)).
    pub async fn ingest(&mut self, head: ChainHead) -> Result<()> {
        let mut stack = vec![head];

        while let Some(&current) = stack.last() {
            match self.tree.add_block(current)? {
                AddOutcome::Duplicate => {
                    // Already known (a backfilled parent we just added, or a
                    // repeat poll) — emitted when first seen; drop it.
                    stack.pop();
                }
                AddOutcome::MissingParent(parent_hash) => {
                    // Fetch the parent and resolve it before retrying `current`.
                    let parent = self
                        .source
                        .head_by_hash(parent_hash)
                        .await
                        .with_context(|| format!("back-filling parent {parent_hash}"))?;
                    stack.push(parent);
                }
                AddOutcome::Fork => {
                    // Newly observed but not (yet) canonical — still a real block
                    // the audit log records as received + assembled.
                    self.publish_all(observed_events(current, self.trace_available).to_vec())
                        .await;
                    stack.pop();
                }
                AddOutcome::Canonical(update) => {
                    let mut events = observed_events(current, self.trace_available).to_vec();
                    events.extend(canonical_events(&update));
                    self.publish_all(events).await;
                    stack.pop();
                }
            }
        }
        self.report_progress();
        Ok(())
    }

    /// Report the current canonical tip on the progress watermark, if one is
    /// wired and the tip advanced since the last report. Called after a head's
    /// events are published (so the ack trails durability), and deduplicated so a
    /// `Fork`/`Duplicate` that didn't move the tip acks nothing.
    fn report_progress(&mut self) {
        let (Some(tx), Some(tip)) = (&self.progress, self.tree.canonical_tip()) else {
            return;
        };
        let tip = tip.block_ref();
        if self.last_progress == Some(tip) {
            return;
        }
        // Non-blocking: never block ingestion on the ack. Only record the tip as
        // reported on a successful send — if the receiver was momentarily full we
        // leave `last_progress` untouched so the next ingest retries this tip (or
        // supersedes it with a higher one); either way the watermark can't be lost.
        match tx.try_send(tip) {
            Ok(()) => self.last_progress = Some(tip),
            Err(mpsc::error::TrySendError::Full(_)) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => self.progress = None,
        }
    }

    /// Poll the source's `finalized` tag and emit a `BlockFinalized` for every
    /// canonical block that crossed the line since the last tick (§5, §15). A
    /// failed fetch is logged and retried next tick — finality only ever advances.
    pub async fn tick_finalize(&mut self) -> Result<()> {
        let finalized = match self.source.finalized_head().await {
            Ok(head) => head,
            Err(err) => {
                tracing::warn!(error = %err, "finalized-head fetch failed; retrying next tick");
                return Ok(());
            }
        };

        let events = self
            .tree
            .finalize(finalized.block_ref())
            .into_iter()
            .map(|block| {
                DomainEvent::BlockFinalized(BlockFinalized {
                    block: block.block_ref(),
                })
            })
            .collect();
        self.publish_all(events).await;
        Ok(())
    }

    /// Ship a batch of events in order, each wrapped in a fresh envelope for this
    /// chain. The envelope (and its `event_id`) is built once and reused across
    /// retries so a redelivery is deduped downstream (§7).
    async fn publish_all(&self, payloads: Vec<DomainEvent>) {
        for payload in payloads {
            // The shared at-least-once policy ([`event_bus::publish_resilient`]):
            // retry a transient broker blip until it succeeds or shutdown, skip a
            // permanent encode bug. The envelope (and its `event_id`) is fixed
            // across retries so a redelivery is deduped downstream (§7).
            publish_resilient(
                self.sink.as_ref(),
                EventEnvelope::new(self.chain, payload),
                self.publish_backoff,
                &self.shutdown,
            )
            .await;
        }
    }
}

/// Pure: the events a head produces when first observed — `RawBlockReceived`
/// then `BlockAssembled` (the head of every block's lifecycle, §5).
fn observed_events(head: ChainHead, trace_available: bool) -> [DomainEvent; 2] {
    [
        DomainEvent::RawBlockReceived(RawBlockReceived {
            block: head.block_ref(),
            timestamp: head.timestamp,
        }),
        DomainEvent::BlockAssembled(BlockAssembled {
            block: head.block_ref(),
            tx_count: head.tx_count,
            trace_available,
        }),
    ]
}

/// Pure: the events a [`CanonicalUpdate`] produces — revert the orphaned blocks
/// first (tip-first, roll back), then canonicalize the new branch (ancestor-first,
/// roll forward). Each `BlockReverted` names the block that now occupies its
/// height, paired from `canonicalized` (§15).
fn canonical_events(update: &CanonicalUpdate) -> Vec<DomainEvent> {
    // height → new canonical hash, for BlockReverted.replaced_by.
    let replaced_by: HashMap<u64, _> = update
        .canonicalized
        .iter()
        .map(|h| (h.number, h.hash))
        .collect();

    let mut events = Vec::with_capacity(update.reverted.len() + update.canonicalized.len());
    for orphan in &update.reverted {
        // Fork choice guarantees the new branch reaches at least the old tip's
        // height, so every reverted height has a replacement. Guard anyway: a
        // missing one is a tree-invariant bug, not lost data.
        let Some(&replacement) = replaced_by.get(&orphan.number) else {
            tracing::error!(
                number = orphan.number,
                hash = %orphan.hash,
                "reverted block has no canonical replacement at its height (tree invariant violated)"
            );
            continue;
        };
        events.push(DomainEvent::BlockReverted(BlockReverted {
            block: orphan.block_ref(),
            replaced_by: replacement,
        }));
    }
    for block in &update.canonicalized {
        events.push(DomainEvent::BlockCanonicalized(BlockCanonicalized {
            block: block.block_ref(),
        }));
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use alloy_primitives::B256;
    use async_trait::async_trait;
    use events::primitives::BlockRef;

    use crate::publisher::PublishError;
    use crate::source::SourceError;

    // ── Pure-mapping tests (no runtime, no sink) ──────────────────────

    fn types(events: &[DomainEvent]) -> Vec<&'static str> {
        events.iter().map(DomainEvent::event_type).collect()
    }

    #[test]
    fn observed_events_are_received_then_assembled_with_head_fields() {
        let [received, assembled] = observed_events(head(7, 0x07, 0x00), false);
        assert!(matches!(received, DomainEvent::RawBlockReceived(_)));
        let DomainEvent::BlockAssembled(a) = assembled else {
            panic!("expected BlockAssembled");
        };
        assert_eq!(a.block, BlockRef::new(7, b(0x07)));
        assert_eq!(a.tx_count, 7, "tx_count carried from the head");
        assert!(
            !a.trace_available,
            "header-only source ⇒ traces unavailable"
        );
    }

    #[test]
    fn canonical_events_revert_tip_first_then_canonicalize_with_replaced_by() {
        // Reverting 3,2 (tip-first); canonicalizing 2',3' (ancestor-first).
        let update = CanonicalUpdate {
            reverted: vec![head(3, 0x03, 0x02), head(2, 0x02, 0x01)],
            canonicalized: vec![head(2, 0x12, 0x01), head(3, 0x13, 0x12)],
        };
        let events = canonical_events(&update);
        assert_eq!(
            types(&events),
            vec![
                "BlockReverted",
                "BlockReverted",
                "BlockCanonicalized",
                "BlockCanonicalized",
            ]
        );
        // Each revert names its height's replacement.
        let reverted: Vec<(BlockRef, B256)> = events
            .iter()
            .filter_map(|e| match e {
                DomainEvent::BlockReverted(r) => Some((r.block, r.replaced_by)),
                _ => None,
            })
            .collect();
        assert_eq!(
            reverted,
            vec![
                (BlockRef::new(3, b(0x03)), b(0x13)),
                (BlockRef::new(2, b(0x02)), b(0x12)),
            ]
        );
    }

    #[test]
    fn canonical_events_for_a_plain_extension_only_canonicalize() {
        let update = CanonicalUpdate {
            reverted: vec![],
            canonicalized: vec![head(2, 0x02, 0x01)],
        };
        assert_eq!(
            types(&canonical_events(&update)),
            vec!["BlockCanonicalized"]
        );
    }

    // ── Effectful-pipeline tests (driver + fakes) ─────────────────────

    use event_bus::test_util::RecordingSink;

    /// Crate-local projections of the recorded lifecycle over the shared
    /// [`RecordingSink`] (`clear` is a shared method): the emitted event *type
    /// names*, and each event paired with the block it carries — for asserting
    /// order and per-block grouping without a broker.
    trait LifecycleExt {
        fn types(&self) -> Vec<String>;
        fn blocks(&self) -> Vec<(String, BlockRef)>;
    }

    impl LifecycleExt for RecordingSink {
        fn types(&self) -> Vec<String> {
            self.events()
                .iter()
                .map(|e| e.event_type().to_owned())
                .collect()
        }
        fn blocks(&self) -> Vec<(String, BlockRef)> {
            self.events()
                .iter()
                .map(|e| (e.event_type().to_owned(), block_ref_of(e)))
                .collect()
        }
    }

    /// A sink that fails transiently `remaining_failures` times, then records —
    /// to prove publish retries over a broker blip.
    struct FlakySink {
        remaining_failures: Mutex<u32>,
        delivered: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl EventSink for FlakySink {
        async fn publish(&self, envelope: EventEnvelope) -> Result<(), PublishError> {
            let mut left = self.remaining_failures.lock().unwrap();
            if *left > 0 {
                *left -= 1;
                return Err(PublishError::Delivery("broker blip".into()));
            }
            self.delivered
                .lock()
                .unwrap()
                .push(envelope.event_type().to_owned());
            Ok(())
        }
    }

    /// The block a chain event carries — every event under test names one.
    fn block_ref_of(event: &DomainEvent) -> BlockRef {
        match event {
            DomainEvent::RawBlockReceived(e) => e.block,
            DomainEvent::BlockAssembled(e) => e.block,
            DomainEvent::BlockCanonicalized(e) => e.block,
            DomainEvent::BlockReverted(e) => e.block,
            DomainEvent::BlockFinalized(e) => e.block,
            other => panic!("unexpected event {}", other.event_type()),
        }
    }

    /// A [`ChainSource`] backed by a fixed set of heads, for back-fill +
    /// finalize. Only `head_by_hash` and `finalized_head` are exercised here.
    struct FakeSource {
        heads: Vec<ChainHead>,
        finalized: Mutex<Option<ChainHead>>,
    }

    impl FakeSource {
        fn new(heads: Vec<ChainHead>) -> Self {
            Self {
                heads,
                finalized: Mutex::new(None),
            }
        }
        fn set_finalized(&self, head: ChainHead) {
            *self.finalized.lock().unwrap() = Some(head);
        }
    }

    #[async_trait]
    impl ChainSource for FakeSource {
        async fn latest_block_number(&self) -> Result<u64, SourceError> {
            unimplemented!("pipeline tests feed heads directly")
        }
        async fn head_by_number(&self, _n: u64) -> Result<ChainHead, SourceError> {
            unimplemented!("pipeline tests feed heads directly")
        }
        async fn head_by_hash(&self, hash: B256) -> Result<ChainHead, SourceError> {
            self.heads
                .iter()
                .find(|h| h.hash == hash)
                .copied()
                .ok_or_else(|| SourceError::BlockNotFound(hash.to_string()))
        }
        async fn finalized_head(&self) -> Result<ChainHead, SourceError> {
            self.finalized
                .lock()
                .unwrap()
                .ok_or_else(|| SourceError::BlockNotFound("finalized".into()))
        }
    }

    fn head(number: u64, hash: u8, parent: u8) -> ChainHead {
        ChainHead {
            number,
            hash: B256::repeat_byte(hash),
            parent_hash: B256::repeat_byte(parent),
            timestamp: 1_700_000_000 + number,
            tx_count: number as u32, // distinct per block, surfaces in BlockAssembled
        }
    }

    fn b(byte: u8) -> B256 {
        B256::repeat_byte(byte)
    }

    fn pipeline(source: Arc<FakeSource>, sink: Arc<RecordingSink>) -> Pipeline {
        Pipeline::new(Chain::ETHEREUM, source, sink, 64, CancellationToken::new())
    }

    #[tokio::test]
    async fn linear_extension_emits_received_assembled_canonicalized_per_block() {
        let source = Arc::new(FakeSource::new(vec![]));
        let sink = Arc::new(RecordingSink::default());
        let mut p = pipeline(source, sink.clone());

        p.ingest(head(1, 0x01, 0x00)).await.unwrap();
        p.ingest(head(2, 0x02, 0x01)).await.unwrap();

        assert_eq!(
            sink.types(),
            vec![
                "RawBlockReceived",
                "BlockAssembled",
                "BlockCanonicalized",
                "RawBlockReceived",
                "BlockAssembled",
                "BlockCanonicalized",
            ]
        );
    }

    #[tokio::test]
    async fn a_repeat_poll_of_a_known_head_emits_nothing() {
        let source = Arc::new(FakeSource::new(vec![]));
        let sink = Arc::new(RecordingSink::default());
        let mut p = pipeline(source, sink.clone());

        p.ingest(head(1, 0x01, 0x00)).await.unwrap();
        let after_first = sink.types().len();
        p.ingest(head(1, 0x01, 0x00)).await.unwrap(); // duplicate

        assert_eq!(
            sink.types().len(),
            after_first,
            "duplicate must not re-emit"
        );
    }

    #[tokio::test]
    async fn missing_parent_is_backfilled_from_the_source_before_emitting() {
        // Block 3 arrives before 2; the driver fetches 2 via head_by_hash.
        let two = head(2, 0x02, 0x01);
        let source = Arc::new(FakeSource::new(vec![two]));
        let sink = Arc::new(RecordingSink::default());
        let mut p = pipeline(source, sink.clone());

        p.ingest(head(1, 0x01, 0x00)).await.unwrap();
        p.ingest(head(3, 0x03, 0x02)).await.unwrap(); // parent 2 missing → backfill

        // Block 2 (backfilled) is emitted before block 3, ascending.
        let blocks: Vec<u64> = sink
            .blocks()
            .into_iter()
            .filter(|(t, _)| t == "RawBlockReceived")
            .map(|(_, b)| b.number)
            .collect();
        assert_eq!(blocks, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn a_reorg_emits_the_full_swap_through_the_driver() {
        // Canonical 1<-2<-3, then a heavier branch 2'<-3' off block 1.
        let source = Arc::new(FakeSource::new(vec![head(2, 0x12, 0x01)]));
        let sink = Arc::new(RecordingSink::default());
        let mut p = pipeline(source, sink.clone());

        p.ingest(head(1, 0x01, 0x00)).await.unwrap();
        p.ingest(head(2, 0x02, 0x01)).await.unwrap();
        p.ingest(head(3, 0x03, 0x02)).await.unwrap();
        sink.clear(); // focus on the reorg

        // 3' (parent 2') beats the tip; 2' is back-filled as a fork first.
        p.ingest(head(3, 0x13, 0x12)).await.unwrap();

        // 2' observed (fork), 3' observed, revert 3 then 2 (tip-first),
        // canonicalize 2' then 3' (ancestor-first).
        assert_eq!(
            sink.types(),
            vec![
                "RawBlockReceived", // 2'
                "BlockAssembled",
                "RawBlockReceived", // 3'
                "BlockAssembled",
                "BlockReverted",      // 3
                "BlockReverted",      // 2
                "BlockCanonicalized", // 2'
                "BlockCanonicalized", // 3'
            ]
        );
    }

    #[tokio::test]
    async fn finalize_emits_blockfinalized_ascending_then_does_not_re_report() {
        let source = Arc::new(FakeSource::new(vec![]));
        let sink = Arc::new(RecordingSink::default());
        let mut p = pipeline(source.clone(), sink.clone());

        for n in 1..=4u64 {
            p.ingest(head(n, n as u8, (n - 1) as u8)).await.unwrap();
        }
        sink.clear();

        source.set_finalized(head(2, 0x02, 0x01));
        p.tick_finalize().await.unwrap();
        assert_eq!(
            sink.blocks(),
            vec![
                ("BlockFinalized".into(), BlockRef::new(1, b(0x01))),
                ("BlockFinalized".into(), BlockRef::new(2, b(0x02))),
            ]
        );

        // Advancing finality only reports the newly-crossed blocks.
        source.set_finalized(head(3, 0x03, 0x02));
        sink.clear();
        p.tick_finalize().await.unwrap();
        assert_eq!(
            sink.blocks(),
            vec![("BlockFinalized".into(), BlockRef::new(3, b(0x03)))]
        );
    }

    #[tokio::test]
    async fn finalize_before_any_finalized_tag_is_a_noop() {
        let source = Arc::new(FakeSource::new(vec![]));
        let sink = Arc::new(RecordingSink::default());
        let mut p = pipeline(source, sink.clone());
        p.ingest(head(1, 0x01, 0x00)).await.unwrap();
        sink.clear();

        // Source has no finalized head yet → fetch errors → no events, no panic.
        p.tick_finalize().await.unwrap();
        assert!(sink.blocks().is_empty());
    }

    #[tokio::test]
    async fn a_transient_publish_failure_is_retried_until_it_succeeds() {
        let source = Arc::new(FakeSource::new(vec![]));
        let sink = Arc::new(FlakySink {
            remaining_failures: Mutex::new(2),
            delivered: Mutex::new(vec![]),
        });
        let mut p = Pipeline::new(
            Chain::ETHEREUM,
            source,
            sink.clone(),
            64,
            CancellationToken::new(),
        );
        p.publish_backoff = Duration::from_millis(1); // keep the test fast

        p.ingest(head(1, 0x01, 0x00)).await.unwrap();

        // The first event survived two transient failures; all three landed in
        // order — none was lost to the blip.
        assert_eq!(
            *sink.delivered.lock().unwrap(),
            vec!["RawBlockReceived", "BlockAssembled", "BlockCanonicalized"]
        );
    }

    #[tokio::test]
    async fn progress_watermark_reports_the_tip_after_publish_and_dedups() {
        let source = Arc::new(FakeSource::new(vec![]));
        let sink = Arc::new(RecordingSink::default());
        let (tx, mut rx) = mpsc::channel::<BlockRef>(16);
        let mut p = pipeline(source, sink);
        p.report_progress_to(tx);

        p.ingest(head(1, 0x01, 0x00)).await.unwrap();
        p.ingest(head(2, 0x02, 0x01)).await.unwrap();
        // A duplicate poll doesn't move the tip, so it acks nothing.
        p.ingest(head(2, 0x02, 0x01)).await.unwrap();

        let mut acked = Vec::new();
        while let Ok(b) = rx.try_recv() {
            acked.push(b);
        }
        assert_eq!(
            acked,
            vec![BlockRef::new(1, b(0x01)), BlockRef::new(2, b(0x02))],
            "watermark advances once per new canonical tip, no duplicate for the repeat poll"
        );
    }

    #[tokio::test]
    async fn progress_watermark_reports_the_new_tip_after_a_reorg() {
        // The ack must follow the reorg's *new* canonical tip, not the orphaned one.
        let source = Arc::new(FakeSource::new(vec![head(2, 0x12, 0x01)]));
        let sink = Arc::new(RecordingSink::default());
        let (tx, mut rx) = mpsc::channel::<BlockRef>(16);
        let mut p = pipeline(source, sink);
        p.report_progress_to(tx);

        p.ingest(head(1, 0x01, 0x00)).await.unwrap();
        p.ingest(head(2, 0x02, 0x01)).await.unwrap();
        while rx.try_recv().is_ok() {} // drain up to the pre-reorg tip
        p.ingest(head(3, 0x13, 0x12)).await.unwrap(); // reorg: 2' back-filled, 3' wins

        let last = std::iter::from_fn(|| rx.try_recv().ok()).last();
        assert_eq!(
            last,
            Some(BlockRef::new(3, b(0x13))),
            "watermark tracks the new canonical tip after the swap"
        );
    }

    #[tokio::test]
    async fn shutdown_during_publish_retry_stops_without_blocking_forever() {
        let source = Arc::new(FakeSource::new(vec![]));
        // Always fails transiently → would retry forever without the shutdown.
        let sink = Arc::new(FlakySink {
            remaining_failures: Mutex::new(u32::MAX),
            delivered: Mutex::new(vec![]),
        });
        let shutdown = CancellationToken::new();
        let mut p = Pipeline::new(Chain::ETHEREUM, source, sink, 64, shutdown.clone());
        p.publish_backoff = Duration::from_secs(3600); // long, so we exit via cancel

        shutdown.cancel(); // already cancelled: the retry's select takes this arm
                           // Completes promptly rather than hanging on the never-succeeding sink.
        p.ingest(head(1, 0x01, 0x00)).await.unwrap();
    }
}
