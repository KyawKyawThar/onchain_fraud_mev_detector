//! Adapter #1 (§5): the **reth ExEx** in-node post-execution source.
//!
//! §5 lists this as the most-preferred source adapter — an *in-node*
//! post-execution pipeline. Instead of polling an RPC endpoint from outside
//! (adapter #3, [`super::rpc`]), the process runs *inside* a reth node as an
//! Execution Extension (ExEx): after reth executes a block it hands the ExEx an
//! `ExExNotification` describing how the canonical chain changed
//! (committed / reverted / reorged), with the executed blocks and their
//! post-execution outcome already in hand.
//!
//! ## Preserving the Sprint 2 contract
//!
//! The RPC path is *pull*-based: a head poller ([`super::head_stream`]) diffs the
//! chain tip and streams [`ChainHead`]s into the [`Pipeline`](crate::pipeline),
//! which owns the reorg-aware [`BlockTree`](crate::tree) and emits the chain
//! lifecycle events. An ExEx is *push*-based. Rather than grow a *second* reorg
//! implementation (and a second, divergent event mapping), this adapter reuses
//! the existing one wholesale: it translates each notification into the same
//! ascending [`ChainHead`] stream the poller produces and feeds it to the same
//! [`Pipeline`]. The [`BlockTree`](crate::tree) then re-derives every
//! `BlockReverted`/`BlockCanonicalized` from the committed branch's `parent_hash`
//! walk exactly as it does for the RPC source — so the emitted
//! `RawBlockReceived`/`BlockAssembled`/`BlockCanonicalized`/`BlockReverted`/
//! `BlockFinalized` events are **identical** whichever adapter is wired. There is
//! one reorg algorithm in this service, and it lives in [`crate::tree`].
//!
//! ## Trace availability is a capability, not a wish
//!
//! [`BlockAssembled::trace_available`](events::chain::BlockAssembled::trace_available)
//! is a *promise* to trace-dependent detectors, so it must follow a real
//! mechanism, never precede it. The mechanism is the [`ExecutedBlockSink`] port:
//! the in-node adapter has each block's post-execution facts (tx set, and later
//! receipts/traces) in hand, and ships them out of the node through this sink to
//! wherever the (out-of-process) detection service reads them — the "tx-carrying
//! layer" §6 is waiting on. A source built with [`ExExSource::new`] has no sink
//! and honestly reports `traces_available() == false` (header-only, like the RPC
//! pool); one built with [`ExExSource::with_execution_sink`] reports exactly what
//! that sink [`delivers_traces`](ExecutedBlockSink::delivers_traces) — so the flag
//! is *structurally* tied to the delivery mechanism and can't be turned on by
//! wishful thinking. (This turn wires the producer port + a tx-set payload; the
//! cross-process store that persists it and the detection-side bundle source that
//! consumes it are the paired follow-on — the sink is the seam they plug into.)
//!
//! ## Durable acknowledgement (pruning safety)
//!
//! reth needs an `ExExEvent::FinishedHeight(N)` to prune executed blocks it no
//! longer has to keep for us. That ack must **trail durability**, not enqueue: if
//! we acked a height as soon as its head entered the channel, a crash before the
//! `BlockAssembled` reached Kafka would let reth prune a block whose event never
//! shipped — a permanent hole in an at-least-once audit stream. So the ack is not
//! produced here; it is the [`Pipeline`](crate::pipeline)'s **progress watermark**
//! ([`report_progress_to`](crate::pipeline::Pipeline::report_progress_to)), which
//! fires the canonical tip only *after* that head's events are published. The
//! reth glue turns the watermark into `FinishedHeight`. [`run_bridge`] just feeds
//! heads and records state.
//!
//! ## Backpressure policy
//!
//! The head channel is bounded. When it fills (a Kafka stall), [`run_bridge`]
//! **blocks** rather than drop a head — losing a `BlockAssembled` is unrecoverable
//! (see above), so correctness wins over node-liveness for this analytics ExEx.
//! Blocking naturally backpressures reth's notification loop; a sustained stall is
//! made visible through the [`BACKPRESSURE_TOTAL`] counter so it is alertable
//! rather than silent.
//!
//! ## The two seams this module provides
//!
//! 1. [`ExExSource`] — a [`ChainSource`] the [`Pipeline`] reads for the two
//!    things it needs beyond the head stream: back-filling a missing parent
//!    ([`head_by_hash`](ChainSource::head_by_hash)) and advancing finality
//!    ([`finalized_head`](ChainSource::finalized_head)). It does no network I/O —
//!    it answers from an in-memory buffer the bridge fills from each notification.
//! 2. [`run_bridge`] — the driver that consumes an [`ExExNotice`] stream, records
//!    each notification into the [`ExExSource`], forwards the committed heads to
//!    the pipeline's head channel (metered, with the backpressure policy above),
//!    and ships each committed block's execution facts to the [`ExecutedBlockSink`].
//!
//! ## reth-agnostic on purpose
//!
//! Everything here is written against [`ExExNotice`] — a plain, reth-free
//! reduction of reth's `ExExNotification` — so the whole bridge is unit-testable
//! **without compiling reth**. The real `ExExNotification` → [`ExExNotice`]
//! mapping and the node registration live in the *excluded* `ingestion-exex-node`
//! crate (not a workspace member): reth's crates pin their own alloy/revm
//! versions that would clash with this workspace's `alloy = "1"` pin (the same
//! reason simulation defers revm's `alloydb` backend), so the reth dependency is
//! isolated in its own lockfile and never enters the default `--workspace
//! --all-features` build. See `crates/ingestion-exex-node/README.md`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use alloy_primitives::B256;
use async_trait::async_trait;
use events::primitives::BlockRef;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::{ChainHead, ChainSource, SourceError};

/// One committed block's **post-execution facts**, shipped out of the node
/// through an [`ExecutedBlockSink`].
///
/// Today it carries the transaction set in block order — exactly the raw facts a
/// detector's `BlockBundle` needs, which the header-only feed can't supply
/// (§6, the "tx-carrying layer"). Receipts and traces extend this struct without
/// changing the seam; when they're present the delivering sink flips
/// [`delivers_traces`](ExecutedBlockSink::delivers_traces) and the pipeline's
/// `trace_available` follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutedBlock {
    /// The block these facts belong to — the key a consumer joins on against the
    /// `BlockAssembled` it sees on Kafka.
    pub block: BlockRef,
    /// Transaction hashes in block order (feeds `BlockBundle::txs`).
    pub txs: Vec<B256>,
}

/// The port for shipping in-node execution outcome to its (out-of-process)
/// consumer — a store the detection service's bundle source reads (§6).
///
/// The ExEx runs inside reth; detection is a separate service, so the executed
/// facts must cross a process boundary. This trait is that boundary: the bridge
/// writes each committed [`ExecutedBlock`] here and stays ignorant of whether the
/// far side is Kafka, a KV store, or a test double. Object-safe (via `async_trait`)
/// so [`ExExSource`] can hold a `dyn` sink chosen by configuration.
#[async_trait]
pub trait ExecutedBlockSink: Send + Sync {
    /// Ship one committed block's post-execution facts. At-least-once semantics
    /// and durability are the sink's concern (mirroring [`crate::publisher`]).
    async fn record(&self, executed: ExecutedBlock);

    /// Whether blocks shipped through this sink carry execution **traces** (not
    /// just the tx set). Drives `BlockAssembled.trace_available`: a tx-set-only
    /// sink returns `false` and trace-gated detectors stay gated; a
    /// trace-carrying sink returns `true`. Defaults to `false` so a new sink can't
    /// accidentally over-promise.
    fn delivers_traces(&self) -> bool {
        false
    }
}

/// Counter: reth notifications processed, labelled `kind` = `commit`/`reorg`/
/// `revert`/`empty`.
pub const NOTIFICATIONS_TOTAL: &str = "ingestion_exex_notifications_total";
/// Counter: committed heads forwarded to the pipeline.
pub const HEADS_FORWARDED_TOTAL: &str = "ingestion_exex_heads_forwarded_total";
/// Histogram: reverted-branch length per reorg (reorg depth).
pub const REORG_DEPTH: &str = "ingestion_exex_reorg_depth";
/// Gauge: blocks currently retained in the [`ExExSource`] back-fill buffer.
pub const BUFFER_BLOCKS: &str = "ingestion_exex_buffer_blocks";
/// Counter: head sends that had to block on a full channel (backpressure). A
/// sustained rate here means the downstream (Kafka) can't keep up and reth is
/// being throttled.
pub const BACKPRESSURE_TOTAL: &str = "ingestion_exex_backpressure_total";
/// Counter: committed [`ExecutedBlock`]s shipped through the execution sink.
pub const EXECUTED_SHIPPED_TOTAL: &str = "ingestion_exex_executed_shipped_total";

/// One reth `ExExNotification`, reduced to the reorg-agnostic facts the
/// ingestion pipeline needs.
///
/// Mirrors reth's three notification shapes (`ChainCommitted`,
/// `ChainReverted`, `ChainReorged`) collapsed into two head lists plus the
/// finalized tag:
///
/// - A plain commit sets [`committed`](Self::committed) (ascending) and leaves
///   [`reverted`](Self::reverted) empty.
/// - A reorg sets both — `committed` is the new canonical segment, `reverted`
///   the old one reth unwound.
///
/// Carrying only [`ChainHead`]s (no reth types) is what keeps the bridge
/// unit-testable without reth.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExExNotice {
    /// New-canonical blocks, **ascending by number** (reth `committed_chain`).
    /// These are the heads fed to the [`Pipeline`](crate::pipeline); the tree
    /// derives the lifecycle events from them.
    pub committed: Vec<ChainHead>,
    /// Blocks reth reverted / reorged out, ascending (reth `reverted_chain`).
    ///
    /// Recorded into the [`ExExSource`] buffer so a subsequent back-fill can find
    /// them, but **not** fed to the tree: the tree re-derives the revert from the
    /// committed branch's `parent_hash` walk (fork choice), so feeding the old
    /// blocks too would double-count. Keeping the *one* reorg implementation
    /// authoritative is what makes the emitted events match the RPC path.
    pub reverted: Vec<ChainHead>,
    /// reth's finalized head at notification time, if the node reported one.
    /// Drives the pipeline's `BlockFinalized` tick via
    /// [`ExExSource::finalized_head`]. `None` leaves finality unchanged.
    pub finalized: Option<ChainHead>,
    /// Post-execution facts for the committed blocks (tx set, later traces),
    /// shipped to the [`ExecutedBlockSink`] if one is wired. Empty on a header-only
    /// deployment or a pure revert. Kept separate from [`committed`](Self::committed)
    /// because [`ChainHead`] is deliberately header-only (shared with the RPC path);
    /// this is the extra the *in-node* adapter can supply.
    pub executed: Vec<ExecutedBlock>,
}

impl ExExNotice {
    /// The metric `kind` label for this notification's shape.
    fn kind(&self) -> &'static str {
        match (self.committed.is_empty(), self.reverted.is_empty()) {
            (false, true) => "commit",
            (false, false) => "reorg",
            (true, false) => "revert",
            (true, true) => "empty",
        }
    }
}

/// The [`ChainSource`] the ExEx pipeline reads for back-fill and finality.
///
/// Unlike the RPC pool it performs no network I/O: the bridge fills an in-memory
/// buffer from each [`ExExNotice`], and this answers from that buffer. It is a
/// full [`ChainSource`] (every method is serviceable) so it composes with the
/// existing [`Pipeline`](crate::pipeline) unchanged, but on the push path the
/// pipeline only ever calls [`head_by_hash`](ChainSource::head_by_hash) (reorg
/// back-fill) and [`finalized_head`](ChainSource::finalized_head) (finality
/// tick) — the poller methods are serviced for completeness, not driven.
pub struct ExExSource {
    inner: Mutex<Buffer>,
    /// Max blocks retained for back-fill lookups; the lowest-numbered are evicted
    /// first. The tree only ever back-fills down to its finality floor, so a few
    /// finalization windows of history is ample; the cap keeps the buffer bounded
    /// like the tree itself (§5: "no persistent store needed").
    capacity: usize,
    /// Where committed blocks' post-execution facts are shipped, or `None` for a
    /// header-only deployment. Its [`delivers_traces`](ExecutedBlockSink::delivers_traces)
    /// is the authority for [`traces_available`](Self::traces_available), so the
    /// trace promise can never outrun the mechanism.
    execution_sink: Option<Arc<dyn ExecutedBlockSink>>,
}

/// The recently-observed blocks, keyed for the [`ChainSource`] lookups, plus the
/// finalized tag. Eviction is by ascending `(number, hash)` so the deepest
/// history drops first.
#[derive(Debug, Default)]
struct Buffer {
    by_hash: HashMap<B256, ChainHead>,
    /// Best-effort height → hash (latest writer wins), for the poller-path
    /// [`head_by_number`](ChainSource::head_by_number) / tip queries.
    by_number: BTreeMap<u64, B256>,
    /// Ascending `(number, hash)`, the eviction order.
    order: BTreeSet<(u64, B256)>,
    finalized: Option<ChainHead>,
}

impl std::fmt::Debug for ExExSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExExSource")
            .field("capacity", &self.capacity)
            .field("has_execution_sink", &self.execution_sink.is_some())
            .field("traces_available", &self.traces_available())
            .finish_non_exhaustive()
    }
}

impl ExExSource {
    /// A **header-only** source buffering up to `capacity` recently-observed
    /// blocks (clamped to at least 1). Size it to a few finalization windows —
    /// enough that a reorg back-fill down to the finality floor always hits. No
    /// execution sink, so `traces_available() == false`, matching the RPC pool.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Buffer::default()),
            capacity: capacity.max(1),
            execution_sink: None,
        }
    }

    /// A source that ships each committed block's post-execution facts through
    /// `sink`. Its [`traces_available`](Self::traces_available) becomes exactly
    /// `sink.delivers_traces()`, so the trace promise follows the delivery
    /// mechanism instead of being asserted independently.
    pub fn with_execution_sink(capacity: usize, sink: Arc<dyn ExecutedBlockSink>) -> Self {
        Self {
            inner: Mutex::new(Buffer::default()),
            capacity: capacity.max(1),
            execution_sink: Some(sink),
        }
    }

    /// Ship the committed blocks' post-execution facts to the execution sink, if
    /// one is wired (a no-op on a header-only deployment). Called by the bridge
    /// after the heads are forwarded.
    async fn ship_executed(&self, executed: &[ExecutedBlock]) {
        let Some(sink) = &self.execution_sink else {
            return;
        };
        for block in executed {
            sink.record(block.clone()).await;
        }
    }

    /// The highest block number currently buffered, or `None` before the first
    /// notification.
    pub fn tip_number(&self) -> Option<u64> {
        self.inner
            .lock()
            .expect("exex buffer poisoned")
            .by_number
            .keys()
            .next_back()
            .copied()
    }

    /// Blocks currently retained in the back-fill buffer (for the [`BUFFER_BLOCKS`]
    /// gauge).
    pub fn buffered_len(&self) -> usize {
        self.inner
            .lock()
            .expect("exex buffer poisoned")
            .by_hash
            .len()
    }

    /// Fold one notification into the buffer: record its reverted then committed
    /// blocks (so a later back-fill finds either branch, and the *canonical*
    /// block wins the `by_number` index at a reorged height) and advance the
    /// finalized tag if the notification carried one. Called by [`run_bridge`]
    /// *before* the committed heads are forwarded, so the pipeline's back-fill can
    /// always resolve a parent it asks for.
    fn absorb(&self, notice: &ExExNotice) {
        let mut buf = self.inner.lock().expect("exex buffer poisoned");
        // Reverted first, committed last: `record` lets the last writer win the
        // height index, so the new-canonical block is the one `head_by_number`
        // returns at a height both branches touched.
        for head in notice.reverted.iter().chain(&notice.committed) {
            buf.record(*head);
        }
        if let Some(finalized) = notice.finalized {
            buf.finalized = Some(finalized);
        }
        buf.evict_to(self.capacity);
    }
}

impl Buffer {
    /// Insert a head: `by_hash` keeps the first record for a hash (idempotent),
    /// `by_number` takes the latest writer (so callers control which branch wins).
    fn record(&mut self, head: ChainHead) {
        self.by_hash.entry(head.hash).or_insert(head);
        self.by_number.insert(head.number, head.hash);
        self.order.insert((head.number, head.hash));
    }

    /// Drop the lowest-numbered blocks until at most `capacity` remain.
    fn evict_to(&mut self, capacity: usize) {
        while self.by_hash.len() > capacity {
            // `order` is non-empty whenever `by_hash` is, and carries the same
            // keys, so the lowest entry always exists here.
            let Some(&(number, hash)) = self.order.iter().next() else {
                break;
            };
            self.order.remove(&(number, hash));
            self.by_hash.remove(&hash);
            // Only clear the height index if it still points at the evicted hash
            // (a reorg may have overwritten it with a newer same-height block).
            if self.by_number.get(&number) == Some(&hash) {
                self.by_number.remove(&number);
            }
        }
    }
}

#[async_trait]
impl ChainSource for ExExSource {
    async fn latest_block_number(&self) -> Result<u64, SourceError> {
        self.tip_number()
            .ok_or(SourceError::Unavailable("exex has observed no blocks yet"))
    }

    async fn head_by_number(&self, number: u64) -> Result<ChainHead, SourceError> {
        let buf = self.inner.lock().expect("exex buffer poisoned");
        buf.by_number
            .get(&number)
            .and_then(|hash| buf.by_hash.get(hash))
            .copied()
            .ok_or_else(|| SourceError::BlockNotFound(number.to_string()))
    }

    async fn head_by_hash(&self, hash: B256) -> Result<ChainHead, SourceError> {
        self.inner
            .lock()
            .expect("exex buffer poisoned")
            .by_hash
            .get(&hash)
            .copied()
            .ok_or_else(|| SourceError::BlockNotFound(hash.to_string()))
    }

    async fn finalized_head(&self) -> Result<ChainHead, SourceError> {
        // Before the node reports a `finalized` tag this is unavailable, not a
        // missing block — `Pipeline::tick_finalize` treats either as "retry next
        // tick", never fatal.
        self.inner
            .lock()
            .expect("exex buffer poisoned")
            .finalized
            .ok_or(SourceError::Unavailable("exex has no finalized head yet"))
    }

    fn traces_available(&self) -> bool {
        // Structurally tied to the delivery mechanism: true only when a wired sink
        // actually carries traces — never an independent assertion.
        self.execution_sink
            .as_ref()
            .is_some_and(|sink| sink.delivers_traces())
    }
}

/// Drive the ExEx notification stream into the ingestion pipeline.
///
/// For each [`ExExNotice`]: record it into `source` (so back-fill and finality
/// can see it) and forward the committed heads — ascending — to `heads` (the same
/// channel [`Pipeline::run`](crate::pipeline::Pipeline::run) consumes). Pruning
/// acks are **not** produced here; they are the pipeline's durable-progress
/// watermark (see the [module docs](self)).
///
/// Returns when `shutdown` is cancelled, the notification stream closes (the
/// node stopped), or the pipeline dropped the head channel. Symmetric with
/// [`run_head_poller`](super::head_stream::run_head_poller) — the ExEx replaces
/// the poller as the head producer; everything downstream is unchanged.
pub async fn run_bridge(
    mut notices: mpsc::Receiver<ExExNotice>,
    heads: mpsc::Sender<ChainHead>,
    source: Arc<ExExSource>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                tracing::info!("exex bridge shutting down");
                return;
            }
            notice = notices.recv() => match notice {
                Some(notice) => {
                    if !forward(&notice, &heads, &source).await {
                        return; // the pipeline dropped the head channel
                    }
                }
                None => {
                    tracing::info!("exex notification stream closed; bridge stopping");
                    return;
                }
            }
        }
    }
}

/// Handle one notification: record it, meter it, and forward the committed heads.
/// Returns `false` if the head consumer went away (the caller should stop).
async fn forward(
    notice: &ExExNotice,
    heads: &mpsc::Sender<ChainHead>,
    source: &ExExSource,
) -> bool {
    source.absorb(notice);

    metrics::counter!(NOTIFICATIONS_TOTAL, "kind" => notice.kind()).increment(1);
    if !notice.reverted.is_empty() {
        metrics::histogram!(REORG_DEPTH).record(notice.reverted.len() as f64);
    }
    metrics::gauge!(BUFFER_BLOCKS).set(source.buffered_len() as f64);

    for &head in &notice.committed {
        // Backpressure policy: try the non-blocking send first; if the channel is
        // full, record it and BLOCK (never drop an audit head — a lost
        // `BlockAssembled` is unrecoverable). Blocking throttles reth's ExEx loop,
        // which is the intended safety trade-off; the counter makes a stall visible.
        match heads.try_send(head) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(head)) => {
                metrics::counter!(BACKPRESSURE_TOTAL).increment(1);
                if heads.send(head).await.is_err() {
                    tracing::info!("head consumer dropped; stopping exex bridge");
                    return false;
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::info!("head consumer dropped; stopping exex bridge");
                return false;
            }
        }
    }
    metrics::counter!(HEADS_FORWARDED_TOTAL).increment(notice.committed.len() as u64);

    // Ship the committed blocks' post-execution facts to the execution sink (a
    // no-op on a header-only deployment). Ordered after the heads so a consumer
    // that joins executed facts to a `BlockAssembled` never sees facts for a block
    // whose head hasn't been forwarded.
    source.ship_executed(&notice.executed).await;
    if !notice.executed.is_empty() {
        metrics::counter!(EXECUTED_SHIPPED_TOTAL).increment(notice.executed.len() as u64);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use events::primitives::{BlockRef, Chain};
    use events::DomainEvent;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use crate::pipeline::Pipeline;
    use event_bus::test_util::RecordingSink;

    fn head(number: u64, hash: u8, parent: u8) -> ChainHead {
        ChainHead {
            number,
            hash: B256::repeat_byte(hash),
            parent_hash: B256::repeat_byte(parent),
            timestamp: 1_700_000_000 + number,
            tx_count: number as u32,
        }
    }

    fn b(byte: u8) -> B256 {
        B256::repeat_byte(byte)
    }

    fn commit(heads: Vec<ChainHead>) -> ExExNotice {
        ExExNotice {
            committed: heads,
            ..Default::default()
        }
    }

    fn executed(number: u64, hash: u8, txs: &[u8]) -> ExecutedBlock {
        ExecutedBlock {
            block: BlockRef::new(number, b(hash)),
            txs: txs.iter().map(|&t| b(t)).collect(),
        }
    }

    /// A recording [`ExecutedBlockSink`] double: captures every shipped block and
    /// reports a configurable `delivers_traces` capability.
    #[derive(Default)]
    struct RecordingExecutedSink {
        recorded: std::sync::Mutex<Vec<ExecutedBlock>>,
        delivers_traces: bool,
    }

    impl RecordingExecutedSink {
        fn tracing() -> Self {
            Self {
                delivers_traces: true,
                ..Default::default()
            }
        }
        fn recorded(&self) -> Vec<ExecutedBlock> {
            self.recorded.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ExecutedBlockSink for RecordingExecutedSink {
        async fn record(&self, executed: ExecutedBlock) {
            self.recorded.lock().unwrap().push(executed);
        }
        fn delivers_traces(&self) -> bool {
            self.delivers_traces
        }
    }

    /// Run the bridge to completion over a fixed list of notices (dropping the
    /// sender closes the stream), returning the forwarded heads. Single-threaded:
    /// the head channel is ample for the small test inputs.
    async fn drive_bridge(source: Arc<ExExSource>, notices: Vec<ExExNotice>) -> Vec<ChainHead> {
        let (ntx, nrx) = mpsc::channel(64);
        let (htx, mut hrx) = mpsc::channel(1024);
        for n in notices {
            ntx.send(n).await.unwrap();
        }
        drop(ntx); // close the stream so run_bridge returns
        run_bridge(nrx, htx, source, CancellationToken::new()).await;

        let mut heads = Vec::new();
        while let Ok(h) = hrx.try_recv() {
            heads.push(h);
        }
        heads
    }

    // ── Bridge behaviour ──────────────────────────────────────────────

    #[tokio::test]
    async fn bridge_forwards_committed_heads_ascending() {
        let source = Arc::new(ExExSource::new(256));
        let notices = vec![
            commit(vec![head(1, 0x01, 0x00), head(2, 0x02, 0x01)]),
            commit(vec![head(3, 0x03, 0x02)]),
        ];
        let heads = drive_bridge(source, notices).await;

        assert_eq!(
            heads.iter().map(|h| h.number).collect::<Vec<_>>(),
            vec![1, 2, 3],
            "committed heads forwarded ascending, across notifications"
        );
    }

    #[tokio::test]
    async fn bridge_records_reverted_blocks_for_backfill_but_does_not_forward_them() {
        let source = Arc::new(ExExSource::new(256));
        let notice = ExExNotice {
            committed: vec![head(2, 0x12, 0x01)],
            reverted: vec![head(2, 0x02, 0x01)],
            finalized: None,
            executed: Vec::new(),
        };
        let heads = drive_bridge(source.clone(), vec![notice]).await;

        assert_eq!(
            heads.iter().map(|h| h.hash).collect::<Vec<_>>(),
            vec![b(0x12)],
            "only the committed (new-canonical) head is forwarded to the tree"
        );
        // The reverted block is still queryable for a back-fill walk…
        assert_eq!(source.head_by_hash(b(0x02)).await.unwrap().hash, b(0x02));
        // …but the canonical block wins the height index (reverted recorded first).
        assert_eq!(
            source.head_by_number(2).await.unwrap().hash,
            b(0x12),
            "canonical block wins by_number at a reorged height"
        );
    }

    #[tokio::test]
    async fn bridge_carries_the_finalized_tag_into_the_source() {
        let source = Arc::new(ExExSource::new(256));
        let notice = ExExNotice {
            committed: vec![head(5, 0x05, 0x04)],
            reverted: vec![],
            finalized: Some(head(3, 0x03, 0x02)),
            executed: Vec::new(),
        };
        drive_bridge(source.clone(), vec![notice]).await;

        assert_eq!(
            source.finalized_head().await.unwrap().block_ref(),
            BlockRef::new(3, b(0x03)),
        );
    }

    #[tokio::test]
    async fn bridge_stops_when_the_head_consumer_is_gone() {
        let source = Arc::new(ExExSource::new(256));
        let (ntx, nrx) = mpsc::channel(8);
        let (htx, hrx) = mpsc::channel(8);
        drop(hrx); // pipeline gone
        ntx.send(commit(vec![head(1, 0x01, 0x00)])).await.unwrap();
        // Does not hang: the failed head send makes the bridge return promptly.
        run_bridge(nrx, htx, source, CancellationToken::new()).await;
    }

    // ── Metrics ───────────────────────────────────────────────────────

    #[test]
    fn bridge_meters_notifications_forwarded_heads_and_reorg_depth() {
        // Sum across label sets: `NOTIFICATIONS_TOTAL{kind}` is several series.
        fn counter(series: &[(String, DebugValue)], name: &str) -> Option<u64> {
            let total: u64 = series
                .iter()
                .filter(|(n, _)| n == name)
                .filter_map(|(_, v)| match v {
                    DebugValue::Counter(c) => Some(*c),
                    _ => None,
                })
                .sum();
            series.iter().any(|(n, _)| n == name).then_some(total)
        }

        let recorder = DebuggingRecorder::new();
        let snap = recorder.snapshotter();
        // A commit (2 heads) then a reorg (depth 2). The recorder is thread-local
        // and a current-thread runtime polls the bridge on this same thread, so it
        // captures every emit (no global install → tests don't contend).
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        metrics::with_local_recorder(&recorder, || {
            rt.block_on(async {
                let source = Arc::new(ExExSource::new(256));
                drive_bridge(
                    source,
                    vec![
                        commit(vec![head(1, 0x01, 0x00), head(2, 0x02, 0x01)]),
                        ExExNotice {
                            committed: vec![head(2, 0x12, 0x01), head(3, 0x13, 0x12)],
                            reverted: vec![head(2, 0x02, 0x01), head(3, 0x03, 0x02)],
                            finalized: None,
                            executed: Vec::new(),
                        },
                    ],
                )
                .await;
            });
        });

        let series: Vec<(String, DebugValue)> = snap
            .snapshot()
            .into_vec()
            .into_iter()
            .map(|(ck, _, _, v)| (ck.key().name().to_owned(), v))
            .collect();

        assert_eq!(
            counter(&series, NOTIFICATIONS_TOTAL),
            Some(2),
            "one commit + one reorg notification"
        );
        assert_eq!(
            counter(&series, HEADS_FORWARDED_TOTAL),
            Some(4),
            "2 committed heads + 2 committed heads"
        );
        match series
            .iter()
            .find(|(n, _)| n == REORG_DEPTH)
            .map(|(_, v)| v)
        {
            Some(DebugValue::Histogram(samples)) => {
                assert_eq!(samples.len(), 1, "one reorg recorded its depth");
                assert_eq!(samples[0].into_inner(), 2.0, "reverted-branch length 2");
            }
            other => panic!("expected a reorg-depth histogram, got {other:?}"),
        }
    }

    // ── ExExSource as a ChainSource ───────────────────────────────────

    #[tokio::test]
    async fn traces_available_follows_the_wired_execution_sink() {
        // Honest default: no sink ⇒ no traces (header-only, like the RPC pool).
        assert!(!ExExSource::new(8).traces_available());
        // A tx-set-only sink still doesn't promise traces…
        let hashes_only: Arc<dyn ExecutedBlockSink> = Arc::new(RecordingExecutedSink::default());
        assert!(!ExExSource::with_execution_sink(8, hashes_only).traces_available());
        // …only a sink that actually carries them flips the flag.
        let tracing: Arc<dyn ExecutedBlockSink> = Arc::new(RecordingExecutedSink::tracing());
        assert!(ExExSource::with_execution_sink(8, tracing).traces_available());
    }

    #[tokio::test]
    async fn bridge_ships_committed_executed_blocks_to_the_sink() {
        let sink = Arc::new(RecordingExecutedSink::tracing());
        let source = Arc::new(ExExSource::with_execution_sink(256, sink.clone()));
        let notice = ExExNotice {
            committed: vec![head(1, 0x01, 0x00), head(2, 0x02, 0x01)],
            executed: vec![executed(1, 0x01, &[0xaa]), executed(2, 0x02, &[0xbb, 0xcc])],
            ..Default::default()
        };
        drive_bridge(source, vec![notice]).await;

        let recorded = sink.recorded();
        assert_eq!(
            recorded.iter().map(|e| e.block.number).collect::<Vec<_>>(),
            vec![1, 2],
            "committed blocks' execution facts shipped in order"
        );
        assert_eq!(recorded[1].txs, vec![b(0xbb), b(0xcc)]);
    }

    #[tokio::test]
    async fn source_answers_lookups_from_the_buffer() {
        let source = Arc::new(ExExSource::new(256));
        drive_bridge(
            source.clone(),
            vec![commit(vec![head(1, 0x01, 0x00), head(2, 0x02, 0x01)])],
        )
        .await;

        assert_eq!(source.head_by_hash(b(0x01)).await.unwrap().number, 1);
        assert_eq!(source.head_by_number(2).await.unwrap().hash, b(0x02));
        assert_eq!(source.latest_block_number().await.unwrap(), 2);
        assert!(source.head_by_hash(b(0xff)).await.is_err());
    }

    #[tokio::test]
    async fn source_reports_unavailable_before_the_first_notification() {
        let source = ExExSource::new(8);
        assert!(matches!(
            source.latest_block_number().await,
            Err(SourceError::Unavailable(_))
        ));
        assert!(matches!(
            source.finalized_head().await,
            Err(SourceError::Unavailable(_))
        ));
    }

    #[tokio::test]
    async fn source_evicts_the_lowest_blocks_beyond_capacity() {
        let source = Arc::new(ExExSource::new(2));
        let notices = (1..=5u64)
            .map(|n| commit(vec![head(n, n as u8, (n - 1) as u8)]))
            .collect();
        drive_bridge(source.clone(), notices).await;

        // Only the two highest survive; the deep history was evicted.
        assert!(source.head_by_hash(b(0x04)).await.is_ok());
        assert!(source.head_by_hash(b(0x05)).await.is_ok());
        assert!(source.head_by_hash(b(0x01)).await.is_err());
        assert_eq!(source.tip_number(), Some(5));
        assert_eq!(source.buffered_len(), 2);
    }

    // ── Same contract as the RPC path (Pipeline over ExExSource) ──────

    /// The event *type names* a [`RecordingSink`] captured, for order assertions.
    /// Excludes `UsageRecorded` (see [`RecordingSink::non_usage_events`]) — the
    /// per-batch `EventProcessed` metering fact (§13) rides the same sink but
    /// isn't part of the chain lifecycle these tests assert on.
    fn types(sink: &RecordingSink) -> Vec<String> {
        sink.non_usage_events()
            .iter()
            .map(|e| e.event_type().to_owned())
            .collect()
    }

    fn exex_pipeline(source: Arc<ExExSource>, sink: Arc<RecordingSink>) -> Pipeline {
        Pipeline::new(Chain::ETHEREUM, source, sink, 64, CancellationToken::new())
    }

    #[tokio::test]
    async fn pipeline_over_exex_source_reproduces_the_lifecycle_with_traces() {
        // A trace-carrying execution sink (as a trace-backed deployment would use)
        // proves the flag rides onto BlockAssembled — the in-node difference.
        let source = Arc::new(ExExSource::with_execution_sink(
            256,
            Arc::new(RecordingExecutedSink::tracing()),
        ));
        let sink = Arc::new(RecordingSink::default());
        source.absorb(&commit(vec![head(1, 0x01, 0x00), head(2, 0x02, 0x01)]));
        let mut p = exex_pipeline(source.clone(), sink.clone());
        p.ingest(head(1, 0x01, 0x00)).await.unwrap();
        p.ingest(head(2, 0x02, 0x01)).await.unwrap();

        // Identical lifecycle to the RPC path's linear-extension test…
        assert_eq!(
            types(&sink),
            vec![
                "RawBlockReceived",
                "BlockAssembled",
                "BlockCanonicalized",
                "RawBlockReceived",
                "BlockAssembled",
                "BlockCanonicalized",
            ]
        );
        // …with traces advertised on every BlockAssembled.
        let all_traced = sink.events().iter().all(|e| match e {
            DomainEvent::BlockAssembled(a) => a.trace_available,
            _ => true,
        });
        assert!(
            all_traced,
            "trace-backed adapter ⇒ trace_available on every block"
        );
    }

    #[tokio::test]
    async fn pipeline_over_exex_source_reproduces_a_reorg() {
        let source = Arc::new(ExExSource::new(256));
        let sink = Arc::new(RecordingSink::default());
        let mut p = exex_pipeline(source.clone(), sink.clone());

        // Canonical 1<-2<-3.
        source.absorb(&commit(vec![
            head(1, 0x01, 0x00),
            head(2, 0x02, 0x01),
            head(3, 0x03, 0x02),
        ]));
        for h in [
            head(1, 0x01, 0x00),
            head(2, 0x02, 0x01),
            head(3, 0x03, 0x02),
        ] {
            p.ingest(h).await.unwrap();
        }
        sink.clear();

        // reth reorgs to a heavier branch 2'<-3' off block 1.
        source.absorb(&ExExNotice {
            committed: vec![head(2, 0x12, 0x01), head(3, 0x13, 0x12)],
            reverted: vec![head(2, 0x02, 0x01), head(3, 0x03, 0x02)],
            finalized: None,
            executed: Vec::new(),
        });
        for h in [head(2, 0x12, 0x01), head(3, 0x13, 0x12)] {
            p.ingest(h).await.unwrap();
        }

        // The tree derives the same revert-then-canonicalize swap the RPC path
        // produces: 2' observed (fork), 3' observed, revert 3 then 2 (tip-first),
        // canonicalize 2' then 3' (ancestor-first).
        assert_eq!(
            types(&sink),
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
    async fn pipeline_over_exex_source_finalizes_from_the_notice_tag() {
        // The notice's finalized tag flows: bridge → ExExSource::finalized →
        // Pipeline::tick_finalize → BlockFinalized (ascending), proving the whole
        // in-node finality path once the glue attaches the node's finalized head.
        let source = Arc::new(ExExSource::new(256));
        let sink = Arc::new(RecordingSink::default());
        let mut p = exex_pipeline(source.clone(), sink.clone());

        for n in 1..=4u64 {
            source.absorb(&commit(vec![head(n, n as u8, (n - 1) as u8)]));
            p.ingest(head(n, n as u8, (n - 1) as u8)).await.unwrap();
        }
        // Before any finalized tag, the tick is a no-op (Unavailable, not fatal).
        p.tick_finalize().await.unwrap();
        sink.clear();

        // A notification reports block 2 finalized.
        source.absorb(&ExExNotice {
            finalized: Some(head(2, 0x02, 0x01)),
            ..Default::default()
        });
        p.tick_finalize().await.unwrap();

        let finalized: Vec<u64> = sink
            .events()
            .iter()
            .filter_map(|e| match e {
                DomainEvent::BlockFinalized(f) => Some(f.block.number),
                _ => None,
            })
            .collect();
        assert_eq!(
            finalized,
            vec![1, 2],
            "blocks that crossed the line, ascending"
        );
    }

    #[tokio::test]
    async fn pipeline_backfills_a_missing_parent_from_the_exex_source() {
        // Prove ExExSource satisfies the tree's back-fill contract: block 3's
        // parent (block 2) is only in the buffer, not yet ingested. The pipeline
        // hits MissingParent and resolves it via ExExSource::head_by_hash.
        let source = Arc::new(ExExSource::new(256));
        let sink = Arc::new(RecordingSink::default());
        let mut p = exex_pipeline(source.clone(), sink.clone());

        source.absorb(&commit(vec![head(1, 0x01, 0x00)]));
        p.ingest(head(1, 0x01, 0x00)).await.unwrap();
        source.absorb(&commit(vec![head(2, 0x02, 0x01), head(3, 0x03, 0x02)]));
        p.ingest(head(3, 0x03, 0x02)).await.unwrap();

        let received: Vec<u64> = sink
            .events()
            .iter()
            .filter_map(|e| match e {
                DomainEvent::RawBlockReceived(r) => Some(r.block.number),
                _ => None,
            })
            .collect();
        assert_eq!(received, vec![1, 2, 3], "parent 2 back-filled before 3");
    }

    #[tokio::test]
    async fn bridge_into_pipeline_acks_only_after_publish() {
        // End-to-end: run_bridge → Pipeline::run → progress watermark. The ack
        // (watermark) reaches the committed tip only after its events are on the
        // sink, so a reth FinishedHeight built from it can never outrun durability.
        let source = Arc::new(ExExSource::new(256));
        let sink = Arc::new(RecordingSink::default());
        let shutdown = CancellationToken::new();
        let (ntx, nrx) = mpsc::channel::<ExExNotice>(16);
        let (htx, hrx) = mpsc::channel::<ChainHead>(64);
        let (ptx, mut prx) = mpsc::channel::<BlockRef>(64);

        let mut pipeline = Pipeline::new(
            Chain::ETHEREUM,
            source.clone(),
            sink.clone(),
            64,
            shutdown.clone(),
        );
        pipeline.report_progress_to(ptx);
        let pipeline_task = tokio::spawn(pipeline.run(hrx, Duration::from_secs(3600)));
        let bridge_task = tokio::spawn(run_bridge(nrx, htx, source, shutdown.clone()));

        ntx.send(commit(vec![
            head(1, 0x01, 0x00),
            head(2, 0x02, 0x01),
            head(3, 0x03, 0x02),
        ]))
        .await
        .unwrap();
        drop(ntx); // close notices → bridge ends → drops heads tx → pipeline ends
        bridge_task.await.unwrap();
        pipeline_task.await.unwrap();

        // Block 3's BlockAssembled is durably on the sink…
        assert!(
            sink.events().iter().any(|e| matches!(
                e, DomainEvent::BlockAssembled(a) if a.block.number == 3
            )),
            "block 3 published before its height is acked"
        );
        // …and the final watermark is the committed tip.
        let last = std::iter::from_fn(|| prx.try_recv().ok()).last();
        assert_eq!(last, Some(BlockRef::new(3, b(0x03))));
    }
}
