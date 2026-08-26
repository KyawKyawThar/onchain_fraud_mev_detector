//! The [`CtxSource`] seam — where a replayed finding gets the
//! [`DetectionCtx`] its feature vector is extracted from.
//!
//! # Why this is a seam
//!
//! `ml-features` extracts from a `DetectionCtx`, and the event store does not
//! hold one. It holds *events*: `BlockAssembled` carries a block's header and
//! `tx_count` but no transaction hashes, and nothing in the schema carries the
//! decoded enrichment (swaps, transfers, gas, prices) at all. Rebuilding a
//! faithful context means re-fetching and re-decoding the block from an
//! archive node — the same missing piece that leaves `simulation`'s
//! `JobResolver` stubbed (`crates/simulation/src/resolver.rs`), for the same
//! reason: the decode/fork path is not wired yet.
//!
//! So this is a trait, not a function. The export pipeline is written against
//! it, [`ReplayCtxSource`] backs it with what the event store *does* carry
//! today, and an archive-backed implementation drops in behind it later
//! without the join, the label rule, the sinks or the manifest changing.
//!
//! # Fidelity is stamped, never assumed
//!
//! A context rebuilt from events is not the context the detector saw, and
//! quietly pretending otherwise is exactly the serving/training skew §20.5
//! exists to catch. Every resolved context therefore carries a [`Fidelity`],
//! every exported row carries it as a column, and the export refuses to write
//! rows below `--min-fidelity`. The distinction that matters most is between
//! *missing* and *wrong*:
//!
//! - Missing enrichment is safe. `ml-features` encodes absence rather than
//!   imputing it (`is_enriched`, `gas_known_fraction`, `priced_*_fraction`),
//!   so a header-only context yields honest zeros behind an explicit presence
//!   feature.
//! - A **partial bundle** is not. `tx_count_log`, `position_in_block` and
//!   `sender_block_tx_share` are computed against the transactions the bundle
//!   holds, so a bundle of the 3 implicated txs out of a 150-tx block produces
//!   confident, *wrong* values — not absent ones. That is why
//!   [`Fidelity::PartialBundle`] exists as its own level and why
//!   [`Fidelity::FullBundle`] is only claimed when the reconstructed bundle
//!   matches `BlockAssembled`'s own `tx_count`.

use std::collections::BTreeMap;

use alloy_primitives::B256;
use async_trait::async_trait;
use detector_api::{BlockBundle, DetectionCtx};
use events::primitives::{BlockRef, Chain};
use events::{DomainEvent, EventEnvelope};
use serde::{Deserialize, Serialize};

/// How faithful a reconstructed [`DetectionCtx`] is to the one the detector
/// actually ran on. Ordered worst-to-best, so `--min-fidelity` is a `>=`
/// comparison and adding a level later keeps the ordering meaningful.
///
/// Deliberately **not** `Default`: whoever builds a context is the only party
/// that knows how complete it is, so there is no such thing as a fidelity you
/// get without saying it. A `Default` here would let a future call site
/// silently claim `HeaderOnly` for something richer, or worse, inherit a level
/// nobody chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fidelity {
    /// The block header only — no transactions at all. Every tx-structural
    /// aggregate is an honest zero, and per-tx vectors cannot be extracted.
    HeaderOnly,
    /// Some of the block's transactions. Block-relative features are computed
    /// against an incomplete denominator, so they are *wrong*, not missing —
    /// usable for inspection, not for training.
    PartialBundle,
    /// Every transaction in the block, but no decoded enrichment. Structural
    /// features are correct; value/gas/pool families report honest zeros
    /// behind their presence features.
    FullBundle,
    /// The full bundle plus decoded enrichment — what the detector saw.
    Enriched,
}

impl Fidelity {
    pub fn as_str(self) -> &'static str {
        match self {
            Fidelity::HeaderOnly => "header_only",
            Fidelity::PartialBundle => "partial_bundle",
            Fidelity::FullBundle => "full_bundle",
            Fidelity::Enriched => "enriched",
        }
    }

    /// Parse the CLI/`serde` spelling. `None` for anything else, so a typo in
    /// `--min-fidelity` fails at argument parsing rather than silently
    /// selecting a level nobody meant.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "header_only" | "header-only" => Some(Fidelity::HeaderOnly),
            "partial_bundle" | "partial-bundle" => Some(Fidelity::PartialBundle),
            "full_bundle" | "full-bundle" => Some(Fidelity::FullBundle),
            "enriched" => Some(Fidelity::Enriched),
            _ => None,
        }
    }

    /// Every level, worst first — for CLI help and the manifest histogram.
    pub const ALL: [Fidelity; 4] = [
        Fidelity::HeaderOnly,
        Fidelity::PartialBundle,
        Fidelity::FullBundle,
        Fidelity::Enriched,
    ];
}

impl std::fmt::Display for Fidelity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A context together with how much of it is real.
#[derive(Debug, Clone)]
pub struct ResolvedCtx {
    pub ctx: DetectionCtx,
    pub fidelity: Fidelity,
}

/// A failure resolving a block's context.
#[derive(Debug, thiserror::Error)]
pub enum CtxError {
    /// The backing source could not be reached or answered with a fault. The
    /// export aborts rather than emitting a half-window dataset: a dataset
    /// silently missing an hour of blocks is not reproducible.
    #[error("resolving context for block {block}: {source_error}")]
    Source { block: u64, source_error: String },
}

/// Supplies the [`DetectionCtx`] for a block. Object-safe (via `async_trait`)
/// so the export holds a `&dyn CtxSource` and the archive-backed
/// implementation is a swap, not a rewrite.
#[async_trait]
pub trait CtxSource: Send + Sync {
    /// The context for `block` on `chain`, or `None` if this source knows
    /// nothing about that block (its findings are then skipped and counted —
    /// distinct from an error, which aborts).
    async fn ctx_for(&self, chain: Chain, block: BlockRef)
        -> Result<Option<ResolvedCtx>, CtxError>;
}

/// Builds the [`CtxSource`] for one replayed window.
///
/// A factory rather than a plain `&dyn CtxSource` because the two kinds of
/// source want opposite things, and sharding makes the difference matter:
///
/// - [`ReplayCtxFactory`] derives its context from the window it is handed, so
///   a sharded export needs a *fresh* source per shard — one built from the
///   whole window would defeat the point of sharding by holding every block's
///   facts in memory at once.
/// - An archive-backed source (or the [`MapCtxSource`] double) is independent
///   of the window entirely and is simply reused; [`StaticCtxFactory`] wraps
///   one of those.
///
/// Putting the choice behind a factory keeps [`crate::export`] from having to
/// know which kind it holds.
#[async_trait]
pub trait CtxSourceFactory: Send + Sync {
    /// A source for `window`, the events of one shard (or of the whole export
    /// when unsharded).
    async fn for_window(&self, window: &[EventEnvelope]) -> Result<Box<dyn CtxSource>, CtxError>;
}

/// Builds a [`ReplayCtxSource`] from each window — the default, and what the
/// binary uses today.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReplayCtxFactory;

#[async_trait]
impl CtxSourceFactory for ReplayCtxFactory {
    async fn for_window(&self, window: &[EventEnvelope]) -> Result<Box<dyn CtxSource>, CtxError> {
        Ok(Box::new(ReplayCtxSource::from_events(window)))
    }
}

/// Hands out one window-independent source for every shard — an archive-backed
/// source once one exists, and [`MapCtxSource`] in tests.
pub struct StaticCtxFactory(std::sync::Arc<dyn CtxSource>);

impl StaticCtxFactory {
    pub fn new(source: std::sync::Arc<dyn CtxSource>) -> Self {
        Self(source)
    }
}

#[async_trait]
impl CtxSourceFactory for StaticCtxFactory {
    async fn for_window(&self, _: &[EventEnvelope]) -> Result<Box<dyn CtxSource>, CtxError> {
        Ok(Box::new(SharedCtxSource(std::sync::Arc::clone(&self.0))))
    }
}

/// Adapts an `Arc<dyn CtxSource>` back into an owned `Box<dyn CtxSource>` so
/// [`StaticCtxFactory`] can hand out the same underlying source repeatedly.
struct SharedCtxSource(std::sync::Arc<dyn CtxSource>);

#[async_trait]
impl CtxSource for SharedCtxSource {
    async fn ctx_for(
        &self,
        chain: Chain,
        block: BlockRef,
    ) -> Result<Option<ResolvedCtx>, CtxError> {
        self.0.ctx_for(chain, block).await
    }
}

/// What the replayed window itself says about one block.
#[derive(Debug, Clone, Default)]
struct BlockFacts {
    /// Transaction hashes named by the window's `DetectorTriggered`s, in
    /// first-seen order, deduplicated.
    txs: Vec<B256>,
    /// The block's true transaction count, from `BlockAssembled` — the only
    /// way to tell a complete reconstruction from a partial one.
    tx_count: Option<u32>,
}

/// The context source available **today**: everything the replayed window
/// itself reveals about each block, and nothing invented.
///
/// A block's bundle is the union of the transaction hashes its
/// `DetectorTriggered`s implicated (first-seen order, deduplicated) — the only
/// transaction-level facts the event store holds. `BlockAssembled`'s `tx_count`
/// is then used to grade the result honestly: equal counts mean the
/// reconstruction is complete ([`Fidelity::FullBundle`]), fewer means
/// [`Fidelity::PartialBundle`], none means [`Fidelity::HeaderOnly`]. No
/// enrichment is ever synthesised, so this source never claims
/// [`Fidelity::Enriched`].
///
/// One consequence worth stating plainly: the reconstructed bundle's *order*
/// is detector-report order, not block order, so `position_in_block` is
/// positional within the reconstruction. That is part of why partial bundles
/// are gated out of training by default rather than merely annotated.
#[derive(Debug, Default)]
pub struct ReplayCtxSource {
    blocks: BTreeMap<B256, BlockFacts>,
}

impl ReplayCtxSource {
    /// Build from the same replayed window the join folds — one pass, no I/O.
    pub fn from_events<'a>(events: impl IntoIterator<Item = &'a EventEnvelope>) -> Self {
        let mut blocks: BTreeMap<B256, BlockFacts> = BTreeMap::new();
        for envelope in events {
            match &envelope.payload {
                DomainEvent::BlockAssembled(assembled) => {
                    blocks.entry(assembled.block.hash).or_default().tx_count =
                        Some(assembled.tx_count);
                }
                DomainEvent::DetectorTriggered(trigger) => {
                    let facts = blocks.entry(trigger.block.hash).or_default();
                    for tx in &trigger.txs {
                        if !facts.txs.contains(tx) {
                            facts.txs.push(*tx);
                        }
                    }
                }
                _ => {}
            }
        }
        Self { blocks }
    }

    /// How many blocks the window described. Surfaced so the export can report
    /// coverage without reaching into the map.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    fn grade(facts: &BlockFacts) -> Fidelity {
        match (facts.txs.len(), facts.tx_count) {
            (0, _) => Fidelity::HeaderOnly,
            (found, Some(total)) if found as u64 == u64::from(total) => Fidelity::FullBundle,
            _ => Fidelity::PartialBundle,
        }
    }
}

#[async_trait]
impl CtxSource for ReplayCtxSource {
    async fn ctx_for(
        &self,
        chain: Chain,
        block: BlockRef,
    ) -> Result<Option<ResolvedCtx>, CtxError> {
        let Some(facts) = self.blocks.get(&block.hash) else {
            return Ok(None);
        };
        Ok(Some(ResolvedCtx {
            ctx: DetectionCtx::new(BlockBundle::new(chain, block, facts.txs.clone())),
            fidelity: Self::grade(facts),
        }))
    }
}

/// An explicit block-hash → context map: the in-memory test double for this
/// seam (the `EventSink` discipline), and the shape an archive-backed source
/// would fill.
#[derive(Debug, Default)]
pub struct MapCtxSource {
    by_block: BTreeMap<B256, ResolvedCtx>,
}

impl MapCtxSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a context, declaring its fidelity. The caller declares it
    /// rather than the source guessing: only whoever built the context knows
    /// whether the enrichment is complete.
    pub fn insert(&mut self, ctx: DetectionCtx, fidelity: Fidelity) -> &mut Self {
        self.by_block
            .insert(ctx.block().hash, ResolvedCtx { ctx, fidelity });
        self
    }

    /// Builder form, for fixture setup.
    pub fn with(mut self, ctx: DetectionCtx, fidelity: Fidelity) -> Self {
        self.insert(ctx, fidelity);
        self
    }
}

#[async_trait]
impl CtxSource for MapCtxSource {
    async fn ctx_for(
        &self,
        _chain: Chain,
        block: BlockRef,
    ) -> Result<Option<ResolvedCtx>, CtxError> {
        Ok(self.by_block.get(&block.hash).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;
    use events::chain::BlockAssembled;
    use events::detection::DetectorTriggered;
    use events::primitives::{Confidence, DetectorRef};
    use uuid::Uuid;

    const CHAIN: Chain = Chain::ETHEREUM;

    fn block(n: u64) -> BlockRef {
        BlockRef::new(n, B256::repeat_byte(n as u8))
    }

    fn envelope(payload: DomainEvent) -> EventEnvelope {
        EventEnvelope::with_metadata(Uuid::new_v4(), Utc::now(), CHAIN, payload)
    }

    fn assembled(block_ref: BlockRef, tx_count: u32) -> EventEnvelope {
        envelope(DomainEvent::BlockAssembled(BlockAssembled {
            block: block_ref,
            tx_count,
            trace_available: false,
        }))
    }

    fn triggered(block_ref: BlockRef, txs: Vec<B256>) -> EventEnvelope {
        envelope(DomainEvent::DetectorTriggered(DetectorTriggered {
            detector: DetectorRef {
                id: "sandwich".into(),
                version: "1.0.0".into(),
                config_hash: "cafe".into(),
            },
            block: block_ref,
            txs,
            raw_confidence: Confidence::new(0.5),
            evidence: serde_json::json!({}),
        }))
    }

    fn tx(b: u8) -> B256 {
        B256::repeat_byte(b)
    }

    #[test]
    fn fidelity_orders_worst_to_best_so_min_fidelity_is_a_comparison() {
        assert!(Fidelity::HeaderOnly < Fidelity::PartialBundle);
        assert!(Fidelity::PartialBundle < Fidelity::FullBundle);
        assert!(Fidelity::FullBundle < Fidelity::Enriched);
        for level in Fidelity::ALL {
            assert_eq!(Fidelity::parse(level.as_str()), Some(level));
        }
        assert_eq!(Fidelity::parse("perfect"), None);
    }

    #[tokio::test]
    async fn a_block_with_no_triggers_resolves_header_only() {
        let events = vec![assembled(block(1), 120)];
        let source = ReplayCtxSource::from_events(&events);
        let resolved = source
            .ctx_for(CHAIN, block(1))
            .await
            .expect("no failure")
            .expect("known block");
        assert_eq!(resolved.fidelity, Fidelity::HeaderOnly);
        assert!(resolved.ctx.txs().is_empty());
    }

    #[tokio::test]
    async fn a_partial_reconstruction_is_graded_partial_not_full() {
        let events = vec![
            assembled(block(1), 120),
            triggered(block(1), vec![tx(1), tx(2)]),
        ];
        let source = ReplayCtxSource::from_events(&events);
        let resolved = source.ctx_for(CHAIN, block(1)).await.unwrap().unwrap();
        assert_eq!(
            resolved.fidelity,
            Fidelity::PartialBundle,
            "2 of 120 txs is a wrong denominator, not a missing one"
        );
        assert_eq!(resolved.ctx.txs(), &[tx(1), tx(2)]);
    }

    #[tokio::test]
    async fn a_reconstruction_matching_the_true_tx_count_is_graded_full() {
        let events = vec![
            assembled(block(1), 2),
            triggered(block(1), vec![tx(1), tx(2)]),
        ];
        let source = ReplayCtxSource::from_events(&events);
        assert_eq!(
            source
                .ctx_for(CHAIN, block(1))
                .await
                .unwrap()
                .unwrap()
                .fidelity,
            Fidelity::FullBundle
        );
    }

    #[tokio::test]
    async fn without_block_assembled_a_bundle_can_never_claim_to_be_complete() {
        let events = vec![triggered(block(1), vec![tx(1), tx(2)])];
        let source = ReplayCtxSource::from_events(&events);
        assert_eq!(
            source
                .ctx_for(CHAIN, block(1))
                .await
                .unwrap()
                .unwrap()
                .fidelity,
            Fidelity::PartialBundle,
            "no tx_count means no evidence of completeness"
        );
    }

    #[tokio::test]
    async fn overlapping_triggers_union_their_txs_in_first_seen_order() {
        let events = vec![
            triggered(block(1), vec![tx(3), tx(1)]),
            triggered(block(1), vec![tx(1), tx(2)]),
        ];
        let source = ReplayCtxSource::from_events(&events);
        let resolved = source.ctx_for(CHAIN, block(1)).await.unwrap().unwrap();
        assert_eq!(
            resolved.ctx.txs(),
            &[tx(3), tx(1), tx(2)],
            "deduplicated, and ordered by first sighting so the bundle is deterministic"
        );
    }

    #[tokio::test]
    async fn an_unknown_block_is_none_not_an_error() {
        let source = ReplayCtxSource::from_events(&[]);
        assert!(source.ctx_for(CHAIN, block(9)).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn the_map_double_returns_exactly_what_was_registered() {
        let ctx = DetectionCtx::new(BlockBundle::new(CHAIN, block(4), vec![tx(1)]));
        let source = MapCtxSource::new().with(ctx, Fidelity::Enriched);
        let resolved = source.ctx_for(CHAIN, block(4)).await.unwrap().unwrap();
        assert_eq!(resolved.fidelity, Fidelity::Enriched);
        assert_eq!(resolved.ctx.txs(), &[tx(1)]);
        assert!(source.ctx_for(CHAIN, block(5)).await.unwrap().is_none());
    }
}
