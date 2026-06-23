//! The in-memory, reorg-aware **block tree** (§5, §15) — Sprint 2 task 2.
//!
//! ## What it is
//!
//! A DAG of observed [`ChainHead`]s linked by `parent_hash`, with one path
//! marked *canonical*. It is the ingestion service's only state: §5 says "no
//! persistent store needed — chain data is re-fetchable; the event store has the
//! event log", so this lives purely in memory and is bounded by the finalization
//! depth.
//!
//! ## What it does
//!
//! Heads arrive from the source layer (the head poller over [`crate::source`]).
//! For each one, [`BlockTree::add_block`] decides what happened to the canonical
//! chain and returns it as an [`AddOutcome`]:
//!
//! - **[`AddOutcome::Canonical`]** — the canonical tip moved. For a plain
//!   extension `reverted` is empty and `canonicalized` is the single new tip;
//!   for a reorg `reverted` lists the orphaned old-canonical blocks (tip-first,
//!   the natural rollback order) and `canonicalized` the new branch
//!   (ancestor-first, the natural apply order). This is the "walk to the common
//!   ancestor" of §5 — computed once, here, so task 4 only has to *emit* the
//!   resulting `BlockReverted`/`BlockCanonicalized` events.
//! - **[`AddOutcome::Fork`]** — stored as a side branch that isn't (yet)
//!   canonical; no events.
//! - **[`AddOutcome::Duplicate`]** — already known; idempotent no-op (a repeat
//!   poll or a replay).
//! - **[`AddOutcome::MissingParent`]** — the block can't be linked because its
//!   parent isn't in the tree. This is the seam for task 4's reorg walk: the
//!   driver fetches the parent (`head_by_hash`), adds it, then re-adds this one.
//!
//! ## Separation of concerns
//!
//! This type is **pure and synchronous** — no async, no network, no events. It
//! is fed [`ChainHead`]s and returns plain data, so the whole reorg algorithm is
//! unit-testable against hand-built forks with no mock RPC. Fetching ancestors,
//! mapping outcomes onto [`events::chain`] events, and publishing them is tasks
//! 3–4, written against the [`AddOutcome`] seam above.
//!
//! ## Fork choice
//!
//! Canonical = the block with the greatest `(number, insertion-sequence)`. A
//! higher block always wins (a normal extension, or a longer reorg); a *newer*
//! block at the same height also wins (the same-height reorg a node reports when
//! it replaces its tip). Back-filled ancestors (lower number) never displace the
//! tip, and a tie can't flap because the sequence is strictly increasing. We
//! can't use post-merge difficulty (it's zero) or beacon attestations from a
//! header-only feed, so "the latest head the source reported, longest-first" is
//! the honest rule.

use std::collections::{HashMap, HashSet};

use alloy_primitives::B256;
use events::primitives::BlockRef;

use crate::source::ChainHead;

/// A change to the canonical chain produced by [`BlockTree::add_block`].
///
/// The two lists share a common ancestor (excluded from both). Task 4 maps
/// these onto events and pairs them by height to fill
/// [`events::chain::BlockReverted::replaced_by`] (the canonical block that now
/// occupies a reverted block's height).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CanonicalUpdate {
    /// Old-canonical blocks orphaned by this change, **tip-first** (highest
    /// number first) — the order cross-block state should roll them back in
    /// (§15). Empty for a plain extension.
    pub reverted: Vec<ChainHead>,
    /// New-canonical blocks, **ancestor-first** (ascending number) — the order
    /// to apply them. For a plain extension this is just the new tip.
    pub canonicalized: Vec<ChainHead>,
}

impl CanonicalUpdate {
    /// Whether this update reorged the chain (orphaned at least one block),
    /// rather than merely extending it.
    pub fn is_reorg(&self) -> bool {
        !self.reverted.is_empty()
    }
}

/// The result of feeding one head to [`BlockTree::add_block`].
///
/// `#[must_use]`: dropping this silently loses a reorg's revert/canonical
/// events — the exact bug this module exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum AddOutcome {
    /// The canonical tip moved; see [`CanonicalUpdate`].
    Canonical(CanonicalUpdate),
    /// Stored as a side branch at or below the canonical tip — not canonical, so
    /// no events. It may become canonical later if it is extended past the tip.
    Fork,
    /// The block is already in the tree — an idempotent no-op (duplicate poll or
    /// replay).
    Duplicate,
    /// The block's parent isn't in the tree, so it can't be linked. The driver
    /// (task 4) must fetch the parent via `head_by_hash`, add it, then re-add
    /// this block. Carries the missing parent hash.
    MissingParent(B256),
}

/// Why a block could not be added.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TreeError {
    /// A block was offered that competes with the finalized chain — a reorg
    /// deeper than finality, which post-merge cannot happen. The tree refuses it
    /// rather than rolling back a block it has already declared final (§15: all
    /// artifacts are provisional only *until* `BlockFinalized`). In practice this
    /// signals a source bug or a wrong-chain endpoint that slipped the health
    /// check.
    #[error(
        "refusing reorg beyond finality: block {attempted:?} is at or below the finalized block {finalized:?}"
    )]
    ReorgBeyondFinality {
        finalized: BlockRef,
        attempted: BlockRef,
    },
}

/// One block in the tree: the observed head plus the insertion sequence used as
/// the fork-choice tie-breaker.
#[derive(Debug, Clone, Copy)]
struct Node {
    head: ChainHead,
    seq: u64,
}

/// An in-memory, reorg-aware block tree bounded by finalization depth (§5, §15).
///
/// See the [module docs](self) for the model. Construct with
/// [`BlockTree::new`], feed heads with [`BlockTree::add_block`], and advance
/// finality with [`BlockTree::finalize`].
#[derive(Debug)]
pub struct BlockTree {
    /// Blocks below `tip.number - finalization_depth` are pruned as a memory
    /// backstop, so the tree stays bounded even when the source's `finalized`
    /// tag lags. [`BlockTree::finalize`] is the authoritative, event-bearing
    /// finality signal; this just caps growth.
    finalization_depth: u64,
    /// Every known block, keyed by hash. The parent-present invariant holds for
    /// every node except the current root (the first block, or the finalized
    /// block after pruning), whose parent has been pruned.
    nodes: HashMap<B256, Node>,
    /// The canonical tip's hash, or `None` until the first block is added.
    canonical_tip: Option<B256>,
    /// The finalized floor: nothing at or below this height can be reorged.
    /// Set by [`BlockTree::finalize`].
    finalized: Option<BlockRef>,
    /// Monotonic insertion counter — the fork-choice tie-breaker (newest wins at
    /// equal height).
    next_seq: u64,
}

impl BlockTree {
    /// A tree bounded to roughly `finalization_depth` blocks below the tip.
    ///
    /// `finalization_depth` should match the source's notion of finality (the
    /// `FINALIZATION_DEPTH` config, §15); it is only a memory backstop — actual
    /// finality events come from [`BlockTree::finalize`] driven by the chain's
    /// `finalized` tag.
    pub fn new(finalization_depth: u64) -> Self {
        Self {
            finalization_depth,
            nodes: HashMap::new(),
            canonical_tip: None,
            finalized: None,
            next_seq: 0,
        }
    }

    /// The current canonical tip, or `None` before the first block.
    pub fn canonical_tip(&self) -> Option<ChainHead> {
        self.canonical_tip.map(|h| self.nodes[&h].head)
    }

    /// The finalized floor, or `None` before the first [`BlockTree::finalize`].
    pub fn finalized(&self) -> Option<BlockRef> {
        self.finalized
    }

    /// Number of blocks currently held (canonical + live side branches).
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the tree holds no blocks.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Whether a block with `hash` is in the tree.
    pub fn contains(&self, hash: &B256) -> bool {
        self.nodes.contains_key(hash)
    }

    /// Add an observed head and report what it did to the canonical chain.
    ///
    /// See [`AddOutcome`] for the cases. Adding is idempotent
    /// ([`AddOutcome::Duplicate`]) and order-tolerant: a block whose parent is
    /// missing is refused with [`AddOutcome::MissingParent`] rather than stored
    /// dangling, which keeps the parent-present invariant the reorg walk relies
    /// on.
    pub fn add_block(&mut self, head: ChainHead) -> Result<AddOutcome, TreeError> {
        if self.nodes.contains_key(&head.hash) {
            return Ok(AddOutcome::Duplicate);
        }

        // A block at or below the finalized floor competes with a block we have
        // declared final — a reorg deeper than finality, which can't happen
        // post-merge. Refuse it rather than corrupt the tree.
        if let Some(finalized) = self.finalized {
            if head.number <= finalized.number {
                return Err(TreeError::ReorgBeyondFinality {
                    finalized,
                    attempted: head.block_ref(),
                });
            }
        }

        // Link to the parent. The first block of an empty tree (and only it) is
        // allowed in without a parent — it becomes the root the chain grows from.
        if !self.nodes.is_empty() && !self.nodes.contains_key(&head.parent_hash) {
            return Ok(AddOutcome::MissingParent(head.parent_hash));
        }

        let seq = self.next_seq;
        self.next_seq += 1;
        self.nodes.insert(head.hash, Node { head, seq });

        // Fork choice: does this block (or the branch it completes) beat the
        // current tip? Greatest (number, seq) wins.
        let beats_tip = match self.canonical_tip {
            None => true,
            Some(tip) => {
                let tip = &self.nodes[&tip];
                (head.number, seq) > (tip.head.number, tip.seq)
            }
        };

        if !beats_tip {
            return Ok(AddOutcome::Fork);
        }

        let update = self.reorg_to(head.hash);
        self.canonical_tip = Some(head.hash);
        self.prune_to_depth();
        Ok(AddOutcome::Canonical(update))
    }

    /// Advance finality to `finalized` (the chain's `finalized`-tag head, §5).
    ///
    /// Returns the canonical blocks that crossed the finalization line since the
    /// last call — ascending by number — so task 4 can emit one `BlockFinalized`
    /// per block (§5). Then prunes everything below the new floor: those blocks
    /// can never be reorged, so they need not stay in memory.
    ///
    /// `finalized` is expected to be on (or an ancestor of) the canonical chain;
    /// blocks not on the canonical chain are not reported as finalized.
    #[must_use = "the returned blocks must be emitted as BlockFinalized events (§5)"]
    pub fn finalize(&mut self, finalized: BlockRef) -> Vec<ChainHead> {
        debug_assert!(
            self.canonical_tip()
                .is_none_or(|t| finalized.number <= t.number),
            "finalized {finalized:?} is ahead of the canonical tip",
        );
        let prev_floor = self.finalized.map(|f| f.number);
        // Clamp the prune floor to the tip: a buggy/lagging source reporting a
        // `finalized` height ahead of our canonical chain must not prune the tip
        // out from under `canonical_tip` (the dangling hash would panic on the
        // next lookup). The debug_assert above flags it for our own driver.
        let floor = self
            .canonical_tip()
            .map_or(finalized.number, |t| finalized.number.min(t.number));

        // Newly finalized canonical blocks: those above the previous floor and at
        // or below the finalized height, walked from the tip down so we only ever
        // report blocks actually on the canonical chain.
        let mut newly_final: Vec<ChainHead> = self
            .canonical_iter()
            .filter(|h| h.number <= floor && prev_floor.is_none_or(|p| h.number > p))
            .collect();
        newly_final.reverse(); // canonical_iter yields tip-first; emit ascending.

        self.finalized = Some(finalized);
        self.prune_below(floor);
        newly_final
    }

    /// Compute the canonical change from the current tip to `new_tip` by walking
    /// both branches back to their common ancestor. `new_tip` and every block
    /// between it and the ancestor must already be in the tree.
    fn reorg_to(&self, new_tip: B256) -> CanonicalUpdate {
        // The old canonical chain as a set, for the "is this the common
        // ancestor?" test while walking the new branch.
        let old_chain: HashSet<B256> = self.canonical_iter().map(|h| h.hash).collect();

        // Walk the new branch from its tip down until we reach a block already on
        // the old canonical chain — that block is the common ancestor.
        let mut canonicalized = Vec::new();
        let mut common_ancestor = None;
        let mut cursor = new_tip;
        loop {
            if old_chain.contains(&cursor) {
                common_ancestor = Some(cursor);
                break;
            }
            let node = self.nodes[&cursor];
            canonicalized.push(node.head);
            match self.nodes.get(&node.head.parent_hash) {
                Some(_) => cursor = node.head.parent_hash,
                None => break, // reached the branch root (no common ancestor in tree)
            }
        }
        canonicalized.reverse(); // collected tip-first; apply ancestor-first.

        // The parent-present invariant guarantees the new branch rejoins the old
        // canonical chain (at worst at the shared root), so a common ancestor
        // always exists after the first block. If it doesn't, `reverted` below
        // would silently orphan the entire old chain — assert instead.
        debug_assert!(
            self.canonical_tip.is_none() || common_ancestor.is_some(),
            "reorg with no common ancestor (parent-present invariant violated)",
        );

        // The orphaned blocks: the old canonical chain from its tip down to (but
        // excluding) the common ancestor. Already tip-first from canonical_iter.
        let reverted = self
            .canonical_iter()
            .take_while(|h| Some(h.hash) != common_ancestor)
            .collect();

        CanonicalUpdate {
            reverted,
            canonicalized,
        }
    }

    /// Walk the canonical chain from the tip toward the root, yielding each head
    /// tip-first. Stops at the root (parent pruned / not present).
    fn canonical_iter(&self) -> impl Iterator<Item = ChainHead> + '_ {
        let mut cursor = self.canonical_tip;
        std::iter::from_fn(move || {
            let hash = cursor?;
            let node = &self.nodes[&hash];
            cursor = self
                .nodes
                .contains_key(&node.head.parent_hash)
                .then_some(node.head.parent_hash);
            Some(node.head)
        })
    }

    /// Memory backstop: drop everything more than `finalization_depth` below the
    /// canonical tip. Independent of [`BlockTree::finalize`] so the tree stays
    /// bounded even if the `finalized` tag is unavailable or lagging.
    fn prune_to_depth(&mut self) {
        let Some(tip) = self.canonical_tip() else {
            return;
        };
        let floor = tip.number.saturating_sub(self.finalization_depth);
        self.prune_below(floor);
    }

    /// Drop every block strictly below `floor` height (canonical or side branch).
    /// Blocks at exactly `floor` are kept so the canonical walk still terminates
    /// on a present root.
    fn prune_below(&mut self, floor: u64) {
        self.nodes.retain(|_, node| node.head.number >= floor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a head at `number` with the given hash/parent bytes. Timestamp
    /// tracks the number so ordering is obvious in failures.
    fn head(number: u64, hash: u8, parent: u8) -> ChainHead {
        ChainHead {
            number,
            hash: B256::repeat_byte(hash),
            parent_hash: B256::repeat_byte(parent),
            timestamp: 1_700_000_000 + number,
        }
    }

    fn b(byte: u8) -> B256 {
        B256::repeat_byte(byte)
    }

    /// Add a block during test setup where the outcome isn't under assertion.
    /// Explicitly discards the `#[must_use]` [`AddOutcome`].
    fn seed(tree: &mut BlockTree, head: ChainHead) {
        let _ = tree.add_block(head).unwrap();
    }

    /// Extract the `Canonical` update or panic — most tests assert on it.
    fn canonical(outcome: AddOutcome) -> CanonicalUpdate {
        match outcome {
            AddOutcome::Canonical(u) => u,
            other => panic!("expected Canonical, got {other:?}"),
        }
    }

    #[test]
    fn first_block_canonicalizes_itself() {
        let mut tree = BlockTree::new(64);
        let update = canonical(tree.add_block(head(1, 0x01, 0x00)).unwrap());

        assert!(update.reverted.is_empty());
        assert_eq!(update.canonicalized, vec![head(1, 0x01, 0x00)]);
        assert_eq!(tree.canonical_tip().unwrap().hash, b(0x01));
        assert!(!update.is_reorg());
    }

    #[test]
    fn linear_extension_canonicalizes_each_block_without_reverting() {
        let mut tree = BlockTree::new(64);
        seed(&mut tree, head(1, 0x01, 0x00));

        let update = canonical(tree.add_block(head(2, 0x02, 0x01)).unwrap());
        assert!(update.reverted.is_empty());
        assert_eq!(update.canonicalized, vec![head(2, 0x02, 0x01)]);
        assert_eq!(tree.canonical_tip().unwrap().number, 2);
    }

    #[test]
    fn re_adding_a_known_block_is_an_idempotent_duplicate() {
        let mut tree = BlockTree::new(64);
        seed(&mut tree, head(1, 0x01, 0x00));
        assert_eq!(
            tree.add_block(head(1, 0x01, 0x00)).unwrap(),
            AddOutcome::Duplicate
        );
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn a_block_with_an_unknown_parent_reports_missing_parent_and_is_not_stored() {
        let mut tree = BlockTree::new(64);
        seed(&mut tree, head(1, 0x01, 0x00));

        // Block 3 skips block 2 (parent 0x02 unknown).
        let outcome = tree.add_block(head(3, 0x03, 0x02)).unwrap();
        assert_eq!(outcome, AddOutcome::MissingParent(b(0x02)));
        assert!(!tree.contains(&b(0x03)));
        assert_eq!(tree.canonical_tip().unwrap().number, 1);
    }

    #[test]
    fn missing_parent_then_backfill_then_retry_canonicalizes() {
        let mut tree = BlockTree::new(64);
        seed(&mut tree, head(1, 0x01, 0x00));

        assert_eq!(
            tree.add_block(head(3, 0x03, 0x02)).unwrap(),
            AddOutcome::MissingParent(b(0x02))
        );
        // Driver back-fills the parent, then re-adds.
        canonical(tree.add_block(head(2, 0x02, 0x01)).unwrap());
        let update = canonical(tree.add_block(head(3, 0x03, 0x02)).unwrap());
        assert!(update.reverted.is_empty());
        assert_eq!(update.canonicalized, vec![head(3, 0x03, 0x02)]);
    }

    #[test]
    fn a_shorter_side_branch_is_a_fork_with_no_events() {
        let mut tree = BlockTree::new(64);
        seed(&mut tree, head(1, 0x01, 0x00));
        seed(&mut tree, head(2, 0x02, 0x01));
        seed(&mut tree, head(3, 0x03, 0x02));

        // A competing block at height 2 (parent block 1) — below the tip (3).
        assert_eq!(
            tree.add_block(head(2, 0x12, 0x01)).unwrap(),
            AddOutcome::Fork
        );
        assert_eq!(tree.canonical_tip().unwrap().hash, b(0x03));
        assert!(tree.contains(&b(0x12)));
    }

    #[test]
    fn same_height_reorg_switches_to_the_newer_block() {
        let mut tree = BlockTree::new(64);
        seed(&mut tree, head(1, 0x01, 0x00));
        seed(&mut tree, head(2, 0x02, 0x01));

        // A different block at the same height 2, also building on block 1: the
        // node replaced its tip. Newer seq wins.
        let update = canonical(tree.add_block(head(2, 0x12, 0x01)).unwrap());
        assert_eq!(update.reverted, vec![head(2, 0x02, 0x01)]);
        assert_eq!(update.canonicalized, vec![head(2, 0x12, 0x01)]);
        assert_eq!(tree.canonical_tip().unwrap().hash, b(0x12));
        assert!(update.is_reorg());
    }

    #[test]
    fn deeper_reorg_walks_to_common_ancestor() {
        // Canonical: 1 <- 2 <- 3 <- 4. Competing branch off block 1:
        // 1 <- 2' <- 3' <- 4' <- 5'. The driver back-fills the branch bottom-up
        // (the order `head_by_hash` walks produce). Each block below the tip is a
        // Fork; the reorg fires the moment the branch reaches the tip's height
        // with a newer block (4'), reverting 2,3,4 and canonicalizing 2',3',4'.
        let mut tree = BlockTree::new(64);
        seed(&mut tree, head(1, 0x01, 0x00));
        seed(&mut tree, head(2, 0x02, 0x01));
        seed(&mut tree, head(3, 0x03, 0x02));
        seed(&mut tree, head(4, 0x04, 0x03));

        // Blocks below the tip (height 4) are side forks: no canonical change yet.
        assert_eq!(
            tree.add_block(head(2, 0x12, 0x01)).unwrap(),
            AddOutcome::Fork
        );
        assert_eq!(
            tree.add_block(head(3, 0x13, 0x12)).unwrap(),
            AddOutcome::Fork
        );

        // Block 4' ties the tip's height but is newer → reorg to the new branch.
        let update = canonical(tree.add_block(head(4, 0x14, 0x13)).unwrap());
        // Orphaned old canonical, tip-first.
        assert_eq!(
            update.reverted,
            vec![
                head(4, 0x04, 0x03),
                head(3, 0x03, 0x02),
                head(2, 0x02, 0x01)
            ]
        );
        // New canonical above the common ancestor (block 1), ancestor-first.
        assert_eq!(
            update.canonicalized,
            vec![
                head(2, 0x12, 0x01),
                head(3, 0x13, 0x12),
                head(4, 0x14, 0x13)
            ]
        );
        assert_eq!(tree.canonical_tip().unwrap().hash, b(0x14));

        // Block 5' then simply extends the now-canonical branch.
        let extend = canonical(tree.add_block(head(5, 0x15, 0x14)).unwrap());
        assert!(extend.reverted.is_empty());
        assert_eq!(extend.canonicalized, vec![head(5, 0x15, 0x14)]);
        assert_eq!(tree.canonical_tip().unwrap().number, 5);
    }

    #[test]
    fn reverted_and_canonicalized_pair_by_height_for_replaced_by() {
        // The mapping task 4 needs for BlockReverted.replaced_by: a reverted
        // block at height h is replaced by the canonicalized block at height h.
        let mut tree = BlockTree::new(64);
        seed(&mut tree, head(1, 0x01, 0x00));
        seed(&mut tree, head(2, 0x02, 0x01));
        seed(&mut tree, head(3, 0x03, 0x02));
        seed(&mut tree, head(2, 0x12, 0x01)); // fork
        let update = canonical(tree.add_block(head(3, 0x13, 0x12)).unwrap());

        let replaced_by: HashMap<u64, B256> = update
            .canonicalized
            .iter()
            .map(|h| (h.number, h.hash))
            .collect();
        for orphan in &update.reverted {
            assert_eq!(
                replaced_by.get(&orphan.number),
                Some(&b(orphan.number as u8 + 0x10))
            );
        }
    }

    #[test]
    fn finalize_reports_crossed_blocks_ascending_and_prunes_below() {
        let mut tree = BlockTree::new(64);
        for n in 1..=5 {
            seed(&mut tree, head(n, n as u8, (n - 1) as u8));
        }

        let finalized = tree.finalize(BlockRef::new(3, b(0x03)));
        assert_eq!(
            finalized.iter().map(|h| h.number).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        // Blocks below the floor (3) are pruned; 3,4,5 remain.
        assert!(!tree.contains(&b(0x01)));
        assert!(!tree.contains(&b(0x02)));
        assert!(tree.contains(&b(0x03)));
        assert_eq!(tree.len(), 3);
        assert_eq!(tree.finalized(), Some(BlockRef::new(3, b(0x03))));
    }

    #[test]
    fn finalize_at_the_tip_keeps_the_tip_queryable() {
        // Regression: the prune floor is clamped to the tip, so finalizing at the
        // tip height must not prune the tip out from under `canonical_tip` (which
        // would dangle its hash and panic on the next lookup).
        let mut tree = BlockTree::new(64);
        for n in 1..=3 {
            seed(&mut tree, head(n, n as u8, (n - 1) as u8));
        }

        let finalized = tree.finalize(BlockRef::new(3, b(0x03)));
        assert_eq!(
            finalized.iter().map(|h| h.number).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        // The tip survives and stays queryable; only it remains.
        assert_eq!(tree.canonical_tip().unwrap().hash, b(0x03));
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn finalize_is_incremental_and_does_not_re_report() {
        let mut tree = BlockTree::new(64);
        for n in 1..=5 {
            seed(&mut tree, head(n, n as u8, (n - 1) as u8));
        }
        let _ = tree.finalize(BlockRef::new(2, b(0x02)));
        let second = tree.finalize(BlockRef::new(4, b(0x04)));
        // Only 3 and 4 cross the line the second time.
        assert_eq!(
            second.iter().map(|h| h.number).collect::<Vec<_>>(),
            vec![3, 4]
        );
    }

    #[test]
    fn a_block_at_or_below_the_finalized_floor_is_refused() {
        let mut tree = BlockTree::new(64);
        for n in 1..=5 {
            seed(&mut tree, head(n, n as u8, (n - 1) as u8));
        }
        let _ = tree.finalize(BlockRef::new(3, b(0x03)));

        // A competing block at height 3 would reorg a finalized block.
        let err = tree.add_block(head(3, 0x33, 0x02)).unwrap_err();
        assert_eq!(
            err,
            TreeError::ReorgBeyondFinality {
                finalized: BlockRef::new(3, b(0x03)),
                attempted: BlockRef::new(3, b(0x33)),
            }
        );
    }

    #[test]
    fn the_depth_backstop_bounds_memory_without_finalize() {
        // With depth 2 and no finalize() calls, the tree never holds more than
        // depth+1 blocks: anything more than 2 below the tip is pruned.
        let mut tree = BlockTree::new(2);
        for n in 1..=10 {
            seed(&mut tree, head(n, n as u8, (n - 1) as u8));
            assert!(tree.len() <= 3, "len {} at block {n}", tree.len());
        }
        assert_eq!(tree.canonical_tip().unwrap().number, 10);
    }
}
