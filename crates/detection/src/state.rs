//! Reorg-versioned, in-memory cross-block detector state (§6, §15, task 5).
//!
//! A `Scope::Block` detector (sandwich, arb — task 4) is a pure function of one
//! [`DetectionCtx`](detector_api::DetectionCtx) and keeps no state between blocks.
//! A [`Scope::CrossBlock`](detector_api::Scope::CrossBlock) detector (e.g.
//! wash-trading over a sliding window) *accumulates* — and that accumulator must
//! survive the one thing the chain does that a naive running total can't:
//! **a reorg.** When the canonical chain rolls back to a common ancestor and a new
//! branch rolls forward (§15), the detector's state has to roll back with it, or
//! it would carry the contributions of orphaned blocks forever and fire on history
//! that never happened.
//!
//! [`CrossBlockState`] is the container that makes that rollback cheap and
//! obviously correct: it keeps one **snapshot of the detector's state per applied
//! canonical block**, ascending by block number. Rolling back to a common ancestor
//! is then just discarding the snapshots above it — the ancestor's snapshot *is*
//! the state as of the ancestor, no replay of undo-deltas required.
//!
//! ## Snapshot-per-block, not a delta/undo-log
//!
//! Storing a full snapshot per block trades memory for correctness, and over a
//! *bounded* window that trade is clearly worth it. The window is bounded because
//! a reorg can never reach below the finalization depth (§15) — the same guarantee
//! the ingestion [`BlockTree`](../../ingestion/src/tree.rs) prune backstop relies
//! on — so any snapshot old enough to fall outside the window is also old enough
//! that it can never be reverted, and dropping it is safe. An undo-log would save
//! memory but reintroduce exactly the replay-ordering subtlety the block tree
//! already solved once; a snapshot stack keeps this layer dumb.
//!
//! ## What lands here vs. later
//!
//! This task (Sprint 3 task 5) ships the **container and its rewind primitive**,
//! tested in isolation — there is no `CrossBlock` detector in the roster yet (both
//! built-ins are `Scope::Block`), so this is the typed home its first writer will
//! use, mirroring how [`Performance`](crate::model::Performance) existed before its
//! metrics job. The wiring that drives it lands in Sprint 4:
//!
//! - **task 1** — consume `BlockReverted` and roll back to the common ancestor by
//!   replaying [`revert_tip`](CrossBlockState::revert_tip) tip-first, matching the
//!   event stream. This is the [`reorg`](crate::reorg) module, the thin consumer
//!   over the [`revert_tip`](CrossBlockState::revert_tip) /
//!   [`rewind_to`](CrossBlockState::rewind_to) primitives below.
//! - **task 2** — the async scheduler threads each `CrossBlock` detector's state
//!   through `detect`, calling [`apply`](CrossBlockState::apply) per canonical block.

use std::collections::VecDeque;

use events::primitives::BlockRef;

/// One stored version: the detector's accumulated state `state` *as of* applying
/// canonical block `block`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Version<S> {
    block: BlockRef,
    state: S,
}

/// A detector's cross-block state, versioned per canonical block so a reorg can
/// rewind it to the common ancestor (§15).
///
/// Generic over the detector's own state type `S` (the snapshot it wants
/// preserved across blocks). Versions are held ascending by block number, one per
/// applied block, bounded to the trailing `window_blocks` — see the [module
/// docs](self) for why a snapshot stack, and why bounding is safe.
#[derive(Debug, Clone)]
pub struct CrossBlockState<S> {
    /// The detector's declared window (`Scope::CrossBlock { window_blocks }`). The
    /// retained history is capped to this many trailing blocks.
    window_blocks: u32,
    /// Ascending by block number; the back is the canonical tip. A `VecDeque` so
    /// the window prune (drop from the front) and the apply (push to the back) are
    /// both O(1) amortised.
    versions: VecDeque<Version<S>>,
}

impl<S> CrossBlockState<S> {
    /// An empty state for a detector with the given trailing window.
    pub fn new(window_blocks: u32) -> Self {
        Self {
            window_blocks,
            versions: VecDeque::new(),
        }
    }

    /// The detector's window — how many trailing blocks of history are retained.
    pub fn window_blocks(&self) -> u32 {
        self.window_blocks
    }

    /// How many block versions are currently retained.
    pub fn len(&self) -> usize {
        self.versions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.versions.is_empty()
    }

    /// The current (canonical-tip) state, or `None` before any block is applied.
    pub fn current(&self) -> Option<&S> {
        self.versions.back().map(|v| &v.state)
    }

    /// The block the current state is as of, or `None` if empty.
    pub fn tip(&self) -> Option<BlockRef> {
        self.versions.back().map(|v| v.block)
    }

    /// Record the detector's `state` as of applying canonical `block`, becoming
    /// the new tip, and prune versions that have fallen outside the window.
    ///
    /// Blocks must be applied in strictly ascending number order (the scheduler
    /// feeds canonical blocks in order). A wiring bug that applies out of order is
    /// caught by `debug_assert!` — loud in test/CI builds, compiled out of the
    /// release hot path, the same discipline as
    /// [`DetectionCtx::with_enrichment`](detector_api::DetectionCtx::with_enrichment).
    pub fn apply(&mut self, block: BlockRef, state: S) {
        debug_assert!(
            self.tip().is_none_or(|tip| block.number > tip.number),
            "cross-block state applied out of order: block {} after tip {}",
            block.number,
            self.tip().map(|t| t.number).unwrap_or_default(),
        );
        self.versions.push_back(Version { block, state });
        self.prune_to_window();
    }

    /// Roll back the tip iff it is exactly `block`, returning whether it was.
    ///
    /// The inverse of [`apply`](Self::apply): undoing one block's contribution is
    /// popping the snapshot it produced. It is tip-conditional so it composes
    /// safely with the tip-first `BlockReverted` stream a reorg produces
    /// (`CanonicalUpdate.reverted`, ingestion `tree.rs`) — replaying that stream
    /// top-down pops exactly the orphaned blocks and stops; a stale/duplicate
    /// revert for a block that isn't the tip is a no-op (`false`) rather than
    /// corrupting state by popping the wrong version.
    #[must_use]
    pub fn revert_tip(&mut self, block: BlockRef) -> bool {
        if self.tip() == Some(block) {
            self.versions.pop_back();
            true
        } else {
            false
        }
    }

    /// Rewind to the common ancestor at `ancestor_number`: drop every version
    /// strictly above it, leaving that block's snapshot as [`current`](Self::current)
    /// — the §15 "roll back to common ancestor" in one step.
    ///
    /// The convenience form of repeated [`revert_tip`](Self::revert_tip) when the
    /// ancestor height is known directly (e.g. from the reorg's `CanonicalUpdate`).
    /// If the ancestor itself has already aged out of the window, the state is left
    /// empty — honest: there is no retained snapshot to rewind to, and the detector
    /// rebuilds from the re-applied branch.
    pub fn rewind_to(&mut self, ancestor_number: u64) {
        while self.tip().is_some_and(|tip| tip.number > ancestor_number) {
            self.versions.pop_back();
        }
    }

    /// Drop versions older than the trailing window relative to the current tip,
    /// retaining the last `window_blocks` heights. A block more than `window_blocks`
    /// behind the tip is beyond any reorg's reach (§15), so its snapshot can never
    /// be reverted and is safe to forget.
    ///
    /// The tip itself is always kept (`current()` must stay readable): with the
    /// degenerate `window_blocks == 0`, the floor equals the tip height, so this
    /// keeps exactly the current block.
    fn prune_to_window(&mut self) {
        let Some(tip) = self.tip() else { return };
        // Keep blocks in `(tip - window_blocks, tip]`; older ones can't be reverted.
        let floor = tip.number.saturating_sub(u64::from(self.window_blocks));
        while self.versions.len() > 1
            && self
                .versions
                .front()
                .is_some_and(|v| v.block.number <= floor)
        {
            self.versions.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    fn block(number: u64) -> BlockRef {
        // Hash derived from the number so distinct heights have distinct hashes,
        // and a re-applied branch at the same height (different hash) is distinct.
        BlockRef::new(number, B256::repeat_byte(number as u8))
    }

    fn forked_block(number: u64, tag: u8) -> BlockRef {
        BlockRef::new(number, B256::repeat_byte(tag))
    }

    #[test]
    fn empty_state_has_no_current() {
        let s: CrossBlockState<u64> = CrossBlockState::new(8);
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert_eq!(s.current(), None);
        assert_eq!(s.tip(), None);
        assert_eq!(s.window_blocks(), 8);
    }

    #[test]
    fn apply_advances_the_tip() {
        let mut s = CrossBlockState::new(8);
        s.apply(block(1), 10u64);
        s.apply(block(2), 25);
        s.apply(block(3), 40);

        assert_eq!(s.current(), Some(&40));
        assert_eq!(s.tip(), Some(block(3)));
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn revert_tip_pops_only_a_matching_tip() {
        let mut s = CrossBlockState::new(8);
        s.apply(block(1), 10u64);
        s.apply(block(2), 25);

        // A revert for a block that isn't the tip is a no-op.
        assert!(!s.revert_tip(block(1)));
        assert_eq!(s.current(), Some(&25));

        // The tip-first revert pops the orphaned block and exposes its parent.
        assert!(s.revert_tip(block(2)));
        assert_eq!(s.current(), Some(&10));
        assert_eq!(s.tip(), Some(block(1)));

        // Reverting past the bottom empties the store, then no-ops.
        assert!(s.revert_tip(block(1)));
        assert!(s.is_empty());
        assert!(!s.revert_tip(block(1)));
    }

    #[test]
    fn reverting_tip_first_unwinds_a_reorg_then_a_new_branch_reapplies() {
        // Canonical 1<-2<-3, then a reorg orphans 3,2 (tip-first) back to ancestor
        // 1, and a heavier branch 2',3' rolls forward — the §15 lifecycle.
        let mut s = CrossBlockState::new(8);
        s.apply(block(1), 10u64);
        s.apply(block(2), 25);
        s.apply(block(3), 40);

        assert!(s.revert_tip(block(3))); // BlockReverted(3)
        assert!(s.revert_tip(block(2))); // BlockReverted(2)
        assert_eq!(s.current(), Some(&10), "rolled back to ancestor 1");

        s.apply(forked_block(2, 0x12), 30); // BlockCanonicalized(2')
        s.apply(forked_block(3, 0x13), 55); // BlockCanonicalized(3')
        assert_eq!(s.current(), Some(&55));
        assert_eq!(s.tip(), Some(forked_block(3, 0x13)));
    }

    #[test]
    fn rewind_to_drops_everything_above_the_ancestor() {
        let mut s = CrossBlockState::new(16);
        for n in 1..=5u64 {
            s.apply(block(n), n * 10);
        }

        s.rewind_to(2); // common ancestor at height 2
        assert_eq!(s.current(), Some(&20), "ancestor 2's snapshot restored");
        assert_eq!(s.tip(), Some(block(2)));
        assert_eq!(s.len(), 2);

        // Rewinding to (or past) the tip height is a no-op.
        s.rewind_to(2);
        assert_eq!(s.len(), 2);
        s.rewind_to(99);
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn rewind_below_retained_history_empties_the_store() {
        let mut s = CrossBlockState::new(16);
        s.apply(block(10), 100u64);
        s.apply(block(11), 110);

        // Ancestor older than anything retained: nothing to rewind to.
        s.rewind_to(5);
        assert!(s.is_empty());
        assert_eq!(s.current(), None);
    }

    #[test]
    fn window_bounds_the_retained_versions() {
        let mut s = CrossBlockState::new(3);
        for n in 1..=10u64 {
            s.apply(block(n), n);
        }

        // Only blocks within (tip - 3, tip] survive: 8, 9, 10.
        assert_eq!(s.len(), 3);
        assert_eq!(s.tip(), Some(block(10)));
        assert_eq!(s.current(), Some(&10));

        // A block aged out of the window can't be rewound back into existence.
        s.rewind_to(1);
        assert!(s.is_empty());
    }

    #[test]
    fn a_zero_window_keeps_only_the_tip() {
        // Degenerate but well-defined: window 0 ⇒ keep only the current block.
        let mut s = CrossBlockState::new(0);
        s.apply(block(1), 1u64);
        s.apply(block(2), 2);
        assert_eq!(s.len(), 1);
        assert_eq!(s.current(), Some(&2));
    }
}
