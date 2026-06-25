//! Driving a [`CrossBlockState`] through a reorg from the `BlockReverted` event
//! stream (§15) — Sprint 4 task 1.
//!
//! [`state`](crate::state) ships the *primitive*: a per-block snapshot stack with
//! [`revert_tip`](CrossBlockState::revert_tip) /
//! [`rewind_to`](CrossBlockState::rewind_to). This module is the thin **consumer**
//! that sits on top of it — the glue the async scheduler (task 2) calls when a
//! reorg's [`BlockReverted`] events arrive: it replays them, tip-first, onto the
//! detector's state, rolling it back exactly to the common ancestor so the
//! detector stops carrying the contributions of orphaned blocks.
//!
//! Three pieces, smallest-first:
//!
//! - [`Rewindable`] — the **object-safe** view of a cross-block state's reorg
//!   operations ([`revert_tip`](Rewindable::revert_tip) /
//!   [`rewind_to`](Rewindable::rewind_to)), so a reorg can rewind a state without
//!   knowing the detector's state type `S`. A reorg is `S`-agnostic — it only moves
//!   the tip — so erasing `S` here is exactly right, and is what lets one collection
//!   hold the heterogeneous states of every cross-block detector.
//! - [`apply_reverts`] — replay one detector's `BlockReverted` stream onto a single
//!   `&mut dyn Rewindable`.
//! - [`CrossBlockStates`] — the **roster**: one type-erased state per cross-block
//!   detector, keyed by `(id, version)`, so a reorg rewinds *all* of them in one
//!   call. The plural analogue of the [`Registry`](crate::registry::Registry) — and
//!   the home Sprint 4 task 2's scheduler threads each detector's state through.
//!
//! ## Why replay `revert_tip`, not `rewind_to`
//!
//! A reorg reaches the detection service as a stream of [`BlockReverted`] events,
//! one per orphaned block, **tip-first** — the order ingestion's reorg walk emits
//! them (`CanonicalUpdate.reverted`, ingestion `tree.rs`). The common ancestor is
//! *implicit*: it's the block one below the lowest reverted height, and it is
//! never named in a `BlockReverted` event (the event carries only the orphaned
//! `block` and its `replaced_by`). So the honest reconstruction over this seam is
//! to pop each orphan in turn — [`rewind_to`](CrossBlockState::rewind_to) is the
//! convenience for when the ancestor *height* is already in hand (e.g. read
//! straight off the ingestion-side `CanonicalUpdate`), which is not the case here.
//!
//! ## Resilient to a stale or partial stream
//!
//! [`revert_tip`](CrossBlockState::revert_tip) is tip-conditional, so replaying
//! the stream is robust to the redelivery an at-least-once event bus allows
//! (ingestion publishes at-least-once; the event store dedupes on `event_id`, but
//! a consumer can still *see* a duplicate). A revert whose block isn't the current
//! tip — already-applied, duplicated, or aged out of the window — is ignored
//! rather than popping the wrong version, and counted separately so the scheduler
//! can log it. Conversely a gapped stream that would require popping past a block
//! it never names simply stops: better to under-rewind and let the detector
//! rebuild from the re-applied branch than to corrupt state by guessing.
//!
//! Resilience covers *staleness* (stream-vs-state), **not** disorder *within* the
//! stream — the events must arrive tip-first, the order ingestion emits them.
//! A mis-ordered stream would silently under-revert (popping the tip but leaving
//! a block beneath it that the reorg orphaned), so that ordering is a checked
//! invariant in [`apply_reverts`], not merely a documented expectation — the same
//! `debug_assert!` discipline as [`CrossBlockState::apply`]'s ascending guard.

use std::collections::BTreeMap;

use events::chain::BlockReverted;
use events::primitives::BlockRef;

use crate::registry::DetectorKey;
use crate::state::CrossBlockState;

/// The object-safe reorg surface of a cross-block state: the two operations a
/// reorg performs, with the detector's state type `S` erased.
///
/// A reorg only ever moves the tip — it never reads or rebuilds the accumulated
/// state — so none of its operations need to know `S`. Erasing it behind this
/// trait is what lets [`CrossBlockStates`] hold the heterogeneous states of every
/// cross-block detector in one `BTreeMap` and rewind them uniformly. Object-safe
/// by construction (no generics, no `Self` by value), so `Box<dyn Rewindable>`
/// works.
///
/// Implemented once, blanketly, for every [`CrossBlockState<S>`]; detectors never
/// implement it themselves.
pub trait Rewindable {
    /// Roll back the tip iff it is exactly `block`; see
    /// [`CrossBlockState::revert_tip`].
    #[must_use]
    fn revert_tip(&mut self, block: BlockRef) -> bool;

    /// Drop every version strictly above `ancestor_number`; see
    /// [`CrossBlockState::rewind_to`].
    fn rewind_to(&mut self, ancestor_number: u64);
}

impl<S> Rewindable for CrossBlockState<S> {
    fn revert_tip(&mut self, block: BlockRef) -> bool {
        // Disambiguate to the inherent method (same name on this trait).
        CrossBlockState::revert_tip(self, block)
    }

    fn rewind_to(&mut self, ancestor_number: u64) {
        CrossBlockState::rewind_to(self, ancestor_number)
    }
}

/// The outcome of replaying a reorg's [`BlockReverted`] stream onto a
/// [`CrossBlockState`] — a small tally for the scheduler's log line, not a
/// failure channel (a reorg rewind can't "fail", it can only pop fewer than the
/// stream named).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReorgRewind {
    /// Snapshots actually popped — orphaned blocks whose contribution was undone.
    pub popped: usize,
    /// Events that matched no tip and were ignored: a stale/duplicate revert, or
    /// one for a block already aged out of the window. A non-zero count is benign
    /// (see the [module docs](self)) but worth surfacing.
    pub ignored: usize,
}

impl ReorgRewind {
    /// Whether anything was rolled back. `false` means every event was a no-op —
    /// a fully stale stream, or one that didn't line up with the retained tip.
    pub fn changed(&self) -> bool {
        self.popped > 0
    }
}

/// Roll `state` back through a reorg's tip-first [`BlockReverted`] `stream`,
/// popping the snapshot each orphaned block produced and leaving the common
/// ancestor's snapshot as [`current`](CrossBlockState::current) — the §15 "roll
/// back to the common ancestor", reconstructed from the event seam.
///
/// Takes `&mut dyn Rewindable` (not a generic `CrossBlockState<S>`) so the reorg
/// path is monomorphized once and a `Box<dyn Rewindable>` from the
/// [`CrossBlockStates`] roster can be passed straight in. A concrete
/// `&mut CrossBlockState<S>` coerces automatically.
///
/// Returns a [`ReorgRewind`] tally. `#[must_use]`: discarding it loses the only
/// signal that a stream under-applied (every event ignored), which is the symptom
/// of a wiring or ordering bug worth a log line.
///
/// The inverse of feeding canonical blocks to [`apply`](CrossBlockState::apply):
/// each `BlockReverted`, replayed in the stream's tip-first order, pops exactly
/// the version its block produced. See the [module docs](self) for why this is
/// `revert_tip` replay rather than a single [`rewind_to`](CrossBlockState::rewind_to),
/// and why a non-matching event is ignored rather than mis-applied.
#[must_use]
pub fn apply_reverts(state: &mut dyn Rewindable, stream: &[BlockReverted]) -> ReorgRewind {
    assert_tip_first(stream);
    replay(state, stream)
}

/// The tip-first ordering invariant the `BlockReverted` stream must satisfy: a
/// reorg orphans blocks top-down, and `revert_tip` only unwinds in that order, so
/// a mis-ordered stream silently under-reverts (see the [module docs](self)).
/// Caught loudly in test/CI and compiled out of the release hot path, mirroring
/// [`CrossBlockState::apply`]'s ascending guard.
fn assert_tip_first(stream: &[BlockReverted]) {
    debug_assert!(
        stream
            .windows(2)
            .all(|pair| pair[0].block.number > pair[1].block.number),
        "BlockReverted stream must be tip-first (strictly descending by number)",
    );
}

/// The replay itself, shared by [`apply_reverts`] and [`CrossBlockStates`] — the
/// ordering assert is the caller's job, so the roster asserts once rather than
/// per detector. `?Sized` so a `&mut dyn Rewindable` (sized-erased) passes through.
fn replay<R: Rewindable + ?Sized>(state: &mut R, stream: &[BlockReverted]) -> ReorgRewind {
    let mut out = ReorgRewind::default();
    for event in stream {
        if state.revert_tip(event.block) {
            out.popped += 1;
        } else {
            out.ignored += 1;
        }
    }
    out
}

/// The cross-block states of every `Scope::CrossBlock` detector, owned together so
/// one reorg rewinds the whole roster — the plural analogue of the
/// [`Registry`](crate::registry::Registry) (Sprint 4 task 1).
///
/// Each detector's state has its own type `S`, so the states are stored type-erased
/// behind [`Rewindable`] (a reorg never needs `S`; see [`Rewindable`]) and keyed by
/// the detector's `(id, version)` [`DetectorKey`] — the same key the registry and
/// model registry use, so a `BlockReverted` (or the per-block apply path) maps to a
/// state with no extra bookkeeping. The reorg path is complete here; the typed
/// per-block `apply` path — which *does* need `S` back — is Sprint 4 task 2, when
/// the scheduler that threads detector state through `detect` lands.
#[derive(Default)]
pub struct CrossBlockStates {
    // `Send` so the async scheduler (task 2) can hold the roster across `.await`
    // points; ordered for deterministic iteration in logs/tests.
    by_key: BTreeMap<DetectorKey, Box<dyn Rewindable + Send>>,
}

impl CrossBlockStates {
    /// An empty roster.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a detector's freshly-built [`CrossBlockState`], erasing its state
    /// type behind [`Rewindable`]. Generic at the call site (the caller knows `S`),
    /// erased in storage. A second insert for the same key replaces the first.
    pub fn insert<S>(&mut self, key: DetectorKey, state: CrossBlockState<S>)
    where
        S: Send + 'static,
    {
        self.by_key.insert(key, Box::new(state));
    }

    /// How many detectors' states the roster holds.
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    /// Whether a state is registered for `key`.
    pub fn contains(&self, key: &DetectorKey) -> bool {
        self.by_key.contains_key(key)
    }

    /// Rewind **every** detector's state through one reorg's tip-first
    /// [`BlockReverted`] `stream` — the same reorg orphans the same blocks for all
    /// of them. Returns a [`RosterRewind`] aggregating the per-detector outcomes.
    ///
    /// Per-detector results can differ (a detector registered later, or one whose
    /// shorter window already aged a block out, pops fewer), which is why the
    /// aggregate counts both how many detectors changed and the total popped.
    #[must_use]
    pub fn apply_reverts(&mut self, stream: &[BlockReverted]) -> RosterRewind {
        assert_tip_first(stream);
        let mut out = RosterRewind::default();
        for state in self.by_key.values_mut() {
            let rewind = replay(state.as_mut(), stream);
            if rewind.changed() {
                out.rewound += 1;
            }
            out.popped += rewind.popped;
        }
        out
    }
}

impl std::fmt::Debug for CrossBlockStates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `dyn Rewindable` isn't `Debug`; show the roster by key, like `Registry`.
        f.debug_struct("CrossBlockStates")
            .field("detectors", &self.by_key.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// The aggregate outcome of rewinding a whole [`CrossBlockStates`] roster through
/// one reorg — a tally for the scheduler's log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RosterRewind {
    /// How many detectors had at least one snapshot popped.
    pub rewound: usize,
    /// Total snapshots popped across the roster.
    pub popped: usize,
}

impl RosterRewind {
    /// Whether the reorg rolled back any detector at all.
    pub fn changed(&self) -> bool {
        self.rewound > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use events::primitives::BlockRef;

    fn block(number: u64) -> BlockRef {
        // Hash derived from the number so distinct heights have distinct hashes,
        // mirroring `state.rs`'s test helper.
        BlockRef::new(number, B256::repeat_byte(number as u8))
    }

    /// A `BlockReverted` orphaning `number`, replaced by a forked block at the
    /// same height (`replaced_by` is irrelevant to the rewind — the state keys on
    /// the orphaned block — but a reorg always supplies one).
    fn reverted(number: u64) -> BlockReverted {
        BlockReverted {
            block: block(number),
            replaced_by: B256::repeat_byte(0xff),
        }
    }

    /// Apply 1..=tip with each block's height as its (placeholder) state.
    fn state_up_to(tip: u64) -> CrossBlockState<u64> {
        let mut s = CrossBlockState::new(16);
        for n in 1..=tip {
            s.apply(block(n), n);
        }
        s
    }

    #[test]
    fn replays_a_reorg_back_to_the_common_ancestor() {
        // Canonical 1<-2<-3<-4; a reorg orphans 4,3,2 (tip-first) back to ancestor 1.
        let mut s = state_up_to(4);

        let out = apply_reverts(&mut s, &[reverted(4), reverted(3), reverted(2)]);

        assert_eq!(out, ReorgRewind { popped: 3, ignored: 0 });
        assert!(out.changed());
        assert_eq!(s.current(), Some(&1), "left at the common ancestor's snapshot");
        assert_eq!(s.tip(), Some(block(1)));
    }

    #[test]
    fn a_single_block_extension_revert_pops_just_the_tip() {
        // The degenerate reorg: a one-block stream orphaning only the current tip.
        let mut s = state_up_to(3);

        let out = apply_reverts(&mut s, &[reverted(3)]);

        assert_eq!(out, ReorgRewind { popped: 1, ignored: 0 });
        assert_eq!(s.current(), Some(&2));
    }

    #[test]
    fn an_empty_stream_is_a_no_op() {
        let mut s = state_up_to(3);
        let out = apply_reverts(&mut s, &[]);
        assert_eq!(out, ReorgRewind::default());
        assert!(!out.changed());
        assert_eq!(s.tip(), Some(block(3)), "tip untouched");
    }

    #[test]
    fn a_redelivered_stream_is_idempotent() {
        // At-least-once delivery can re-present a reorg already applied. The first
        // pass rewinds; replaying the identical stream pops nothing and ignores all.
        let mut s = state_up_to(4);

        let first = apply_reverts(&mut s, &[reverted(4), reverted(3)]);
        assert_eq!(first, ReorgRewind { popped: 2, ignored: 0 });
        assert_eq!(s.tip(), Some(block(2)));

        let again = apply_reverts(&mut s, &[reverted(4), reverted(3)]);
        assert_eq!(again, ReorgRewind { popped: 0, ignored: 2 }, "all stale");
        assert!(!again.changed());
        assert_eq!(s.tip(), Some(block(2)), "tip unchanged on redelivery");
    }

    #[test]
    fn a_leading_stale_revert_is_skipped_then_the_rest_apply() {
        // Tip is already 3 (block 4 was popped earlier); the stream still leads
        // with the stale revert(4). It's ignored, then 3 and 2 pop as normal.
        let mut s = state_up_to(3);

        let out = apply_reverts(&mut s, &[reverted(4), reverted(3), reverted(2)]);

        assert_eq!(out, ReorgRewind { popped: 2, ignored: 1 });
        assert_eq!(s.current(), Some(&1), "rolled back to ancestor 1");
    }

    #[test]
    #[cfg(debug_assertions)] // the guard is a `debug_assert!`, compiled out in release
    #[should_panic(expected = "tip-first")]
    fn a_mis_ordered_stream_trips_the_debug_assert() {
        // A stream that isn't tip-first is a wiring bug — it would silently
        // under-revert, so it must fail loudly in test/CI rather than corrupt state.
        let mut s = state_up_to(4);
        let _ = apply_reverts(&mut s, &[reverted(3), reverted(4)]);
    }

    #[test]
    fn a_gapped_stream_that_misses_the_tip_pops_nothing() {
        // A stream that names 2 but not the current tip 3 must not pop 3 (it would
        // be undoing a block the reorg didn't orphan). Conservative: ignore it.
        let mut s = state_up_to(3);

        let out = apply_reverts(&mut s, &[reverted(2)]);

        assert_eq!(out, ReorgRewind { popped: 0, ignored: 1 });
        assert_eq!(s.tip(), Some(block(3)), "tip preserved — no wrong-version pop");
    }

    // ── Rewindable / dyn dispatch ─────────────────────────────────────────

    #[test]
    fn apply_reverts_works_through_a_trait_object() {
        // The reorg path runs over `&mut dyn Rewindable`, so a boxed, type-erased
        // state rewinds identically to the concrete one.
        let mut boxed: Box<dyn Rewindable + Send> = Box::new(state_up_to(3));
        let out = apply_reverts(boxed.as_mut(), &[reverted(3), reverted(2)]);
        assert_eq!(out, ReorgRewind { popped: 2, ignored: 0 });
    }

    // ── CrossBlockStates roster ───────────────────────────────────────────

    use crate::registry::DetectorKey;
    use detector_api::{DetectorId, SemVer};

    fn key(id: &'static str) -> DetectorKey {
        (DetectorId::new(id), SemVer::new(1, 0, 0))
    }

    /// A `CrossBlockState<S>` advanced to `tip`, with each height as placeholder
    /// state — generic so the roster can hold *different* `S` per detector.
    fn ramp<S: From<u8>>(tip: u64) -> CrossBlockState<S> {
        let mut s = CrossBlockState::new(16);
        for n in 1..=tip {
            s.apply(block(n), S::from(n as u8));
        }
        s
    }

    #[test]
    fn roster_rewinds_every_detectors_state_through_one_reorg() {
        // Two cross-block detectors with *different* state types, both at tip 4.
        let mut roster = CrossBlockStates::new();
        roster.insert(key("wash"), ramp::<u64>(4));
        roster.insert(key("spoof"), ramp::<i32>(4));
        assert_eq!(roster.len(), 2);

        // One reorg orphans 4,3,2 for the whole roster → 3 popped per detector.
        let out = roster.apply_reverts(&[reverted(4), reverted(3), reverted(2)]);

        assert_eq!(out, RosterRewind { rewound: 2, popped: 6 });
        assert!(out.changed());
    }

    #[test]
    fn roster_aggregates_differing_per_detector_outcomes() {
        // `a` is at tip 4, `b` only at tip 2 (registered later / shorter history).
        let mut roster = CrossBlockStates::new();
        roster.insert(key("a"), ramp::<u64>(4));
        roster.insert(key("b"), ramp::<u64>(2));

        // Stream orphans 4,3,2: `a` pops 4,3,2 (3); `b`'s tip is 2 so it ignores
        // 4,3 and pops only 2 (1). Aggregate: both changed, 4 popped total.
        let out = roster.apply_reverts(&[reverted(4), reverted(3), reverted(2)]);
        assert_eq!(out, RosterRewind { rewound: 2, popped: 4 });
    }

    #[test]
    fn an_empty_roster_rewinds_nothing() {
        let mut roster = CrossBlockStates::new();
        let out = roster.apply_reverts(&[reverted(3)]);
        assert_eq!(out, RosterRewind::default());
        assert!(!out.changed());
        assert!(roster.is_empty());
    }

    #[test]
    fn insert_replaces_and_contains_reflects_membership() {
        let mut roster = CrossBlockStates::new();
        assert!(!roster.contains(&key("wash")));

        roster.insert(key("wash"), ramp::<u64>(3));
        assert!(roster.contains(&key("wash")));
        assert_eq!(roster.len(), 1);

        // Re-inserting the same key replaces rather than duplicates.
        roster.insert(key("wash"), ramp::<u64>(1));
        assert_eq!(roster.len(), 1);
    }
}
