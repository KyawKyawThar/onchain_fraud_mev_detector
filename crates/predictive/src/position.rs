//! Lending-protocol position tracking (§16.1, Sprint 16 task 1) — the platform's
//! **first cross-block *predictive* writer**: it folds decoded Aave/Compound
//! position events into a running per-`(protocol, account)` state, reusing the
//! exact reorg-versioned snapshot store [`detection`]'s `Scope::CrossBlock`
//! detectors already use ([`detector_api::CrossBlockState`], §15) — see that
//! module's docs for why a snapshot-per-block store makes reorg rollback a cheap
//! discard rather than a replayed undo-log.
//!
//! Unlike a [`CrossBlockDetector`](detector_api::CrossBlockDetector), this isn't
//! a `Scope::CrossBlock` *detector*: it never emits [`Evidence`](detector_api::Evidence)
//! and there is no roster (one process tracks one running position book), so it
//! drives [`CrossBlockState`] directly rather than through
//! `detection::reorg::CrossBlockStates`'s type-erased, multi-detector roster. Its
//! output is state a later stage reads — the Sprint 16 task 2 cascade engine
//! recomputes health factors off [`PositionTracker::current`] on every
//! oracle/mark-price update, and folds in a live price to turn these raw balances
//! into a liquidation distance.
//!
//! # Shape: `Aave/Compound-shape`, per-asset
//!
//! A real lending position is **per-reserve**: a user's collateral and debt are
//! each spread across whichever assets they supplied/borrowed, and Aave's
//! liquidation math weighs each reserve's own threshold. [`Position`] mirrors
//! that — `collateral`/`debt` are keyed by asset address, raw base units (not
//! decimal- or USD-adjusted; that conversion needs a live price, which is
//! deliberately *not* this task's job — see the module docs above). Rolling every
//! asset into one scalar here would make task 2's per-asset mark-price fold
//! impossible without re-deriving the breakdown from raw events.
//!
//! `liquidation_threshold` is **one blended [`Bps`] per position**, not
//! per-reserve: Aave/Compound's real per-reserve thresholds (and Aave's
//! collateral-weighted blend across a user's reserves) are protocol *config*
//! state, not something a `Supply`/`Borrow` log carries — recovering it exactly
//! needs a reserve-config view call this log-only decode pass doesn't make. A
//! single [`LiquidationThresholds`]-sourced default per protocol is the accepted
//! first-cut approximation; refining it to a real per-reserve/weighted figure is
//! task 2/3's job once the cascade engine is reading live reserve config anyway.

use std::collections::BTreeMap;
use std::sync::Arc;

use alloy_primitives::{Address, U256};
use detector_api::{Bps, CrossBlockState};
use events::primitives::BlockRef;

use crate::lending_decode::LendingEvent;

/// A lending protocol this tracker knows how to decode. `Ord` so it's usable as
/// (part of) a `BTreeMap` key ([`PositionKey`]) with a stable iteration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Protocol {
    Aave,
    Compound,
}

/// Default liquidation threshold assumed for a position on first touch, when no
/// override is configured — see [`LiquidationThresholds`]. Aave V3's blue-chip
/// reserves (WETH/WBTC/stables) commonly sit around 80–83%; 80% is a
/// representative single figure for a first cut.
const DEFAULT_AAVE_LIQUIDATION_THRESHOLD_BPS: u32 = 8_000;
/// Compound v2's typical collateral factor for its major markets is closer to
/// 75%.
const DEFAULT_COMPOUND_LIQUIDATION_THRESHOLD_BPS: u32 = 7_500;

/// Per-protocol liquidation threshold used to seed a position's
/// [`Position::liquidation_threshold`] on first touch (§16.1 — see the module
/// docs' note on why this is one blended figure, not per-reserve).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiquidationThresholds {
    aave: Bps,
    compound: Bps,
}

impl LiquidationThresholds {
    pub fn new(aave: Bps, compound: Bps) -> Self {
        Self { aave, compound }
    }

    /// The configured (or default) threshold for `protocol`.
    pub fn for_protocol(&self, protocol: Protocol) -> Bps {
        match protocol {
            Protocol::Aave => self.aave,
            Protocol::Compound => self.compound,
        }
    }
}

impl Default for LiquidationThresholds {
    fn default() -> Self {
        Self {
            aave: Bps::new(DEFAULT_AAVE_LIQUIDATION_THRESHOLD_BPS),
            compound: Bps::new(DEFAULT_COMPOUND_LIQUIDATION_THRESHOLD_BPS),
        }
    }
}

/// One account's position on one protocol — the key the task's roster is keyed
/// by (§16.1: "keyed by `(protocol, account)`").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PositionKey {
    pub protocol: Protocol,
    pub account: Address,
}

/// One account's decoded lending position: collateral/debt per reserve asset
/// (raw base units — see the module docs), plus the blended liquidation
/// threshold assumed for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Position {
    pub collateral: BTreeMap<Address, U256>,
    pub debt: BTreeMap<Address, U256>,
    pub liquidation_threshold: Bps,
}

impl Position {
    fn new(liquidation_threshold: Bps) -> Self {
        Self {
            collateral: BTreeMap::new(),
            debt: BTreeMap::new(),
            liquidation_threshold,
        }
    }

    /// Whether this position has fully closed out (no collateral, no debt) and
    /// its entry can be dropped — bounds the tracker's memory to accounts with
    /// an open position rather than growing forever over the account's history.
    fn is_closed(&self) -> bool {
        self.collateral.values().all(U256::is_zero) && self.debt.values().all(U256::is_zero)
    }
}

/// Apply `op` (a saturating add/sub) to `book`'s entry for `asset`, seeding a
/// zero balance on first touch. `op` is a plain `fn`, not a closure, so the
/// two call sites (`add_amount`/`sub_amount` below) stay zero-cost.
fn adjust(
    book: &mut BTreeMap<Address, U256>,
    asset: Address,
    amount: U256,
    op: fn(U256, U256) -> U256,
) {
    let entry = book.entry(asset).or_insert(U256::ZERO);
    *entry = op(*entry, amount);
}

fn add_amount(book: &mut BTreeMap<Address, U256>, asset: Address, amount: U256) {
    adjust(book, asset, amount, U256::saturating_add);
}

fn sub_amount(book: &mut BTreeMap<Address, U256>, asset: Address, amount: U256) {
    adjust(book, asset, amount, U256::saturating_sub);
}

/// The tracker's accumulated cross-block state: every open position, keyed by
/// `(protocol, account)`. `Clone` (the tracker forks it per block, mirroring
/// `detection`'s `Scope::CrossBlock` slot) and `Default` (the seed for the first
/// block).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PositionState {
    positions: BTreeMap<PositionKey, Position>,
}

impl PositionState {
    /// The position for `key`, if the account has one open.
    pub fn get(&self, key: &PositionKey) -> Option<&Position> {
        self.positions.get(key)
    }

    /// How many open positions are tracked.
    pub fn len(&self) -> usize {
        self.positions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.positions.is_empty()
    }

    /// Every open position, `(protocol, account)`-ordered.
    pub fn iter(&self) -> impl Iterator<Item = (&PositionKey, &Position)> {
        self.positions.iter()
    }

    /// Fold one decoded lending event into the position book, seeding a fresh
    /// [`Position`] at `thresholds`' default for a first-touched account and
    /// pruning the entry back out if the event fully closed it.
    pub fn apply(&mut self, event: &LendingEvent, thresholds: &LiquidationThresholds) {
        let key = event.position_key();
        let position = self
            .positions
            .entry(key)
            .or_insert_with(|| Position::new(thresholds.for_protocol(key.protocol)));

        match *event {
            LendingEvent::Supply { asset, amount, .. } => {
                add_amount(&mut position.collateral, asset, amount);
            }
            LendingEvent::Withdraw { asset, amount, .. } => {
                sub_amount(&mut position.collateral, asset, amount);
            }
            LendingEvent::Borrow { asset, amount, .. } => {
                add_amount(&mut position.debt, asset, amount);
            }
            LendingEvent::Repay { asset, amount, .. } => {
                sub_amount(&mut position.debt, asset, amount);
            }
            LendingEvent::Liquidation {
                debt_asset,
                debt_repaid,
                collateral_asset,
                collateral_seized,
                ..
            } => {
                sub_amount(&mut position.debt, debt_asset, debt_repaid);
                // Aave's `liquidatedCollateralAmount` is underlying-denominated,
                // same units as `Supply`/`Withdraw`. Compound's `seizeTokens` is
                // **cToken**-denominated (scaled by the market's exchange rate),
                // not underlying — netting it directly against `collateral` (which
                // `Mint`/`Redeem` populate in underlying units) is a known
                // first-cut approximation for a Compound liquidation until the
                // exchange-rate conversion lands (accepted debt, §16.1 task 1).
                sub_amount(
                    &mut position.collateral,
                    collateral_asset,
                    collateral_seized,
                );
            }
        }

        if position.is_closed() {
            self.positions.remove(&key);
        }
    }
}

/// The lending position tracker: [`PositionState`] wrapped in the reorg-versioned
/// [`CrossBlockState`] snapshot store, so a `BlockReverted` rewinds tracked
/// positions exactly like `detection`'s cross-block detectors (§15).
///
/// `window_blocks` should be sized to the chain's reorg depth (its
/// finalization-depth guarantee, e.g. [`Chain::default_finalization_depth`]
/// (events::primitives::Chain::default_finalization_depth)), **not** an
/// analytical pattern window like a `CrossBlockDetector`'s — a position must
/// stay rewindable for as long as a reorg could plausibly reach, however long
/// ago it was last touched.
pub struct PositionTracker {
    thresholds: LiquidationThresholds,
    /// `Arc`-wrapped so a block that folds in no events (the common case —
    /// most blocks touch none of the tracked lending contracts) can carry the
    /// prior snapshot forward as an O(1) refcount bump rather than deep-cloning
    /// every tracked account's whole collateral/debt map just to store an
    /// identical copy.
    state: CrossBlockState<Arc<PositionState>>,
}

impl PositionTracker {
    pub fn new(window_blocks: u32, thresholds: LiquidationThresholds) -> Self {
        Self {
            thresholds,
            state: CrossBlockState::new(window_blocks),
        }
    }

    /// Fold `events` into the tip snapshot (or start from empty on the first
    /// block) and record the result as the new tip — the same fork-mutate-apply
    /// shape `detection::reorg::Slot::observe_and_detect` uses for a
    /// `CrossBlockDetector`, except an empty `events` skips the fork entirely
    /// (see the `state` field docs). Must be called in ascending block order
    /// (`CrossBlockState::apply` asserts it).
    pub fn apply_block(&mut self, block: BlockRef, events: &[LendingEvent]) {
        let current = self.state.current().cloned().unwrap_or_default();
        let next = if events.is_empty() {
            current
        } else {
            let mut owned = PositionState::clone(&current);
            for event in events {
                owned.apply(event, &self.thresholds);
            }
            Arc::new(owned)
        };
        self.state.apply(block, next);
    }

    /// Roll back the tip iff it is exactly the orphaned `block` — the
    /// tip-conditional discipline that makes replaying a reorg's tip-first
    /// `BlockReverted` stream, one event at a time as it's consumed off Kafka,
    /// exactly as safe as `detection::reorg`'s batch replay (§15): a
    /// stale/duplicate/out-of-window revert is a no-op rather than popping the
    /// wrong version.
    #[must_use]
    pub fn revert_tip(&mut self, block: BlockRef) -> bool {
        self.state.revert_tip(block)
    }

    /// The tracked position book as of the current tip, or `None` before any
    /// block has been applied.
    pub fn current(&self) -> Option<&PositionState> {
        self.state.current().map(|arc| &**arc)
    }

    /// The block the current position book is as of.
    pub fn tip(&self) -> Option<BlockRef> {
        self.state.tip()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    fn addr(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }

    fn block(number: u64) -> BlockRef {
        BlockRef::new(number, B256::repeat_byte(number as u8))
    }

    fn forked_block(number: u64, tag: u8) -> BlockRef {
        BlockRef::new(number, B256::repeat_byte(tag))
    }

    const USER: u8 = 0x11;
    const WETH: u8 = 0xE0;
    const USDC: u8 = 0xC0;

    fn key() -> PositionKey {
        PositionKey {
            protocol: Protocol::Aave,
            account: addr(USER),
        }
    }

    fn supply(amount: u64) -> LendingEvent {
        LendingEvent::Supply {
            protocol: Protocol::Aave,
            account: addr(USER),
            asset: addr(WETH),
            amount: U256::from(amount),
        }
    }

    fn borrow(amount: u64) -> LendingEvent {
        LendingEvent::Borrow {
            protocol: Protocol::Aave,
            account: addr(USER),
            asset: addr(USDC),
            amount: U256::from(amount),
        }
    }

    #[test]
    fn supply_and_borrow_seed_a_new_position_with_the_default_threshold() {
        let mut state = PositionState::default();
        let thresholds = LiquidationThresholds::default();
        state.apply(&supply(1_000), &thresholds);
        state.apply(&borrow(500), &thresholds);

        let position = state.get(&key()).expect("position opened");
        assert_eq!(
            position.collateral.get(&addr(WETH)),
            Some(&U256::from(1_000u64))
        );
        assert_eq!(position.debt.get(&addr(USDC)), Some(&U256::from(500u64)));
        assert_eq!(
            position.liquidation_threshold,
            Bps::new(DEFAULT_AAVE_LIQUIDATION_THRESHOLD_BPS)
        );
        assert_eq!(state.len(), 1);
    }

    #[test]
    fn withdraw_and_repay_reduce_the_position_and_full_close_prunes_it() {
        let mut state = PositionState::default();
        let thresholds = LiquidationThresholds::default();
        state.apply(&supply(1_000), &thresholds);
        state.apply(&borrow(500), &thresholds);

        state.apply(
            &LendingEvent::Repay {
                protocol: Protocol::Aave,
                account: addr(USER),
                asset: addr(USDC),
                amount: U256::from(500u64),
            },
            &thresholds,
        );
        state.apply(
            &LendingEvent::Withdraw {
                protocol: Protocol::Aave,
                account: addr(USER),
                asset: addr(WETH),
                amount: U256::from(1_000u64),
            },
            &thresholds,
        );

        assert!(state.is_empty(), "a fully closed position is pruned");
    }

    #[test]
    fn withdraw_and_repay_saturate_rather_than_underflow() {
        let mut state = PositionState::default();
        let thresholds = LiquidationThresholds::default();
        state.apply(&supply(100), &thresholds);

        state.apply(
            &LendingEvent::Withdraw {
                protocol: Protocol::Aave,
                account: addr(USER),
                asset: addr(WETH),
                amount: U256::from(1_000u64),
            },
            &thresholds,
        );
        // A malformed/out-of-order stream must not panic or wrap around U256::MAX.
        assert!(state.is_empty());
    }

    #[test]
    fn liquidation_reduces_both_debt_and_collateral() {
        let mut state = PositionState::default();
        let thresholds = LiquidationThresholds::default();
        state.apply(&supply(1_000), &thresholds);
        state.apply(&borrow(500), &thresholds);

        state.apply(
            &LendingEvent::Liquidation {
                protocol: Protocol::Aave,
                account: addr(USER),
                debt_asset: addr(USDC),
                debt_repaid: U256::from(200u64),
                collateral_asset: addr(WETH),
                collateral_seized: U256::from(220u64),
            },
            &thresholds,
        );

        let position = state.get(&key()).unwrap();
        assert_eq!(position.debt.get(&addr(USDC)), Some(&U256::from(300u64)));
        assert_eq!(
            position.collateral.get(&addr(WETH)),
            Some(&U256::from(780u64))
        );
    }

    #[test]
    fn different_protocols_key_separately_for_the_same_account() {
        let mut state = PositionState::default();
        let thresholds = LiquidationThresholds::default();
        state.apply(&supply(1_000), &thresholds); // Aave
        state.apply(
            &LendingEvent::Supply {
                protocol: Protocol::Compound,
                account: addr(USER),
                asset: addr(WETH),
                amount: U256::from(1_000u64),
            },
            &thresholds,
        );

        assert_eq!(state.len(), 2);
        let compound = state
            .get(&PositionKey {
                protocol: Protocol::Compound,
                account: addr(USER),
            })
            .unwrap();
        assert_eq!(
            compound.liquidation_threshold,
            Bps::new(DEFAULT_COMPOUND_LIQUIDATION_THRESHOLD_BPS)
        );
    }

    // ── PositionTracker: reorg rollback (§15) ────────────────────────────────

    #[test]
    fn tracker_applies_blocks_and_advances_the_tip() {
        let mut tracker = PositionTracker::new(16, LiquidationThresholds::default());
        tracker.apply_block(block(1), &[supply(1_000)]);
        tracker.apply_block(block(2), &[borrow(500)]);

        let position = tracker.current().unwrap().get(&key()).unwrap();
        assert_eq!(
            position.collateral.get(&addr(WETH)),
            Some(&U256::from(1_000u64))
        );
        assert_eq!(position.debt.get(&addr(USDC)), Some(&U256::from(500u64)));
        assert_eq!(tracker.tip(), Some(block(2)));
    }

    #[test]
    fn revert_tip_rolls_back_to_the_prior_block_and_a_new_branch_reapplies() {
        let mut tracker = PositionTracker::new(16, LiquidationThresholds::default());
        tracker.apply_block(block(1), &[supply(1_000)]);
        tracker.apply_block(block(2), &[borrow(500)]);

        // Reorg orphans block 2 (tip-first, one BlockReverted at a time as Kafka
        // delivers them).
        assert!(tracker.revert_tip(block(2)));
        let position = tracker.current().unwrap().get(&key()).unwrap();
        assert!(position.debt.get(&addr(USDC)).is_none_or(U256::is_zero));

        // A stale revert for a block that isn't the tip is a no-op.
        assert!(!tracker.revert_tip(block(2)));

        // The re-applied branch folds in cleanly from the rolled-back tip.
        tracker.apply_block(forked_block(2, 0x22), &[borrow(300)]);
        let position = tracker.current().unwrap().get(&key()).unwrap();
        assert_eq!(position.debt.get(&addr(USDC)), Some(&U256::from(300u64)));
        assert_eq!(tracker.tip(), Some(forked_block(2, 0x22)));
    }

    #[test]
    fn an_empty_block_still_advances_the_tip() {
        let mut tracker = PositionTracker::new(16, LiquidationThresholds::default());
        tracker.apply_block(block(1), &[supply(1_000)]);
        tracker.apply_block(block(2), &[]);

        assert_eq!(tracker.tip(), Some(block(2)));
        assert_eq!(
            tracker.current().unwrap().get(&key()).unwrap().collateral[&addr(WETH)],
            U256::from(1_000u64)
        );
    }

    #[test]
    fn a_block_with_no_events_reuses_the_prior_snapshots_allocation() {
        // The common case (most blocks touch none of the tracked lending
        // contracts) must carry the snapshot forward as a cheap `Arc` clone,
        // not a deep clone of the whole position book — reaches into the
        // private `state` field (this test module is a child of `position`,
        // so it shares that visibility) to assert the two tips are the exact
        // same allocation.
        let mut tracker = PositionTracker::new(16, LiquidationThresholds::default());
        tracker.apply_block(block(1), &[supply(1_000)]);
        let first = tracker.state.current().unwrap().clone();

        tracker.apply_block(block(2), &[]);
        let second = tracker.state.current().unwrap().clone();

        assert!(
            Arc::ptr_eq(&first, &second),
            "an empty block should reuse the prior snapshot's allocation"
        );
    }
}
