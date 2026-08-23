//! The bounded, time-window-evicted candidate-leg buffer (§24) — the
//! cross-chain analogue of [`detector_api::CrossBlockState`]: instead of
//! retaining a trailing window of *blocks*, it retains a trailing window of
//! *wall-clock observation time*, because chains finalize at different rates
//! and the join is explicitly windowed on when a leg was observed, not on
//! block numbers (§24). Same memory-DoS discipline as
//! `simulation::cache::CachingSimulator`/`simulation::reorg::OrphanedBlocks`:
//! a hand-rolled bounded collection, insertion-order FIFO as the hard
//! backstop once the time window alone isn't enough (a burst faster than the
//! window drains, or a misconfigured capacity).
//!
//! Pure core, like [`detector_api::CrossBlockState`]: this container does no
//! logging or metrics recording itself — [`Self::insert`]/[`Self::evict_expired`]
//! report what they evicted and leave logging/recording to the caller
//! ([`crate::actor::CorrelationActor::on_leg`]), the same split
//! `PositionConsumer` keeps around `CrossBlockState::revert_tip`.
//!
//! **Secondary index (production hardening).** `legs` remains the source of
//! truth (a `VecDeque`, so the capacity backstop's oldest-first drop stays
//! O(1)), but every arriving leg's [`CandidateLeg::correlation_key`] almost
//! never matches anything else in the buffer — [`crate::join::join_leg`]'s
//! common case is "no match." Without an index that common case still costs
//! a full scan of the buffer for *every single leg*. `by_key` turns it into
//! an O(1)-average hash lookup, falling back to scanning only the (typically
//! tiny) handful of legs that actually share a key.

use std::collections::{HashMap, VecDeque};

use alloy_primitives::{Address, B256};
use chrono::{DateTime, TimeDelta, Utc};

use crate::leg::CandidateLeg;

/// Default hard cap on legs retained per bridge/pair, if a deployment doesn't
/// override it — generous enough that the time window is the binding
/// constraint in normal operation, the same "backstop, not the everyday
/// limit" role `simulation::reorg::DEFAULT_ORPHAN_BLOCK_CAPACITY` plays.
pub const DEFAULT_CANDIDATE_LEG_CAPACITY: usize = 10_000;

/// What [`CandidateLegBuffer::insert`] had to evict to make room, for the
/// caller to log/record — the buffer itself stays silent (see module docs).
/// Carries the evicted legs themselves (not just a count) so the caller can
/// also durably log their removal to the leg-buffer changelog
/// (`crate::changelog`, production hardening) — a restart replaying the log
/// must see exactly the mutations that happened, not just how many.
#[derive(Debug, Default)]
pub struct InsertOutcome {
    /// Every leg that aged out of the window (a normal, expected outcome).
    pub window_evicted: Vec<CandidateLeg>,
    /// The oldest leg, if the hard capacity backstop had to drop it after
    /// the window eviction alone wasn't enough — worth alerting on, unlike
    /// a window eviction.
    pub capacity_evicted: Option<CandidateLeg>,
}

/// One bridge/pair's window of unmatched candidate legs.
pub struct CandidateLegBuffer {
    window: TimeDelta,
    capacity: usize,
    /// Not required to stay strictly ascending by `observed_at` — legs from
    /// different chains can arrive with clock skew (§24) — so eviction is a
    /// full scan ([`Self::evict_expired`]), not a front-only pop.
    legs: VecDeque<CandidateLeg>,
    /// Secondary index: `correlation_key` -> txs of legs currently holding
    /// that key (see module docs). Kept in lockstep with `legs` by every
    /// mutating method; never read directly outside this module.
    by_key: HashMap<Address, Vec<B256>>,
}

impl CandidateLegBuffer {
    pub fn new(window: TimeDelta, capacity: usize) -> Self {
        Self {
            window,
            capacity: capacity.max(1),
            legs: VecDeque::new(),
            by_key: HashMap::new(),
        }
    }

    pub fn window(&self) -> TimeDelta {
        self.window
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.legs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.legs.is_empty()
    }

    /// Every currently-buffered leg — an unindexed full scan. Callers doing
    /// a key-scoped lookup should prefer [`Self::candidates_for`] instead;
    /// this remains for callers that genuinely need every leg (tests, and
    /// [`Self::seed`]'s bulk restore).
    pub fn iter(&self) -> impl Iterator<Item = &CandidateLeg> {
        self.legs.iter()
    }

    /// Every buffered leg sharing `key`, via the secondary index — the
    /// windowed join's ([`crate::join::join_leg`]) primary lookup. O(1)
    /// average when nothing shares the key (the common case); otherwise
    /// bounded by however many legs actually do, not by the whole buffer.
    pub fn candidates_for(&self, key: Address) -> impl Iterator<Item = &CandidateLeg> + '_ {
        self.by_key
            .get(&key)
            .into_iter()
            .flatten()
            .filter_map(move |tx| self.legs.iter().find(|leg| leg.tx == *tx))
    }

    /// Buffer `leg` as observed at `now`: first evict anything that's aged
    /// out of the window, then — the hard backstop — drop the oldest
    /// remaining entry if still at capacity, so a leg flood can't grow this
    /// buffer without bound regardless of the window setting.
    pub fn insert(&mut self, leg: CandidateLeg, now: DateTime<Utc>) -> InsertOutcome {
        let window_evicted = self.evict_expired(now);
        let capacity_evicted = if self.legs.len() >= self.capacity {
            let dropped = self.legs.pop_front();
            if let Some(dropped) = &dropped {
                self.deindex(dropped);
            }
            dropped
        } else {
            None
        };
        self.index_insert(&leg);
        self.legs.push_back(leg);
        InsertOutcome {
            window_evicted,
            capacity_evicted,
        }
    }

    /// Remove and return the buffered leg whose tx is `tx`, if any — how the
    /// windowed join (Sprint 17 task 2, [`crate::join`]) consumes a leg that
    /// just completed a match, rather than leaving it to age out.
    pub fn remove(&mut self, tx: B256) -> Option<CandidateLeg> {
        let pos = self.legs.iter().position(|leg| leg.tx == tx)?;
        let removed = self.legs.remove(pos);
        if let Some(removed) = &removed {
            self.deindex(removed);
        }
        removed
    }

    /// Drop every leg older than [`Self::window`] relative to `now` — an
    /// unmatched leg ages out (§24). Called on every insert; also callable on
    /// its own so an idle bridge/pair's buffer doesn't hold stale legs
    /// indefinitely between arrivals. Returns the evicted legs.
    #[must_use]
    pub fn evict_expired(&mut self, now: DateTime<Utc>) -> Vec<CandidateLeg> {
        let window = self.window;
        let mut evicted = Vec::new();
        let mut i = 0;
        while i < self.legs.len() {
            if now.signed_duration_since(self.legs[i].observed_at) > window {
                // `VecDeque::remove` always succeeds for an in-bounds index.
                let leg = self.legs.remove(i).expect("index in bounds");
                self.deindex(&leg);
                evicted.push(leg);
            } else {
                i += 1;
            }
        }
        evicted
    }

    /// Restore legs already known to be live — a changelog replay at boot
    /// (`crate::changelog::replay`, production hardening), *not* the normal
    /// live-arrival path. Bypasses [`Self::insert`]'s per-leg
    /// window-eviction dance (each replayed leg's own `observed_at` is
    /// historical, and inserting one at a time would repeatedly re-run
    /// eviction against restore order rather than true observation order)
    /// while still respecting the hard capacity backstop as a defensive
    /// floor. Callers must call [`Self::evict_expired`] against the current
    /// time immediately afterward to prune anything that aged out during
    /// downtime — `crate::changelog::replay`'s caller does exactly this.
    pub fn seed(&mut self, mut legs: Vec<CandidateLeg>) {
        legs.sort_by_key(|leg| leg.observed_at);
        for leg in legs {
            if self.legs.len() >= self.capacity {
                if let Some(dropped) = self.legs.pop_front() {
                    self.deindex(&dropped);
                }
            }
            self.index_insert(&leg);
            self.legs.push_back(leg);
        }
    }

    fn index_insert(&mut self, leg: &CandidateLeg) {
        self.by_key
            .entry(leg.correlation_key)
            .or_default()
            .push(leg.tx);
    }

    fn deindex(&mut self, leg: &CandidateLeg) {
        if let Some(txs) = self.by_key.get_mut(&leg.correlation_key) {
            txs.retain(|&tx| tx != leg.tx);
            if txs.is_empty() {
                self.by_key.remove(&leg.correlation_key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leg::{BridgeOrPair, LegKind};
    use alloy_primitives::{Address, B256};
    use events::primitives::{BlockRef, Chain};

    fn bridge() -> BridgeOrPair {
        BridgeOrPair("usdc-eth-base".to_owned())
    }

    fn leg_at(observed_at: DateTime<Utc>, tag: u8) -> CandidateLeg {
        CandidateLeg {
            chain: Chain::ETHEREUM,
            block: BlockRef::new(1, B256::repeat_byte(tag)),
            tx: B256::repeat_byte(tag),
            kind: LegKind::BridgeDeposit,
            bridge_or_pair: bridge(),
            correlation_key: Address::repeat_byte(tag),
            observed_at,
            confidence: events::primitives::Confidence::CERTAIN,
            impact_usd: None,
        }
    }

    fn leg_with_key(observed_at: DateTime<Utc>, tag: u8, key: u8) -> CandidateLeg {
        CandidateLeg {
            correlation_key: Address::repeat_byte(key),
            ..leg_at(observed_at, tag)
        }
    }

    #[test]
    fn a_fresh_buffer_is_empty() {
        let buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.window(), TimeDelta::minutes(10));
    }

    #[test]
    fn insert_grows_the_buffer_within_the_window() {
        let now = Utc::now();
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        buf.insert(leg_at(now, 1), now);
        buf.insert(leg_at(now, 2), now);
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn insert_reports_no_eviction_when_nothing_ages_out_or_overflows() {
        let now = Utc::now();
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        let outcome = buf.insert(leg_at(now, 1), now);
        assert!(outcome.window_evicted.is_empty());
        assert!(outcome.capacity_evicted.is_none());
    }

    #[test]
    fn a_leg_older_than_the_window_is_evicted_on_the_next_insert() {
        let t0 = Utc::now();
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        buf.insert(leg_at(t0, 1), t0);

        let t1 = t0 + TimeDelta::minutes(11);
        let outcome = buf.insert(leg_at(t1, 2), t1);

        assert_eq!(buf.len(), 1, "the aged-out leg must be evicted");
        assert_eq!(buf.iter().next().unwrap().tx, B256::repeat_byte(2));
        assert_eq!(outcome.window_evicted.len(), 1);
        assert_eq!(outcome.window_evicted[0].tx, B256::repeat_byte(1));
        assert!(outcome.capacity_evicted.is_none());
    }

    #[test]
    fn evict_expired_can_be_called_without_an_insert() {
        let t0 = Utc::now();
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        buf.insert(leg_at(t0, 1), t0);

        let evicted = buf.evict_expired(t0 + TimeDelta::minutes(11));
        assert!(buf.is_empty(), "an idle buffer must still age out its legs");
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].tx, B256::repeat_byte(1));
    }

    #[test]
    fn out_of_order_observed_at_is_still_evicted_correctly() {
        // §24: legs from different chains arrive with clock skew, so the
        // leg at the *front* of the queue (inserted first) is not
        // necessarily the one with the oldest `observed_at`. A front-only
        // pop (stop at the first non-expired entry) would wrongly keep
        // scanning no further and miss an expired entry sitting behind a
        // fresher one — this pins the full-scan behavior instead.
        let t0 = Utc::now();
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        // Inserted first (at the front), but stamped *fresher* than leg 2.
        buf.insert(
            leg_at(t0 + TimeDelta::minutes(8), 1),
            t0 + TimeDelta::minutes(8),
        );
        // Inserted second, but stamped older — clock-skewed relative to leg 1.
        buf.insert(leg_at(t0, 2), t0 + TimeDelta::minutes(8));

        let now = t0 + TimeDelta::minutes(11);
        let evicted = buf.evict_expired(now);
        // Leg 1 is 3 minutes old at `now` (within the 10-minute window);
        // leg 2 is 11 minutes old (expired) despite sitting behind leg 1 in
        // insertion order.
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].tx, B256::repeat_byte(2));
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.iter().next().unwrap().tx, B256::repeat_byte(1));
    }

    #[test]
    fn capacity_is_a_hard_backstop_even_within_the_window() {
        let t0 = Utc::now();
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 2);
        buf.insert(leg_at(t0, 1), t0);
        buf.insert(leg_at(t0, 2), t0);
        let outcome = buf.insert(leg_at(t0, 3), t0); // still well within the window

        assert_eq!(
            buf.len(),
            2,
            "capacity must bound the buffer regardless of window"
        );
        let txs: Vec<B256> = buf.iter().map(|leg| leg.tx).collect();
        assert_eq!(
            txs,
            vec![B256::repeat_byte(2), B256::repeat_byte(3)],
            "the oldest-inserted leg is the one dropped"
        );
        assert_eq!(
            outcome.capacity_evicted.map(|leg| leg.tx),
            Some(B256::repeat_byte(1)),
            "the caller must be told which leg the backstop dropped"
        );
    }

    #[test]
    fn zero_capacity_is_clamped_to_one_rather_than_wedging() {
        let buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 0);
        assert_eq!(buf.capacity(), 1);
    }

    #[test]
    fn remove_takes_out_the_leg_with_a_matching_tx() {
        let t0 = Utc::now();
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        buf.insert(leg_at(t0, 1), t0);
        buf.insert(leg_at(t0, 2), t0);

        let removed = buf.remove(B256::repeat_byte(1)).expect("leg 1 is buffered");
        assert_eq!(removed.tx, B256::repeat_byte(1));
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.iter().next().unwrap().tx, B256::repeat_byte(2));
    }

    #[test]
    fn remove_of_an_unknown_tx_is_a_no_op() {
        let t0 = Utc::now();
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        buf.insert(leg_at(t0, 1), t0);

        assert!(buf.remove(B256::repeat_byte(99)).is_none());
        assert_eq!(
            buf.len(),
            1,
            "an unmatched remove must not disturb the buffer"
        );
    }

    #[test]
    fn candidates_for_returns_only_legs_sharing_the_key() {
        let t0 = Utc::now();
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        buf.insert(leg_with_key(t0, 1, 7), t0);
        buf.insert(leg_with_key(t0, 2, 7), t0);
        buf.insert(leg_with_key(t0, 3, 8), t0);

        let matches: Vec<B256> = buf
            .candidates_for(Address::repeat_byte(7))
            .map(|leg| leg.tx)
            .collect();
        assert_eq!(matches.len(), 2);
        assert!(matches.contains(&B256::repeat_byte(1)));
        assert!(matches.contains(&B256::repeat_byte(2)));
    }

    #[test]
    fn candidates_for_an_absent_key_is_empty() {
        let t0 = Utc::now();
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        buf.insert(leg_with_key(t0, 1, 7), t0);
        assert_eq!(buf.candidates_for(Address::repeat_byte(99)).count(), 0);
    }

    #[test]
    fn the_index_stays_consistent_after_a_remove() {
        let t0 = Utc::now();
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        buf.insert(leg_with_key(t0, 1, 7), t0);
        buf.remove(B256::repeat_byte(1));
        assert_eq!(buf.candidates_for(Address::repeat_byte(7)).count(), 0);
    }

    #[test]
    fn the_index_stays_consistent_after_window_eviction() {
        let t0 = Utc::now();
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        buf.insert(leg_with_key(t0, 1, 7), t0);
        let _ = buf.evict_expired(t0 + TimeDelta::minutes(11));
        assert_eq!(buf.candidates_for(Address::repeat_byte(7)).count(), 0);
    }

    #[test]
    fn the_index_stays_consistent_after_capacity_eviction() {
        let t0 = Utc::now();
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 1);
        buf.insert(leg_with_key(t0, 1, 7), t0);
        buf.insert(leg_with_key(t0, 2, 8), t0); // evicts leg 1 via the backstop
        assert_eq!(buf.candidates_for(Address::repeat_byte(7)).count(), 0);
        assert_eq!(buf.candidates_for(Address::repeat_byte(8)).count(), 1);
    }

    #[test]
    fn seed_restores_legs_in_observation_order_regardless_of_input_order() {
        let t0 = Utc::now();
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        // Fed out of order — `seed` must sort by `observed_at` itself.
        buf.seed(vec![
            leg_at(t0 + TimeDelta::seconds(2), 2),
            leg_at(t0, 1),
            leg_at(t0 + TimeDelta::seconds(1), 3),
        ]);
        let txs: Vec<B256> = buf.iter().map(|leg| leg.tx).collect();
        assert_eq!(
            txs,
            vec![
                B256::repeat_byte(1),
                B256::repeat_byte(3),
                B256::repeat_byte(2)
            ]
        );
    }

    #[test]
    fn seed_respects_the_capacity_backstop() {
        let t0 = Utc::now();
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 2);
        buf.seed(vec![leg_at(t0, 1), leg_at(t0, 2), leg_at(t0, 3)]);
        assert_eq!(buf.len(), 2, "seed must not exceed the hard capacity");
        let txs: Vec<B256> = buf.iter().map(|leg| leg.tx).collect();
        assert_eq!(
            txs,
            vec![B256::repeat_byte(2), B256::repeat_byte(3)],
            "the oldest-observed leg is the one dropped"
        );
    }

    #[test]
    fn seed_keeps_the_index_usable() {
        let t0 = Utc::now();
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        buf.seed(vec![leg_with_key(t0, 1, 7)]);
        assert_eq!(buf.candidates_for(Address::repeat_byte(7)).count(), 1);
    }
}
