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

use std::collections::VecDeque;

use chrono::{DateTime, TimeDelta, Utc};

use crate::leg::CandidateLeg;

/// Default hard cap on legs retained per bridge/pair, if a deployment doesn't
/// override it — generous enough that the time window is the binding
/// constraint in normal operation, the same "backstop, not the everyday
/// limit" role `simulation::reorg::DEFAULT_ORPHAN_BLOCK_CAPACITY` plays.
pub const DEFAULT_CANDIDATE_LEG_CAPACITY: usize = 10_000;

/// What [`CandidateLegBuffer::insert`] had to evict to make room, for the
/// caller to log/record — the buffer itself stays silent (see module docs).
#[derive(Debug, Default)]
pub struct InsertOutcome {
    /// How many legs aged out of the window (a normal, expected outcome).
    pub window_evicted: usize,
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
}

impl CandidateLegBuffer {
    pub fn new(window: TimeDelta, capacity: usize) -> Self {
        Self {
            window,
            capacity: capacity.max(1),
            legs: VecDeque::new(),
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

    /// Every currently-buffered leg — the scan Sprint 17 task 2's join logic
    /// reads over to look for a match against a newly-arrived leg.
    pub fn iter(&self) -> impl Iterator<Item = &CandidateLeg> {
        self.legs.iter()
    }

    /// Buffer `leg` as observed at `now`: first evict anything that's aged
    /// out of the window, then — the hard backstop — drop the oldest
    /// remaining entry if still at capacity, so a leg flood can't grow this
    /// buffer without bound regardless of the window setting.
    pub fn insert(&mut self, leg: CandidateLeg, now: DateTime<Utc>) -> InsertOutcome {
        let window_evicted = self.evict_expired(now);
        let capacity_evicted = if self.legs.len() >= self.capacity {
            self.legs.pop_front()
        } else {
            None
        };
        self.legs.push_back(leg);
        InsertOutcome {
            window_evicted,
            capacity_evicted,
        }
    }

    /// Drop every leg older than [`Self::window`] relative to `now` — an
    /// unmatched leg ages out (§24). Called on every insert; also callable on
    /// its own so an idle bridge/pair's buffer doesn't hold stale legs
    /// indefinitely between arrivals. Returns how many were dropped.
    #[must_use]
    pub fn evict_expired(&mut self, now: DateTime<Utc>) -> usize {
        let window = self.window;
        let before = self.legs.len();
        self.legs
            .retain(|leg| now.signed_duration_since(leg.observed_at) <= window);
        before - self.legs.len()
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
        assert_eq!(outcome.window_evicted, 0);
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
        assert_eq!(outcome.window_evicted, 1);
        assert!(outcome.capacity_evicted.is_none());
    }

    #[test]
    fn evict_expired_can_be_called_without_an_insert() {
        let t0 = Utc::now();
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        buf.insert(leg_at(t0, 1), t0);

        let evicted = buf.evict_expired(t0 + TimeDelta::minutes(11));
        assert!(buf.is_empty(), "an idle buffer must still age out its legs");
        assert_eq!(evicted, 1);
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
        assert_eq!(evicted, 1);
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
}
