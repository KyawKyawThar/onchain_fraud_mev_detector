//! Lead-time-to-actual-liquidation tracking (§16.4/§19, Sprint 16 task 4) —
//! how much runway a `LiquidationRiskPredicted` forecast actually gave before
//! the position it warned about was really liquidated on-chain.
//! `main.rs::run_cascade` records a prediction the moment it publishes one;
//! `position_consumer.rs::on_canonicalized` consumes it the moment it folds a
//! real `LendingEvent::Liquidation` for the same key — the pairing is what
//! the §19 "lead-time-to-actual-liquidation" accuracy signal measures
//! (`crate::metrics::record_liquidation_lead_time`).
//!
//! A dedicated, `Arc<Mutex<_>>`-shared struct rather than folding this into
//! [`crate::cascade::CascadeEngine`] itself: that engine's whole design is a
//! pure, I/O-free state fold (its own module docs) so it stays unit-tested
//! without a live clock — this tracker is the one place in the cascade path
//! that actually reads wall-clock time, kept out of the pure core the same
//! way `main.rs` keeps Kafka/RPC I/O out of `predict`/`cascade`/`reflexivity`.

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use crate::position::PositionKey;

/// Remembers when each `(protocol, account)` was last forecast at risk, so a
/// later real liquidation for the same key can report how much warning it
/// got.
#[derive(Debug, Default)]
pub struct LeadTimeTracker {
    predicted_at: HashMap<PositionKey, DateTime<Utc>>,
}

impl LeadTimeTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `key` was just forecast at risk, at `at`. Overwrites any
    /// earlier prediction for the same key — only the most recent warning's
    /// lead time is meaningful, since an account can cross into a worse band
    /// more than once before it's actually liquidated.
    pub fn record_prediction(&mut self, key: PositionKey, at: DateTime<Utc>) {
        self.predicted_at.insert(key, at);
    }

    /// Consume the prediction recorded for `key`, if any, returning how long
    /// ago it fired relative to `at` (a real liquidation's observed time).
    /// `None` means either no risk warning preceded this liquidation (a
    /// "surprise" the cascade engine never flagged) **or** `at` precedes the
    /// recorded prediction — `std::time::Duration` can't represent a negative
    /// span, so a clock-skew edge case collapses into the same "unpredicted"
    /// signal downstream ([`crate::metrics::record_liquidation_lead_time`])
    /// rather than being silently clamped to zero. Accepted: `record_prediction`
    /// and `take_lead_time` are always called from tasks sharing one process's
    /// clock (`main.rs`/`position_consumer.rs`), so `at < predicted_at` is
    /// practically unreachable — this is "make the invariant unrepresentable"
    /// over "defend against it downstream," not a real accuracy loss.
    ///
    /// Removes the entry either way (see below), so a later liquidation of
    /// the same account needs a fresh prediction to report a lead time again.
    pub fn take_lead_time(
        &mut self,
        key: &PositionKey,
        at: DateTime<Utc>,
    ) -> Option<std::time::Duration> {
        let predicted_at = self.predicted_at.remove(key)?;
        (at - predicted_at).to_std().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::position::Protocol;
    use alloy_primitives::Address;

    fn key() -> PositionKey {
        PositionKey {
            protocol: Protocol::Aave,
            account: Address::repeat_byte(0x11),
        }
    }

    #[test]
    fn a_liquidation_with_no_prior_prediction_reports_none() {
        let mut tracker = LeadTimeTracker::new();
        assert!(tracker.take_lead_time(&key(), Utc::now()).is_none());
    }

    #[test]
    fn a_liquidation_after_a_prediction_reports_the_elapsed_time() {
        let mut tracker = LeadTimeTracker::new();
        let predicted_at = Utc::now();
        tracker.record_prediction(key(), predicted_at);

        let liquidated_at = predicted_at + chrono::Duration::seconds(90);
        let lead_time = tracker.take_lead_time(&key(), liquidated_at).unwrap();
        assert_eq!(lead_time.as_secs(), 90);
    }

    /// `std::time::Duration` can't represent a negative span, so `at`
    /// preceding `predicted_at` (a clock-skew edge case, not reachable in
    /// production since both callers share one process's clock) collapses
    /// into `None` — but the entry must still be consumed, not leaked.
    #[test]
    fn a_liquidation_observed_before_its_prediction_is_none_but_still_consumes_the_entry() {
        let mut tracker = LeadTimeTracker::new();
        let predicted_at = Utc::now();
        tracker.record_prediction(key(), predicted_at);

        let liquidated_at = predicted_at - chrono::Duration::seconds(5);
        assert!(tracker.take_lead_time(&key(), liquidated_at).is_none());
        assert!(
            tracker.predicted_at.is_empty(),
            "the entry must be consumed even when the duration doesn't convert"
        );
    }

    #[test]
    fn taking_a_lead_time_consumes_it_so_a_later_liquidation_reports_none() {
        let mut tracker = LeadTimeTracker::new();
        let predicted_at = Utc::now();
        tracker.record_prediction(key(), predicted_at);
        assert!(tracker.take_lead_time(&key(), predicted_at).is_some());
        assert!(
            tracker.take_lead_time(&key(), predicted_at).is_none(),
            "the prediction was consumed by the first liquidation"
        );
    }

    #[test]
    fn a_fresh_prediction_overwrites_an_earlier_one_for_the_same_key() {
        let mut tracker = LeadTimeTracker::new();
        let first = Utc::now();
        tracker.record_prediction(key(), first);
        let second = first + chrono::Duration::seconds(30);
        tracker.record_prediction(key(), second);

        let liquidated_at = second + chrono::Duration::seconds(10);
        let lead_time = tracker.take_lead_time(&key(), liquidated_at).unwrap();
        assert_eq!(
            lead_time.as_secs(),
            10,
            "measured from the latest prediction, not the first"
        );
    }

    #[test]
    fn different_keys_track_independently() {
        let mut tracker = LeadTimeTracker::new();
        let account_a = PositionKey {
            protocol: Protocol::Aave,
            account: Address::repeat_byte(0x11),
        };
        let account_b = PositionKey {
            protocol: Protocol::Aave,
            account: Address::repeat_byte(0x22),
        };
        let at = Utc::now();
        tracker.record_prediction(account_a, at);

        assert!(
            tracker.take_lead_time(&account_b, at).is_none(),
            "no prediction was recorded for account_b"
        );
        assert!(
            tracker.take_lead_time(&account_a, at).is_some(),
            "account_a's prediction is untouched by account_b's lookup"
        );
    }
}
