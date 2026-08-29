//! The retry *policy*, separated from the retry *loop* so both are testable
//! on their own: [`Backoff::decide`] is a pure function of (attempt number,
//! server-supplied `retry-after`), and the loop that obeys it belongs to the
//! caller (the LLM seam's `RetryingClient` is the first).
//!
//! Two properties that this workspace's hand-rolled backoff loops
//! (`notification::http_delivery`, `notification::email_delivery`,
//! `rule_engine::webhook`) do not have, and that a call to a rate-limited
//! third party cannot ship without:
//!
//! # Jitter, because N pods retry in lockstep otherwise
//!
//! A deterministic doubling backoff synchronises every replica that was hit by
//! the same rate-limit wave: they all sleep the same 2s, all retry in the same
//! millisecond, and all get 429'd again. The retry storm *is* the outage. This
//! uses **equal jitter** — half the computed delay, plus a random draw over the
//! other half — which keeps a floor under the wait (full jitter can return
//! ~0ms and hammer a service that just asked for room) while decorrelating the
//! replicas.
//!
//! The jitter source is a small xorshift, not the `rand` crate: this workspace
//! treats every dependency as a decision (conventions §10), and jitter needs
//! decorrelation, not statistical quality or unpredictability. It is seeded
//! per-thread from the clock, so two pods that start in the same second still
//! diverge.
//!
//! # A `retry-after` past the cap is a *hand-back*, not a sleep
//!
//! The provider can legitimately answer `retry-after: 3600`. Sleeping that
//! inside one call parks a worker for an hour — and if the caller is a message
//! consumer, it parks the consumer's partition with it, which is how a rate
//! limit turns into a rebalance loop that re-does (and re-bills) the work.
//!
//! So a wait longer than [`Backoff::retry_after_cap`] returns
//! [`RetryDecision::GiveUp`] instead. The caller should surface that failure
//! still classified as *transient*, so the queue above it — whose clock is
//! minutes-to-hours, not seconds — reschedules the work. **There are two
//! clocks, and this is the boundary between them:** an in-process retry loop
//! exists to ride out a blip, not to wait out a quota.

use std::time::Duration;

/// What the retry loop should do after one failed attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// Sleep this long, then try again.
    Wait(Duration),
    /// Stop. Either the attempt budget is spent, or the provider asked for
    /// longer than this process is willing to hold a worker.
    GiveUp,
}

/// A bounded, jittered exponential-backoff policy.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    first: Duration,
    max: Duration,
    retry_after_cap: Duration,
    attempts: u32,
    jitter: bool,
}

impl Backoff {
    /// * `first` — delay before the second attempt; doubles from there.
    /// * `max` — ceiling on the computed delay (before jitter).
    /// * `retry_after_cap` — the longest server-directed wait this process
    ///   will hold a worker for; past it, hand back to the caller's queue.
    /// * `attempts` — total attempts including the first. Clamped to >= 1.
    pub fn new(first: Duration, max: Duration, retry_after_cap: Duration, attempts: u32) -> Self {
        Self {
            first,
            max,
            retry_after_cap,
            attempts: attempts.max(1),
            jitter: true,
        }
    }

    /// The same policy with jitter switched off — for tests that assert on an
    /// exact delay. Never for production: see the module docs.
    pub fn without_jitter(mut self) -> Self {
        self.jitter = false;
        self
    }

    /// Total attempts, including the first.
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// The longest server-directed wait this policy will sleep through.
    pub fn retry_after_cap(&self) -> Duration {
        self.retry_after_cap
    }

    /// Decide what to do after `attempt` (1-based) has failed.
    ///
    /// `retry_after` is what the provider asked for, when it said. A server's
    /// number always wins over ours *within the cap* — it knows when its
    /// window resets and we are guessing.
    pub fn decide(&self, attempt: u32, retry_after: Option<Duration>) -> RetryDecision {
        if attempt >= self.attempts {
            return RetryDecision::GiveUp;
        }
        match retry_after {
            // Longer than we are willing to hold a worker: hand back.
            Some(wait) if wait > self.retry_after_cap => RetryDecision::GiveUp,
            Some(wait) => RetryDecision::Wait(self.apply_jitter(wait)),
            None => RetryDecision::Wait(self.apply_jitter(self.base_delay(attempt))),
        }
    }

    /// `first * 2^(attempt-1)`, clamped to `max` and saturating rather than
    /// overflowing on a misconfigured attempt count.
    fn base_delay(&self, attempt: u32) -> Duration {
        let shift = attempt.saturating_sub(1).min(16);
        self.first.saturating_mul(1_u32 << shift).min(self.max)
    }

    /// Equal jitter: `d/2 + rand(0, d/2)`.
    fn apply_jitter(&self, delay: Duration) -> Duration {
        if !self.jitter {
            return delay;
        }
        let half = delay / 2;
        half + Duration::from_nanos(next_u64() % (half.as_nanos() as u64).max(1))
    }
}

/// A xorshift64* draw, seeded per thread from the clock.
///
/// Deliberately not `rand`: the requirement is "two replicas do not sleep the
/// same duration", which does not need a statistical generator, and adding a
/// dependency for it would be a supply-chain decision taken for nothing
/// (conventions §10). Nothing security-relevant reads this.
fn next_u64() -> u64 {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u64> = const { Cell::new(0) };
    }
    STATE.with(|state| {
        let mut x = state.get();
        if x == 0 {
            // Seed from the clock, mixed with this thread-local's own address
            // so two threads starting in the same nanosecond still diverge.
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0x9E37_79B9_7F4A_7C15);
            x = nanos ^ (state as *const _ as u64).rotate_left(17);
            x |= 1; // xorshift is degenerate at zero
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        state.set(x);
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Backoff {
        Backoff::new(
            Duration::from_secs(1),
            Duration::from_secs(30),
            Duration::from_secs(30),
            4,
        )
    }

    #[test]
    fn the_delay_doubles_and_then_clamps() {
        let backoff = policy().without_jitter();
        assert_eq!(backoff.base_delay(1), Duration::from_secs(1));
        assert_eq!(backoff.base_delay(2), Duration::from_secs(2));
        assert_eq!(backoff.base_delay(3), Duration::from_secs(4));
        // Clamped at `max`, and a wild attempt number can't overflow.
        assert_eq!(backoff.base_delay(20), Duration::from_secs(30));
        assert_eq!(backoff.base_delay(u32::MAX), Duration::from_secs(30));
    }

    #[test]
    fn the_budget_is_total_attempts_not_retries() {
        let backoff = policy().without_jitter();
        assert_eq!(
            backoff.decide(3, None),
            RetryDecision::Wait(Duration::from_secs(4))
        );
        assert_eq!(backoff.decide(4, None), RetryDecision::GiveUp);
    }

    /// The provider knows when its window resets; we are guessing.
    #[test]
    fn a_server_directed_wait_wins_inside_the_cap() {
        let backoff = policy().without_jitter();
        assert_eq!(
            backoff.decide(1, Some(Duration::from_secs(12))),
            RetryDecision::Wait(Duration::from_secs(12)),
            "12s beats our 1s guess"
        );
    }

    /// The finding this policy exists for: an hour-long `retry-after` must not
    /// park a worker (and, through it, a consumer's partition).
    #[test]
    fn a_wait_past_the_cap_hands_back_instead_of_sleeping() {
        let backoff = policy();
        assert_eq!(
            backoff.decide(1, Some(Duration::from_secs(3_600))),
            RetryDecision::GiveUp
        );
        assert_eq!(
            backoff.decide(1, Some(Duration::from_secs(31))),
            RetryDecision::GiveUp,
            "one second past the cap is still past the cap"
        );
    }

    /// Equal jitter: never below half the delay (so a service that asked for
    /// room gets it), never above it (so the budget stays bounded), and not
    /// the same value twice in a row.
    #[test]
    fn jitter_stays_inside_the_half_window_and_decorrelates() {
        let backoff = policy();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let RetryDecision::Wait(delay) = backoff.decide(2, None) else {
                panic!("attempt 2 of 4 must retry");
            };
            assert!(
                delay >= Duration::from_secs(1) && delay <= Duration::from_secs(2),
                "{delay:?} outside [d/2, d] for d=2s"
            );
            seen.insert(delay);
        }
        assert!(
            seen.len() > 8,
            "64 draws collapsed to {} distinct delays — that is lockstep, not jitter",
            seen.len()
        );
    }
}
