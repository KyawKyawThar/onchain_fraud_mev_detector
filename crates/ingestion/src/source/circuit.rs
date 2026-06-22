//! A per-endpoint circuit breaker (§5 — the RPC pool is "health-checked,
//! circuit-broken").
//!
//! The classic three-state breaker: while **closed**, calls flow and
//! consecutive failures are counted; once they cross `failure_threshold` the
//! breaker trips **open** and the pool stops routing to the endpoint (failing
//! over to a sibling) so a sick endpoint isn't hammered. After `open_cooldown`
//! it goes **half-open** and admits trial calls; `success_threshold` of them in
//! a row closes it again, while a single failure re-opens it.
//!
//! Time is passed in (`now: Instant`) rather than read from the clock inside, so
//! the state machine is deterministic and unit-testable without sleeping.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Which state the breaker is in. Surfaced for health logging/metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Healthy — calls flow normally.
    Closed,
    /// Tripped — calls are rejected until the cooldown elapses.
    Open,
    /// Cooldown elapsed — admitting trial calls to test recovery.
    HalfOpen,
}

/// Tunables for [`CircuitBreaker`]. Resolved from env in [`crate::config`].
#[derive(Debug, Clone, Copy)]
pub struct BreakerConfig {
    /// Consecutive failures (while closed) that trip the breaker open.
    pub failure_threshold: u32,
    /// How long to stay open before admitting a trial call (half-open).
    pub open_cooldown: Duration,
    /// Consecutive half-open successes needed to close again.
    pub success_threshold: u32,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_cooldown: Duration::from_secs(30),
            success_threshold: 1,
        }
    }
}

#[derive(Debug)]
struct Inner {
    state: CircuitState,
    /// Consecutive failures while closed; consecutive successes while half-open.
    /// (Only one is meaningful at a time, given the current state.)
    run: u32,
    /// When the breaker last opened — drives the cooldown.
    opened_at: Option<Instant>,
}

/// Lock-guarded breaker state. Decisions are synchronous (no `.await` held
/// across the lock), so a `std::sync::Mutex` is correct and contention is
/// trivial (a handful of endpoints).
#[derive(Debug)]
pub struct CircuitBreaker {
    config: BreakerConfig,
    inner: Mutex<Inner>,
}

impl CircuitBreaker {
    pub fn new(config: BreakerConfig) -> Self {
        Self {
            config,
            inner: Mutex::new(Inner {
                state: CircuitState::Closed,
                run: 0,
                opened_at: None,
            }),
        }
    }

    /// Lock the inner state. One place so the poison message can't drift.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("breaker mutex poisoned")
    }

    /// Apply the time-based open→half-open transition in place, if the cooldown
    /// has elapsed. The single source of truth shared by [`allows`](Self::allows)
    /// and [`state`](Self::state) so they can never disagree.
    fn maybe_half_open(&self, g: &mut Inner, now: Instant) {
        if g.state == CircuitState::Open {
            let elapsed = g
                .opened_at
                .map(|t| now.duration_since(t) >= self.config.open_cooldown)
                .unwrap_or(true);
            if elapsed {
                g.state = CircuitState::HalfOpen;
                g.run = 0;
            }
        }
    }

    /// Whether a call may be routed to this endpoint right now. When open, this
    /// also performs the open→half-open transition once the cooldown has
    /// elapsed, so the next call becomes the trial.
    pub fn allows(&self, now: Instant) -> bool {
        let mut g = self.lock();
        self.maybe_half_open(&mut g, now);
        g.state != CircuitState::Open
    }

    /// Record a successful call. Closes a half-open breaker once enough trials
    /// have succeeded; resets the failure run while closed.
    pub fn on_success(&self) {
        let mut g = self.lock();
        match g.state {
            CircuitState::Closed => g.run = 0,
            CircuitState::HalfOpen => {
                g.run += 1;
                if g.run >= self.config.success_threshold {
                    g.state = CircuitState::Closed;
                    g.run = 0;
                    g.opened_at = None;
                }
            }
            // A success while open shouldn't happen (we don't route there), but
            // if it does, treat it like the start of recovery.
            CircuitState::Open => {
                g.state = CircuitState::Closed;
                g.run = 0;
                g.opened_at = None;
            }
        }
    }

    /// Record a failed call. Trips the breaker open on the threshold-th
    /// consecutive failure while closed, and re-opens immediately on a failed
    /// half-open trial.
    pub fn on_failure(&self, now: Instant) {
        let mut g = self.lock();
        match g.state {
            CircuitState::Closed => {
                g.run += 1;
                if g.run >= self.config.failure_threshold {
                    g.state = CircuitState::Open;
                    g.opened_at = Some(now);
                }
            }
            CircuitState::HalfOpen | CircuitState::Open => {
                g.state = CircuitState::Open;
                g.run = 0;
                g.opened_at = Some(now);
            }
        }
    }

    /// Current state, applying the open→half-open transition if the cooldown has
    /// elapsed (so observers see the same view [`allows`](Self::allows) would).
    /// This mutates only the cooldown transition — it never records traffic — so
    /// it stays a faithful query of "what would the next call see?".
    pub fn state(&self, now: Instant) -> CircuitState {
        let mut g = self.lock();
        self.maybe_half_open(&mut g, now);
        g.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn breaker() -> CircuitBreaker {
        CircuitBreaker::new(BreakerConfig {
            failure_threshold: 3,
            open_cooldown: Duration::from_secs(10),
            success_threshold: 2,
        })
    }

    #[test]
    fn opens_after_threshold_consecutive_failures() {
        let b = breaker();
        let t = Instant::now();
        assert!(b.allows(t));
        b.on_failure(t);
        b.on_failure(t);
        // Still closed at 2 < 3 failures.
        assert_eq!(b.state(t), CircuitState::Closed);
        assert!(b.allows(t));
        b.on_failure(t);
        // Third failure trips it.
        assert_eq!(b.state(t), CircuitState::Open);
        assert!(!b.allows(t));
    }

    #[test]
    fn a_success_resets_the_failure_run_while_closed() {
        let b = breaker();
        let t = Instant::now();
        b.on_failure(t);
        b.on_failure(t);
        b.on_success(); // run back to 0
        b.on_failure(t);
        b.on_failure(t);
        // Only 2 consecutive after the reset → still closed.
        assert_eq!(b.state(t), CircuitState::Closed);
    }

    #[test]
    fn half_opens_after_cooldown_then_closes_on_successful_trials() {
        let b = breaker();
        let t0 = Instant::now();
        for _ in 0..3 {
            b.on_failure(t0);
        }
        assert_eq!(b.state(t0), CircuitState::Open);

        // Before cooldown: still open, no routing.
        let t1 = t0 + Duration::from_secs(5);
        assert!(!b.allows(t1));
        assert_eq!(b.state(t1), CircuitState::Open);

        // After cooldown: half-open, trial admitted.
        let t2 = t0 + Duration::from_secs(10);
        assert!(b.allows(t2));
        assert_eq!(b.state(t2), CircuitState::HalfOpen);

        // success_threshold = 2 trials close it.
        b.on_success();
        assert_eq!(b.state(t2), CircuitState::HalfOpen);
        b.on_success();
        assert_eq!(b.state(t2), CircuitState::Closed);
    }

    #[test]
    fn a_failed_half_open_trial_reopens_immediately() {
        let b = breaker();
        let t0 = Instant::now();
        for _ in 0..3 {
            b.on_failure(t0);
        }
        let t1 = t0 + Duration::from_secs(10);
        assert!(b.allows(t1)); // half-open
        b.on_failure(t1);
        assert_eq!(b.state(t1), CircuitState::Open);
        // And the cooldown restarts from t1.
        assert!(!b.allows(t1 + Duration::from_secs(9)));
        assert!(b.allows(t1 + Duration::from_secs(10)));
    }
}
