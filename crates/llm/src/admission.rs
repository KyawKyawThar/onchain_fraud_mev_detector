//! Admission control: the bulkhead in front of the provider.
//!
//! # Why a per-pod semaphore is not enough, and is still necessary
//!
//! The provider's rate limit is **organisation-wide**. An HPA'd copilot with
//! `N` replicas each allowing `M` in-flight calls admits `N × M`, so a fleet
//! that scales out to absorb a queue backlog scales straight through the
//! limit and converts a capacity problem into a 429 storm it caused itself.
//! Per-pod limits cannot express an org-wide budget — that arithmetic needs a
//! shared counter.
//!
//! Hence a **seam**, not a concrete limiter: [`CallAdmission`] is object-safe,
//! [`LocalAdmission`] is the in-process default that ships here, and a
//! deployment that needs the org-wide budget supplies a Redis-backed
//! implementation from the *service* crate. That split is not a compromise, it
//! is the same one `server::rate_limit::ScreeningRateLimiter` already makes —
//! and it is why arch-conformance can keep `llm` free of a store edge while
//! the distributed policy still exists.
//!
//! The local limiter stays useful either way: it bounds this process's own
//! memory and connection use, and it is the layer that keeps working when
//! Redis is the thing that is down.
//!
//! # Shed, never queue
//!
//! [`try_admit`](CallAdmission::try_admit) fails fast when it cannot admit. An
//! unbounded wait queue is precisely how one caller's burst becomes everyone's
//! latency — the argument Sprint 19 already made when `/similar` got its
//! bulkhead. A shed call comes back as `LlmError::Shed`, which is *transient*
//! (the queue above re-runs it later) but not `retry_now` (the ceiling it hit
//! is still there in 200ms).
//!
//! # Scopes keep the backfill out of the investigator's way
//!
//! Admission is asked per `purpose`, so a historical backfill and an
//! investigator's on-demand draft can hold separate budgets. One shared pool
//! would let a 100k-incident backfill starve the interactive path — the same
//! reason `/similar` and `/screen` were given independent buckets rather than
//! one.
//!
//! # The spend ceiling is a safety valve, not a quota
//!
//! [`LocalAdmission`] can also refuse once a rolling window's token spend
//! passes a ceiling. This is **platform-wide protection against a runaway
//! loop** — a prompt bug at 3am that would otherwise bill until someone wakes
//! up. It is deliberately *not* per-customer: this product meters usage and
//! never gates on it, and a per-customer ceiling here would be request-time
//! quota enforcement by another name. Per-customer spend stays a metering
//! question answered from the `UsageRecorded` stream, with alarms.

use std::sync::Mutex;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::client::{Completion, CompletionRequest, LlmClient, LlmError, TokenUsage};
use crate::metrics::record_admission;

/// Why admission was refused. Both map to `LlmError::Shed` with this as the
/// (bounded, static) metrics reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    /// This process is already at its in-flight ceiling.
    AtCapacity,
    /// The rolling spend window is exhausted.
    SpendCeiling,
}

impl Denied {
    pub fn as_str(self) -> &'static str {
        match self {
            Denied::AtCapacity => "at_capacity",
            Denied::SpendCeiling => "spend_ceiling",
        }
    }
}

/// Permission to make one call, released on drop.
///
/// Concrete rather than a trait object: a local limiter holds a semaphore
/// permit, a distributed one holds nothing (its counter has already moved), and
/// both fit here without a `dyn Any` dance.
#[derive(Debug)]
pub struct Admission(#[allow(dead_code)] Option<OwnedSemaphorePermit>);

impl Admission {
    /// An admission that holds no local resource — what a store-backed
    /// implementation returns.
    pub fn granted() -> Self {
        Self(None)
    }
}

/// The bulkhead seam.
///
/// Object-safe so the stack holds `Arc<dyn CallAdmission>` and a deployment
/// swaps the in-process limiter for a Redis-backed one without anything above
/// noticing.
pub trait CallAdmission: Send + Sync + std::fmt::Debug {
    /// May a call for `purpose` proceed right now?
    fn try_admit(&self, purpose: &'static str) -> Result<Admission, Denied>;

    /// Report what a completed call actually cost, so a spend-aware policy can
    /// see it. Called on success only — a failed call reports no usage.
    fn record_usage(&self, purpose: &'static str, usage: &TokenUsage);
}

/// Admission that never refuses — for tests, and for a deployment that puts
/// the ceiling somewhere else entirely (an egress proxy, a gateway).
#[derive(Debug, Default)]
pub struct UnlimitedAdmission;

impl CallAdmission for UnlimitedAdmission {
    fn try_admit(&self, _purpose: &'static str) -> Result<Admission, Denied> {
        Ok(Admission::granted())
    }

    fn record_usage(&self, _purpose: &'static str, _usage: &TokenUsage) {}
}

/// How [`LocalAdmission`] is sized.
#[derive(Debug, Clone, Copy)]
pub struct AdmissionConfig {
    /// Calls in flight at once from this process.
    pub max_in_flight: usize,
    /// Tokens per [`spend_window`](Self::spend_window) before calls are
    /// refused. `0` disables the ceiling.
    pub spend_ceiling: u64,
    /// The window the ceiling applies over.
    pub spend_window: Duration,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            // Conservative on purpose: this is a *per-pod* number and the
            // provider's limit is org-wide, so the safe default is one that
            // stays under the limit even at a moderate replica count. Raise it
            // deliberately, alongside a shared limiter.
            max_in_flight: 4,
            spend_ceiling: 0,
            spend_window: Duration::from_secs(3_600),
        }
    }
}

/// The in-process bulkhead: a shedding semaphore plus an optional rolling
/// spend ceiling.
#[derive(Debug)]
pub struct LocalAdmission {
    config: AdmissionConfig,
    permits: Arc<Semaphore>,
    spend: Mutex<SpendWindow>,
    /// Cumulative tokens observed, for the boot log and tests. Separate from
    /// the window so a reset never loses the lifetime total.
    observed: AtomicU64,
}

impl LocalAdmission {
    pub fn new(config: AdmissionConfig) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(config.max_in_flight.max(1))),
            spend: Mutex::new(SpendWindow::new(Instant::now())),
            config,
            observed: AtomicU64::new(0),
        }
    }

    /// Calls that could still be admitted right now — for the boot log and for
    /// a saturation gauge.
    pub fn available(&self) -> usize {
        self.permits.available_permits()
    }

    /// Tokens spent in the current window.
    pub fn window_spend(&self) -> u64 {
        let mut window = self.lock();
        window.roll(Instant::now(), self.config.spend_window);
        window.tokens
    }

    /// Lifetime tokens observed by this process.
    pub fn observed_tokens(&self) -> u64 {
        self.observed.load(Ordering::Relaxed)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SpendWindow> {
        self.spend.lock().expect("admission spend mutex poisoned")
    }
}

impl CallAdmission for LocalAdmission {
    fn try_admit(&self, _purpose: &'static str) -> Result<Admission, Denied> {
        // Spend first: it is the cheaper check, and a process past its ceiling
        // should not even consume a permit.
        if self.config.spend_ceiling > 0 {
            let mut window = self.lock();
            window.roll(Instant::now(), self.config.spend_window);
            if window.tokens >= self.config.spend_ceiling {
                return Err(Denied::SpendCeiling);
            }
        }
        self.permits
            .clone()
            .try_acquire_owned()
            .map(|permit| Admission(Some(permit)))
            .map_err(|_| Denied::AtCapacity)
    }

    fn record_usage(&self, _purpose: &'static str, usage: &TokenUsage) {
        let total = usage.total();
        self.observed.fetch_add(total, Ordering::Relaxed);
        if self.config.spend_ceiling > 0 {
            let mut window = self.lock();
            window.roll(Instant::now(), self.config.spend_window);
            window.tokens = window.tokens.saturating_add(total);
        }
    }
}

/// A fixed window of token spend.
///
/// Fixed, not sliding — the same tradeoff `server::rate_limit` documents: a
/// burst straddling a boundary can briefly admit close to 2× the ceiling, and
/// that is fine for a runaway-loop backstop, where the number is an order of
/// magnitude rather than a contract. A sliding window would need a log of
/// every call to be exact, which is a lot of machinery for a safety valve.
#[derive(Debug)]
struct SpendWindow {
    started: Instant,
    tokens: u64,
}

impl SpendWindow {
    fn new(now: Instant) -> Self {
        Self {
            started: now,
            tokens: 0,
        }
    }

    fn roll(&mut self, now: Instant, window: Duration) {
        if now.duration_since(self.started) >= window {
            self.started = now;
            self.tokens = 0;
        }
    }
}

/// Wraps any [`LlmClient`] in a [`CallAdmission`] bulkhead.
///
/// Sits **innermost** in the stack, just above the transport: a permit is held
/// for the HTTP call and released the moment it returns, rather than being
/// occupied by a task that is sleeping out a retry backoff. Putting it outside
/// the retry loop instead would mean in-flight capacity is spent on waiting,
/// which is the opposite of what a bulkhead is for.
#[derive(Debug)]
pub struct AdmittedClient<C> {
    inner: C,
    admission: Arc<dyn CallAdmission>,
}

impl<C: LlmClient> AdmittedClient<C> {
    pub fn new(inner: C, admission: Arc<dyn CallAdmission>) -> Self {
        Self { inner, admission }
    }

    pub fn inner(&self) -> &C {
        &self.inner
    }
}

#[async_trait::async_trait]
impl<C: LlmClient> LlmClient for AdmittedClient<C> {
    fn model(&self) -> &str {
        self.inner.model()
    }

    async fn complete(&self, request: &CompletionRequest) -> Result<Completion, LlmError> {
        let permit = match self.admission.try_admit(request.purpose) {
            Ok(permit) => permit,
            Err(denied) => {
                record_admission(request.purpose, denied.as_str());
                tracing::warn!(
                    purpose = request.purpose,
                    reason = denied.as_str(),
                    "llm call shed by admission control"
                );
                return Err(LlmError::Shed {
                    reason: denied.as_str(),
                });
            }
        };
        record_admission(request.purpose, "admitted");

        let outcome = self.inner.complete(request).await;
        // Only a completed call has token counts to report; a failure tells the
        // spend policy nothing, which is the same honest under-count the
        // metering decorator documents.
        if let Ok(completion) = &outcome {
            self.admission
                .record_usage(request.purpose, &completion.usage);
        }
        drop(permit);
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(tokens: u64) -> TokenUsage {
        TokenUsage {
            input_tokens: tokens,
            ..TokenUsage::default()
        }
    }

    #[test]
    fn the_bulkhead_sheds_instead_of_queueing() {
        let admission = LocalAdmission::new(AdmissionConfig {
            max_in_flight: 2,
            ..AdmissionConfig::default()
        });

        let first = admission.try_admit("narrative").expect("1 of 2");
        let _second = admission.try_admit("narrative").expect("2 of 2");
        assert_eq!(
            admission.try_admit("narrative").expect_err("full"),
            Denied::AtCapacity,
            "a third call must be refused, not parked"
        );

        // A permit released by drop is immediately reusable.
        drop(first);
        assert!(admission.try_admit("narrative").is_ok());
    }

    #[test]
    fn the_spend_ceiling_refuses_once_the_window_is_exhausted() {
        let admission = LocalAdmission::new(AdmissionConfig {
            max_in_flight: 8,
            spend_ceiling: 1_000,
            spend_window: Duration::from_secs(3_600),
        });

        let permit = admission.try_admit("backfill").expect("under ceiling");
        admission.record_usage("backfill", &usage(999));
        drop(permit);
        assert!(
            admission.try_admit("backfill").is_ok(),
            "999 < 1000 is still under"
        );

        admission.record_usage("backfill", &usage(1));
        assert_eq!(
            admission.try_admit("backfill").expect_err("exhausted"),
            Denied::SpendCeiling
        );
        assert_eq!(admission.window_spend(), 1_000);
        assert_eq!(admission.observed_tokens(), 1_000);
    }

    #[test]
    fn a_zero_ceiling_disables_the_spend_check_entirely() {
        let admission = LocalAdmission::new(AdmissionConfig {
            max_in_flight: 1,
            spend_ceiling: 0,
            ..AdmissionConfig::default()
        });
        admission.record_usage("p", &usage(u64::MAX / 2));
        assert!(admission.try_admit("p").is_ok());
        assert_eq!(admission.window_spend(), 0, "nothing is tracked when off");
    }

    /// The window rolls, so a ceiling is a rate and not a lifetime cap — a
    /// process that hit it must recover without a restart.
    #[test]
    fn the_window_rolls_and_the_ceiling_clears() {
        let admission = LocalAdmission::new(AdmissionConfig {
            max_in_flight: 4,
            spend_ceiling: 10,
            spend_window: Duration::from_millis(1),
        });
        admission.record_usage("p", &usage(50));

        // The window is 1ms; by the time the check runs it has rolled.
        std::thread::sleep(Duration::from_millis(3));
        assert!(admission.try_admit("p").is_ok());
        assert_eq!(admission.window_spend(), 0);
        assert_eq!(
            admission.observed_tokens(),
            50,
            "the lifetime total survives a window roll"
        );
    }

    #[test]
    fn unlimited_admission_never_refuses() {
        let admission = UnlimitedAdmission;
        for _ in 0..1_000 {
            assert!(admission.try_admit("p").is_ok());
        }
    }
}
