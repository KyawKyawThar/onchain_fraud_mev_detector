//! Resilience decorators over [`FactsSource`] — the screening read path's
//! protection *before* degradation has to answer (§11, readiness Epic D).
//!
//! [`crate::degrade`] decides what to serve when a fresh read is slow or
//! failing. These decide how the fresh read is attempted, and each closes a
//! specific way the SLO breaks at scale:
//!
//! * [`BreakerSource`] — with intelligence persistently slow, every call would
//!   still wait the full fresh budget before a snapshot answers, so the
//!   endpoint serves customers but its p50 sits *above* the < 100ms contract
//!   for the whole incident. Open, the breaker fails immediately and the
//!   snapshot answers in one Redis read; it also stops hammering intelligence
//!   while it is struggling.
//! * [`BulkheadSource`] — caps in-flight fresh reads, so a latency spike in
//!   intelligence cannot turn into unbounded tasks and sockets in the API pod.
//!   Past the cap a call is refused at once (a transient fault), which the
//!   resolver answers from a snapshot or fails closed.
//! * [`HedgedSource`] — the slow tail is often one slow replica. Past the
//!   recent p95, a second read goes to a second channel (a separate HTTP/2
//!   connection, so a different pod behind the ClusterIP or a different
//!   configured endpoint), and the first answer wins. Tail latency is cut with
//!   *fresh* data; staleness stays the last resort. Hedging is capped by a
//!   token budget, so it cannot become a retry storm against an overloaded
//!   dependency.
//! * [`TrackedSource`] + [`AdaptiveBudget`] — a fixed fresh budget is wrong in
//!   both directions depending on the day. The budget follows the recent p99 of
//!   what intelligence is actually doing, clamped to a floor and ceiling.
//!
//! Every decorator is a `FactsSource`, so they compose at the binary
//! (`main.rs`) and the resolver sees one source — the same decorator shape as
//! `inference::ObservedEngine`. Each is tested alone against a scripted source
//! on a paused clock.
//!
//! **Cancellation is an outcome.** When the resolver serves a snapshot it drops
//! the in-flight fresh read. A decorator that only recorded completed calls
//! would never see the slowness that caused the drop — the breaker would stay
//! closed and the tracker would learn intelligence is fast from exactly the
//! calls that were not. Both record on drop.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use events::primitives::AccountAddress;
use intelligence::pb::ScreeningFactsReply;
use resilience::circuit::{BreakerConfig, CircuitBreaker, CircuitState};
use tokio::sync::Semaphore;
use tokio::time::Instant;
use tonic::Status;

use crate::degrade::FactsSource;
use crate::intelligence_client;

/// Gauge: the intelligence breaker's state — `0` closed, `1` half-open, `2`
/// open.
pub const BREAKER_STATE: &str = "screening_intelligence_breaker_state";
/// Counter: fresh reads refused because the breaker was open.
pub const BREAKER_REJECTED_TOTAL: &str = "screening_intelligence_breaker_rejected_total";
/// Counter: fresh reads refused because the bulkhead was full.
pub const BULKHEAD_REJECTED_TOTAL: &str = "screening_bulkhead_rejected_total";
/// Counter: hedging decisions, by `outcome` — `fired` (a second read was
/// sent), `won` (the second read answered first), `skipped_budget` (a hedge
/// was due but the budget was spent).
pub const HEDGES_TOTAL: &str = "screening_hedges_total";
/// Gauge: the fresh budget the resolver is using right now, in seconds.
pub const FRESH_BUDGET_SECONDS: &str = "screening_fresh_budget_seconds";

/// How much history one [`LatencyTracker`] window holds. With two windows
/// read together the budget follows between 30s and 60s of intelligence
/// latency: long enough that one slow second does not move it, short enough to
/// follow an incident as it starts.
pub const LATENCY_WINDOW: Duration = Duration::from_secs(30);
/// Samples a tracker needs before its quantiles count. Below this the adaptive
/// budget uses its ceiling and hedging its maximum delay — no evidence, no
/// tightening.
pub const LATENCY_MIN_SAMPLES: u64 = 50;
/// The quantile the adaptive fresh budget follows.
pub const BUDGET_QUANTILE: f64 = 0.99;
/// The earliest a hedge may fire: below this the second request is load, not
/// tail-cutting.
pub const HEDGE_MIN_DELAY: Duration = Duration::from_millis(10);
/// Hedges that may fire back-to-back before the ratio limits them.
pub const HEDGE_BURST: f64 = 10.0;

// ── Circuit breaker ───────────────────────────────────────────────

/// Breaker over a [`FactsSource`], counting **slow** calls as failures.
///
/// A read that answers after `slow_call` counts against the breaker even
/// though it succeeded: for this endpoint a late answer is an SLO failure, and
/// a breaker that only counts errors stays closed through exactly the incident
/// it exists for. A *permanent* error (`NotFound`, `Internal`) counts as a
/// success — intelligence answered, and that is not a health problem.
pub struct BreakerSource {
    inner: Arc<dyn FactsSource>,
    breaker: CircuitBreaker,
    slow_call: Duration,
}

impl BreakerSource {
    pub fn new(inner: Arc<dyn FactsSource>, config: BreakerConfig, slow_call: Duration) -> Self {
        let source = Self {
            inner,
            breaker: CircuitBreaker::new(config),
            slow_call,
        };
        source.publish_state();
        source
    }

    fn now() -> std::time::Instant {
        // The tokio clock, not `std`: under a paused test runtime the breaker's
        // cooldown advances with the scripted time.
        Instant::now().into_std()
    }

    fn publish_state(&self) {
        let state = match self.breaker.state(Self::now()) {
            CircuitState::Closed => 0.0,
            CircuitState::HalfOpen => 1.0,
            CircuitState::Open => 2.0,
        };
        metrics::gauge!(BREAKER_STATE).set(state);
    }

    pub fn state(&self) -> CircuitState {
        self.breaker.state(Self::now())
    }
}

/// Records exactly one outcome per admitted call — on completion, or on drop
/// if the caller gave up first.
struct BreakerCall<'a> {
    source: &'a BreakerSource,
    started: Instant,
    settled: bool,
}

impl BreakerCall<'_> {
    fn settle(&mut self, result: &Result<ScreeningFactsReply, Status>) {
        self.settled = true;
        let slow = self.started.elapsed() >= self.source.slow_call;
        let healthy = match result {
            Ok(_) => !slow,
            Err(status) => !intelligence_client::is_transient(status),
        };
        if healthy {
            self.source.breaker.on_success();
        } else {
            self.source.breaker.on_failure(BreakerSource::now());
        }
        self.source.publish_state();
    }
}

impl Drop for BreakerCall<'_> {
    fn drop(&mut self) {
        // Abandoned before it answered. Only a call that was already slow is
        // evidence against intelligence; one cancelled early (a client hang-up)
        // says nothing about it.
        if !self.settled && self.started.elapsed() >= self.source.slow_call {
            self.source.breaker.on_failure(BreakerSource::now());
            self.source.publish_state();
        }
    }
}

#[async_trait]
impl FactsSource for BreakerSource {
    async fn screening_facts(
        &self,
        address: AccountAddress,
    ) -> Result<ScreeningFactsReply, Status> {
        if !self.breaker.allows(Self::now()) {
            metrics::counter!(BREAKER_REJECTED_TOTAL).increment(1);
            self.publish_state();
            return Err(Status::unavailable("intelligence circuit breaker is open"));
        }
        let mut call = BreakerCall {
            source: self,
            started: Instant::now(),
            settled: false,
        };
        let result = self.inner.screening_facts(address).await;
        call.settle(&result);
        result
    }
}

// ── Bulkhead ──────────────────────────────────────────────────────

/// Caps concurrent fresh reads. Refuses immediately past the cap rather than
/// queueing: a queue in front of a slow dependency is the latency this whole
/// module exists to bound.
pub struct BulkheadSource {
    inner: Arc<dyn FactsSource>,
    permits: Arc<Semaphore>,
}

impl BulkheadSource {
    pub fn new(inner: Arc<dyn FactsSource>, max_in_flight: usize) -> Self {
        Self {
            inner,
            permits: Arc::new(Semaphore::new(max_in_flight)),
        }
    }
}

#[async_trait]
impl FactsSource for BulkheadSource {
    async fn screening_facts(
        &self,
        address: AccountAddress,
    ) -> Result<ScreeningFactsReply, Status> {
        let Ok(_permit) = self.permits.try_acquire() else {
            metrics::counter!(BULKHEAD_REJECTED_TOTAL).increment(1);
            return Err(Status::resource_exhausted(
                "screening bulkhead is full: too many in-flight intelligence reads",
            ));
        };
        self.inner.screening_facts(address).await
    }
}

// ── Latency tracking + adaptive budget ────────────────────────────

/// Recent fresh-read latency, as a two-window histogram over the shared latency
/// ladder: samples land in `current`, and every `window` the current window
/// becomes `previous`. A quantile reads both, so it always covers between one
/// and two windows of history — recent enough to follow an incident, long
/// enough not to swing on a handful of calls.
pub struct LatencyTracker {
    window: Duration,
    min_samples: u64,
    state: Mutex<TrackerState>,
}

struct TrackerState {
    current: Vec<u64>,
    previous: Vec<u64>,
    rotated_at: Instant,
}

impl LatencyTracker {
    pub fn new(window: Duration, min_samples: u64) -> Self {
        let slots = telemetry::metrics::LATENCY_BUCKETS_SECONDS.len() + 1;
        Self {
            window,
            min_samples,
            state: Mutex::new(TrackerState {
                current: vec![0; slots],
                previous: vec![0; slots],
                rotated_at: Instant::now(),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, TrackerState> {
        // A panic while holding this lock cannot leave the counts invalid (every
        // mutation is a single increment or a swap), so poisoning is recovered
        // rather than latched — a tracker that stopped tracking would silently
        // pin the budget (§15).
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.rotated_at.elapsed() >= self.window {
            let slots = state.current.len();
            let current = std::mem::replace(&mut state.current, vec![0; slots]);
            state.previous = current;
            state.rotated_at = Instant::now();
        }
        state
    }

    /// A read that answered after `elapsed`.
    pub fn record(&self, elapsed: Duration) {
        let ladder = telemetry::metrics::LATENCY_BUCKETS_SECONDS;
        let seconds = elapsed.as_secs_f64();
        let slot = ladder
            .iter()
            .position(|bound| seconds <= *bound)
            .unwrap_or(ladder.len());
        self.lock().current[slot] += 1;
    }

    /// A read that never answered — abandoned, or failed with a deadline-class
    /// fault. Its true latency is unknown but at least what was observed, so it
    /// counts above the ladder: under persistent slowness the quantile has to
    /// *rise*, and samples censored at the budget would pin it there.
    pub fn record_unanswered(&self) {
        let mut state = self.lock();
        let overflow = state.current.len() - 1;
        state.current[overflow] += 1;
    }

    /// The smallest ladder bound at or below which at least `q` of recent reads
    /// answered. `None` with too few samples to say, and `Some(None)` when the
    /// quantile is above the ladder (unanswered reads dominate).
    pub fn quantile_upper_bound(&self, q: f64) -> Option<Option<Duration>> {
        let state = self.lock();
        let counts: Vec<u64> = state
            .current
            .iter()
            .zip(&state.previous)
            .map(|(a, b)| a + b)
            .collect();
        drop(state);
        let total: u64 = counts.iter().sum();
        if total < self.min_samples {
            return None;
        }
        let needed = (q * total as f64).ceil() as u64;
        let mut cumulative = 0;
        for (bound, count) in telemetry::metrics::LATENCY_BUCKETS_SECONDS
            .iter()
            .zip(&counts)
        {
            cumulative += count;
            if cumulative >= needed {
                return Some(Some(Duration::from_secs_f64(*bound)));
            }
        }
        Some(None)
    }
}

/// Wraps a source and feeds a [`LatencyTracker`] with every outcome.
pub struct TrackedSource {
    inner: Arc<dyn FactsSource>,
    tracker: Arc<LatencyTracker>,
}

impl TrackedSource {
    pub fn new(inner: Arc<dyn FactsSource>, tracker: Arc<LatencyTracker>) -> Self {
        Self { inner, tracker }
    }
}

struct TrackedCall<'a> {
    tracker: &'a LatencyTracker,
    settled: bool,
}

impl Drop for TrackedCall<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.tracker.record_unanswered();
        }
    }
}

#[async_trait]
impl FactsSource for TrackedSource {
    async fn screening_facts(
        &self,
        address: AccountAddress,
    ) -> Result<ScreeningFactsReply, Status> {
        let started = Instant::now();
        let mut call = TrackedCall {
            tracker: &self.tracker,
            settled: false,
        };
        let result = self.inner.screening_facts(address).await;
        call.settled = true;
        match &result {
            Ok(_) => self.tracker.record(started.elapsed()),
            Err(status) if reason_is_deadline(status) => self.tracker.record_unanswered(),
            // Refusals and permanent faults answer fast and say nothing about
            // how long a real read takes.
            Err(_) => {}
        }
        result
    }
}

fn reason_is_deadline(status: &Status) -> bool {
    matches!(
        status.code(),
        tonic::Code::DeadlineExceeded | tonic::Code::Cancelled
    )
}

/// The fresh budget, following recent intelligence latency.
///
/// `budget = clamp(recent p-quantile, floor, ceiling)`. Too few samples, or a
/// quantile above the ladder, yields the **ceiling**: with no evidence the
/// conservative choice is to wait longer and serve fewer stale answers.
///
/// The ladder is coarse (…, 50ms, 100ms, 250ms, …), so the budget moves in
/// steps rather than continuously. That is deliberate: a budget that tracked
/// every millisecond of jitter would make which requests are served stale
/// arbitrary, and the step boundaries are the same ones every latency alert and
/// load-test gate is decided on.
#[derive(Clone)]
pub struct AdaptiveBudget {
    tracker: Arc<LatencyTracker>,
    quantile: f64,
    floor: Duration,
    ceiling: Duration,
}

impl AdaptiveBudget {
    pub fn new(
        tracker: Arc<LatencyTracker>,
        quantile: f64,
        floor: Duration,
        ceiling: Duration,
    ) -> Self {
        assert!(floor <= ceiling, "fresh budget floor above its ceiling");
        Self {
            tracker,
            quantile,
            floor,
            ceiling,
        }
    }

    pub fn current(&self) -> Duration {
        let budget = match self.tracker.quantile_upper_bound(self.quantile) {
            Some(Some(bound)) => bound.clamp(self.floor, self.ceiling),
            _ => self.ceiling,
        };
        metrics::gauge!(FRESH_BUDGET_SECONDS).set(budget.as_secs_f64());
        budget
    }
}

// ── Hedging ───────────────────────────────────────────────────────

/// A token bucket that lets hedges be at most `ratio` of requests (plus a small
/// burst). Every request deposits `ratio`; every hedge spends one.
pub struct HedgeBudget {
    ratio: f64,
    burst: f64,
    tokens: Mutex<f64>,
}

impl HedgeBudget {
    pub fn new(ratio: f64, burst: f64) -> Self {
        Self {
            ratio,
            burst,
            tokens: Mutex::new(burst),
        }
    }

    fn deposit(&self) {
        let mut tokens = self.tokens.lock().unwrap_or_else(|p| p.into_inner());
        *tokens = (*tokens + self.ratio).min(self.burst);
    }

    fn try_spend(&self) -> bool {
        let mut tokens = self.tokens.lock().unwrap_or_else(|p| p.into_inner());
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Sends a second, identical read to `secondary` once the primary has been
/// out longer than the recent p95, and returns whichever answers first.
///
/// Safe only because `GetScreeningFacts` is a pure read. The loser is dropped,
/// which cancels its RPC.
pub struct HedgedSource {
    primary: Arc<dyn FactsSource>,
    secondary: Arc<dyn FactsSource>,
    tracker: Arc<LatencyTracker>,
    min_delay: Duration,
    max_delay: Duration,
    budget: HedgeBudget,
}

impl HedgedSource {
    pub fn new(
        primary: Arc<dyn FactsSource>,
        secondary: Arc<dyn FactsSource>,
        tracker: Arc<LatencyTracker>,
        min_delay: Duration,
        max_delay: Duration,
        budget: HedgeBudget,
    ) -> Self {
        Self {
            primary,
            secondary,
            tracker,
            min_delay,
            max_delay,
            budget,
        }
    }

    /// The recent p95, clamped; the maximum without enough evidence, so a cold
    /// pod does not hedge everything.
    fn delay(&self) -> Duration {
        match self.tracker.quantile_upper_bound(0.95) {
            Some(Some(p95)) => p95.clamp(self.min_delay, self.max_delay),
            _ => self.max_delay,
        }
    }
}

#[async_trait]
impl FactsSource for HedgedSource {
    async fn screening_facts(
        &self,
        address: AccountAddress,
    ) -> Result<ScreeningFactsReply, Status> {
        self.budget.deposit();
        let primary = self.primary.screening_facts(address);
        tokio::pin!(primary);

        tokio::select! {
            biased;
            result = &mut primary => return result,
            () = tokio::time::sleep(self.delay()) => {}
        }

        if !self.budget.try_spend() {
            metrics::counter!(HEDGES_TOTAL, "outcome" => "skipped_budget").increment(1);
            return primary.await;
        }
        metrics::counter!(HEDGES_TOTAL, "outcome" => "fired").increment(1);

        let secondary = self.secondary.screening_facts(address);
        tokio::pin!(secondary);
        tokio::select! {
            biased;
            result = &mut primary => match result {
                // A transient failure of one leg is not the answer while the
                // other can still give one.
                Err(status) if intelligence_client::is_transient(&status) => secondary.await,
                settled => settled,
            },
            result = &mut secondary => match result {
                Err(status) if intelligence_client::is_transient(&status) => primary.await,
                settled => {
                    metrics::counter!(HEDGES_TOTAL, "outcome" => "won").increment(1);
                    settled
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU32, Ordering};

    /// Answers after `after` with `result`, counting calls.
    struct Scripted {
        after: Duration,
        result: Result<ScreeningFactsReply, Status>,
        calls: AtomicU32,
    }

    impl Scripted {
        fn answers(after: Duration, score: u32) -> Arc<Self> {
            Arc::new(Self {
                after,
                result: Ok(ScreeningFactsReply {
                    score,
                    ..Default::default()
                }),
                calls: AtomicU32::new(0),
            })
        }

        fn fails(after: Duration, status: Status) -> Arc<Self> {
            Arc::new(Self {
                after,
                result: Err(status),
                calls: AtomicU32::new(0),
            })
        }

        fn calls(&self) -> u32 {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl FactsSource for Scripted {
        async fn screening_facts(
            &self,
            _address: AccountAddress,
        ) -> Result<ScreeningFactsReply, Status> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.after).await;
            self.result.clone()
        }
    }

    fn address() -> AccountAddress {
        alloy_primitives::Address::repeat_byte(0x11)
    }

    fn breaker_config() -> BreakerConfig {
        BreakerConfig {
            failure_threshold: 3,
            open_cooldown: Duration::from_secs(10),
            success_threshold: 1,
        }
    }

    const SLOW: Duration = Duration::from_millis(150);

    #[tokio::test(start_paused = true)]
    async fn slow_successes_trip_the_breaker_and_an_open_breaker_fails_fast() {
        let inner = Scripted::answers(Duration::from_millis(400), 1);
        let source = BreakerSource::new(inner.clone(), breaker_config(), SLOW);

        for _ in 0..3 {
            assert!(source.screening_facts(address()).await.is_ok());
        }
        assert_eq!(
            source.state(),
            CircuitState::Open,
            "three late answers trip it"
        );

        let started = Instant::now();
        let status = source.screening_facts(address()).await.unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unavailable);
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "open means no wait at all"
        );
        assert_eq!(
            inner.calls(),
            3,
            "an open breaker does not touch intelligence"
        );
    }

    /// The cancellation case: the resolver drops a fresh read to serve a
    /// snapshot. Those drops are the evidence of slowness and must count.
    #[tokio::test(start_paused = true)]
    async fn reads_abandoned_after_the_slow_threshold_count_as_failures() {
        let inner = Scripted::answers(Duration::from_secs(5), 1);
        let source = BreakerSource::new(inner, breaker_config(), SLOW);

        for _ in 0..3 {
            let abandoned = tokio::time::timeout(
                Duration::from_millis(200),
                source.screening_facts(address()),
            )
            .await;
            assert!(abandoned.is_err());
        }
        assert_eq!(source.state(), CircuitState::Open);
    }

    #[tokio::test(start_paused = true)]
    async fn an_early_client_hang_up_is_not_evidence_against_intelligence() {
        let inner = Scripted::answers(Duration::from_secs(5), 1);
        let source = BreakerSource::new(inner, breaker_config(), SLOW);

        for _ in 0..5 {
            let _ =
                tokio::time::timeout(Duration::from_millis(10), source.screening_facts(address()))
                    .await;
        }
        assert_eq!(source.state(), CircuitState::Closed);
    }

    #[tokio::test(start_paused = true)]
    async fn a_permanent_error_is_intelligence_answering_not_failing() {
        let inner = Scripted::fails(Duration::from_millis(1), Status::not_found("x"));
        let source = BreakerSource::new(inner, breaker_config(), SLOW);
        for _ in 0..10 {
            let _ = source.screening_facts(address()).await;
        }
        assert_eq!(source.state(), CircuitState::Closed);
    }

    #[tokio::test(start_paused = true)]
    async fn the_breaker_probes_back_to_closed_after_its_cooldown() {
        let slow = Scripted::fails(Duration::from_millis(1), Status::unavailable("down"));
        let source = BreakerSource::new(slow, breaker_config(), SLOW);
        for _ in 0..3 {
            let _ = source.screening_facts(address()).await;
        }
        assert_eq!(source.state(), CircuitState::Open);

        tokio::time::advance(Duration::from_secs(11)).await;
        assert_eq!(source.state(), CircuitState::HalfOpen);
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_bulkhead_refuses_at_once_with_a_transient_fault() {
        let inner = Scripted::answers(Duration::from_secs(1), 1);
        let source = Arc::new(BulkheadSource::new(inner, 2));

        let held: Vec<_> = (0..2)
            .map(|_| {
                let source = source.clone();
                tokio::spawn(async move { source.screening_facts(address()).await })
            })
            .collect();
        tokio::task::yield_now().await;

        let status = source.screening_facts(address()).await.unwrap_err();
        assert_eq!(status.code(), tonic::Code::ResourceExhausted);
        assert!(intelligence_client::is_transient(&status));

        for task in held {
            assert!(task.await.unwrap().is_ok());
        }
        assert!(
            source.screening_facts(address()).await.is_ok(),
            "permits come back"
        );
    }

    #[test]
    fn the_tracker_needs_evidence_before_it_answers() {
        let tracker = LatencyTracker::new(Duration::from_secs(60), 10);
        for _ in 0..9 {
            tracker.record(Duration::from_millis(20));
        }
        assert_eq!(tracker.quantile_upper_bound(0.99), None);
        tracker.record(Duration::from_millis(20));
        assert_eq!(
            tracker.quantile_upper_bound(0.99),
            Some(Some(Duration::from_millis(25)))
        );
    }

    #[test]
    fn unanswered_reads_push_the_quantile_off_the_ladder() {
        let tracker = LatencyTracker::new(Duration::from_secs(60), 10);
        for _ in 0..90 {
            tracker.record(Duration::from_millis(20));
        }
        for _ in 0..10 {
            tracker.record_unanswered();
        }
        assert_eq!(tracker.quantile_upper_bound(0.99), Some(None));
        assert_eq!(
            tracker.quantile_upper_bound(0.9),
            Some(Some(Duration::from_millis(25)))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_tracker_forgets_after_two_windows() {
        let tracker = LatencyTracker::new(Duration::from_secs(10), 1);
        tracker.record_unanswered();
        tokio::time::advance(Duration::from_secs(11)).await;
        tracker.record(Duration::from_millis(1));
        assert_eq!(
            tracker.quantile_upper_bound(1.0),
            Some(None),
            "one window back still counts"
        );
        tokio::time::advance(Duration::from_secs(11)).await;
        tracker.record(Duration::from_millis(1));
        assert_eq!(
            tracker.quantile_upper_bound(1.0),
            Some(Some(Duration::from_millis(1))),
            "two windows back is forgotten"
        );
    }

    #[test]
    fn the_adaptive_budget_clamps_and_defaults_to_the_ceiling() {
        let tracker = Arc::new(LatencyTracker::new(Duration::from_secs(60), 10));
        let floor = Duration::from_millis(60);
        let ceiling = Duration::from_millis(150);
        let budget = AdaptiveBudget::new(tracker.clone(), 0.99, floor, ceiling);

        assert_eq!(budget.current(), ceiling, "no evidence: wait the longest");
        for _ in 0..100 {
            tracker.record(Duration::from_millis(5));
        }
        assert_eq!(
            budget.current(),
            floor,
            "a fast intelligence cannot push below the floor"
        );
        for _ in 0..100 {
            tracker.record_unanswered();
        }
        assert_eq!(
            budget.current(),
            ceiling,
            "a slow one cannot push past the ceiling"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_tracked_source_records_answers_and_abandonments() {
        let tracker = Arc::new(LatencyTracker::new(Duration::from_secs(60), 2));
        let source = TrackedSource::new(
            Scripted::answers(Duration::from_millis(30), 1),
            tracker.clone(),
        );
        source.screening_facts(address()).await.unwrap();
        let _ = tokio::time::timeout(Duration::from_millis(10), source.screening_facts(address()))
            .await;
        assert_eq!(
            tracker.quantile_upper_bound(0.5),
            Some(Some(Duration::from_millis(50)))
        );
        assert_eq!(
            tracker.quantile_upper_bound(1.0),
            Some(None),
            "the abandoned read counts as slow"
        );
    }

    fn hedged(
        primary: Arc<Scripted>,
        secondary: Arc<Scripted>,
        budget: HedgeBudget,
    ) -> HedgedSource {
        HedgedSource::new(
            primary,
            secondary,
            Arc::new(LatencyTracker::new(Duration::from_secs(60), 1_000_000)),
            Duration::from_millis(20),
            Duration::from_millis(60),
            budget,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_primary_is_raced_by_a_hedge_that_wins() {
        let primary = Scripted::answers(Duration::from_secs(2), 1);
        let secondary = Scripted::answers(Duration::from_millis(10), 2);
        let source = hedged(
            primary.clone(),
            secondary.clone(),
            HedgeBudget::new(0.05, 5.0),
        );
        let started = Instant::now();

        let reply = source.screening_facts(address()).await.unwrap();

        assert_eq!(reply.score, 2);
        assert_eq!(
            started.elapsed(),
            Duration::from_millis(70),
            "hedge delay (60ms, no evidence) + 10ms"
        );
        assert_eq!(secondary.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_fast_primary_never_hedges() {
        let primary = Scripted::answers(Duration::from_millis(5), 1);
        let secondary = Scripted::answers(Duration::from_millis(1), 2);
        let source = hedged(primary, secondary.clone(), HedgeBudget::new(0.05, 5.0));
        assert_eq!(source.screening_facts(address()).await.unwrap().score, 1);
        assert_eq!(secondary.calls(), 0);
    }

    /// The retry-storm guard: once the burst is spent, hedges are limited to the
    /// deposit ratio, however slow the primary is.
    #[tokio::test(start_paused = true)]
    async fn the_hedge_budget_caps_hedges_to_its_ratio() {
        let primary = Scripted::answers(Duration::from_millis(100), 1);
        let secondary = Scripted::answers(Duration::from_millis(100), 2);
        let source = hedged(primary, secondary.clone(), HedgeBudget::new(0.1, 1.0));

        for _ in 0..40 {
            source.screening_facts(address()).await.unwrap();
        }
        let hedges = secondary.calls();
        assert!(
            (4..=6).contains(&hedges),
            "≈10% of 40 plus the burst, got {hedges}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_transient_failure_on_one_leg_waits_for_the_other() {
        let primary = Scripted::fails(Duration::from_millis(70), Status::unavailable("reset"));
        let secondary = Scripted::answers(Duration::from_millis(50), 2);
        let source = hedged(primary, secondary, HedgeBudget::new(0.05, 5.0));
        assert_eq!(source.screening_facts(address()).await.unwrap().score, 2);
    }
}
