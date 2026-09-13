//! Orchestration: pre-flight, warm up, offer load, **drain**, measure, judge.
//!
//! The order is the design. Three things go wrong in a load test that have no
//! obvious symptom, and each maps to a step here:
//!
//! 1. **Measuring cold.** JIT, connection pools, partition leader election and
//!    page cache all resolve in the first seconds. Their cost is real but it is
//!    not the steady-state latency the SLO is about, so the measurement window
//!    opens with a *baseline scrape* after warmup and everything before it is
//!    subtracted away rather than merely ignored.
//!
//! 2. **Measuring before the pipeline caught up.** When the load stops, the
//!    blocks still sitting in consumer lag and the work channel have not been
//!    timed yet — and under saturation they are precisely the slowest ones.
//!    Scraping at that instant reports the p99 of the subset that kept up. So
//!    the run [`drain`]s first, and a run that never settles is inconclusive,
//!    not fast.
//!
//! 3. **Measuring a system that was never loaded.** If a driver could not reach
//!    its target rate, a green p99 describes a system at whatever rate it
//!    managed. The achieved-rate gates run alongside the latency verdict and
//!    demote the run to inconclusive.
//!
//! ## Why this module talks to traits
//!
//! Those three steps are the part that, when silently wrong, produces a
//! confidently green run — so they are the part that most needs a test. Behind
//! [`crate::source::LoadSource`] and [`SubjectMetrics`] they can be driven
//! against in-memory doubles: the tests below assert that a pipeline which
//! never settles reports `TimedOut`, that one quiet poll is not a drain, that
//! the baseline really is subtracted, and that a subject restarting mid-run is
//! an error rather than a clamp. None of that was assertable while this
//! function constructed a Kafka producer and a `reqwest::Client` itself.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::gates::{self, RunData};
use crate::profile::Profile;
use crate::report::{Observation, Report};
use crate::scrape::{Exposition, Histogram};
use crate::slo::{Measured, Slo};
use crate::source::LoadSource;

/// One scrape of the subject's fast-path series.
///
/// The load test reads the subject's *own* instrument rather than timing alerts
/// off the broker itself. That is deliberate: a second broker hop would put the
/// harness's own consumer latency inside the number, and §6's span ends at
/// publication. The cost is that the harness cannot detect a mis-calibrated
/// metric — which is why the runbook recommends cross-checking it once per
/// release rather than pretending the question does not exist.
#[async_trait]
pub trait SubjectMetrics: Send + Sync {
    async fn sample(&self) -> Result<FastPathWindow>;
}

/// The four fast-path series, as of one scrape — or, after differencing two
/// scrapes, over the measurement window.
///
/// One type for both, because a window *is* a difference of snapshots. Separate
/// types would invite a verdict computed over a cumulative snapshot, which is
/// the "warmup dilutes the run" bug in a form the compiler would accept.
#[derive(Debug, Clone, Default)]
pub struct FastPathWindow {
    pub alerting: Histogram,
    pub quiet: Histogram,
    pub queue_wait: Histogram,
    pub processing: Histogram,
}

impl FastPathWindow {
    /// This window minus an earlier snapshot.
    pub fn since(&self, baseline: &Self) -> Result<Self> {
        Ok(Self {
            alerting: self.alerting.since(&baseline.alerting)?,
            quiet: self.quiet.since(&baseline.quiet)?,
            queue_wait: self.queue_wait.since(&baseline.queue_wait)?,
            processing: self.processing.since(&baseline.processing)?,
        })
    }

    /// This window plus another replica's — how [`CompositeSubject`] folds a
    /// multi-pod deployment into the one series an SLO is stated over.
    pub fn plus(&self, other: &Self) -> Self {
        Self {
            alerting: self.alerting.plus(&other.alerting),
            quiet: self.quiet.plus(&other.quiet),
            queue_wait: self.queue_wait.plus(&other.queue_wait),
            processing: self.processing.plus(&other.processing),
        }
    }

    /// Every fast-path sample seen, both outcomes — the drain's progress signal
    /// and the accounting gate's numerator.
    pub fn total_samples(&self) -> u64 {
        self.alerting.count + self.quiet.count
    }
}

/// How the drain ended — reported, because "we waited and it settled" and "we
/// gave up waiting" produce very different p99s and must not look alike.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drain {
    /// The fast-path sample count stopped rising within the timeout.
    Settled { waited: Duration },
    /// It was still rising when the timeout expired — the pipeline never caught
    /// up with the offered load, which is itself a finding.
    TimedOut { waited: Duration, observed: u64 },
}

/// How often the drain re-reads the subject.
const DRAIN_POLL: Duration = Duration::from_secs(1);

/// Consecutive polls with no new samples before the pipeline counts as drained.
///
/// Two, not one: a single quiet poll can land in the gap between two blocks at
/// a low block rate and declare a still-backlogged pipeline settled.
const QUIET_POLLS_TO_SETTLE: u32 = 2;

/// The API service's screening counters, as of one scrape — or, differenced,
/// over the measurement window. Plain `f64`s because Prometheus counters are.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ScreeningCounters {
    pub fresh: f64,
    pub stale: f64,
    pub failed_closed: f64,
}

impl ScreeningCounters {
    /// This scrape minus an earlier one. A counter that went *down* means a
    /// replica restarted mid-run, which silently discards its history — an
    /// error, the same stance [`Histogram::since`] takes.
    pub fn since(&self, baseline: &Self) -> Result<Self> {
        let window = Self {
            fresh: self.fresh - baseline.fresh,
            stale: self.stale - baseline.stale,
            failed_closed: self.failed_closed - baseline.failed_closed,
        };
        anyhow::ensure!(
            window.fresh >= 0.0 && window.stale >= 0.0 && window.failed_closed >= 0.0,
            "a screening counter went backwards — an API replica restarted during the run"
        );
        Ok(window)
    }

    fn plus(&self, other: &Self) -> Self {
        Self {
            fresh: self.fresh + other.fresh,
            stale: self.stale + other.stale,
            failed_closed: self.failed_closed + other.failed_closed,
        }
    }

    /// Screening calls that left the fresh path at all.
    pub fn degraded(&self) -> f64 {
        self.stale + self.failed_closed
    }

    /// Of every screening call the service handled, the share that got a
    /// decision (fresh or stale) rather than a fail-closed 502.
    pub fn decided_share(&self) -> Option<f64> {
        let total = self.fresh + self.stale + self.failed_closed;
        (total > 0.0).then(|| (self.fresh + self.stale) / total)
    }

    /// Of the decisions rendered, the share rendered over stale facts.
    pub fn stale_share(&self) -> Option<f64> {
        let decided = self.fresh + self.stale;
        (decided > 0.0).then(|| self.stale / decided)
    }
}

/// Reads the API service's screening counters.
#[async_trait]
pub trait ScreeningMetrics: Send + Sync {
    async fn sample(&self) -> Result<ScreeningCounters>;
}

/// Every API replica's `/metrics`, summed — the same reasoning as
/// [`CompositeSubject`]: the budget is about the deployment, not one pod.
pub struct PrometheusScreeningScrape {
    client: reqwest::Client,
    urls: Vec<String>,
}

impl PrometheusScreeningScrape {
    pub fn new(client: reqwest::Client, urls: &[String]) -> Self {
        Self {
            client,
            urls: urls.to_vec(),
        }
    }
}

#[async_trait]
impl ScreeningMetrics for PrometheusScreeningScrape {
    async fn sample(&self) -> Result<ScreeningCounters> {
        let served = telemetry::metrics::SCREENING_FACTS_SERVED_TOTAL;
        let degraded = telemetry::metrics::SCREENING_DEGRADED_TOTAL;
        let mut total = ScreeningCounters::default();
        for url in &self.urls {
            let body = self
                .client
                .get(url)
                .send()
                .await
                .with_context(|| format!("scraping {url}"))?
                .error_for_status()
                .with_context(|| format!("{url} returned an error status"))?
                .text()
                .await
                .context("reading the API metrics body")?;
            let exposition = Exposition::parse(&body);
            total = total.plus(&ScreeningCounters {
                fresh: exposition.counter(served, &[("freshness", "fresh")]),
                stale: exposition.counter(served, &[("freshness", "stale")]),
                failed_closed: exposition.counter(degraded, &[("outcome", "failed_closed")]),
            });
        }
        Ok(total)
    }
}

/// Instruments a run may carry beyond the fast path. Default is none of them —
/// what [`run`] passes.
#[derive(Default)]
pub struct RunExtras<'a> {
    /// The fault proxy the subject's intelligence traffic passes through.
    pub fault: Option<&'a crate::fault::LatencyProxy>,
    /// The API service's screening counters.
    pub screening: Option<&'a dyn ScreeningMetrics>,
}

/// Run the whole procedure and return the report.
///
/// Never treats an unreachable subject as a pass: the pre-flight scrape fails
/// the run before any load is offered, so a harness pointed at the wrong
/// address says so instead of spending its full duration producing traffic it
/// can never measure and reporting the empty histogram as merely inconclusive.
pub async fn run(
    profile: &Profile,
    slo: &Slo,
    sources: &[Arc<dyn LoadSource>],
    metrics: &dyn SubjectMetrics,
    shutdown: CancellationToken,
) -> Result<Report> {
    run_with(
        profile,
        slo,
        sources,
        metrics,
        RunExtras::default(),
        shutdown,
    )
    .await
}

/// [`run`], with the degraded-mode instruments.
///
/// The fault is switched on **when the measurement window opens** and off when
/// the load stops: warmup runs against a healthy intelligence so the subject has
/// the snapshots, sanctions view and latency history production would have when
/// an incident begins. A profile that declares a fault without a proxy to
/// inject it is refused before any load is offered — the alternative is a run
/// that measures a healthy system and reports it under the fault's name.
pub async fn run_with(
    profile: &Profile,
    slo: &Slo,
    sources: &[Arc<dyn LoadSource>],
    metrics: &dyn SubjectMetrics,
    extras: RunExtras<'_>,
    shutdown: CancellationToken,
) -> Result<Report> {
    anyhow::ensure!(
        profile.fault.is_none() || extras.fault.is_some(),
        "profile `{}` injects a fault but no fault proxy is configured — set \
         LOADTEST_INTELLIGENCE_PROXY_LISTEN and LOADTEST_INTELLIGENCE_UPSTREAM, and point \
         the subject's INTELLIGENCE_GRPC_ADDR at the proxy",
        profile.name
    );
    if let Some(screening) = extras.screening {
        screening
            .sample()
            .await
            .context("pre-flight read of the API service's screening counters")?;
    }
    metrics
        .sample()
        .await
        .context("pre-flight read of the subject's fast-path metrics")?;

    // Warmup and measurement are one continuous stream of load with a scrape in
    // the middle: stopping and restarting the drivers would let the queue drain
    // and measure a pipeline that had just been idle.
    // One clock, owned here and handed to every source, so a shortened or
    // cancelled run shortens all of them together (see [`Window`]).
    let window = profile.window();

    let mut running = tokio::task::JoinSet::new();
    for source in sources {
        let (source, shutdown) = (Arc::clone(source), shutdown.clone());
        running.spawn(async move { source.offer(window, shutdown).await });
    }

    tokio::time::sleep(window.warmup).await;
    let baseline = metrics
        .sample()
        .await
        .context("reading the subject at the start of the measurement window")?;
    let screening_baseline = match extras.screening {
        Some(screening) => Some(
            screening
                .sample()
                .await
                .context("reading the screening counters at the start of the window")?,
        ),
        None => None,
    };
    if let (Some(proxy), Some(fault)) = (extras.fault, profile.fault) {
        proxy.set_delay(Duration::from_millis(fault.intelligence_latency_ms));
        tracing::info!(
            latency_ms = fault.intelligence_latency_ms,
            "intelligence fault injected for the measurement window"
        );
    }
    tracing::info!(
        warmup_secs = window.warmup.as_secs(),
        duration_secs = window.duration.as_secs(),
        "warmup complete; measurement window open"
    );

    let mut offered = Vec::with_capacity(sources.len());
    while let Some(joined) = running.join_next().await {
        offered.push(joined.context("a load source panicked")??);
    }
    // Report order follows the configured order, not completion order, so two
    // runs of one profile render the same.
    offered.sort_by_key(|load| {
        sources
            .iter()
            .position(|s| s.name() == load.source)
            .unwrap_or(usize::MAX)
    });

    // The API load has stopped, so its window is closed: read the counters now,
    // then lift the fault so the drain is not measuring it.
    let screening = match (extras.screening, screening_baseline) {
        (Some(screening), Some(baseline)) => Some(
            screening
                .sample()
                .await
                .context("reading the screening counters at the close of the window")?
                .since(&baseline)?,
        ),
        _ => None,
    };
    if let Some(proxy) = extras.fault {
        proxy.set_delay(Duration::ZERO);
    }

    let drained = drain(metrics, profile.drain_timeout).await?;
    let measured = metrics
        .sample()
        .await
        .context("reading the subject at the close of the measurement window")?
        .since(&baseline)
        .context("differencing the closing read against the measurement window's baseline")?;

    let data = RunData {
        profile,
        slo,
        offered: &offered,
        window: &measured,
        window_share: window.measured_share(),
        drain: &drained,
        screening: screening.as_ref(),
    };

    Ok(Report::new(
        profile.clone(),
        slo.clone(),
        offered.clone(),
        &measured,
        &drained,
        gates::evaluate(&data),
        observations(&data),
    ))
}

/// Context for reading the gates — never a budget.
///
/// The two latency terms are the whole reason the fast path is split: a breach
/// says *which* half grew, and that is attribution, not a second SLO nobody
/// agreed to.
fn observations(run: &RunData<'_>) -> Vec<Observation> {
    let mut observations = vec![
        Observation::p99(
            "queue_wait_p99",
            "queue wait (the term that grows when detection is the bottleneck)",
            &run.window.queue_wait,
        ),
        Observation::p99(
            "processing_p99",
            "in-process (roster fan-out + publish)",
            &run.window.processing,
        ),
        Observation::new(
            "quiet_blocks",
            "blocks measured that produced no alert",
            Some(Measured::Count(run.window.quiet.count)),
        ),
    ];
    if let Some(screening) = run.screening {
        observations.push(Observation::new(
            "screen_stale_share",
            "share of screening decisions rendered over last-known-good facts",
            screening.stale_share().map(Measured::Share),
        ));
    }
    if let Some(api) = run.source(crate::source::API) {
        if let Some(latency) = &api.latency {
            observations.push(Observation::p99(
                "api_latency_p99",
                "client-observed API latency",
                latency,
            ));
        }
    }
    observations
}

/// Poll the subject until its fast-path sample count stops rising, or the
/// timeout expires.
async fn drain(metrics: &dyn SubjectMetrics, timeout: Duration) -> Result<Drain> {
    let started = Instant::now();
    let mut last = metrics.sample().await?.total_samples();
    let mut quiet_polls = 0;

    while started.elapsed() < timeout {
        tokio::time::sleep(DRAIN_POLL).await;
        let now = metrics.sample().await?.total_samples();
        if now == last {
            quiet_polls += 1;
            if quiet_polls >= QUIET_POLLS_TO_SETTLE {
                return Ok(Drain::Settled {
                    waited: started.elapsed(),
                });
            }
        } else {
            quiet_polls = 0;
        }
        last = now;
    }

    Ok(Drain::TimedOut {
        waited: started.elapsed(),
        observed: last,
    })
}

/// The production [`SubjectMetrics`]: scrape detection's `/metrics` over HTTP.
pub struct PrometheusScrape {
    client: reqwest::Client,
    url: String,
}

impl PrometheusScrape {
    pub fn new(client: reqwest::Client, url: impl Into<String>) -> Self {
        Self {
            client,
            url: url.into(),
        }
    }
}

#[async_trait]
impl SubjectMetrics for PrometheusScrape {
    async fn sample(&self) -> Result<FastPathWindow> {
        let body = self
            .client
            .get(&self.url)
            .send()
            .await
            .with_context(|| format!("scraping {}", self.url))?
            .error_for_status()
            .with_context(|| format!("{} returned an error status", self.url))?
            .text()
            .await
            .context("reading the metrics body")?;
        let exposition = Exposition::parse(&body);

        // The metric *names* come from the crate that defines them, so a rename
        // breaks the build rather than leaving this scraping a series that no
        // longer exists and passing on an empty histogram.
        let fast = detection::metrics::FAST_PATH_SECONDS;
        Ok(FastPathWindow {
            alerting: exposition.histogram(fast, &[("outcome", "alert")]),
            quiet: exposition.histogram(fast, &[("outcome", "no_alert")]),
            queue_wait: exposition.histogram(detection::metrics::QUEUE_WAIT_SECONDS, &[]),
            processing: exposition.histogram(detection::metrics::BLOCK_PROCESS_SECONDS, &[]),
        })
    }
}

/// Every replica of the subject, read as one.
///
/// The SLO is stated over the whole deployment — `sum by (le)` in PromQL — and
/// detection runs **one instance per chain** (§20) with several replicas each
/// once the HPA lands. A single-endpoint harness measures one pod and reports
/// it as the platform, which is a quietly wrong answer on exactly the
/// infrastructure the staging exit-gate run happens on.
///
/// Summing is the whole implementation, because a histogram's buckets add: the
/// quantile of the union is what an SLO means, and
/// [`Exposition::histogram`] already sums across label dimensions for the same
/// reason.
pub struct CompositeSubject {
    replicas: Vec<PrometheusScrape>,
}

impl CompositeSubject {
    /// Build from one or more `/metrics` URLs. Empty is refused: a subject with
    /// no endpoints would scrape nothing, difference nothing, and report an
    /// empty histogram as merely inconclusive when the real answer is that the
    /// harness was pointed at nowhere.
    pub fn new(client: reqwest::Client, urls: &[String]) -> Result<Self> {
        anyhow::ensure!(
            !urls.is_empty(),
            "no subject metrics endpoints given — the fast-path series is the only \
             place the §6 number exists"
        );
        Ok(Self {
            replicas: urls
                .iter()
                .map(|url| PrometheusScrape::new(client.clone(), url))
                .collect(),
        })
    }
}

#[async_trait]
impl SubjectMetrics for CompositeSubject {
    async fn sample(&self) -> Result<FastPathWindow> {
        // Sequential, not concurrent: the reads are seconds apart in a run that
        // lasts minutes, and a fan-out would add its own scheduling jitter to
        // the gap between the first and last replica's counters — which is
        // exactly the skew a summed histogram cannot see but a drain check can
        // trip over.
        let mut total = FastPathWindow::default();
        for replica in &self.replicas {
            total = total.plus(&replica.sample().await?);
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use crate::scrape::OrderedBound;
    use crate::slo::{LatencyBudget, Outcome, Verdict};
    use crate::source::{self, Offered, Outcomes, Window};

    /// A subject whose successive reads are scripted. The last entry repeats,
    /// so a test only has to describe the interesting prefix.
    struct ScriptedSubject {
        reads: Mutex<std::collections::VecDeque<FastPathWindow>>,
        last: Mutex<FastPathWindow>,
        calls: Mutex<usize>,
    }

    impl ScriptedSubject {
        fn new(reads: Vec<FastPathWindow>) -> Self {
            let last = reads.last().cloned().unwrap_or_default();
            Self {
                reads: Mutex::new(reads.into()),
                last: Mutex::new(last),
                calls: Mutex::new(0),
            }
        }

        /// A subject whose sample count climbs by `step` on every read — a
        /// pipeline that never catches up.
        fn always_climbing(step: u64, reads: usize) -> Self {
            Self::new(
                (0..reads)
                    .map(|n| window_of(alerting(step * (n as u64 + 1), step * (n as u64 + 1))))
                    .collect(),
            )
        }

        fn calls(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }

    #[async_trait]
    impl SubjectMetrics for ScriptedSubject {
        async fn sample(&self) -> Result<FastPathWindow> {
            *self.calls.lock().unwrap() += 1;
            match self.reads.lock().unwrap().pop_front() {
                Some(read) => {
                    *self.last.lock().unwrap() = read.clone();
                    Ok(read)
                }
                None => Ok(self.last.lock().unwrap().clone()),
            }
        }
    }

    /// A subject that refuses to be read — the harness pointed at nothing.
    struct UnreachableSubject;

    #[async_trait]
    impl SubjectMetrics for UnreachableSubject {
        async fn sample(&self) -> Result<FastPathWindow> {
            anyhow::bail!("connection refused")
        }
    }

    /// A load source that reports a canned result without doing anything.
    struct CannedSource(Offered);

    #[async_trait]
    impl LoadSource for CannedSource {
        fn name(&self) -> &'static str {
            self.0.source
        }
        async fn offer(&self, _window: Window, _shutdown: CancellationToken) -> Result<Offered> {
            Ok(self.0.clone())
        }
    }

    /// `total` samples, `under` of them at or below one second.
    fn alerting(total: u64, under: u64) -> Histogram {
        let mut buckets = BTreeMap::new();
        buckets.insert(OrderedBound(0.5), under);
        buckets.insert(OrderedBound(1.0), under);
        buckets.insert(OrderedBound(2.5), total);
        Histogram {
            buckets,
            count: total,
            sum: 0.0,
        }
    }

    fn window_of(alerting: Histogram) -> FastPathWindow {
        FastPathWindow {
            alerting,
            ..Default::default()
        }
    }

    /// A subject that is empty for the pre-flight and baseline reads, then
    /// holds `total` samples (`under` of them within a second) for the drain
    /// and the closing read.
    ///
    /// Spelled out because the *number of reads before the baseline* is load
    /// bearing: a script whose first entry already contains the samples puts
    /// them in the baseline, and `since` then measures an empty window — which
    /// looks exactly like a pipeline that produced nothing.
    fn subject_reporting(total: u64, under: u64) -> ScriptedSubject {
        ScriptedSubject::new(vec![
            FastPathWindow::default(), // pre-flight
            FastPathWindow::default(), // baseline: the window opens here
            window_of(alerting(total, under)),
        ])
    }

    fn slo() -> Slo {
        Slo {
            fast_path_p99_seconds: LatencyBudget::try_from(1.0).unwrap(),
            api_p99_seconds: LatencyBudget::try_from(0.5).unwrap(),
            screen_p50_seconds: LatencyBudget::try_from(0.1).unwrap(),
            screen_p99_seconds: LatencyBudget::try_from(0.25).unwrap(),
            min_alert_samples: 100,
            min_achieved_ratio: 0.95,
            min_api_success_ratio: 0.99,
            max_screen_failed_closed_share: 0.01,
        }
    }

    fn profile() -> Profile {
        Profile {
            name: "t".into(),
            rationale: "t".into(),
            chain: 1,
            blocks_per_second: 2.0,
            txs_per_block: 200,
            alerting_block_fraction: 1.0,
            api_qps: 0.0,
            api_routes: vec![],
            warmup: Duration::from_secs(1),
            duration: Duration::from_secs(60),
            drain_timeout: Duration::from_secs(30),
            address_pool: None,
            fault: None,
        }
    }

    fn chain_at_target() -> Arc<dyn LoadSource> {
        Arc::new(CannedSource(Offered {
            scheduled: 120,
            delivered: 120,
            elapsed: Duration::from_secs(60),
            ..Offered::none(source::CHAIN, "blocks/s", 2.0)
        }))
    }

    // ── the drain ────────────────────────────────────────────────────

    #[tokio::test(start_paused = true)]
    async fn a_pipeline_that_never_catches_up_times_out_rather_than_reporting_fast() {
        let subject = ScriptedSubject::always_climbing(10, 64);
        let drained = drain(&subject, Duration::from_secs(10)).await.unwrap();
        assert!(
            matches!(drained, Drain::TimedOut { .. }),
            "samples still arriving must never read as settled: {drained:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn one_quiet_poll_is_not_a_drain_but_two_are() {
        // 100, 100 (one quiet poll), 150 (still arriving), then flat.
        let subject = ScriptedSubject::new(vec![
            window_of(alerting(100, 100)),
            window_of(alerting(100, 100)),
            window_of(alerting(150, 150)),
            window_of(alerting(150, 150)),
            window_of(alerting(150, 150)),
        ]);
        let drained = drain(&subject, Duration::from_secs(30)).await.unwrap();
        assert!(
            matches!(drained, Drain::Settled { .. }),
            "it does settle eventually: {drained:?}"
        );
        assert!(
            subject.calls() >= 5,
            "a lone quiet poll must not have ended it early ({} reads)",
            subject.calls()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_settled_pipeline_stops_polling_instead_of_burning_the_timeout() {
        let subject = ScriptedSubject::new(vec![window_of(alerting(100, 100))]);
        let drained = drain(&subject, Duration::from_secs(600)).await.unwrap();
        match drained {
            Drain::Settled { waited } => assert!(waited < Duration::from_secs(10)),
            other => panic!("expected a settle, got {other:?}"),
        }
    }

    // ── the procedure ────────────────────────────────────────────────

    #[tokio::test(start_paused = true)]
    async fn an_unreachable_subject_fails_before_any_load_is_offered() {
        let err = run(
            &profile(),
            &slo(),
            &[chain_at_target()],
            &UnreachableSubject,
            CancellationToken::new(),
        )
        .await
        .expect_err("a subject that cannot be read is an error, not a pass");
        assert!(format!("{err:#}").contains("pre-flight"), "{err:#}");
    }

    /// The measurement is a *difference*. Here the subject arrives with a large,
    /// entirely healthy history and then does badly during the window: folding
    /// the two together would hide the breach in the denominator.
    #[tokio::test(start_paused = true)]
    async fn the_warmup_history_is_subtracted_rather_than_diluting_the_window() {
        let subject = ScriptedSubject::new(vec![
            // pre-flight + baseline: 10 000 samples, all under a second.
            window_of(alerting(10_000, 10_000)),
            window_of(alerting(10_000, 10_000)),
            // the window adds 1 000 samples, only half of them in budget.
            window_of(alerting(11_000, 10_500)),
        ]);

        let report = run(
            &profile(),
            &slo(),
            &[chain_at_target()],
            &subject,
            CancellationToken::new(),
        )
        .await
        .unwrap();

        assert_eq!(
            report.measured.alerting_samples, 1_000,
            "the window, not the total"
        );
        let fast_path = report
            .gates
            .iter()
            .find(|g| g.id == "fast_path_p99")
            .expect("the §6 gate always applies");
        assert!(
            fast_path.verdict.is_breach(),
            "50% in budget over the window must breach even though 95% of all-time \
             samples were fine: {}",
            fast_path.verdict
        );
        assert_eq!(report.outcome(), Outcome::Breached);
    }

    #[tokio::test(start_paused = true)]
    async fn a_subject_restarting_mid_run_is_an_error_not_a_clamp_to_zero() {
        let subject = ScriptedSubject::new(vec![
            window_of(alerting(5_000, 5_000)),
            window_of(alerting(5_000, 5_000)),
            // counters reset: fewer samples than the baseline.
            window_of(alerting(3, 3)),
        ]);
        let err = run(
            &profile(),
            &slo(),
            &[chain_at_target()],
            &subject,
            CancellationToken::new(),
        )
        .await
        .expect_err("a restart means no window of samples was observed");
        assert!(format!("{err:#}").contains("restarted"), "{err:#}");
    }

    /// A run whose numbers are all fine but whose *pipeline never drained* must
    /// not exit 0: the p99 describes only the blocks that kept up.
    #[tokio::test(start_paused = true)]
    async fn a_run_that_never_drained_cannot_pass_however_good_the_p99_looks() {
        let mut profile = profile();
        profile.drain_timeout = Duration::from_secs(5);
        let subject = ScriptedSubject::always_climbing(500, 64);

        let report = run(
            &profile,
            &slo(),
            &[chain_at_target()],
            &subject,
            CancellationToken::new(),
        )
        .await
        .unwrap();

        let drained = report
            .gates
            .iter()
            .find(|g| g.id == "pipeline_drained")
            .unwrap();
        assert!(drained.verdict.is_inconclusive(), "{}", drained.verdict);
        assert_ne!(report.outcome(), Outcome::Held);
    }

    // ── gate applicability ───────────────────────────────────────────

    // ── accounting: "never offered" is not "offered and dropped" ─────

    /// The bug this is a regression test for, with the numbers from the run
    /// that exposed it: the broker was dying, the generator delivered ~52% of
    /// target, and the accounting gate — dividing by the *target* — announced
    /// "blocks are being lost before they are timed … check the DLQ". Nothing
    /// was lost. It sent its reader to the wrong subsystem while the chain-load
    /// gate beside it already said exactly what had happened.
    #[tokio::test(start_paused = true)]
    async fn a_generator_that_fell_short_is_not_reported_as_blocks_being_lost() {
        let profile = profile(); // 2 blocks/s over 1s warmup + 60s window
        let window = profile.window();

        // Half the target reached the broker…
        let half: Arc<dyn LoadSource> = Arc::new(CannedSource(Offered {
            scheduled: 122,
            delivered: 62,
            elapsed: window.total(),
            ..Offered::none(source::CHAIN, "blocks/s", 2.0)
        }));
        // …and essentially all of *those* came back out.
        let observed = (62.0 * window.measured_share()).round() as u64;
        let subject = subject_reporting(observed, observed);

        let report = run(
            &profile,
            &slo_min_samples(1),
            &[half],
            &subject,
            CancellationToken::new(),
        )
        .await
        .unwrap();

        let accounting = report
            .gates
            .iter()
            .find(|g| g.id == "blocks_accounted_for")
            .expect("a chain source that ran always accounts");
        assert!(
            matches!(accounting.verdict, Verdict::Held { .. }),
            "blocks that were never sent cannot have been lost: {}",
            accounting.verdict
        );
        assert!(
            !format!("{}", accounting.verdict).contains("DLQ"),
            "must not send anyone to the DLQ for blocks the generator never published"
        );

        // The shortfall is still reported — by the gate whose job it is.
        let load = report
            .gates
            .iter()
            .find(|g| g.id == "chain_load_achieved")
            .unwrap();
        assert!(load.verdict.is_inconclusive(), "{}", load.verdict);
    }

    /// …and the gate still fires when blocks really are disappearing inside the
    /// pipeline: full load delivered, a quarter of it timed.
    #[tokio::test(start_paused = true)]
    async fn blocks_delivered_but_never_timed_still_trip_the_accounting_gate() {
        let profile = profile();
        let window = profile.window();

        let full: Arc<dyn LoadSource> = Arc::new(CannedSource(Offered {
            scheduled: 122,
            delivered: 122,
            elapsed: window.total(),
            ..Offered::none(source::CHAIN, "blocks/s", 2.0)
        }));
        let subject = subject_reporting(30, 30);

        let report = run(
            &profile,
            &slo_min_samples(1),
            &[full],
            &subject,
            CancellationToken::new(),
        )
        .await
        .unwrap();

        let accounting = report
            .gates
            .iter()
            .find(|g| g.id == "blocks_accounted_for")
            .unwrap();
        assert!(
            accounting.verdict.is_inconclusive(),
            "{}",
            accounting.verdict
        );
        assert!(
            format!("{}", accounting.verdict).contains("DLQ"),
            "this time the DLQ really is where to look"
        );
    }

    /// A failed precondition must not leave a green claim reading like a result.
    #[tokio::test(start_paused = true)]
    async fn a_run_that_was_never_loaded_marks_its_claims_unsupported() {
        let profile = profile();
        let short: Arc<dyn LoadSource> = Arc::new(CannedSource(Offered {
            scheduled: 122,
            delivered: 30,
            elapsed: profile.window().total(),
            ..Offered::none(source::CHAIN, "blocks/s", 2.0)
        }));
        let subject = subject_reporting(30, 30);

        let report = run(
            &profile,
            &slo_min_samples(1),
            &[short],
            &subject,
            CancellationToken::new(),
        )
        .await
        .unwrap();

        assert!(!report.preconditions_hold);
        assert!(report.to_string().contains("[UNSUPPORTED]"));
    }

    fn slo_min_samples(min: u64) -> Slo {
        Slo {
            min_alert_samples: min,
            ..slo()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_fast_path_only_profile_emits_no_api_gates_at_all() {
        let subject = ScriptedSubject::new(vec![window_of(alerting(200, 200))]);
        let report = run(
            &profile(), // api_qps == 0
            &slo(),
            &[chain_at_target()],
            &subject,
            CancellationToken::new(),
        )
        .await
        .unwrap();

        assert!(
            !report.gates.iter().any(|g| g.id.starts_with("api_")),
            "a profile that drives no API must not report API gates — 'not covered' \
             is not the same claim as 'measured and fine', nor as 'went wrong'"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_api_profile_whose_driver_never_started_names_the_missing_setting() {
        let mut profile = profile();
        profile.api_qps = 100.0;
        profile.api_routes = vec![crate::profile::ApiRoute {
            path: "/v1/incidents".into(),
            weight: 1,
            method: crate::profile::Method::Get,
            body: None,
        }];

        let never_started: Arc<dyn LoadSource> =
            Arc::new(CannedSource(Offered::none(source::API, "qps", 100.0)));
        let subject = ScriptedSubject::new(vec![window_of(alerting(200, 200))]);

        let report = run(
            &profile,
            &slo(),
            &[chain_at_target(), never_started],
            &subject,
            CancellationToken::new(),
        )
        .await
        .unwrap();

        let gate = report
            .gates
            .iter()
            .find(|g| g.id == "api_load_achieved")
            .expect("a configured-but-absent driver still reports");
        assert!(
            format!("{}", gate.verdict).contains("LOADTEST_API_BASE_URL"),
            "a misconfigured harness and a slow API want different messages: {}",
            gate.verdict
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_api_that_errored_its_way_to_a_fast_p99_breaches_the_success_gate() {
        let mut profile = profile();
        profile.api_qps = 10.0;
        profile.api_routes = vec![crate::profile::ApiRoute {
            path: "/v1/incidents".into(),
            weight: 1,
            method: crate::profile::Method::Get,
            body: None,
        }];

        let mostly_429s: Arc<dyn LoadSource> = Arc::new(CannedSource(Offered {
            scheduled: 600,
            delivered: 600,
            elapsed: Duration::from_secs(60),
            latency: Some(alerting(600, 600)),
            outcomes: Some(Outcomes {
                succeeded: 100,
                client_errors: 500,
                server_errors: 0,
            }),
            ..Offered::none(source::API, "qps", 10.0)
        }));
        let subject = ScriptedSubject::new(vec![window_of(alerting(200, 200))]);

        let report = run(
            &profile,
            &slo(),
            &[chain_at_target(), mostly_429s],
            &subject,
            CancellationToken::new(),
        )
        .await
        .unwrap();

        let success = report
            .gates
            .iter()
            .find(|g| g.id == "api_success_ratio")
            .unwrap();
        assert!(success.verdict.is_breach(), "{}", success.verdict);
        assert_eq!(report.outcome(), Outcome::Breached);
    }

    #[tokio::test(start_paused = true)]
    async fn the_report_orders_sources_by_configuration_not_by_completion() {
        let mut profile = profile();
        profile.api_qps = 1.0;
        profile.api_routes = vec![crate::profile::ApiRoute {
            path: "/v1/incidents".into(),
            weight: 1,
            method: crate::profile::Method::Get,
            body: None,
        }];
        let api: Arc<dyn LoadSource> =
            Arc::new(CannedSource(Offered::none(source::API, "qps", 1.0)));
        let subject = ScriptedSubject::new(vec![window_of(alerting(200, 200))]);

        let report = run(
            &profile,
            &slo(),
            &[chain_at_target(), api],
            &subject,
            CancellationToken::new(),
        )
        .await
        .unwrap();

        let names: Vec<&str> = report.offered.iter().map(|o| o.source).collect();
        assert_eq!(names, vec![source::CHAIN, source::API]);
    }
}
