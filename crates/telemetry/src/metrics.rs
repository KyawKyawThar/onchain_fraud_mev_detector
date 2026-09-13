//! Prometheus metrics exporter (§19) — the metrics counterpart to
//! [`crate::init`].
//!
//! A service records measurements through the [`metrics`] facade at the call site
//! (e.g. the detection service's per-detector hit/latency, §19). Those macros are
//! a near-free no-op until *some* process installs a global recorder — that
//! install is this module's one job. [`init`] stands up the
//! [`metrics_exporter_prometheus`] recorder and serves the textual Prometheus
//! exposition over an HTTP listener, so a Prometheus server can scrape
//! `http://<addr>/metrics`.
//!
//! Like [`crate::init`], the service owns config resolution and passes the bind
//! address in explicitly, so this stays a thin, side-effecting wire-up with no
//! reach into ambient process state. Call it once at startup, **inside the Tokio
//! runtime** (the exporter spawns its listener + metric-upkeep tasks onto it).

use std::net::SocketAddr;

use anyhow::Context as _;
use metrics_exporter_prometheus::{Matcher, NativeHistogramConfig, PrometheusBuilder};

/// Histogram buckets (seconds) for every latency metric — anything whose name
/// ends `_seconds` (e.g. detection's `detector_detect_duration_seconds`, §19).
///
/// Without explicit buckets the exporter renders a histogram as a Prometheus
/// *summary* (client-side quantiles), which can't be re-aggregated across
/// instances and isn't queryable with `histogram_quantile`. Declaring buckets
/// makes it a real histogram (`_bucket{le=…}`), so dashboards compute p50/p99 in
/// PromQL and the series sum cleanly across replicas.
///
/// The ladder spans ~10µs (a pure in-process detector on a header-only block) to
/// 10s (a slow detector over a full block), roughly 2–3 buckets per decade — fine
/// resolution where detector latencies actually sit without exploding cardinality.
///
/// Public because it is a contract, not an implementation detail: a latency SLO
/// can only be decided from a histogram if the ladder has a bucket boundary
/// exactly on the budget, so anything that gates on one (the load-test harness,
/// `alert-conformance`) validates its thresholds against this list rather than
/// keeping a copy that can drift.
///
/// **This ladder's ceiling is load-bearing.** `histogram_quantile` reports the
/// highest finite bound for a quantile that lands in `+Inf`, so nothing
/// measured on this ladder can ever *report* more than 10s, whatever it
/// actually took. A quantity that legitimately runs longer belongs on
/// [`JOB_DURATION_BUCKETS_SECONDS`] — see [`bucket_class`].
pub const LATENCY_BUCKETS_SECONDS: &[f64] = &[
    0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05,
    0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Counter: facts `POST /v1/address/{addr}/screen` rendered a decision over, by
/// `freshness` (`fresh` | `stale`). Exported by `server::degrade`, read by
/// `loadtest`'s degraded-mode gate — defined here, in the leaf both depend on,
/// because the load test may not depend on a service crate and a copied string
/// would drift silently.
pub const SCREENING_FACTS_SERVED_TOTAL: &str = "screening_facts_served_total";
/// Counter: screening requests that left the fresh path, by `reason` and
/// `outcome` (`served_stale` | `served_fresh_late` | `failed_closed`). Same
/// sharing rationale as [`SCREENING_FACTS_SERVED_TOTAL`].
pub const SCREENING_DEGRADED_TOTAL: &str = "screening_degraded_total";

/// Histogram buckets (seconds) for durations that are **not** request
/// latencies: scheduled sweeps, batch jobs, model calls, and the gap between a
/// forecast and the event it predicted. ~1s to 1 day.
///
/// This ladder exists because the `_seconds` suffix does not distinguish "how
/// long did this function take" from "how long until this comes round again",
/// and for three sprints everything got the latency ladder. The result was
/// silent and plausible-looking: `predictive_liquidation_lead_time_seconds` is
/// the §19 signal for how far ahead a liquidation was forecast — *the product's
/// headline claim* — and every quantile over it was pinned at 10s, because a
/// useful lead time is minutes. Same for a `copilot` LLM call (tens of seconds
/// routinely), an `exposure_report` cycle, and an embedding sweep lap (hours).
///
/// Note the failure is confined to quantiles: `_sum` and `_count` are exact
/// whatever the bucketing, so a *mean* over these metrics was always right. It
/// is `histogram_quantile` that quietly returns the ceiling — which is worse
/// than an error, because 10.0 looks like a real answer.
///
/// Boundaries are the round numbers an operator actually reasons in (1m, 5m,
/// 1h, 6h, 12h, 1d): a budget is only decidable if a boundary sits exactly on
/// it, so these ARE the expressible SLOs for anything on this ladder.
pub const JOB_DURATION_BUCKETS_SECONDS: &[f64] = &[
    1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0, 3600.0, 7200.0, 21600.0, 43200.0,
    86400.0,
];

/// The metrics that take [`JOB_DURATION_BUCKETS_SECONDS`] instead of the
/// latency ladder, by exact name.
///
/// An explicit list rather than a naming convention, deliberately. A suffix
/// rule is what created the problem: `_seconds` silently swept up four
/// quantities it was never sized for, and nothing failed. A name has to be
/// *added here* to change ladders, which is a reviewable act — and
/// `alert-conformance` reads this same function, so an alert's threshold is
/// always checked against the ladder its metric really uses.
///
/// Adding a metric here is not free: it changes the exported bucket boundaries,
/// so any existing recorded history for that series is on the old ladder.
pub const JOB_DURATION_METRICS: &[&str] = &[
    // The §20.3 staleness SLI — a sweep lap is hours (Sprint 19 t1).
    "intelligence_embedding_sweep_lap_seconds",
    // §19 lead-time accuracy: forecast → real liquidation, minutes to hours.
    "predictive_liquidation_lead_time_seconds",
    // An LLM call end to end, including retries (§20.4).
    "copilot_job_duration_seconds",
    // One full exposure-report cycle (§7).
    "exposure_report_cycle_duration_seconds",
];

/// Which ladder a metric is exported on — `None` for anything that is not a
/// bucketed histogram here (counters, gauges, and any name not ending
/// `_seconds`).
///
/// One definition, three readers: the exporter below builds its matchers from
/// it, `loadtest` validates its budgets against it, and `alert-conformance`
/// checks every PromQL threshold against it. That is the whole point — the
/// alternative is three copies of a ladder and a rule that is true in one of
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BucketClass {
    /// Request/call latency: µs to 10s.
    Latency,
    /// Scheduled, batched or elapsed-time durations: 1s to 1 day.
    JobDuration,
}

/// See [`BucketClass`].
pub fn bucket_class(metric: &str) -> Option<BucketClass> {
    if JOB_DURATION_METRICS.contains(&metric) {
        Some(BucketClass::JobDuration)
    } else if metric.ends_with("_seconds") {
        Some(BucketClass::Latency)
    } else {
        None
    }
}

/// The exact bucket boundaries `metric` is exported with, or `None` if it is
/// not a bucketed histogram.
pub fn buckets_for(metric: &str) -> Option<&'static [f64]> {
    match bucket_class(metric)? {
        BucketClass::Latency => Some(LATENCY_BUCKETS_SECONDS),
        BucketClass::JobDuration => Some(JOB_DURATION_BUCKETS_SECONDS),
    }
}

/// A duration metric declared **together with the ladder it belongs on**.
///
/// The problem this solves: [`JOB_DURATION_METRICS`] must live here, because
/// `telemetry` is a leaf crate and the services that declare these metrics
/// depend on it rather than the other way round. So the classification sits in
/// one crate and the metric in another, joined by a duplicated string literal
/// — and a mismatch is invisible, because a `Matcher::Full` that matches
/// nothing does not error, it just leaves the metric on the 10s ladder.
///
/// That duplication is structural and cannot be removed without a dependency
/// cycle. What it CAN stop being is silent. Declaring a metric as a
/// `DurationMetric` at its own definition site, and recording through
/// [`record_duration`], means the declared class is checked against the
/// exporter's on every recording in every debug build — so any test that
/// exercises the metric catches a missing or misspelled registration, instead
/// of a source-text grep noticing later.
///
/// ```ignore
/// pub const SWEEP_LAP: DurationMetric =
///     DurationMetric::job_duration("intelligence_embedding_sweep_lap_seconds");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurationMetric {
    name: &'static str,
    class: BucketClass,
}

impl DurationMetric {
    /// A request/call latency — µs to 10s ([`LATENCY_BUCKETS_SECONDS`]).
    pub const fn latency(name: &'static str) -> Self {
        Self {
            name,
            class: BucketClass::Latency,
        }
    }

    /// A scheduled, batched or elapsed-time duration — 1s to 1 day
    /// ([`JOB_DURATION_BUCKETS_SECONDS`]). The name must also appear in
    /// [`JOB_DURATION_METRICS`]; [`record_duration`] asserts that it does.
    pub const fn job_duration(name: &'static str) -> Self {
        Self {
            name,
            class: BucketClass::JobDuration,
        }
    }

    pub const fn name(self) -> &'static str {
        self.name
    }

    pub const fn class(self) -> BucketClass {
        self.class
    }

    /// The metric name, after asserting (debug builds) that the exporter will
    /// put it on the ladder this declaration claims.
    ///
    /// Use this at **labelled** call sites, where [`record_duration`]'s fixed
    /// arity does not fit:
    ///
    /// ```ignore
    /// metrics::histogram!(JOB_DURATION.name_checked(), "kind" => kind).record(secs);
    /// ```
    pub fn name_checked(self) -> &'static str {
        debug_assert_eq!(
            bucket_class(self.name),
            Some(self.class),
            "`{}` is declared as {:?} but the exporter will give it {:?}. A \
             Matcher::Full override that matches nothing fails silently — add \
             the name to telemetry::metrics::JOB_DURATION_METRICS, or fix the \
             spelling.",
            self.name,
            self.class,
            bucket_class(self.name),
        );
        self.name
    }
}

/// Record a duration against the ladder its declaration says it belongs on.
///
/// In debug builds this asserts the declared class matches what the exporter
/// will actually apply. That assertion is the whole point: it converts "this
/// metric is silently on the wrong ladder, and its quantiles are pinned at
/// 10s" — which took three sprints and a manual audit to notice — into a test
/// failure on the first test that records the metric.
///
/// Release builds pay nothing: `debug_assert!` compiles out, and the recording
/// is the same `histogram!` call it always was.
pub fn record_duration(metric: DurationMetric, seconds: f64) {
    metrics::histogram!(metric.name_checked()).record(seconds);
}

/// The largest value a `histogram_quantile` over `metric` can ever report.
///
/// Not the same question as "the largest bucket": a quantile landing in `+Inf`
/// reports the highest *finite* bound, so this is the ceiling a threshold must
/// stay strictly below to be decidable at all.
pub fn quantile_ceiling_for(metric: &str) -> Option<f64> {
    buckets_for(metric)?.last().copied()
}

/// Install the global Prometheus recorder and start the `/metrics` HTTP listener
/// on `addr`. Call once per process, from within the Tokio runtime.
///
/// After this returns, every [`metrics`] macro elsewhere in the process records
/// into the installed recorder, and a scrape of `http://{addr}/metrics` renders
/// the current series in Prometheus text format. `_seconds` metrics are exported
/// as bucketed histograms (see [`LATENCY_BUCKETS_SECONDS`]). Installing a second
/// recorder in the same process fails — there is only one global — so this is a
/// boot-time, fail-fast call, mirroring [`crate::init`].
pub fn init(addr: SocketAddr) -> anyhow::Result<()> {
    init_labeled(addr, &[])
}

/// [`init`] with process-wide labels stamped onto **every** series this
/// process exports — the §19 convention for per-chain service instances
/// (`("chain", chain.metrics_label())` on detection/predictive): one label at
/// the exporter beats threading a chain through every call site, and two
/// chains' instances then aggregate/filter cleanly in PromQL.
pub fn init_labeled(addr: SocketAddr, global_labels: &[(&str, String)]) -> anyhow::Result<()> {
    let mut builder = with_bucket_ladders(PrometheusBuilder::new().with_http_listener(addr))?;
    for (key, value) in global_labels {
        builder = builder.add_global_label(*key, value.clone());
    }
    builder
        .install()
        .context("installing the Prometheus metrics exporter")?;
    tracing::info!(%addr, "metrics exporter listening on /metrics");
    Ok(())
}

/// Apply both bucket ladders to a builder, most-specific first.
///
/// Split out from [`init_labeled`] so the tests below can exercise the exact
/// bucketing a real process gets without installing a global recorder.
///
/// **Order here is not the thing that decides precedence** — the exporter sorts
/// its overrides by `Matcher`'s own `Ord` and takes the first match, and
/// `Matcher::Full` is declared before `Matcher::Suffix`, so an exact-name
/// override wins over the `_seconds` blanket. That is a property of a
/// third-party enum's variant order, which is exactly the kind of assumption
/// that should not be load-bearing and silent: `job_duration_metrics_win_over_
/// the_seconds_suffix` below asserts it against rendered output, so a crate
/// upgrade that reorders them fails here rather than quietly re-capping four
/// metrics at 10s.
/// Opt into Prometheus **native histograms** for duration metrics.
///
/// Set to `true` to replace both fixed ladders with exponential, auto-scaling
/// buckets. This dissolves the entire defect class the ladders exist to manage:
/// there is no top bucket, so no threshold can sit above a ceiling, and no
/// boundary alignment is needed because the resolution is relative rather than
/// enumerated.
///
/// **Default off, and that is not timidity.** Native histograms are rendered
/// only in the protobuf exposition format, and this exporter *stores* a metric
/// as native once configured — so a deployment that turns this on without a
/// Prometheus that (a) is 2.40+, (b) runs with
/// `--enable-feature=native-histograms`, and (c) negotiates protobuf on scrape,
/// loses those histograms rather than degrading. Neither `deploy/prometheus.yml`
/// nor `deploy/k8s/` enables any of that today, so turning this on is a
/// deliberate, coordinated migration — and, until it is done against a real
/// Prometheus, this path is code-complete and **unproven in this repo**.
///
/// Enabling it also relaxes `alert-conformance`'s ladder rules, which are
/// correct for the classic mode and moot for this one. That crate checks a
/// static file and cannot know the deployment's mode, so the migration has to
/// change both together.
pub const NATIVE_HISTOGRAMS_ENV: &str = "TELEMETRY_NATIVE_HISTOGRAMS";

/// The metrics that have been **migrated** to native histograms.
///
/// Deliberately a list, and deliberately empty. [`NATIVE_HISTOGRAMS_ENV`] says
/// "this deployment's Prometheus can read native histograms"; this says "and
/// these specific series have been moved". Both are required, because either
/// alone is a bad migration:
///
/// - One switch over `Matcher::Suffix("_seconds")` — which is what the first
///   cut of this did — moves every duration metric in the platform in a single
///   step. If the protobuf negotiation is wrong, every latency panel and every
///   SLO alert goes blank **at the same moment**. That is the largest blast
///   radius obtainable from one boolean, which is the wrong thing to hand an
///   operator on a platform this size.
/// - A list with no readiness flag would let a metric be migrated in code and
///   silently lost on a cluster that cannot render it.
///
/// So the migration is: enable the flag on a cluster that is ready, add ONE
/// metric here, confirm it renders, then widen. Reverting is deleting a line.
pub const NATIVE_HISTOGRAM_METRICS: &[&str] = &[];

/// Growth factor per bucket — 1.1 is ~10% relative resolution, which is finer
/// than either fixed ladder across the whole range rather than only where the
/// rungs happen to be dense.
const NATIVE_BUCKET_FACTOR: f64 = 1.1;
/// Memory bound per series. At factor 1.1, 160 buckets spans roughly 1µs to 1
/// day, which covers both ladders with room over.
const NATIVE_MAX_BUCKETS: u32 = 160;
/// Durations below this collapse into the zero bucket (1µs — below the finest
/// rung the latency ladder ever had).
const NATIVE_ZERO_THRESHOLD: f64 = 0.000_001;

fn with_bucket_ladders(builder: PrometheusBuilder) -> anyhow::Result<PrometheusBuilder> {
    // The fixed ladders are applied FIRST and always, so any metric that has not
    // been explicitly migrated keeps behaving exactly as it does today. Native
    // overrides are layered on top for the named few: the exporter gives native
    // overrides precedence, and `Matcher::Full` precedence within them.
    let mut builder = with_fixed_ladders(builder)?;

    if !crate::env::parse_or(NATIVE_HISTOGRAMS_ENV, false)? {
        if !NATIVE_HISTOGRAM_METRICS.is_empty() {
            tracing::info!(
                env = NATIVE_HISTOGRAMS_ENV,
                count = NATIVE_HISTOGRAM_METRICS.len(),
                "native-histogram metrics are declared but this deployment's flag is \
                 off — they stay on the fixed ladders"
            );
        }
        return Ok(builder);
    }

    if NATIVE_HISTOGRAM_METRICS.is_empty() {
        tracing::warn!(
            env = NATIVE_HISTOGRAMS_ENV,
            "native histograms are enabled for this deployment but no metric has \
             been migrated (NATIVE_HISTOGRAM_METRICS is empty) — the flag is a no-op"
        );
        return Ok(builder);
    }

    let config = NativeHistogramConfig::new(
        NATIVE_BUCKET_FACTOR,
        NATIVE_MAX_BUCKETS,
        NATIVE_ZERO_THRESHOLD,
    )
    .map_err(|e| anyhow::anyhow!("invalid native histogram configuration: {e}"))?;
    tracing::warn!(
        env = NATIVE_HISTOGRAMS_ENV,
        metrics = ?NATIVE_HISTOGRAM_METRICS,
        "exporting these metrics as NATIVE histograms — the scrape must negotiate \
         protobuf against Prometheus 2.40+ with `--enable-feature=native-histograms`, \
         or these specific series will not render at all. The fixed ladders are NOT \
         a fallback for a migrated metric."
    );
    for metric in NATIVE_HISTOGRAM_METRICS {
        // Infallible: the config is validated above and this setter returns the
        // builder rather than a Result.
        builder = builder
            .set_native_histogram_for_metric(Matcher::Full((*metric).to_owned()), config.clone());
    }
    Ok(builder)
}

/// The default, classic-histogram configuration: two fixed ladders, most
/// specific first.
fn with_fixed_ladders(builder: PrometheusBuilder) -> anyhow::Result<PrometheusBuilder> {
    // Blanket: any `_seconds` metric is a latency histogram.
    let mut builder = builder
        .set_buckets_for_metric(
            Matcher::Suffix("_seconds".to_owned()),
            LATENCY_BUCKETS_SECONDS,
        )
        .context("configuring latency histogram buckets")?;
    // Exact-name overrides for the durations that are not latencies.
    for metric in JOB_DURATION_METRICS {
        builder = builder
            .set_buckets_for_metric(
                Matcher::Full((*metric).to_owned()),
                JOB_DURATION_BUCKETS_SECONDS,
            )
            .with_context(|| format!("configuring job-duration buckets for {metric}"))?;
    }
    Ok(builder)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Render a recorder that has seen one observation of `metric`, and return
    /// the `le` boundaries it exported.
    fn exported_bounds(metric: &'static str, value: f64) -> Vec<String> {
        let recorder = with_bucket_ladders(PrometheusBuilder::new())
            .expect("ladders configure")
            .build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            metrics::histogram!(metric).record(value);
        });
        handle
            .render()
            .lines()
            .filter(|line| line.starts_with(&format!("{metric}_bucket")))
            .filter_map(|line| {
                let start = line.find("le=\"")? + 4;
                let rest = &line[start..];
                Some(rest[..rest.find('"')?].to_owned())
            })
            .collect()
    }

    /// The assumption `with_bucket_ladders` rests on, pinned against real
    /// rendered output rather than trusted.
    #[test]
    fn job_duration_metrics_win_over_the_seconds_suffix() {
        let sweep = exported_bounds("intelligence_embedding_sweep_lap_seconds", 7_200.0);
        assert!(
            sweep.iter().any(|b| b == "86400"),
            "a job-duration metric must get the long ladder, not the 10s latency \
             one — got {sweep:?}"
        );
        assert!(
            !sweep.iter().any(|b| b == "0.00001"),
            "the `_seconds` suffix override must NOT win over the exact-name one"
        );
    }

    /// The blanket rule still applies to everything else.
    #[test]
    fn ordinary_seconds_metrics_stay_on_the_latency_ladder() {
        let fast_path = exported_bounds("detection_fast_path_duration_seconds", 0.5);
        assert!(fast_path.iter().any(|b| b == "10"));
        assert!(
            !fast_path.iter().any(|b| b == "86400"),
            "a latency metric must not get the job-duration ladder"
        );
    }

    /// The classifier and the exporter must agree, or `alert-conformance` is
    /// validating thresholds against a ladder the process does not use.
    #[test]
    fn buckets_for_matches_what_is_actually_exported() {
        for metric in JOB_DURATION_METRICS {
            assert_eq!(buckets_for(metric), Some(JOB_DURATION_BUCKETS_SECONDS));
            assert_eq!(bucket_class(metric), Some(BucketClass::JobDuration));
        }
        assert_eq!(
            buckets_for("detection_fast_path_duration_seconds"),
            Some(LATENCY_BUCKETS_SECONDS)
        );
        assert_eq!(
            buckets_for("detector_hits_total"),
            None,
            "counters are not bucketed"
        );
        assert_eq!(
            quantile_ceiling_for("copilot_job_duration_seconds"),
            Some(86_400.0)
        );
        assert_eq!(
            quantile_ceiling_for("http_request_duration_seconds"),
            Some(10.0)
        );
    }

    /// A metric whose declaration disagrees with the exporter must trip the
    /// debug assertion — this is the check that turns a silent Matcher::Full
    /// typo into a test failure on the first test that records the metric.
    #[test]
    #[should_panic(expected = "JOB_DURATION_METRICS")]
    fn a_job_duration_declaration_for_an_unregistered_name_panics_in_debug() {
        // Never added to JOB_DURATION_METRICS, so the exporter would leave it
        // on the 10s latency ladder.
        const TYPO: DurationMetric = DurationMetric::job_duration("copilot_job_durations_seconds");
        let _ = TYPO.name_checked();
    }

    /// The happy path, so the test above is not passing for a trivial reason.
    #[test]
    fn a_correctly_registered_declaration_passes_its_check() {
        const OK: DurationMetric = DurationMetric::job_duration("copilot_job_duration_seconds");
        assert_eq!(OK.name_checked(), "copilot_job_duration_seconds");
        const LAT: DurationMetric = DurationMetric::latency("detection_fast_path_duration_seconds");
        assert_eq!(LAT.name_checked(), "detection_fast_path_duration_seconds");
    }

    /// Native histograms must be opt-in on BOTH axes, and the shipped default
    /// must leave every metric on its fixed ladder.
    #[test]
    fn native_histograms_require_both_a_ready_deployment_and_a_migrated_metric() {
        assert!(
            NATIVE_HISTOGRAM_METRICS.is_empty(),
            "no metric has been migrated yet; migrating one is a deliberate, \
             reviewed act that needs a Prometheus proven to render it"
        );
        // With the flag off (the default here), the ladders still apply.
        assert!(!exported_bounds("detection_fast_path_duration_seconds", 0.5).is_empty());

        let config = NativeHistogramConfig::new(
            NATIVE_BUCKET_FACTOR,
            NATIVE_MAX_BUCKETS,
            NATIVE_ZERO_THRESHOLD,
        );
        assert!(
            config.is_ok(),
            "the shipped native-histogram constants must be valid: {config:?}"
        );
    }

    /// Every migrated metric must be a real duration metric — a name here that
    /// nothing exports is a silent no-op, the same trap as JOB_DURATION_METRICS.
    #[test]
    fn migrated_metrics_are_duration_metrics() {
        for metric in NATIVE_HISTOGRAM_METRICS {
            assert!(
                bucket_class(metric).is_some(),
                "`{metric}` is listed for native histograms but is not a bucketed \
                 duration metric — a Matcher::Full that matches nothing does nothing"
            );
        }
    }

    /// Both ladders must be sorted and free of duplicates — `histogram_quantile`
    /// interpolates between adjacent bounds, so an out-of-order rung would make
    /// every quantile over that metric nonsense.
    #[test]
    fn both_ladders_are_strictly_increasing() {
        for ladder in [LATENCY_BUCKETS_SECONDS, JOB_DURATION_BUCKETS_SECONDS] {
            assert!(
                ladder.windows(2).all(|w| w[0] < w[1]),
                "ladder must be strictly increasing: {ladder:?}"
            );
        }
    }
}
