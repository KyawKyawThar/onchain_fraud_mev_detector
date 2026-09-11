//! Detection's metrics (§19): the per-detector hit rate + latency, and the
//! **fast path's own clock**.
//!
//! Two call sites, each the only one of its kind:
//!
//! - [`record_fast_path`] — once per block, at the end of the §6 fast path.
//!   This is the series the "< 1 second" claim is checked against; see
//!   [`FAST_PATH_SECONDS`] for why it is measured from the *source's* timestamp
//!   rather than from anything in this process.
//! - [`record_detector_run`] — once per detector invocation (below).
//!
//! The distinction matters under load and only under load: a detector's own
//! `detect` call is unaffected by a queue building up in front of it, so the
//! per-detector histogram stays flat while the pipeline misses its budget by
//! seconds. Both are needed; neither substitutes for the other.
//!
//! One function, [`record_detector_run`], called once per detector invocation —
//! from every emit path (`Block` sequential + rayon-parallel in [`crate::emit`],
//! and the cross-block slot in [`crate::reorg`]) so the numbers can't drift
//! between them. It records, **labeled by the detector's `(id, version)`**:
//!
//! - [`RUNS_TOTAL`] — every `detect` invocation (the hit-rate denominator).
//! - [`HITS_TOTAL`] — invocations that produced at least one finding (the
//!   numerator). **Hit rate is derived in PromQL** as `hits / runs` rather than
//!   stored: a ratio computed from two monotonic counters survives restarts and
//!   re-aggregates cleanly across instances, where a gauge wouldn't.
//! - [`FINDINGS_TOTAL`] — total findings emitted (a detector can fire more than
//!   once per block), so `findings / hits` gives the average burst size.
//! - [`DETECT_SECONDS`] — a latency histogram of each `detect` call's wall time.
//!
//! These go through the [`metrics`] facade, which is a near-free no-op until the
//! binary installs the Prometheus exporter ([`telemetry::metrics::init`]). So the
//! detection *library* (and its tests, replay, backtests) stay exporter-agnostic:
//! recording never changes the events produced, only what a scrape can observe.
//!
//! Why here and not inside each detector: latency must wrap the *seam* call
//! (`DetectorPlugin::detect`) uniformly, and a detector that forgot to count
//! itself would silently vanish from the dashboard. Measuring at the single call
//! site the scheduler drives makes the coverage total by construction — the same
//! discipline as the link-or-fail emit plan.

use std::time::Duration;

use events::primitives::DetectorRef;

/// Counter: every detector invocation. Hit-rate denominator (`hits / runs`).
pub const RUNS_TOTAL: &str = "detector_runs_total";
/// Counter: invocations that produced ≥1 finding. Hit-rate numerator.
pub const HITS_TOTAL: &str = "detector_hits_total";
/// Counter: total findings emitted across all invocations.
pub const FINDINGS_TOTAL: &str = "detector_findings_total";
/// Histogram: `detect` call wall-clock latency, in seconds.
pub const DETECT_SECONDS: &str = "detector_detect_duration_seconds";

/// Histogram: the **§6 fast path** — `BlockAssembled.occurred_at` (stamped by
/// ingestion) to the moment this block's events are durably published.
///
/// This is the platform's headline latency number, and the only series the
/// "< 1 second" claim can be checked against. It deliberately spans the broker
/// hop and the scheduler's bounded work queue, because those are exactly what a
/// saturated pipeline adds: [`DETECT_SECONDS`] measures one detector call and
/// stays flat under load, so a fast path judged on it would report health while
/// blocks queued for seconds behind it.
///
/// Labeled `outcome` (`alert` | `no_alert`) — §6 claims a *preliminary alert*
/// in under a second, so the SLO reads `outcome="alert"`. The other half is
/// kept rather than dropped because a run in which no detector fired proves
/// nothing about the claim, and the two must be distinguishable: a gate that
/// cannot tell them apart passes a pipeline that emitted no alerts at all.
///
/// Not to be confused with `notification_alert_end_to_end_seconds`, which
/// measures block → *delivered notification* — a strictly larger budget over a
/// different (slow-path-inclusive) span.
pub const FAST_PATH_SECONDS: &str = "detection_fast_path_duration_seconds";

/// Histogram: how long a decoded block waited in the bounded work channel
/// before the scheduler picked it up.
///
/// The backpressure component of [`FAST_PATH_SECONDS`], split out because it is
/// the term that grows when detection is the bottleneck. In-process and
/// monotonic ([`std::time::Instant`]), so it is immune to the wall clock
/// stepping mid-block.
pub const QUEUE_WAIT_SECONDS: &str = "detection_queue_wait_seconds";

/// Histogram: scheduler pickup → durably published — the work itself (roster
/// fan-out, cross-block slots, publish + its retries).
///
/// [`QUEUE_WAIT_SECONDS`] + this ≈ the in-process share of
/// [`FAST_PATH_SECONDS`]; whatever the fast path has left over is the broker
/// hop and any clock skew between ingestion and this process.
pub const BLOCK_PROCESS_SECONDS: &str = "detection_block_process_seconds";

/// One block's fast-path timings, recorded together by [`record_fast_path`].
#[derive(Debug, Clone, Copy)]
pub struct FastPathSample {
    /// Enqueue → scheduler pickup.
    pub queue_wait: Duration,
    /// Scheduler pickup → durably published.
    pub processing: Duration,
    /// Source `occurred_at` → durably published: the §6 budget.
    pub total: Duration,
    /// Whether this block produced at least one `PreliminaryAlertCreated`.
    pub alerted: bool,
}

/// Record one block's trip through the fast path. Called from the single site
/// that completes it ([`crate::scheduler::Scheduler::run`], after the block's
/// events are published) — the same one-call-site discipline
/// [`record_detector_run`] uses, so the three series always describe the same
/// block.
pub fn record_fast_path(sample: FastPathSample) {
    let outcome = if sample.alerted { "alert" } else { "no_alert" };
    metrics::histogram!(FAST_PATH_SECONDS, "outcome" => outcome).record(sample.total.as_secs_f64());
    metrics::histogram!(QUEUE_WAIT_SECONDS).record(sample.queue_wait.as_secs_f64());
    metrics::histogram!(BLOCK_PROCESS_SECONDS).record(sample.processing.as_secs_f64());
}

/// Counter: `ModelDriftDetected` events published, labeled by `model` (§20.5).
///
/// The bridge between the drift *gauges* (continuous, ephemeral) and the drift
/// *record* (discrete, durable): `inference`'s `model_drift_windows_total`
/// counts every reading, this counts the ones that breached and became an
/// event. The two together answer "is drift being measured?" and "is it being
/// recorded?" — which fail independently, and only the first has a gauge.
pub const DRIFT_EVENTS_TOTAL: &str = "detection_drift_events_total";

/// Record one published drift event. Called from the single site that renders
/// them ([`crate::drift::DriftPublisher`]).
pub fn record_drift_event(model_id: &str) {
    metrics::counter!(DRIFT_EVENTS_TOTAL, "model" => model_id.to_owned()).increment(1);
}

/// Record one detector invocation: its `detect` latency and how many findings it
/// produced (`0` for the common no-op case — still a run, not a hit).
///
/// `detector` is the resolved `(id, version, config_hash)` triple; only `id` and
/// `version` become metric labels — `config_hash` would explode label cardinality
/// on every redeploy for no dashboard value (it lives on the events instead, §18).
pub fn record_detector_run(detector: &DetectorRef, elapsed: Duration, findings: usize) {
    let id = detector.id.clone();
    let version = detector.version.clone();

    metrics::counter!(RUNS_TOTAL, "detector" => id.clone(), "version" => version.clone())
        .increment(1);
    metrics::histogram!(DETECT_SECONDS, "detector" => id.clone(), "version" => version.clone())
        .record(elapsed.as_secs_f64());
    metrics::counter!(FINDINGS_TOTAL, "detector" => id.clone(), "version" => version.clone())
        .increment(findings as u64);
    if findings > 0 {
        metrics::counter!(HITS_TOTAL, "detector" => id, "version" => version).increment(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::CompositeKey;

    type Series = Vec<(
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    )>;

    fn a_ref(id: &str) -> DetectorRef {
        DetectorRef {
            id: id.into(),
            version: "1.0.0".into(),
            config_hash: "deadbeef".into(),
        }
    }

    /// Run `f` under a scoped in-memory recorder and return the captured series —
    /// no global install (so tests don't contend) and no scrape.
    ///
    /// One `snapshot()` only: it *drains* the recorder (counters `swap(0)`,
    /// histograms `clear`), so every lookup must read from this single capture.
    fn captured(f: impl FnOnce()) -> Series {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, f);
        snapshotter.snapshot().into_vec()
    }

    /// The value of the first series whose metric name is `name`, if recorded.
    fn value<'a>(series: &'a Series, name: &str) -> Option<&'a DebugValue> {
        series
            .iter()
            .find(|(ck, _, _, _)| ck.key().name() == name)
            .map(|(_, _, _, v)| v)
    }

    fn counter(series: &Series, name: &str) -> Option<u64> {
        match value(series, name) {
            Some(DebugValue::Counter(n)) => Some(*n),
            _ => None,
        }
    }

    fn histogram_len(series: &Series, name: &str) -> Option<usize> {
        match value(series, name) {
            Some(DebugValue::Histogram(samples)) => Some(samples.len()),
            _ => None,
        }
    }

    /// The label the SLO query filters on. A run that emitted no alert must not
    /// contribute to the series §6's claim is read from — a gate that cannot
    /// tell the two apart passes a pipeline that alerted on nothing.
    fn outcome_labels(series: &Series, name: &str) -> Vec<String> {
        series
            .iter()
            .filter(|(ck, ..)| ck.key().name() == name)
            .flat_map(|(ck, ..)| ck.key().labels())
            .filter(|l| l.key() == "outcome")
            .map(|l| l.value().to_owned())
            .collect()
    }

    fn a_sample(total_ms: u64, alerted: bool) -> FastPathSample {
        FastPathSample {
            queue_wait: Duration::from_millis(total_ms / 4),
            processing: Duration::from_millis(total_ms / 4),
            total: Duration::from_millis(total_ms),
            alerted,
        }
    }

    #[test]
    fn a_fast_path_sample_records_the_total_and_both_of_its_terms() {
        let series = captured(|| record_fast_path(a_sample(800, true)));

        assert_eq!(histogram_len(&series, FAST_PATH_SECONDS), Some(1));
        assert_eq!(histogram_len(&series, QUEUE_WAIT_SECONDS), Some(1));
        assert_eq!(histogram_len(&series, BLOCK_PROCESS_SECONDS), Some(1));
    }

    #[test]
    fn an_alerting_block_and_a_quiet_one_land_on_different_outcome_labels() {
        let series = captured(|| {
            record_fast_path(a_sample(400, true));
            record_fast_path(a_sample(400, false));
        });

        let mut labels = outcome_labels(&series, FAST_PATH_SECONDS);
        labels.sort();
        assert_eq!(labels, vec!["alert".to_owned(), "no_alert".to_owned()]);
    }

    #[test]
    fn the_terms_are_unlabeled_so_they_aggregate_across_both_outcomes() {
        let series = captured(|| record_fast_path(a_sample(400, true)));
        assert!(
            outcome_labels(&series, QUEUE_WAIT_SECONDS).is_empty(),
            "queue wait is a property of the pipeline, not of whether a detector fired"
        );
    }

    #[test]
    fn a_hit_counts_a_run_a_hit_findings_and_one_latency_sample() {
        let series = captured(|| {
            record_detector_run(&a_ref("arb"), Duration::from_millis(3), 2);
        });

        assert_eq!(counter(&series, RUNS_TOTAL), Some(1));
        assert_eq!(counter(&series, HITS_TOTAL), Some(1), "≥1 finding ⇒ a hit");
        assert_eq!(counter(&series, FINDINGS_TOTAL), Some(2));
        match value(&series, DETECT_SECONDS) {
            Some(DebugValue::Histogram(samples)) => {
                assert_eq!(samples.len(), 1, "one latency observation");
            }
            other => panic!("expected a histogram, got {other:?}"),
        }
    }

    #[test]
    fn a_miss_counts_a_run_but_no_hit() {
        let series = captured(|| {
            record_detector_run(&a_ref("arb"), Duration::from_millis(1), 0);
        });

        assert_eq!(
            counter(&series, RUNS_TOTAL),
            Some(1),
            "a miss is still a run"
        );
        assert_eq!(
            counter(&series, HITS_TOTAL),
            None,
            "no finding ⇒ the hit counter is never touched"
        );
        assert_eq!(counter(&series, FINDINGS_TOTAL), Some(0));
    }

    #[test]
    fn repeated_runs_accumulate_on_the_monotonic_counters() {
        // 3 runs, 2 of them hits (1 + 2 findings) — the shape a hit-rate query reads.
        let series = captured(|| {
            record_detector_run(&a_ref("sandwich"), Duration::from_millis(2), 1);
            record_detector_run(&a_ref("sandwich"), Duration::from_millis(2), 0);
            record_detector_run(&a_ref("sandwich"), Duration::from_millis(2), 2);
        });

        assert_eq!(counter(&series, RUNS_TOTAL), Some(3));
        assert_eq!(counter(&series, HITS_TOTAL), Some(2), "hit rate = 2/3");
        assert_eq!(counter(&series, FINDINGS_TOTAL), Some(3));
    }
}
