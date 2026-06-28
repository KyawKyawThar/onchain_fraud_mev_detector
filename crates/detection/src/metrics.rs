//! Per-detector metrics (§19, Sprint 4 task 3): hit rate + latency.
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
