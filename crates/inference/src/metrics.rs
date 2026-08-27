//! Serving-side metrics for the inference seam (§19, §20.2, §20.5).
//!
//! One function, [`record_inference`](crate::metrics::record_inference), called
//! from exactly one place —
//! [`crate::ObservedEngine`] — so the numbers cannot drift between backends or
//! between the single-vector and batch call paths. That single-call-site
//! discipline is the same one `detection::metrics::record_detector_run` uses,
//! and for the same reason: a model that forgot to count itself would silently
//! vanish from the dashboard with no compile error to catch it.
//!
//! Everything goes through the [`metrics`] facade, which is a near-free no-op
//! until the binary installs the Prometheus exporter (`telemetry::metrics::init`),
//! so the library — and its tests, replay and backtests — stays
//! exporter-agnostic (conventions §8).
//!
//! The drift family ([`record_drift`](crate::metrics::record_drift)) is the same
//! discipline one level out:
//! its single call site is [`crate::DriftEngine`], and it adds exactly one
//! label — `feature` — whose values are a frozen schema's feature names (24
//! block-level, 19 per transaction). That is a *bounded, static* set, unlike
//! the digests below: a new feature name means a new `FEATURE_VERSION`, which
//! is a deliberate release, not a per-deploy churn.
//!
//! **Labels are `model` (plus `reason` on failures) and nothing else.** The
//! artifact digest and `config_hash` deliberately stay off the labels: they
//! change on every retrain, which would spawn a fresh time series per deploy
//! for no dashboard value. They live on the events and in the boot log instead
//! — the same trade-off §18 already makes for `config_hash`.

use std::time::Duration;

use ml_features::DriftReport;

use crate::engine::{InferenceError, Score};

/// Counter: seam calls (one per `infer`/`infer_batch`, not per vector).
pub const CALLS_TOTAL: &str = "model_inference_calls_total";
/// Counter: feature vectors scored. `SECONDS / VECTORS_TOTAL` is the
/// per-vector cost — the number the < 1s fast-path budget (§6, §20.2) is
/// actually spent against, which a per-call histogram alone can't give once
/// batching makes call size vary.
pub const VECTORS_TOTAL: &str = "model_inference_vectors_total";
/// Counter: failed calls, by [`InferenceErrorKind::as_str`] reason.
///
/// [`InferenceErrorKind::as_str`]: crate::InferenceErrorKind::as_str
pub const FAILURES_TOTAL: &str = "model_inference_failures_total";
/// Histogram: wall time of one seam call, in seconds.
pub const SECONDS: &str = "model_inference_duration_seconds";
/// Histogram: every score served.
///
/// Not a vanity metric: §20.5 asks for serving-time distributions monitored
/// against the training snapshot, and the *score* distribution is the cheapest
/// drift signal there is — a model whose output distribution has shifted is
/// visible here before precision decays, without instrumenting all 24 input
/// features. The per-feature population-stability statistics t5 adds sit on
/// top of this, they don't replace it.
pub const SCORE: &str = "model_inference_score";

/// Gauge: one feature's serving-time drift magnitude, labeled `{model, feature}`
/// — the §20.5 per-feature reading, in the units
/// [`ml_features::FeatureDrift::magnitude`] defines.
///
/// A gauge and not a counter: it is the *current* state of one window, and the
/// question a dashboard asks of it ("has this feature moved?") is about the
/// latest reading, not an accumulation. Every feature is published on every
/// window, including the unmoved ones — a feature whose series went missing
/// and one that reads `0` mean opposite things, and only publishing the
/// interesting ones would make them indistinguishable.
pub const FEATURE_DRIFT: &str = "model_feature_drift";
/// Gauge: the worst feature's magnitude for a model — the one series a drift
/// alert rule needs, without fanning out over `feature`.
pub const DRIFT_MAX: &str = "model_drift_max";
/// Counter: windows in which a feature was at or past the configured
/// threshold, labeled `{model, feature}`. The rate over this is "how often is
/// this feature drifted", which a gauge alone cannot answer.
pub const DRIFT_BREACHES_TOTAL: &str = "model_drift_breaches_total";
/// Counter: completed drift windows per model — the denominator that says
/// whether [`FEATURE_DRIFT`] means anything yet (a model that has served fewer
/// vectors than its window has published nothing).
pub const DRIFT_WINDOWS_TOTAL: &str = "model_drift_windows_total";
/// Gauge: the magnitude at which a model reports a breach, labeled `{model}`.
///
/// Exported so an alert rule can compare against it — `model_drift_max >
/// on(model) model_drift_threshold` — instead of restating the number in
/// PromQL. The threshold is per-model *config*, so a rule with a literal in it
/// is both a duplicate definition and silently wrong for any model that tuned
/// its own. Published alongside the readings it applies to, so the two series
/// always appear and disappear together.
pub const DRIFT_THRESHOLD: &str = "model_drift_threshold";
/// Counter: observations the drift monitor dropped without measuring, by
/// `reason` (`contended`, `poisoned`).
///
/// A monitor is allowed to fail open — it must never be why the fast path
/// stops scoring blocks — but failing open silently is how a dashboard comes
/// to show a confident zero for something nobody is watching any more. This is
/// the difference between the two.
pub const DRIFT_SKIPPED_TOTAL: &str = "model_drift_skipped_total";
/// Counter: vectors the drift monitor refused because they did not match its
/// baseline's schema — serving/training skew (§20.5) at *serving* time rather
/// than at boot. Any nonzero rate here is a wiring bug: it means a model is
/// being fed vectors its own training snapshot cannot describe.
pub const DRIFT_REJECTED_TOTAL: &str = "model_drift_rejected_total";

/// Record one seam call: its latency, how many vectors it covered, and either
/// the scores served or the reason it failed.
///
/// `vectors` is passed separately from `result` because a failed call still
/// attempted a known number of vectors, and the failure counter would
/// otherwise under-report exactly the batches that hurt most.
pub fn record_inference(
    model_id: &str,
    elapsed: Duration,
    vectors: usize,
    result: &Result<Vec<Score>, InferenceError>,
) {
    let model = model_id.to_owned();

    metrics::counter!(CALLS_TOTAL, "model" => model.clone()).increment(1);
    metrics::counter!(VECTORS_TOTAL, "model" => model.clone()).increment(vectors as u64);
    metrics::histogram!(SECONDS, "model" => model.clone()).record(elapsed.as_secs_f64());

    match result {
        Ok(scores) => {
            for score in scores {
                metrics::histogram!(SCORE, "model" => model.clone()).record(score.get());
            }
        }
        Err(err) => {
            metrics::counter!(
                FAILURES_TOTAL,
                "model" => model,
                "reason" => err.kind.as_str(),
            )
            .increment(1);
        }
    }
}

/// Record one completed drift window (§20.5): a gauge per feature, the
/// model-level worst, and a breach counter for everything at or past
/// `threshold`.
///
/// Called from exactly one place, [`crate::DriftEngine`] — the same
/// single-call-site rule as [`record_inference`], and for the same reason.
pub fn record_drift(model_id: &str, report: &DriftReport, threshold: f64) {
    let model = model_id.to_owned();
    metrics::counter!(
        DRIFT_WINDOWS_TOTAL,
        "model" => model.clone(),
        "closed_by" => report.closed_by.as_str(),
    )
    .increment(1);
    metrics::gauge!(DRIFT_MAX, "model" => model.clone()).set(report.max_magnitude());
    // Published here rather than once at boot so it cannot outlive, or precede,
    // the readings an alert compares it against.
    metrics::gauge!(DRIFT_THRESHOLD, "model" => model.clone()).set(threshold);

    for feature in &report.features {
        let magnitude = feature.magnitude();
        metrics::gauge!(
            FEATURE_DRIFT,
            "model" => model.clone(),
            "feature" => feature.name(),
        )
        .set(magnitude);
        if magnitude >= threshold {
            metrics::counter!(
                DRIFT_BREACHES_TOTAL,
                "model" => model.clone(),
                "feature" => feature.name(),
            )
            .increment(1);
        }
    }
}

/// Record vectors the drift monitor could not measure — serving/training skew.
///
/// Separate from [`record_drift`] because it happens *without* a completed
/// window: a model fed nothing but foreign vectors would otherwise report
/// silence, which is the one thing this counter exists to prevent.
pub fn record_drift_rejected(model_id: &str, vectors: u64) {
    metrics::counter!(DRIFT_REJECTED_TOTAL, "model" => model_id.to_owned()).increment(vectors);
}

/// Record observations the monitor could not take at all.
///
/// `reason` is a `&'static str` from a closed set, never a formatted message —
/// the label-cardinality rule this module already applies to
/// `InferenceErrorKind::as_str`.
pub fn record_drift_skipped(model_id: &str, reason: &'static str, vectors: u64) {
    metrics::counter!(
        DRIFT_SKIPPED_TOTAL,
        "model" => model_id.to_owned(),
        "reason" => reason,
    )
    .increment(vectors);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::InferenceErrorKind;

    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::CompositeKey;

    type Series = Vec<(
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    )>;

    /// Run `f` under a scoped in-memory recorder and return the captured
    /// series. One `snapshot()` only: it *drains* the recorder, so every
    /// lookup must read from this single capture.
    fn captured(f: impl FnOnce()) -> Series {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, f);
        snapshotter.snapshot().into_vec()
    }

    fn find<'a>(
        series: &'a Series,
        name: &str,
    ) -> Option<&'a (
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    )> {
        series.iter().find(|(ck, _, _, _)| ck.key().name() == name)
    }

    fn counter(series: &Series, name: &str) -> Option<u64> {
        match find(series, name).map(|(_, _, _, v)| v) {
            Some(DebugValue::Counter(n)) => Some(*n),
            _ => None,
        }
    }

    fn histogram(series: &Series, name: &str) -> Option<Vec<f64>> {
        match find(series, name).map(|(_, _, _, v)| v) {
            Some(DebugValue::Histogram(values)) => {
                Some(values.iter().map(|v| v.into_inner()).collect())
            }
            _ => None,
        }
    }

    fn labels(series: &Series, name: &str) -> Vec<(String, String)> {
        find(series, name)
            .map(|(ck, _, _, _)| {
                ck.key()
                    .labels()
                    .map(|l| (l.key().to_owned(), l.value().to_owned()))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn a_successful_batch_records_calls_vectors_latency_and_every_score() {
        let scores = Ok(vec![Score::new(0.2).unwrap(), Score::new(0.8).unwrap()]);
        let series = captured(|| {
            record_inference("anomaly-gbdt", Duration::from_millis(3), 2, &scores);
        });

        assert_eq!(counter(&series, CALLS_TOTAL), Some(1));
        assert_eq!(
            counter(&series, VECTORS_TOTAL),
            Some(2),
            "batch size, not 1"
        );
        assert_eq!(histogram(&series, SECONDS).unwrap().len(), 1);
        // Every served score reaches the drift histogram, not just the first.
        assert_eq!(histogram(&series, SCORE), Some(vec![0.2, 0.8]));
        assert_eq!(counter(&series, FAILURES_TOTAL), None);
    }

    #[test]
    fn a_failure_still_counts_the_vectors_it_attempted() {
        // The under-reporting trap this guards: counting vectors only on the
        // success path would make a batch that always fails look like no load
        // at all.
        let failed: Result<Vec<Score>, _> = Err(InferenceError::new(
            "anomaly-gbdt",
            InferenceErrorKind::Backend("session gone".into()),
        ));
        let series = captured(|| {
            record_inference("anomaly-gbdt", Duration::from_millis(1), 150, &failed);
        });

        assert_eq!(counter(&series, CALLS_TOTAL), Some(1));
        assert_eq!(counter(&series, VECTORS_TOTAL), Some(150));
        assert_eq!(counter(&series, FAILURES_TOTAL), Some(1));
        assert_eq!(histogram(&series, SCORE), None, "nothing was served");
    }

    #[test]
    fn the_failure_reason_is_the_variant_not_the_message() {
        // Cardinality: a `reason` built from the backend's error text would
        // spawn a new time series per distinct message.
        let noisy = |message: &str| {
            Err(InferenceError::new(
                "m",
                InferenceErrorKind::Backend(message.to_owned()),
            ))
        };
        let series = captured(|| {
            record_inference("m", Duration::ZERO, 1, &noisy("tensor 0x41 failed"));
            record_inference("m", Duration::ZERO, 1, &noisy("tensor 0x99 failed"));
        });

        assert_eq!(
            counter(&series, FAILURES_TOTAL),
            Some(2),
            "two different messages must land on ONE series"
        );
        let mut got = labels(&series, FAILURES_TOTAL);
        got.sort();
        assert_eq!(
            got,
            vec![
                ("model".to_owned(), "m".to_owned()),
                ("reason".to_owned(), "backend".to_owned()),
            ]
        );
    }

    #[test]
    fn every_error_kind_has_a_distinct_stable_reason() {
        use crate::descriptor::FeatureSkew;
        use crate::engine::ScoreOutOfRange;
        use ml_features::Granularity;

        let kinds = [
            InferenceErrorKind::Skew(FeatureSkew::Granularity {
                expected: Granularity::Block,
                actual: Granularity::Tx,
            }),
            InferenceErrorKind::Backend("x".into()),
            InferenceErrorKind::MalformedOutput("x".into()),
            InferenceErrorKind::Score(ScoreOutOfRange { value: 2.0 }),
        ];
        let mut reasons: Vec<&str> = kinds.iter().map(InferenceErrorKind::as_str).collect();
        let count = reasons.len();
        reasons.sort_unstable();
        reasons.dedup();
        assert_eq!(
            reasons.len(),
            count,
            "reasons must be distinct: {reasons:?}"
        );
    }
}
