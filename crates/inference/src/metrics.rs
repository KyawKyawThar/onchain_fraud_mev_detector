//! Serving-side metrics for the inference seam (§19, §20.2, §20.5).
//!
//! One function, [`record_inference`], called from exactly one place —
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
//! **Labels are `model` (plus `reason` on failures) and nothing else.** The
//! artifact digest and `config_hash` deliberately stay off the labels: they
//! change on every retrain, which would spawn a fresh time series per deploy
//! for no dashboard value. They live on the events and in the boot log instead
//! — the same trade-off §18 already makes for `config_hash`.

use std::time::Duration;

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
