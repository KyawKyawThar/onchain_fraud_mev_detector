//! [`ObservedEngine`] — the thin observed outer for the inference seam
//! (conventions §14, §8).
//!
//! §14 says a cross-cutting concern that must fire on *every* exit path gets a
//! thin outer wrapping an inner that owns the logic. Elsewhere in the
//! workspace that split is two functions in one type
//! (`simulation::Worker::process` / `process_inner`). Here it is a **decorator
//! over the seam itself**, which is strictly stronger for the same cost:
//!
//! - it observes *any* backend, so a future engine can't ship unmeasured;
//! - it observes the test double too, so a consumer's tests can assert on what
//!   the dashboard will show;
//! - it can't miss a call path — `infer` and `infer_batch` are the only two,
//!   and both are overridden here;
//! - and it keeps `OrtEngine` free of metrics entirely, so the backend stays
//!   about ONNX and nothing else.
//!
//! Composing it is the binary's job, once at boot, next to where the model is
//! loaded:
//!
//! ```text
//! let engine: Arc<dyn InferenceEngine> =
//!     Arc::new(ObservedEngine::new(inference::onnx::OrtEngine::load(config)?));
//! ```
//!
//! That line is `text` and not a compiled example on purpose: `onnx::OrtEngine`
//! lives behind the `onnx` feature, which is **off by default** so the seam
//! costs nothing to link (see the crate docs). A doctest naming it does not
//! compile on the feature set anything in this workspace actually builds — so
//! the compiled example below wraps the double instead, which is the same
//! composition and is checked on every `cargo test`:
//!
//! ```
//! use std::sync::Arc;
//! use inference::test_util::{block_descriptor, StubEngine};
//! use inference::{InferenceEngine, ObservedEngine, Score};
//!
//! let engine: Arc<dyn InferenceEngine> = Arc::new(ObservedEngine::new(
//!     StubEngine::constant(block_descriptor("anomaly-gbdt"), Score::new(0.9)?),
//! ));
//! assert_eq!(engine.descriptor().model_id(), "anomaly-gbdt");
//! # Ok::<_, Box<dyn std::error::Error>>(())
//! ```
//!
//! # Double counting
//!
//! Wrapping is not idempotent: `ObservedEngine::new(ObservedEngine::new(e))`
//! would count every call twice. Nesting is meaningless — there is nothing to
//! layer between them — but it still compiles, so this is a doc contract, not
//! a type-level ban: **wrap exactly once, at the boot site that owns the
//! engine**, and hand the rest of the process an `Arc<dyn InferenceEngine>` it
//! cannot re-wrap by accident.
//!
//! Note the *inner* engine delegating between its own methods is not double
//! counting: `OrtEngine::infer` calls `OrtEngine::infer_batch` directly, below
//! this decorator, so one seam call is one observation either way.

use std::time::Instant;

use ml_features::FeatureVector;

use crate::descriptor::ModelDescriptor;
use crate::engine::{InferenceEngine, InferenceError, Score};
use crate::metrics::record_inference;

/// An [`InferenceEngine`] that records every call through
/// [`crate::metrics`] and delegates to `E`.
#[derive(Debug)]
pub struct ObservedEngine<E> {
    inner: E,
}

impl<E: InferenceEngine> ObservedEngine<E> {
    /// Wrap `inner`. Call this **once**, at the boot site that owns the
    /// engine: a nested `ObservedEngine<ObservedEngine<_>>` compiles and would
    /// double-count every call (see the module docs).
    pub fn new(inner: E) -> Self {
        Self { inner }
    }

    /// The wrapped engine — for a caller that needs a backend-specific method
    /// (`OrtEngine::session_count`, say) that the seam deliberately doesn't
    /// expose.
    pub fn inner(&self) -> &E {
        &self.inner
    }

    /// Unwrap, discarding the observation layer.
    pub fn into_inner(self) -> E {
        self.inner
    }
}

impl<E: InferenceEngine> InferenceEngine for ObservedEngine<E> {
    fn descriptor(&self) -> &ModelDescriptor {
        self.inner.descriptor()
    }

    fn infer(&self, features: &FeatureVector) -> Result<Score, InferenceError> {
        // Routed through `infer_batch` rather than duplicating the timing: one
        // observation site, and a single-vector call is genuinely a batch of
        // one everywhere it matters (the `vectors` counter included).
        let mut scores = self.infer_batch(std::slice::from_ref(features))?;
        scores.pop().ok_or_else(|| {
            InferenceError::new(
                self.descriptor().model_id(),
                crate::engine::InferenceErrorKind::MalformedOutput(
                    "a one-row batch produced no score".to_owned(),
                ),
            )
        })
    }

    fn infer_batch(&self, features: &[FeatureVector]) -> Result<Vec<Score>, InferenceError> {
        let started = Instant::now();
        let result = self.inner.infer_batch(features);
        // Deliberately after the call and before the `?`-free return: the
        // whole reason this is a wrapper is that timing must fire on the error
        // path too (§14's anti-pattern is a metric recorded only at the `Ok`).
        record_inference(
            self.descriptor().model_id(),
            started.elapsed(),
            features.len(),
            &result,
        );
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::{CALLS_TOTAL, FAILURES_TOTAL, SCORE, SECONDS, VECTORS_TOTAL};
    use crate::test_util::{block_descriptor, StubEngine};
    use detector_api::test_util::CtxBuilder;

    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::CompositeKey;

    type Series = Vec<(
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    )>;

    fn captured(f: impl FnOnce()) -> Series {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, f);
        snapshotter.snapshot().into_vec()
    }

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

    fn histogram_len(series: &Series, name: &str) -> usize {
        match value(series, name) {
            Some(DebugValue::Histogram(v)) => v.len(),
            _ => 0,
        }
    }

    fn block_vector() -> FeatureVector {
        ml_features::extract_block(&CtxBuilder::new().build())
    }

    #[test]
    fn a_single_infer_is_observed_as_a_batch_of_one() {
        let engine = ObservedEngine::new(StubEngine::constant(
            block_descriptor("anomaly-gbdt"),
            Score::new(0.6).unwrap(),
        ));
        let series = captured(|| {
            engine.infer(&block_vector()).expect("current version");
        });

        assert_eq!(counter(&series, CALLS_TOTAL), Some(1));
        assert_eq!(counter(&series, VECTORS_TOTAL), Some(1));
        assert_eq!(histogram_len(&series, SECONDS), 1);
        assert_eq!(histogram_len(&series, SCORE), 1);
    }

    #[test]
    fn a_batch_is_one_call_and_many_vectors() {
        let engine = ObservedEngine::new(StubEngine::constant(
            block_descriptor("anomaly-gbdt"),
            Score::ONE,
        ));
        let batch = vec![block_vector(), block_vector(), block_vector()];
        let series = captured(|| {
            engine.infer_batch(&batch).expect("current version");
        });

        assert_eq!(counter(&series, CALLS_TOTAL), Some(1), "one runtime call");
        assert_eq!(counter(&series, VECTORS_TOTAL), Some(3));
        assert_eq!(
            histogram_len(&series, SECONDS),
            1,
            "latency is per call, so `seconds / vectors` is the per-vector cost"
        );
        assert_eq!(histogram_len(&series, SCORE), 3);
    }

    /// The §14 anti-pattern, asserted directly: a hand-rolled metric at the
    /// `Ok` return would leave the error path uncounted, and the failure
    /// counter would drift from the call counter.
    #[test]
    fn the_error_path_is_timed_and_counted_too() {
        let engine = ObservedEngine::new(StubEngine::failing(
            block_descriptor("anomaly-gbdt"),
            "session gone",
        ));
        let batch = vec![block_vector(), block_vector()];
        let series = captured(|| {
            assert!(engine.infer_batch(&batch).is_err());
        });

        assert_eq!(counter(&series, CALLS_TOTAL), Some(1));
        assert_eq!(counter(&series, VECTORS_TOTAL), Some(2));
        assert_eq!(counter(&series, FAILURES_TOTAL), Some(1));
        assert_eq!(histogram_len(&series, SECONDS), 1, "timed on failure too");
        assert_eq!(histogram_len(&series, SCORE), 0);
    }

    #[test]
    fn a_skew_rejection_is_observed_as_a_skew_failure() {
        let engine = ObservedEngine::new(StubEngine::constant(
            crate::test_util::tx_descriptor("anomaly-gbdt"),
            Score::ONE,
        ));
        let series = captured(|| {
            assert!(engine.infer(&block_vector()).is_err());
        });
        assert_eq!(counter(&series, FAILURES_TOTAL), Some(1));
        let labeled = series
            .iter()
            .find(|(ck, _, _, _)| ck.key().name() == FAILURES_TOTAL)
            .map(|(ck, _, _, _)| {
                ck.key()
                    .labels()
                    .any(|l| l.key() == "reason" && l.value() == "skew")
            });
        assert_eq!(labeled, Some(true));
    }

    #[test]
    fn observation_is_transparent_to_the_seam() {
        // The decorator must not change behaviour — same descriptor, same
        // scores, same errors — or a consumer's tests would stop describing
        // production.
        let descriptor = block_descriptor("anomaly-gbdt");
        let bare = StubEngine::constant(descriptor.clone(), Score::new(0.33).unwrap());
        let observed = ObservedEngine::new(StubEngine::constant(
            descriptor.clone(),
            Score::new(0.33).unwrap(),
        ));
        let v = block_vector();

        assert_eq!(observed.descriptor(), bare.descriptor());
        assert_eq!(observed.infer(&v).unwrap(), bare.infer(&v).unwrap());
        assert_eq!(observed.inner().call_count(), 1);
    }

    #[test]
    fn recording_is_a_no_op_without_an_installed_exporter() {
        // Conventions §8: the library never depends on an exporter existing.
        // Outside `with_local_recorder` there is no global recorder in tests,
        // and the call must still be a plain success.
        let engine = ObservedEngine::new(StubEngine::constant(
            block_descriptor("anomaly-gbdt"),
            Score::ZERO,
        ));
        assert_eq!(engine.infer(&block_vector()).unwrap(), Score::ZERO);
    }
}
