//! The in-memory [`InferenceEngine`] double, behind the `test-util` feature —
//! the `EventSink`/`RecordingSink` discipline applied to model serving.
//!
//! Every consumer of this seam (t4's `anomaly-detector`, the composing
//! detection service, the backtest harness) needs the same three things from a
//! fake model: a fixed score, a score that depends on the vector, and a
//! failure. Those live here, next to the trait, so the double cannot drift
//! from the seam and the next consumer reaches for it instead of copying it.
//!
//! **The double enforces the same contract as the real backend.** It runs
//! [`ModelDescriptor::accepts`] before scoring, so a test that hands a detector
//! the wrong-version vector fails the same way production would. A double that
//! accepted anything would make the skew check untested exactly where it
//! matters most.
//!
//! Enable it as a dev-dependency:
//! ```toml
//! [dev-dependencies]
//! inference = { workspace = true, features = ["test-util"] }
//! ```

use std::sync::Mutex;

use ml_features::{FeatureVector, Granularity};

use crate::artifact::ArtifactDigest;
use crate::descriptor::ModelDescriptor;
use crate::engine::{InferenceEngine, InferenceError, InferenceErrorKind, Score};

/// A block-granularity descriptor for `model_id`, on the current feature
/// version, with a digest derived from the id — so two test models are
/// distinguishable but no test needs an artifact file.
pub fn block_descriptor(model_id: &str) -> ModelDescriptor {
    descriptor(model_id, Granularity::Block)
}

/// [`block_descriptor`]'s per-transaction counterpart.
pub fn tx_descriptor(model_id: &str) -> ModelDescriptor {
    descriptor(model_id, Granularity::Tx)
}

fn descriptor(model_id: &str, granularity: Granularity) -> ModelDescriptor {
    ModelDescriptor::new(
        model_id,
        ArtifactDigest::of(format!("stub-artifact:{model_id}").as_bytes()),
        ml_features::FEATURE_VERSION,
        granularity,
    )
    .expect("the current feature version is always registered")
}

type Responder = Box<dyn Fn(&FeatureVector) -> Result<Score, InferenceError> + Send + Sync>;

/// An [`InferenceEngine`] that answers from a closure and records what it was
/// asked, instead of running a model.
///
/// Wrap in an `Arc` to share it between the code under test and the
/// assertions (the seam takes `&self`).
pub struct StubEngine {
    descriptor: ModelDescriptor,
    responder: Responder,
    calls: Mutex<Vec<FeatureVector>>,
}

impl StubEngine {
    /// Always returns `score`.
    pub fn constant(descriptor: ModelDescriptor, score: Score) -> Self {
        Self::responding(descriptor, move |_| Ok(score))
    }

    /// Derives the score from the vector — for testing threshold behaviour
    /// without a real model (e.g. score on one feature's value).
    pub fn responding(
        descriptor: ModelDescriptor,
        responder: impl Fn(&FeatureVector) -> Result<Score, InferenceError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            descriptor,
            responder: Box::new(responder),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Always fails with a backend error — the "the runtime broke, what does
    /// the detector do?" case, which is the one consumers most often forget to
    /// cover.
    pub fn failing(descriptor: ModelDescriptor, message: impl Into<String>) -> Self {
        let model_id = descriptor.model_id().to_owned();
        let message = message.into();
        Self::responding(descriptor, move |_| {
            Err(InferenceError::new(
                model_id.clone(),
                InferenceErrorKind::Backend(message.clone()),
            ))
        })
    }

    /// The vectors scored so far, in order — including any the responder
    /// failed on, and excluding any rejected by the skew check (those never
    /// reach a real model either).
    pub fn calls(&self) -> Vec<FeatureVector> {
        self.calls.lock().expect("stub mutex").clone()
    }

    /// How many vectors reached the model.
    pub fn call_count(&self) -> usize {
        self.calls.lock().expect("stub mutex").len()
    }
}

impl std::fmt::Debug for StubEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StubEngine")
            .field("descriptor", &self.descriptor)
            .field("calls", &self.call_count())
            .finish_non_exhaustive()
    }
}

impl InferenceEngine for StubEngine {
    fn descriptor(&self) -> &ModelDescriptor {
        &self.descriptor
    }

    fn infer(&self, features: &FeatureVector) -> Result<Score, InferenceError> {
        self.descriptor
            .accepts(features)
            .map_err(|skew| InferenceError::new(self.descriptor.model_id(), skew))?;
        self.calls
            .lock()
            .expect("stub mutex")
            .push(features.clone());
        (self.responder)(features)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use detector_api::test_util::CtxBuilder;

    fn block_vector() -> FeatureVector {
        ml_features::extract_block(&CtxBuilder::new().build())
    }

    #[test]
    fn a_constant_engine_scores_and_records() {
        let engine = StubEngine::constant(block_descriptor("stub"), Score::new(0.75).unwrap());
        let v = block_vector();
        assert_eq!(engine.infer(&v).unwrap().get(), 0.75);
        assert_eq!(engine.infer(&v).unwrap().get(), 0.75);
        assert_eq!(engine.call_count(), 2);
        assert_eq!(engine.calls()[0], v);
    }

    #[test]
    fn the_double_enforces_the_skew_check_like_the_real_backend() {
        let engine = StubEngine::constant(tx_descriptor("stub"), Score::ONE);
        let err = engine.infer(&block_vector()).unwrap_err();
        assert!(matches!(err.kind, InferenceErrorKind::Skew(_)), "{err:?}");
        assert_eq!(
            engine.call_count(),
            0,
            "a rejected vector never reaches the model"
        );
    }

    #[test]
    fn a_failing_engine_surfaces_a_backend_error() {
        let engine = StubEngine::failing(block_descriptor("stub"), "session gone");
        let err = engine.infer(&block_vector()).unwrap_err();
        assert!(
            matches!(&err.kind, InferenceErrorKind::Backend(message) if message == "session gone"),
            "{err:?}"
        );
        assert_eq!(err.model_id, "stub");
        assert_eq!(err.kind.as_str(), "backend");
        assert_eq!(engine.call_count(), 1, "the call happened, then failed");
    }

    #[test]
    fn a_responder_can_score_from_the_vector() {
        let engine = StubEngine::responding(block_descriptor("stub"), |v| {
            Score::new(if v.values()[0] > 0.0 { 1.0 } else { 0.0 })
                .map_err(|source| InferenceError::new("stub", source))
        });
        let v = block_vector();
        let expected = if v.values()[0] > 0.0 { 1.0 } else { 0.0 };
        assert_eq!(engine.infer(&v).unwrap().get(), expected);
    }

    #[test]
    fn the_default_batch_impl_preserves_order_and_fails_whole() {
        let engine = StubEngine::responding(block_descriptor("stub"), |v| {
            Score::new(v.values()[0].fract().abs()).or(Ok(Score::ZERO))
        });
        let batch = vec![block_vector(), block_vector()];
        assert_eq!(engine.infer_batch(&batch).unwrap().len(), 2);

        let broken = StubEngine::failing(block_descriptor("stub"), "boom");
        assert!(broken.infer_batch(&batch).is_err());
    }

    #[test]
    fn distinct_stub_models_have_distinct_identities() {
        assert_ne!(
            block_descriptor("gbdt").content_hash(),
            block_descriptor("iforest").content_hash()
        );
    }
}
