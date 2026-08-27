//! The seam itself: [`InferenceEngine`] and the [`Score`] it returns.
//!
//! `InferenceEngine` is to model serving what `EventSink` is to publishing —
//! an object-safe trait with one production implementation (the `ort` backend)
//! and one in-memory double, so the *logic* that consumes scores (t4's
//! anomaly detector: thresholds, evidence assembly, top contributing features)
//! is unit-testable with no ONNX Runtime, no artifact, and no native library
//! anywhere near the test binary.
//!
//! Two shape decisions worth stating, because they aren't the obvious ones:
//!
//! - **`infer` is fallible.** §20.2 sketches it as `fn infer(&_) -> Score`.
//!   A real runtime call can fail — a malformed graph output, a poisoned
//!   session, a vector from the wrong feature version — and the alternative to
//!   a `Result` is a fabricated score, which is the one outcome a detection
//!   system must never produce. The caller decides what a failure means (t4:
//!   skip the candidate and count it in a metric); this seam refuses to decide
//!   for it. Every [`InferenceError`] is permanent for the input that caused
//!   it, so "decide" never means "retry".
//! - **The scored unit is a `FeatureVector`, not a `DetectionCtx`.** The
//!   engine cannot see the block, so it cannot become attribution-aware even
//!   by accident — the §6 blindness rule holds by construction on the serving
//!   side, exactly as `ml-features` makes it hold on the extraction side.

use ml_features::FeatureVector;

use crate::descriptor::{FeatureSkew, ModelDescriptor};

/// A model's output, normalised to a confidence in `[0, 1]`.
///
/// The seam's contract is a confidence because that is what the fast path
/// consumes: a detector's `raw_confidence` is a `Confidence` in `[0, 1]`
/// (§6), and a score that could be `-0.37` (an isolation forest's decision
/// function) or `12.4` (a GBDT margin) would push that mapping into every
/// call site. Backends declare how their raw output becomes a confidence —
/// see `onnx::Squash` — so the mapping is reviewable config, in one place,
/// instead of an ad-hoc `1.0 / (1.0 + (-x).exp())` scattered through detectors.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Score(f64);

impl Score {
    /// The zero-confidence score.
    pub const ZERO: Self = Self(0.0);
    /// The full-confidence score.
    pub const ONE: Self = Self(1.0);

    /// Build a score, rejecting anything outside `[0, 1]` or non-finite.
    ///
    /// A `NaN` from a runtime is the failure mode that hurts most: it compares
    /// false against every threshold, so a detector silently stops firing
    /// rather than erroring. Parsed at the boundary, it cannot get that far.
    pub fn new(value: f64) -> Result<Self, ScoreOutOfRange> {
        if value.is_finite() && (0.0..=1.0).contains(&value) {
            Ok(Self(value))
        } else {
            Err(ScoreOutOfRange { value })
        }
    }

    /// The confidence in `[0, 1]`.
    pub fn get(self) -> f64 {
        self.0
    }
}

impl std::fmt::Display for Score {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.6}", self.0)
    }
}

/// A model produced a value that is not a confidence.
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
#[error("model output {value} is not a confidence in [0, 1]")]
pub struct ScoreOutOfRange {
    pub value: f64,
}

/// The model-serving seam (§20.2).
///
/// Object-safe on purpose (the `EventSink` discipline): a detector holds an
/// `Arc<dyn InferenceEngine>` resolved once at boot, link-or-fail, and never
/// learns which backend is behind it.
///
/// Implementations must be cheap to call concurrently: inference runs inside
/// the detection scheduler's rayon fan-out (§15), on the < 1s fast path (§6).
pub trait InferenceEngine: Send + Sync + std::fmt::Debug {
    /// What this engine serves — weights, feature contract, arity. Boot logs
    /// it; the registry folds its
    /// [`content_hash`](ModelDescriptor::content_hash) into `config_hash`.
    fn descriptor(&self) -> &ModelDescriptor;

    /// Score one feature vector.
    fn infer(&self, features: &FeatureVector) -> Result<Score, InferenceError>;

    /// Score a batch, in order.
    ///
    /// The default implementation loops [`infer`](Self::infer) — correct for
    /// every backend, and all a test double needs. A real runtime overrides
    /// it: one `[N, features]` call amortises the per-call overhead across a
    /// block's transactions, which is the difference between one runtime
    /// invocation per block and one per transaction on the fast path.
    ///
    /// All-or-nothing by design: a batch is scored for one block, and a
    /// partially-scored block is a harder thing for a caller to reason about
    /// than a failed one. Score vectors individually if partial results are
    /// wanted.
    fn infer_batch(&self, features: &[FeatureVector]) -> Result<Vec<Score>, InferenceError> {
        features.iter().map(|f| self.infer(f)).collect()
    }
}

/// Why one inference did not produce a score, and which model it was.
///
/// Identity is attached **once**, on the outer struct, rather than repeated in
/// every variant — the same split as `onnx::OrtLoadError`/`OrtLoadKind`. That
/// is not only tidiness: it lets a caller match on *what happened* without
/// destructuring identity, which is exactly what the observability decorator
/// needs to derive its low-cardinality `reason` label
/// ([`InferenceErrorKind::as_str`]).
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("model {model_id}: {kind}")]
pub struct InferenceError {
    pub model_id: String,
    #[source]
    pub kind: InferenceErrorKind,
}

impl InferenceError {
    pub fn new(model_id: impl Into<String>, kind: impl Into<InferenceErrorKind>) -> Self {
        Self {
            model_id: model_id.into(),
            kind: kind.into(),
        }
    }
}

/// What went wrong, independent of which model it happened to.
///
/// **Every variant is permanent for the input that caused it** — there is no
/// transient case here, which is why this type deliberately does not
/// participate in the workspace's retry classification: re-running the same
/// vector through the same session fails identically. A caller's only sound
/// responses are to skip the candidate and count it, or (for a
/// [`Skew`](Self::Skew), which is a wiring bug) to fail loudly.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum InferenceErrorKind {
    /// The vector doesn't match what this model consumes (§20.5).
    #[error(transparent)]
    Skew(#[from] FeatureSkew),

    /// The runtime rejected the call. Carries the backend's message as text,
    /// deliberately: the seam must not leak an `ort` type into the detector
    /// logic, for the same reason `PublishError` doesn't leak an `rdkafka` one.
    #[error("inference backend failed: {0}")]
    Backend(String),

    /// The graph ran, but its output isn't the shape the deployment declared —
    /// a wrong output name, an unexpected dtype, a tensor too short for the
    /// configured element index. A model/config mismatch, caught rather than
    /// indexed past.
    #[error("produced an output this deployment cannot read: {0}")]
    MalformedOutput(String),

    /// The output was read, but isn't a confidence.
    #[error(transparent)]
    Score(#[from] ScoreOutOfRange),
}

impl InferenceErrorKind {
    /// A stable, finite label for metrics and logs.
    ///
    /// Deliberately derived from the variant rather than the message: a
    /// `reason` label built from `to_string()` would carry the backend's own
    /// error text and blow up Prometheus label cardinality on the first noisy
    /// failure (§19).
    pub fn as_str(&self) -> &'static str {
        match self {
            InferenceErrorKind::Skew(_) => "skew",
            InferenceErrorKind::Backend(_) => "backend",
            InferenceErrorKind::MalformedOutput(_) => "malformed_output",
            InferenceErrorKind::Score(_) => "score_out_of_range",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_score_is_a_confidence() {
        assert_eq!(Score::new(0.0).unwrap(), Score::ZERO);
        assert_eq!(Score::new(1.0).unwrap(), Score::ONE);
        assert_eq!(Score::new(0.25).unwrap().get(), 0.25);
    }

    #[test]
    fn out_of_range_and_nan_are_refused() {
        for bad in [-0.001, 1.001, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(Score::new(bad).is_err(), "{bad} should not be a Score");
        }
    }

    #[test]
    fn scores_order_by_confidence() {
        assert!(Score::new(0.9).unwrap() > Score::new(0.1).unwrap());
    }

    #[test]
    fn the_seam_is_object_safe() {
        // The whole point of the trait's shape: a detector holds one of these.
        fn takes_dyn(_: &dyn InferenceEngine) {}
        let engine = crate::test_util::StubEngine::constant(
            crate::test_util::block_descriptor("obj-safe"),
            Score::new(0.5).unwrap(),
        );
        takes_dyn(&engine);
    }
}
