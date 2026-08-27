//! Deployment config for the ONNX backend — resolved once, at boot
//! (conventions §9), and hashed into the model's identity.
//!
//! Everything here describes *how to read a particular artifact*: which output
//! carries the score, which element of it, and how that number becomes a
//! confidence. It is config rather than code because the two models §20.2 asks
//! for read differently — a supervised classifier's positive-class probability
//! is already in `[0, 1]`, while an isolation forest's decision function is a
//! signed margin whose *negative* side is the anomalous one — and neither
//! should require a new backend.

use std::num::NonZeroUsize;
use std::path::PathBuf;

use ml_features::{FeatureVersion, Granularity};
use serde::{Deserialize, Serialize};

use crate::artifact::ArtifactDigest;
use crate::engine::{Score, ScoreOutOfRange};

/// One deployed ONNX model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrtConfig {
    /// The model's name in logs, metrics and evidence.
    pub model_id: String,

    /// Where the `.onnx` artifact lives — a file the deployment mounts, read
    /// once at boot.
    pub artifact_path: PathBuf,

    /// The artifact digest this deployment expects, if pinned.
    ///
    /// Optional, and the option is the point: a first deploy has nothing to
    /// pin, but once pinned this is what stops a weight swap from reaching
    /// production without a new registry triple (§20.2). Set it from the
    /// digest the previous boot logged.
    #[serde(default)]
    pub expected_artifact: Option<ArtifactDigest>,

    /// The `ml-features` version the artifact was **trained** against — not
    /// necessarily the one this build extracts by default. Checked against the
    /// version registry at boot (§20.5).
    pub feature_version: FeatureVersion,

    /// Whether the model consumes block-level or per-transaction vectors.
    pub granularity: Granularity,

    /// How to turn the graph's output into a [`Score`](crate::Score).
    #[serde(default)]
    pub output: OutputMapping,

    /// How many independent sessions to hold.
    ///
    /// ONNX Runtime's `Run` is *not* thread-safe in `ort`'s model (its own
    /// docs recommend one session per thread), so each session is behind a
    /// lock and the pool is what stops inference from serialising the
    /// detection scheduler's rayon fan-out (§15). One is right for a
    /// block-granularity model called once per block; a per-transaction model
    /// wants roughly the fan-out width. Sessions of a GBDT / isolation forest
    /// are small, but they are not free — this is a deliberate knob, not a
    /// "set it to the core count and forget" default.
    #[serde(default = "one")]
    pub sessions: NonZeroUsize,

    /// Intra-op threads *per session*. Defaults to 1 deliberately: the fan-out
    /// above is already parallel, and letting each session spawn its own
    /// thread pool inside a rayon worker oversubscribes the box — the same
    /// reason the simulation workers don't nest pools.
    #[serde(default = "one")]
    pub intra_threads: NonZeroUsize,

    /// Explicit path to the ONNX Runtime shared library. `None` falls back to
    /// `ORT_DYLIB_PATH`, then to the platform default name on the loader path.
    ///
    /// The runtime is loaded dynamically rather than linked, so the build
    /// stays hermetic (see this crate's manifest); the cost is that its
    /// location is a deployment fact, and this is where it is stated.
    #[serde(default)]
    pub dylib_path: Option<PathBuf>,
}

fn one() -> NonZeroUsize {
    NonZeroUsize::MIN
}

/// Which number in the graph's output is the score, and what it means.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct OutputMapping {
    /// Which graph output to read.
    #[serde(default)]
    pub output: OutputRef,

    /// Which element *within one row* of that output. A regressor emitting
    /// `[N, 1]` (or `[N]`) uses `0`; a binary classifier emitting `[N, 2]`
    /// probabilities uses `1` for the positive class.
    #[serde(default)]
    pub element: usize,

    /// How the raw number becomes a confidence.
    #[serde(default)]
    pub squash: Squash,
}

impl OutputMapping {
    /// Read one row of the graph's output into a confidence.
    ///
    /// The pure half of the backend (conventions §1): everything about
    /// *interpreting* a model's numbers lives here, testable without an ONNX
    /// Runtime anywhere in sight, while the engine keeps only the parts that
    /// genuinely need a session. The caller attaches the model id and output
    /// name to the error — this function doesn't know them.
    pub(crate) fn score(&self, row: &[f32]) -> Result<Score, RowError> {
        let raw = *row.get(self.element).ok_or(RowError::TooShort {
            width: row.len(),
            element: self.element,
        })?;
        Score::new(self.squash.apply(f64::from(raw))).map_err(RowError::NotAConfidence)
    }
}

/// Why one output row could not be read as a score. Turned into an
/// `InferenceError` by the engine, which knows which model and output it was.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum RowError {
    /// The configured element index is past the end of the row — the output
    /// has fewer columns than the deployment assumed (e.g. `element: 1` for
    /// the positive class against a single-column regressor output).
    TooShort { width: usize, element: usize },
    /// The squashed value isn't in `[0, 1]`. With `Squash::Unit` this is the
    /// misconfiguration the enum's docs warn about: a signed margin read as a
    /// probability.
    NotAConfidence(ScoreOutOfRange),
}

/// A graph output, by position or by name. Name is preferable in config — it
/// survives a re-export that reorders outputs — but position is what a
/// single-output model needs and is therefore the default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputRef {
    Index(usize),
    Name(String),
}

impl Default for OutputRef {
    fn default() -> Self {
        Self::Index(0)
    }
}

impl std::fmt::Display for OutputRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputRef::Index(i) => write!(f, "output #{i}"),
            OutputRef::Name(n) => write!(f, "output {n:?}"),
        }
    }
}

/// How a raw model output maps onto `[0, 1]`.
///
/// Declared per deployment rather than inferred, because guessing wrong is
/// silent: a signed margin read as a probability yields a score that is *out
/// of range half the time and plausible the other half*. Stating it means a
/// mismatch fails at the first inference with a range error naming the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Squash {
    /// Already a probability. Values outside `[0, 1]` are an error, not
    /// something to clamp — clamping would hide exactly the misconfiguration
    /// this enum exists to catch.
    #[default]
    Unit,

    /// Logistic on a signed margin: higher raw value ⇒ higher confidence.
    Logistic,

    /// Logistic on a *negated* signed margin: lower raw value ⇒ higher
    /// confidence. This is the isolation-forest shape — `decision_function` is
    /// negative for outliers, so "how anomalous" is the negated margin.
    NegatedLogistic,
}

impl Squash {
    /// Apply the mapping. Total: `Unit` passes the value through (the range
    /// check happens at `Score::new`), and both logistic forms are finite for
    /// every finite input and saturate rather than overflow at the extremes.
    ///
    /// `exp` is the platform's, not `libm`'s (contrast `ml-features`, which
    /// pins `log10` for bit-exact datasets): ONNX inference itself is not
    /// bit-reproducible across CPUs and runtime versions, so pinning the last
    /// ulp of the squash would buy nothing. A model's *identity* is
    /// reproducible — its artifact digest — its floating-point output is not.
    pub fn apply(self, raw: f64) -> f64 {
        match self {
            Squash::Unit => raw,
            Squash::Logistic => logistic(raw),
            Squash::NegatedLogistic => logistic(-raw),
        }
    }
}

fn logistic(x: f64) -> f64 {
    // `1/(1+e^-x)` overflows `e^-x` for very negative x; the algebraically
    // equivalent branch keeps both tails finite and inside [0, 1].
    if x >= 0.0 {
        1.0 / (1.0 + (-x).exp())
    } else {
        let e = x.exp();
        e / (1.0 + e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_deserializes_with_boot_defaults() {
        let config: OrtConfig = serde_json::from_str(
            r#"{
                "model_id": "anomaly-gbdt",
                "artifact_path": "/models/anomaly-gbdt.onnx",
                "feature_version": 1,
                "granularity": "tx"
            }"#,
        )
        .expect("the required fields are id, path, version, granularity");

        assert_eq!(config.model_id, "anomaly-gbdt");
        assert_eq!(config.expected_artifact, None);
        assert_eq!(config.sessions.get(), 1);
        assert_eq!(config.intra_threads.get(), 1);
        assert_eq!(config.output, OutputMapping::default());
        assert_eq!(config.output.output, OutputRef::Index(0));
        assert_eq!(config.output.squash, Squash::Unit);
    }

    #[test]
    fn a_pinned_artifact_and_named_output_round_trip() {
        let digest = ArtifactDigest::of(b"weights");
        let json = format!(
            r#"{{
                "model_id": "iforest",
                "artifact_path": "/models/iforest.onnx",
                "expected_artifact": "{}",
                "feature_version": 1,
                "granularity": "block",
                "output": {{ "output": {{ "name": "scores" }}, "element": 0,
                             "squash": "negated_logistic" }},
                "sessions": 4
            }}"#,
            digest.to_hex()
        );
        let config: OrtConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.expected_artifact, Some(digest));
        assert_eq!(config.output.output, OutputRef::Name("scores".into()));
        assert_eq!(config.output.squash, Squash::NegatedLogistic);
        assert_eq!(config.sessions.get(), 4);
        assert_eq!(
            serde_json::from_str::<OrtConfig>(&serde_json::to_string(&config).unwrap()).unwrap(),
            config
        );
    }

    #[test]
    fn a_mistyped_digest_fails_at_config_load_not_at_first_mismatch() {
        let err = serde_json::from_str::<OrtConfig>(
            r#"{"model_id":"m","artifact_path":"/m.onnx","feature_version":1,
                "granularity":"block","expected_artifact":"abcd"}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("32 bytes"), "{err}");
    }

    #[test]
    fn unit_passes_through() {
        assert_eq!(Squash::Unit.apply(0.25), 0.25);
        // Deliberately *not* clamped — the range check is Score::new's job.
        assert_eq!(Squash::Unit.apply(-3.0), -3.0);
    }

    #[test]
    fn logistic_is_monotonic_centred_and_bounded() {
        assert_eq!(Squash::Logistic.apply(0.0), 0.5);
        assert!(Squash::Logistic.apply(1.0) > Squash::Logistic.apply(-1.0));
        for x in [-1e300, -800.0, -1.0, 0.0, 1.0, 800.0, 1e300] {
            let y = Squash::Logistic.apply(x);
            assert!(y.is_finite() && (0.0..=1.0).contains(&y), "{x} -> {y}");
        }
    }

    #[test]
    fn a_probability_row_reads_the_configured_class() {
        // A binary classifier's `[1, 2]` probabilities: element 1 is P(positive).
        let mapping = OutputMapping {
            element: 1,
            ..OutputMapping::default()
        };
        assert_eq!(mapping.score(&[0.3, 0.7]).unwrap().get(), 0.7_f32 as f64);
    }

    #[test]
    fn a_single_column_regressor_row_reads_element_zero() {
        assert_eq!(
            OutputMapping::default().score(&[0.42]).unwrap().get(),
            0.42_f32 as f64
        );
    }

    #[test]
    fn an_element_past_the_row_is_a_config_error_not_a_panic() {
        let mapping = OutputMapping {
            element: 1,
            ..OutputMapping::default()
        };
        assert_eq!(
            mapping.score(&[0.42]),
            Err(RowError::TooShort {
                width: 1,
                element: 1
            })
        );
    }

    #[test]
    fn a_margin_read_as_a_probability_fails_loudly() {
        // The misconfiguration `Squash` exists to catch: an isolation forest's
        // decision function fed through `Unit`. Refused, not clamped — a
        // clamp would turn every anomalous margin into a confident 0.0.
        let err = OutputMapping::default().score(&[-1.7]).unwrap_err();
        assert!(matches!(err, RowError::NotAConfidence(_)), "{err:?}");
    }

    #[test]
    fn the_same_margin_under_the_right_squash_is_a_high_confidence() {
        let mapping = OutputMapping {
            squash: Squash::NegatedLogistic,
            ..OutputMapping::default()
        };
        assert!(mapping.score(&[-1.7]).unwrap().get() > 0.8);
    }

    #[test]
    fn the_negated_form_makes_a_more_negative_margin_more_confident() {
        // An isolation forest: decision_function << 0 is "very anomalous".
        let anomalous = Squash::NegatedLogistic.apply(-2.0);
        let normal = Squash::NegatedLogistic.apply(2.0);
        assert!(anomalous > normal, "{anomalous} !> {normal}");
        assert_eq!(Squash::NegatedLogistic.apply(0.0), 0.5);
    }
}
