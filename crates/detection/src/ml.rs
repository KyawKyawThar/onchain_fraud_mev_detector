//! Boot wiring for the ML detector (§20.2) — behind the `anomaly` feature.
//!
//! Every other detector is a compile-time constant: `register_builtins` calls
//! `sandwich_detector::plugin()` and that is the whole story. The ML detector
//! cannot be, because two of its inputs are *files a deployment mounts* — the
//! ONNX artifacts and the training-window baselines exported beside them. This
//! module is the effectful shell that turns those files into a detector, and
//! it is deliberately the only asymmetry: once built, the detector goes into
//! the same roster, gets the same [`ModelCard`](crate::model::ModelCard), and
//! is staged by the same [`RolloutPolicy`](crate::model::RolloutPolicy) as any
//! heuristic detector. ML gets no path around the gates (§20.2).
//!
//! # Nothing is discovered at block time
//!
//! [`load_anomaly_detector`] does all of it at boot, link-or-fail: read and
//! digest each artifact, check any pinned digest, resolve the trained
//! `feature_version` through the feature registry (§20.5 skew), build the
//! sessions, validate the graph, run a probe inference, parse each baseline
//! against the live schema, and refuse the pairing if a baseline does not
//! describe the vectors its model consumes. A deployment that is going to fail
//! fails before the first block, not on it.
//!
//! # One config file, not eight environment variables
//!
//! An ML deployment is a *set* of related facts — two artifacts, two
//! baselines, output mappings, thresholds — that only make sense together, so
//! it is one JSON document named by one variable
//! ([`ANOMALY_CONFIG_ENV`]), the same shape as the committed
//! `model_performance.json` the rollout gate reads. Unset means no ML detector,
//! and the service behaves exactly as it did before this landed.
//!
//! ```json
//! {
//!   "detector": { "novelty_min_score": 0.93 },
//!   "supervised": {
//!     "baseline": "/models/gbdt-baseline.json",
//!     "drift": { "window": 512, "max_age_seconds": 900, "threshold": 3.0 },
//!     "model": {
//!       "model_id": "anomaly-gbdt",
//!       "artifact_path": "/models/gbdt.onnx",
//!       "feature_version": 1,
//!       "granularity": "tx",
//!       "sessions": 8,
//!       "output": { "output": { "name": "probabilities" }, "element": 1, "squash": "unit" }
//!     }
//!   },
//!   "novelty": {
//!     "baseline": "/models/iforest-baseline.json",
//!     "model": {
//!       "model_id": "anomaly-iforest",
//!       "artifact_path": "/models/iforest.onnx",
//!       "feature_version": 1,
//!       "granularity": "block",
//!       "output": { "output": { "name": "scores" }, "element": 0, "squash": "negated_logistic" }
//!     }
//!   }
//! }
//! ```
//!
//! The deployment must also provide the ONNX Runtime shared library
//! (`ORT_DYLIB_PATH`, or `dylib_path` per model) — `ort` is loaded, not linked.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anomaly_detector::{AnomalyConfig, AnomalyDetector, ModelSlot};
use detector_api::DetectorPlugin;
use inference::onnx::{OrtConfig, OrtEngine};
use inference::{DriftConfig, DriftEngine, DriftSource, InferenceEngine, ObservedEngine};
use ml_features::{BaselineSnapshot, FeatureBaseline};
use serde::{Deserialize, Serialize};

/// Environment variable naming the ML deployment's JSON config. Unset → no ML
/// detector.
pub const ANOMALY_CONFIG_ENV: &str = "DETECTION_ANOMALY_CONFIG";

/// One deployed model: how to serve it, and the training snapshot its findings
/// are explained against.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelDeployment {
    /// How to load and read the artifact (§20.2).
    pub model: OrtConfig,
    /// Path to the [`BaselineSnapshot`] JSON exported by the training run that
    /// produced `model` — the distribution its "top contributing features" are
    /// measured against, and the training snapshot the §20.5 drift monitor
    /// compares serving-time vectors to.
    pub baseline: PathBuf,
    /// Drift monitoring for this model (§20.5). Absent means monitored with
    /// the shipped defaults — an omitted section must not be a quiet way to
    /// stop watching a model, so turning it off takes an explicit
    /// `"drift": {"disabled": true}`.
    #[serde(default)]
    pub drift: DriftConfig,
}

/// The ML detector's whole deployment.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlConfig {
    /// Thresholds and explanation policy. Absent means the shipped defaults.
    #[serde(default)]
    pub detector: AnomalyConfig,
    /// The supervised GBDT scorer, if this deployment serves one.
    #[serde(default)]
    pub supervised: Option<ModelDeployment>,
    /// The isolation-forest novelty model, if this deployment serves one.
    #[serde(default)]
    pub novelty: Option<ModelDeployment>,
}

/// The ML detector could not be wired. Every variant is a refused boot: a
/// service that starts with a half-loaded model would emit evidence nobody can
/// reproduce (§6, §18).
#[derive(Debug, thiserror::Error)]
pub enum MlBootError {
    #[error("reading {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("parsing {path}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("the baseline at {path} does not describe a schema this build can extract")]
    Baseline {
        path: PathBuf,
        #[source]
        source: ml_features::BaselineError,
    },

    #[error("loading the {role} model")]
    Engine {
        role: &'static str,
        #[source]
        source: Box<inference::onnx::OrtLoadError>,
    },

    #[error("wiring the anomaly detector")]
    Wiring {
        #[source]
        source: anomaly_detector::WiringError,
    },

    #[error(
        "{path} configures no models — remove {ANOMALY_CONFIG_ENV} to run without the ML \
         detector, or name at least one of `supervised`/`novelty`"
    )]
    NoModelsConfigured { path: PathBuf },
}

/// Everything a boot needs from one ML config file: the detector to register,
/// and the drift monitors to drain (§20.5).
///
/// The two travel together because they are two views of the *same* engines —
/// the detector holds them as `Arc<dyn InferenceEngine>` to score with, the
/// publisher holds them as `Arc<dyn DriftSource>` to drain, and both point at
/// one allocation. Returning them separately would let a caller wire a detector
/// whose monitors nobody reads, which is the silent-degradation case this whole
/// task exists to close.
///
/// `Default` is the no-ML deployment: empty on both sides, so a binary's boot
/// path reads identically whether or not a bundle is configured.
#[derive(Default)]
pub struct MlDeployment {
    /// Ready for [`register_builtins_with`](crate::registry::register_builtins_with).
    pub detectors: Vec<Arc<dyn DetectorPlugin>>,
    /// One per served model with drift monitoring on, ready for
    /// [`DriftPublisher`](crate::drift::DriftPublisher).
    pub drift_sources: Vec<Arc<dyn DriftSource>>,
}

impl std::fmt::Debug for MlDeployment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `dyn DetectorPlugin` isn't `Debug` (the same reason `Registry` and
        // `DetectionPlan` hand-roll theirs); show what a boot log actually
        // wants — how much was wired.
        f.debug_struct("MlDeployment")
            .field("detectors", &self.detectors.len())
            .field(
                "monitored_models",
                &self
                    .drift_sources
                    .iter()
                    .map(|s| s.model_id())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Build the ML deployment from the config file `ANOMALY_CONFIG_ENV` names, or
/// an empty one when it is unset.
pub fn anomaly_detector_from_env() -> Result<MlDeployment, MlBootError> {
    let Ok(path) = std::env::var(ANOMALY_CONFIG_ENV) else {
        tracing::info!("{ANOMALY_CONFIG_ENV} is unset — running without the ML detector (§20.2)");
        return Ok(MlDeployment::default());
    };
    let (detector, drift_sources) = load_anomaly_deployment(Path::new(&path))?;
    Ok(MlDeployment {
        detectors: vec![Arc::new(detector)],
        drift_sources,
    })
}

/// Load, validate and wire the ML detector from one config file.
///
/// Separate from the env read so the whole boot path is drivable from a test
/// (and from a future `detection validate-models` arm) without touching the
/// process environment.
pub fn load_anomaly_detector(path: &Path) -> Result<AnomalyDetector, MlBootError> {
    load_anomaly_deployment(path).map(|(detector, _)| detector)
}

/// [`load_anomaly_detector`], also returning the drift monitors to drain.
///
/// Separate from the above so `detection check-models` — which validates a
/// bundle and exits — is not handed monitors nobody will ever drain.
pub fn load_anomaly_deployment(
    path: &Path,
) -> Result<(AnomalyDetector, Vec<Arc<dyn DriftSource>>), MlBootError> {
    let config: MlConfig = read_json(path)?;

    let mut slots = Vec::new();
    let mut drift_sources = Vec::new();
    if let Some(deployment) = config.supervised {
        let loaded = load_slot("supervised", deployment, ModelSlot::supervised)?;
        slots.push(loaded.slot);
        drift_sources.extend(loaded.drift);
    }
    if let Some(deployment) = config.novelty {
        let loaded = load_slot("novelty", deployment, ModelSlot::novelty)?;
        slots.push(loaded.slot);
        drift_sources.extend(loaded.drift);
    }
    if slots.is_empty() {
        return Err(MlBootError::NoModelsConfigured {
            path: path.to_path_buf(),
        });
    }

    let detector = AnomalyDetector::new(config.detector, slots)
        .map_err(|source| MlBootError::Wiring { source })?;

    for slot in detector.models() {
        let descriptor = slot.engine().descriptor();
        // Running one feature version behind is a legitimate rollout state, not
        // an error (§20.5) — `ml-features` keeps shipped versions linkable
        // forever precisely so serving needn't move in lockstep with
        // extraction. It is worth *saying* at boot, though: it is also what a
        // drift investigation asks about first.
        if !descriptor.is_current_feature_version() {
            tracing::warn!(
                role = %slot.role(),
                model = descriptor.model_id(),
                trained_on = %descriptor.feature_version(),
                current = %ml_features::FEATURE_VERSION,
                "serving a model trained on an older feature schema"
            );
        }
        tracing::info!(
            role = %slot.role(),
            model = descriptor.model_id(),
            artifact = %descriptor.artifact(),
            feature_version = %descriptor.feature_version(),
            granularity = ?descriptor.granularity(),
            baseline = %slot.baseline().content_hash(),
            "loaded ML model"
        );
    }

    Ok((detector, drift_sources))
}

/// One model slot plus, unless the deployment turned it off, the drift monitor
/// watching the same engine.
struct LoadedSlot {
    slot: ModelSlot,
    drift: Option<Arc<dyn DriftSource>>,
}

fn load_slot(
    role: &'static str,
    deployment: ModelDeployment,
    build: fn(
        Arc<dyn InferenceEngine>,
        FeatureBaseline,
    ) -> Result<ModelSlot, anomaly_detector::WiringError>,
) -> Result<LoadedSlot, MlBootError> {
    let baseline = load_baseline(&deployment.baseline)?;
    let engine = OrtEngine::load(deployment.model).map_err(|source| MlBootError::Engine {
        role,
        source: Box::new(source),
    })?;

    // Two decorators, wrapped **once** each, here — this is the boot site that
    // owns the engine, and nesting either twice would double-count.
    //
    //   DriftEngine      §20.5: the served vectors vs. the training snapshot
    //     └ ObservedEngine  §19/§14: latency, throughput, failures, scores
    //         └ OrtEngine   the runtime
    //
    // Drift on the outside so `model_inference_duration_seconds` measures
    // inference and not inference-plus-bookkeeping — that histogram is what
    // the < 1s fast-path budget is checked against (§6, §20.2). The drift
    // monitor's own cost still lands inside the detector's
    // `detector_detect_duration_seconds`, which is where it belongs.
    let observed = ObservedEngine::new(engine);
    let (engine, drift): (Arc<dyn InferenceEngine>, Option<Arc<dyn DriftSource>>) =
        if deployment.drift.disabled {
            tracing::warn!(
                role,
                "drift monitoring is disabled for this model — serving-time feature \
                 distributions will not be compared against the training snapshot (§20.5)"
            );
            (Arc::new(observed), None)
        } else {
            // Both halves need the same baseline: the detector explains findings
            // against it, the monitor measures drift against it — which is the
            // point of it living in `ml-features` rather than in either. Cloned
            // rather than `Arc`-shared because it is immutable and this is a
            // one-off boot-time `Vec<FeatureStats>` copy, not a hot path.
            let monitored = Arc::new(DriftEngine::new(
                observed,
                baseline.clone(),
                deployment.drift,
            ));
            // ONE allocation, two views: the detector scores through
            // `InferenceEngine`, the publisher drains through `DriftSource`.
            // Building two objects here would monitor an engine nobody serves.
            let engine: Arc<dyn InferenceEngine> = monitored.clone();
            let drift: Arc<dyn DriftSource> = monitored;
            (engine, Some(drift))
        };
    let slot = build(engine, baseline).map_err(|source| MlBootError::Wiring { source })?;
    Ok(LoadedSlot { slot, drift })
}

fn load_baseline(path: &Path) -> Result<FeatureBaseline, MlBootError> {
    let snapshot: BaselineSnapshot = read_json(path)?;
    snapshot
        .into_baseline()
        .map_err(|source| MlBootError::Baseline {
            path: path.to_path_buf(),
            source,
        })
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, MlBootError> {
    let text = std::fs::read_to_string(path).map_err(|source| MlBootError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&text).map_err(|source| MlBootError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A config naming both models, as a deployment would write it.
    const BOTH: &str = r#"{
        "detector": { "novelty_min_score": 0.93 },
        "supervised": {
            "baseline": "/models/gbdt-baseline.json",
            "model": {
                "model_id": "anomaly-gbdt",
                "artifact_path": "/models/gbdt.onnx",
                "feature_version": 1,
                "granularity": "tx",
                "output": { "output": { "name": "probabilities" }, "element": 1, "squash": "unit" }
            }
        },
        "novelty": {
            "baseline": "/models/iforest-baseline.json",
            "model": {
                "model_id": "anomaly-iforest",
                "artifact_path": "/models/iforest.onnx",
                "feature_version": 1,
                "granularity": "block",
                "output": { "output": { "name": "scores" }, "element": 0, "squash": "negated_logistic" }
            }
        }
    }"#;

    #[test]
    fn the_documented_config_parses_into_both_deployments() {
        let config: MlConfig = serde_json::from_str(BOTH).expect("the module docs' example");
        assert_eq!(config.detector.novelty_min_score, 0.93);
        assert_eq!(
            config.detector.supervised_min_score,
            anomaly_detector::DEFAULT_SUPERVISED_MIN_SCORE,
            "an unstated threshold inherits the shipped default"
        );

        let supervised = config.supervised.expect("named in the config");
        assert_eq!(supervised.model.model_id, "anomaly-gbdt");
        assert_eq!(
            supervised.drift,
            inference::DriftConfig::default(),
            "an unstated drift section means monitored with the shipped defaults (§20.5)"
        );
        assert_eq!(supervised.model.granularity, ml_features::Granularity::Tx);
        assert_eq!(supervised.model.output.element, 1);
        assert_eq!(
            supervised.baseline,
            PathBuf::from("/models/gbdt-baseline.json")
        );

        let novelty = config.novelty.expect("named in the config");
        assert_eq!(
            novelty.model.output.squash,
            inference::onnx::Squash::NegatedLogistic,
            "the isolation-forest shape: a negative margin is the anomalous side"
        );
    }

    #[test]
    fn a_deployment_may_serve_one_model() {
        let config: MlConfig = serde_json::from_str(
            r#"{"novelty": {"baseline": "b.json", "model": {
                "model_id": "m", "artifact_path": "m.onnx",
                "feature_version": 1, "granularity": "block"}}}"#,
        )
        .unwrap();
        assert!(config.supervised.is_none());
        assert!(config.novelty.is_some());
        assert_eq!(config.detector, AnomalyConfig::default());
    }

    #[test]
    fn a_typo_in_the_config_fails_at_boot_rather_than_being_ignored() {
        // `deny_unknown_fields` throughout: a misspelled key that silently left
        // a default in place is exactly the kind of "config says A, reality is
        // B" this crate refuses for weights.
        for bad in [
            r#"{"noveltie": {}}"#,
            r#"{"novelty": {"baselines": "b.json", "model": {}}}"#,
            r#"{"detector": {"novelty_min_scores": 0.9}}"#,
            r#"{"novelty": {"baseline": "b.json", "drift": {"windows": 512}, "model": {
                "model_id": "m", "artifact_path": "m.onnx",
                "feature_version": 1, "granularity": "block"}}}"#,
        ] {
            assert!(serde_json::from_str::<MlConfig>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn an_empty_config_names_no_models_and_is_refused() {
        // Reached through the real loader, so the error names the file an
        // operator has to fix.
        let dir = std::env::temp_dir().join("detection-ml-empty-config");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("anomaly.json");
        std::fs::write(&path, "{}").unwrap();

        let err = load_anomaly_detector(&path).expect_err("no models configured");
        assert!(
            matches!(&err, MlBootError::NoModelsConfigured { path: p } if p == &path),
            "{err}"
        );
        assert!(err.to_string().contains(ANOMALY_CONFIG_ENV), "{err}");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_missing_file_names_the_path_it_could_not_read() {
        let path = Path::new("/nonexistent/anomaly.json");
        let err = load_anomaly_detector(path).expect_err("no such file");
        assert!(
            matches!(&err, MlBootError::Read { path: p, .. } if p == path),
            "{err}"
        );
    }

    #[test]
    fn an_unset_env_var_means_no_ml_detector_not_a_failure() {
        // The default deployment. Asserted because the alternative — erroring
        // when ML is simply not deployed — would make every existing install
        // fail to boot on upgrade.
        std::env::remove_var(ANOMALY_CONFIG_ENV);
        let deployment = anomaly_detector_from_env().expect("an unset variable is not an error");
        assert!(deployment.detectors.is_empty());
        assert!(
            deployment.drift_sources.is_empty(),
            "no models means nothing to monitor either (§20.5)"
        );
    }
}
