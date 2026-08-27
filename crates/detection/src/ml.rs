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
use inference::{InferenceEngine, ObservedEngine};
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
    /// measured against.
    pub baseline: PathBuf,
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

/// Build the ML detector from the config file `ANOMALY_CONFIG_ENV` names, or
/// `Ok(None)` when it is unset.
///
/// The `Vec` return shape is what
/// [`register_builtins_with`](crate::registry::register_builtins_with) takes,
/// so a binary's boot path reads the same whether or not ML is deployed.
pub fn anomaly_detector_from_env() -> Result<Vec<Arc<dyn DetectorPlugin>>, MlBootError> {
    let Ok(path) = std::env::var(ANOMALY_CONFIG_ENV) else {
        tracing::info!("{ANOMALY_CONFIG_ENV} is unset — running without the ML detector (§20.2)");
        return Ok(Vec::new());
    };
    let detector = load_anomaly_detector(Path::new(&path))?;
    Ok(vec![Arc::new(detector)])
}

/// Load, validate and wire the ML detector from one config file.
///
/// Separate from the env read so the whole boot path is drivable from a test
/// (and from a future `detection validate-models` arm) without touching the
/// process environment.
pub fn load_anomaly_detector(path: &Path) -> Result<AnomalyDetector, MlBootError> {
    let config: MlConfig = read_json(path)?;

    let mut slots = Vec::new();
    if let Some(deployment) = config.supervised {
        slots.push(load_slot("supervised", deployment, ModelSlot::supervised)?);
    }
    if let Some(deployment) = config.novelty {
        slots.push(load_slot("novelty", deployment, ModelSlot::novelty)?);
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

    Ok(detector)
}

fn load_slot(
    role: &'static str,
    deployment: ModelDeployment,
    build: fn(
        Arc<dyn InferenceEngine>,
        FeatureBaseline,
    ) -> Result<ModelSlot, anomaly_detector::WiringError>,
) -> Result<ModelSlot, MlBootError> {
    let baseline = load_baseline(&deployment.baseline)?;
    // Wrapped **once**, here, in the observability decorator: conventions §14's
    // thin observed outer expressed over the seam, so no backend and no call
    // path can ship unmeasured — and nesting it twice would double-count.
    let engine = OrtEngine::load(deployment.model).map_err(|source| MlBootError::Engine {
        role,
        source: Box::new(source),
    })?;
    let engine: Arc<dyn InferenceEngine> = Arc::new(ObservedEngine::new(engine));
    build(engine, baseline).map_err(|source| MlBootError::Wiring { source })
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
        assert!(anomaly_detector_from_env().unwrap().is_empty());
    }
}
