//! The two models §20.2 asks for, and the boot-time wiring that pairs each
//! one with the baseline its findings are explained against.
//!
//! A [`ModelSlot`] is a served model plus its training-window
//! [`FeatureBaseline`], checked once to describe the *same* schema the model
//! consumes. That check is the point of the type: an engine and a baseline are
//! two files a deployment mounts side by side, and mounting last quarter's
//! baseline next to this quarter's model would not fail — it would produce
//! findings whose explanations quietly describe a different distribution. The
//! pairing is therefore parsed, not validated (conventions §4): a `ModelSlot`
//! that exists explains what it scores.

use std::sync::Arc;

use inference::InferenceEngine;
use ml_features::{FeatureBaseline, FeatureVersion, Granularity};
use serde::{Deserialize, Serialize};

/// Which of the detector's two models produced a finding — and therefore what
/// the finding *claims* (§20.2).
///
/// The distinction is not bookkeeping: the two make different statements, and
/// a consumer that treats them alike will read one of them wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyModel {
    /// Gradient-boosted trees trained on the flywheel labels — the incidents
    /// simulation confirmed (§20.1). It claims "this looks like the things
    /// that turned out to be real", so it is only as good as the patterns the
    /// heuristic detectors already surface, and it sharpens ambiguous
    /// structures rather than finding new ones.
    Supervised,
    /// An isolation forest over the same feature vectors, trained
    /// unsupervised. It claims "this looks like *nothing* in the training
    /// window" — the detector for attacks with no signature yet — and
    /// deliberately never names a pattern.
    Novelty,
}

impl AnomalyModel {
    /// Both roles, in the order a detector runs and emits them.
    pub const ALL: [AnomalyModel; 2] = [AnomalyModel::Supervised, AnomalyModel::Novelty];

    /// The stable wire/metric string, matching the serde form.
    pub const fn as_str(self) -> &'static str {
        match self {
            AnomalyModel::Supervised => "supervised",
            AnomalyModel::Novelty => "novelty",
        }
    }
}

impl std::fmt::Display for AnomalyModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One served model: its role, the engine that scores it, and the baseline its
/// findings are explained against.
///
/// Construct through [`ModelSlot::new`] (or the role-named shorthands), which
/// is where the model/baseline schema agreement is established.
pub struct ModelSlot {
    role: AnomalyModel,
    engine: Arc<dyn InferenceEngine>,
    baseline: FeatureBaseline,
}

impl ModelSlot {
    /// Pair `engine` with the `baseline` that explains its findings.
    ///
    /// `Err` iff they describe different `(feature_version, granularity)`
    /// schemas — a mounted-file mismatch, caught at boot rather than surfacing
    /// as explanations measured against the wrong distribution.
    pub fn new(
        role: AnomalyModel,
        engine: Arc<dyn InferenceEngine>,
        baseline: FeatureBaseline,
    ) -> Result<Self, WiringError> {
        let descriptor = engine.descriptor();
        if descriptor.feature_version() != baseline.feature_version()
            || descriptor.granularity() != baseline.granularity()
        {
            return Err(WiringError::BaselineSchemaMismatch {
                role,
                model_id: descriptor.model_id().to_owned(),
                model: (descriptor.feature_version(), descriptor.granularity()),
                baseline: (baseline.feature_version(), baseline.granularity()),
            });
        }
        Ok(Self {
            role,
            engine,
            baseline,
        })
    }

    /// The supervised classifier (§20.2) — per-transaction in the shipped
    /// deployment, though the granularity is the descriptor's to declare.
    pub fn supervised(
        engine: Arc<dyn InferenceEngine>,
        baseline: FeatureBaseline,
    ) -> Result<Self, WiringError> {
        Self::new(AnomalyModel::Supervised, engine, baseline)
    }

    /// The isolation-forest novelty model (§20.2) — block-level in the shipped
    /// deployment.
    pub fn novelty(
        engine: Arc<dyn InferenceEngine>,
        baseline: FeatureBaseline,
    ) -> Result<Self, WiringError> {
        Self::new(AnomalyModel::Novelty, engine, baseline)
    }

    pub fn role(&self) -> AnomalyModel {
        self.role
    }

    pub fn engine(&self) -> &dyn InferenceEngine {
        self.engine.as_ref()
    }

    pub fn baseline(&self) -> &FeatureBaseline {
        &self.baseline
    }

    /// Which vectors this slot scores — read from the *model*, since it is the
    /// side that cannot adapt.
    pub fn granularity(&self) -> Granularity {
        self.engine.descriptor().granularity()
    }
}

impl std::fmt::Debug for ModelSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelSlot")
            .field("role", &self.role)
            .field("model", &self.engine.descriptor().model_id())
            .field("granularity", &self.granularity())
            .field("baseline", &self.baseline.content_hash())
            .finish()
    }
}

/// The detector could not be wired. Every variant is a deployment mistake
/// surfaced at boot — link-or-fail, the same discipline as
/// `DetectionPlan::link` and `OrtEngine::load`. None is a runtime condition.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WiringError {
    #[error(
        "the {role} model {model_id} consumes {model:?} vectors but its baseline describes \
         {baseline:?} — the mounted baseline does not belong to this model (§20.5)"
    )]
    BaselineSchemaMismatch {
        role: AnomalyModel,
        model_id: String,
        model: (FeatureVersion, Granularity),
        baseline: (FeatureVersion, Granularity),
    },

    #[error(
        "the anomaly detector was given no models — it would run on every block and never \
         score anything; link at least one of {:?} or leave the detector unregistered",
        AnomalyModel::ALL
    )]
    NoModels,

    #[error("two {role} models were supplied — each role is served by exactly one model")]
    DuplicateRole { role: AnomalyModel },

    #[error("anomaly detector config field `{field}` is unusable: {reason}")]
    InvalidConfig {
        field: &'static str,
        reason: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{baseline_for, engine};
    use ml_features::FEATURE_VERSION;

    #[test]
    fn roles_render_the_same_way_everywhere() {
        for role in AnomalyModel::ALL {
            assert_eq!(role.to_string(), role.as_str());
            assert_eq!(
                serde_json::to_string(&role).unwrap(),
                format!("\"{role}\""),
                "the wire form and the metric label must not drift"
            );
        }
    }

    #[test]
    fn a_slot_pairs_a_model_with_a_baseline_for_its_own_schema() {
        let slot = ModelSlot::novelty(
            engine("iforest", Granularity::Block, 0.5),
            baseline_for(Granularity::Block),
        )
        .expect("matching schemas");
        assert_eq!(slot.role(), AnomalyModel::Novelty);
        assert_eq!(slot.granularity(), Granularity::Block);
        assert_eq!(slot.baseline().feature_version(), FEATURE_VERSION);
    }

    #[test]
    fn a_baseline_from_the_wrong_granularity_is_refused_at_boot() {
        // The realistic mounted-file mistake: the right version, the wrong
        // half of it. Explanations would have been measured against block
        // statistics for per-transaction vectors — plausible, and wrong.
        let err = ModelSlot::supervised(
            engine("gbdt", Granularity::Tx, 0.9),
            baseline_for(Granularity::Block),
        )
        .expect_err("a tx model cannot be explained by a block baseline");
        assert!(
            matches!(err, WiringError::BaselineSchemaMismatch { role, .. } if role == AnomalyModel::Supervised),
            "{err}"
        );
        assert!(err.to_string().contains("gbdt"), "{err}");
    }
}
