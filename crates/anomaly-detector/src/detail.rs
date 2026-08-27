//! [`AnomalyDetail`] — the typed evidence document an ML finding carries.
//!
//! Every detector defines its own `detail` shape (§6); this one has to answer
//! a question a heuristic detector's never does: *which model said so, reading
//! what, and compared to what?* A `LiquidationDetail` is checkable from the
//! chain alone — the transfers either netted that way or they did not. An ML
//! finding is only checkable against the exact model, feature schema and
//! training distribution that produced it, so all three travel with it (§8.3's
//! "versioned"), alongside the contributing features that justify it (§8.3's
//! "explainable").
//!
//! It stays attribution-blind like every other detail payload: feature
//! magnitudes and model identity, never an actor.

use inference::ArtifactDigest;
use ml_features::{FeatureVersion, Granularity};
use serde::{Deserialize, Serialize};

use crate::explain::FeatureContribution;
use crate::model::AnomalyModel;

/// The evidence document of an [`AlertKind::Anomaly`](events::primitives::AlertKind::Anomaly)
/// finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnomalyDetail {
    /// Which model fired, and therefore what the finding claims — see
    /// [`AnomalyModel`].
    pub model: AnomalyModel,
    /// The model's deployment name (`inference::ModelDescriptor::model_id`).
    pub model_id: String,
    /// SHA-256 of the ONNX artifact that produced the score. The same digest
    /// the detector folds into its `config_hash`, repeated in the evidence so
    /// a finding names its weights even when read on its own.
    pub artifact: ArtifactDigest,
    /// The feature schema version the vector was extracted under — the model's
    /// trained version, which may legitimately lag the build's current one.
    pub feature_version: FeatureVersion,
    /// Whether the score describes the whole block or one transaction.
    pub granularity: Granularity,
    /// The feature schema's content hash (names + kinds, in order).
    pub schema_hash: String,
    /// The training-window baseline's content hash — what the contributions
    /// below were measured against.
    pub baseline_hash: String,
    /// The model's confidence for this candidate, in `[0, 1]`. Identical to
    /// the finding's `raw_confidence`: the fast path carries a detector's own
    /// number unadjusted (§6).
    pub score: f64,
    /// The threshold it had to clear — carried so a finding explains why it
    /// was emitted without a reader having to fetch the deployment's config.
    pub threshold: f64,
    /// The most-deviating features, ranked. May be **empty**: a tree ensemble
    /// can fire on interactions with no single feature past the reporting
    /// floor, and saying so is more honest than listing the least-boring ones
    /// (see [`crate::top_contributions`]).
    pub top_features: Vec<FeatureContribution>,
    /// The fraction of the vector's total absolute deviation the reported
    /// features account for, in `[0, 1]` — how *complete* the explanation is.
    pub explained_share: f64,
    /// How many transactions the block held.
    pub block_tx_count: usize,
    /// How many of them this finding names. Equal to `block_tx_count` for a
    /// block-level finding unless the deployment's cap truncated it (`1` for a
    /// per-transaction finding), so a truncated implication is visible rather
    /// than implied.
    pub implicated_tx_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_detail() -> AnomalyDetail {
        AnomalyDetail {
            model: AnomalyModel::Novelty,
            model_id: "anomaly-iforest".to_owned(),
            artifact: ArtifactDigest::of(b"weights"),
            feature_version: ml_features::FEATURE_VERSION,
            granularity: Granularity::Block,
            schema_hash: ml_features::block_schema().content_hash(),
            baseline_hash: "abc".to_owned(),
            score: 0.97,
            threshold: 0.9,
            top_features: Vec::new(),
            explained_share: 0.0,
            block_tx_count: 120,
            implicated_tx_count: 32,
        }
    }

    #[test]
    fn round_trips_through_the_evidence_field() {
        // `Evidence::from_detail` serializes into `serde_json::Value`, and the
        // event store hands it back as JSON — so the detail has to survive the
        // round trip that every consumer of `DetectorTriggered.evidence`
        // performs.
        let detail = a_detail();
        let value = serde_json::to_value(&detail).unwrap();
        assert_eq!(
            serde_json::from_value::<AnomalyDetail>(value).unwrap(),
            detail
        );
    }

    #[test]
    fn identity_is_rendered_for_a_human_reader() {
        let json = serde_json::to_value(a_detail()).unwrap();
        assert_eq!(json["model"], "novelty");
        assert_eq!(json["granularity"], "block");
        // The artifact digest is hex, not a byte array: a boot log line, a
        // pinned config value and this field all read the same string.
        assert_eq!(
            json["artifact"].as_str().expect("hex"),
            ArtifactDigest::of(b"weights").to_hex()
        );
        assert_eq!(json["feature_version"], 1);
    }
}
