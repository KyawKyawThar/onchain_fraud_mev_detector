//! Tunable thresholds for [`AnomalyDetector`](crate::AnomalyDetector).
//!
//! Everything here is *reviewable deployment policy* rather than code: how
//! confident a model must be before a finding is worth emitting, and how much
//! of an explanation travels with it. It is serialized into the detector's
//! identity digest (§20.2), so lowering a threshold produces a new
//! `(id, version, config_hash)` triple exactly as a retrain does — a
//! threshold change is not a quieter kind of model change.

use serde::{Deserialize, Serialize};

/// Default score a supervised classification must reach to be emitted.
///
/// The supervised model is trained on flywheel labels — simulation-confirmed
/// incidents (§20.1) — so its positive class is "an incident the slow path
/// would confirm". `0.80` is a deliberately conservative first-deployment bar:
/// the detector ships `Shadow` (§20.2), and a threshold chosen from the
/// backtest gate replaces this before promotion.
pub const DEFAULT_SUPERVISED_MIN_SCORE: f64 = 0.80;

/// Default score an isolation-forest novelty finding must reach.
///
/// Higher than the supervised bar on purpose. "Nothing like the training
/// window" is a much weaker claim than "the pattern that got confirmed 4,000
/// times", and an unsupervised model has no notion of *interesting* — every
/// quiet block on a chain the model has not seen much of is technically novel.
pub const DEFAULT_NOVELTY_MIN_SCORE: f64 = 0.90;

/// Default number of contributing features carried in a finding's evidence.
pub const DEFAULT_TOP_FEATURES: usize = 5;

/// Default `|deviation|` a feature must reach to be *reported* as
/// contributing — two robust sigmas from the training window.
///
/// A floor, not a ranking cutoff: without it, a finding driven by feature
/// interactions rather than any single extreme value would still list its five
/// least-boring features and read as though they explained it. Reporting
/// nothing is the honest answer there (see [`crate::AnomalyDetail`]).
pub const DEFAULT_MIN_DEVIATION: f64 = 2.0;

/// Default cap on the transactions a block-granularity finding names.
pub const DEFAULT_MAX_IMPLICATED_TXS: usize = 32;

/// Thresholds and explanation policy for the ML detector.
///
/// `Deserialize` so a deployment loads it from the same JSON that names the
/// model artifacts; `Serialize` because it is hashed into the detector's
/// identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnomalyConfig {
    /// Minimum supervised score to emit a finding.
    #[serde(default = "default_supervised_min_score")]
    pub supervised_min_score: f64,
    /// Minimum novelty score to emit a finding.
    #[serde(default = "default_novelty_min_score")]
    pub novelty_min_score: f64,
    /// How many contributing features a finding's evidence carries.
    #[serde(default = "default_top_features")]
    pub top_features: usize,
    /// Minimum `|deviation|` for a feature to be reported at all.
    #[serde(default = "default_min_deviation")]
    pub min_deviation: f64,
    /// Cap on the transactions a *block*-granularity finding implicates. A
    /// block-level model scores the block, so the honest implicated set is the
    /// block's transactions; the cap keeps one event from carrying every hash
    /// in a 300-transaction block, and the detail records how many there were.
    #[serde(default = "default_max_implicated_txs")]
    pub max_implicated_txs: usize,
}

fn default_supervised_min_score() -> f64 {
    DEFAULT_SUPERVISED_MIN_SCORE
}

fn default_novelty_min_score() -> f64 {
    DEFAULT_NOVELTY_MIN_SCORE
}

fn default_top_features() -> usize {
    DEFAULT_TOP_FEATURES
}

fn default_min_deviation() -> f64 {
    DEFAULT_MIN_DEVIATION
}

fn default_max_implicated_txs() -> usize {
    DEFAULT_MAX_IMPLICATED_TXS
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            supervised_min_score: DEFAULT_SUPERVISED_MIN_SCORE,
            novelty_min_score: DEFAULT_NOVELTY_MIN_SCORE,
            top_features: DEFAULT_TOP_FEATURES,
            min_deviation: DEFAULT_MIN_DEVIATION,
            max_implicated_txs: DEFAULT_MAX_IMPLICATED_TXS,
        }
    }
}

impl AnomalyConfig {
    /// The threshold for one model role.
    pub fn min_score(&self, role: crate::AnomalyModel) -> f64 {
        match role {
            crate::AnomalyModel::Supervised => self.supervised_min_score,
            crate::AnomalyModel::Novelty => self.novelty_min_score,
        }
    }

    /// Reject a config that would make the detector behave nonsensically,
    /// before it can score a block.
    ///
    /// A threshold outside `[0, 1]` is unreachable in one direction or fires
    /// on everything in the other, and `top_features: 0` would ship findings
    /// with no explanation at all — §20.2 requires the contributing features,
    /// so an operator cannot switch them off by config.
    pub(crate) fn validate(&self) -> Result<(), crate::WiringError> {
        let invalid = |field: &'static str, reason: &'static str| {
            Err(crate::WiringError::InvalidConfig { field, reason })
        };
        for (field, value) in [
            ("supervised_min_score", self.supervised_min_score),
            ("novelty_min_score", self.novelty_min_score),
        ] {
            if !value.is_finite() || !(0.0..=1.0).contains(&value) {
                return invalid(field, "must be a score in [0, 1]");
            }
        }
        if self.top_features == 0 {
            return invalid(
                "top_features",
                "must be at least 1 — evidence carries its contributing features (§20.2)",
            );
        }
        if !self.min_deviation.is_finite() || self.min_deviation < 0.0 {
            return invalid("min_deviation", "must be a finite, non-negative magnitude");
        }
        if self.max_implicated_txs == 0 {
            return invalid(
                "max_implicated_txs",
                "must be at least 1 — a finding that names no transaction implicates nothing",
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AnomalyModel, WiringError};

    #[test]
    fn defaults_validate_and_are_role_addressable() {
        let config = AnomalyConfig::default();
        config.validate().expect("the shipped defaults are usable");
        assert_eq!(
            config.min_score(AnomalyModel::Supervised),
            DEFAULT_SUPERVISED_MIN_SCORE
        );
        assert_eq!(
            config.min_score(AnomalyModel::Novelty),
            DEFAULT_NOVELTY_MIN_SCORE
        );
    }

    /// A named way of breaking one config field, for the table below.
    type Mutation = (&'static str, fn(&mut AnomalyConfig));

    #[test]
    fn unusable_values_are_refused_by_field() {
        let cases: &[Mutation] = &[
            ("supervised_min_score", |c| c.supervised_min_score = 1.5),
            ("supervised_min_score", |c| {
                c.supervised_min_score = f64::NAN
            }),
            ("novelty_min_score", |c| c.novelty_min_score = -0.1),
            ("top_features", |c| c.top_features = 0),
            ("min_deviation", |c| c.min_deviation = -1.0),
            ("max_implicated_txs", |c| c.max_implicated_txs = 0),
        ];
        for (field, break_it) in cases {
            let mut config = AnomalyConfig::default();
            break_it(&mut config);
            match config.validate() {
                Err(WiringError::InvalidConfig { field: got, .. }) => assert_eq!(&got, field),
                other => panic!("{field} should be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_partial_config_file_fills_in_the_shipped_defaults() {
        // The deployment shape: state the one threshold being tuned, inherit
        // the rest, and have a typo'd key fail at boot rather than silently
        // leaving the default in place.
        let config: AnomalyConfig = serde_json::from_str(r#"{"novelty_min_score": 0.95}"#).unwrap();
        assert_eq!(config.novelty_min_score, 0.95);
        assert_eq!(config.top_features, DEFAULT_TOP_FEATURES);
        assert!(serde_json::from_str::<AnomalyConfig>(r#"{"novelty_min_scores": 0.95}"#).is_err());
    }
}
