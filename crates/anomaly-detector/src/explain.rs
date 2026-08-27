//! Explainability: turning a feature vector into the "top contributing
//! features" §20.2 requires an anomaly finding's evidence to carry.
//!
//! **This lives above the model-serving seam, deliberately.** `inference`
//! returns a [`Score`](inference::Score) and nothing else — no
//! `infer_with_attribution` — so that a model format with no attribution
//! output is still explainable and one place owns the answer to "why did this
//! fire?". The answer is computed here, from the extracted vector against the
//! model's training-window [`FeatureBaseline`] (the same statistics the drift
//! monitor keys off, §20.5).
//!
//! The §8.3 discipline, applied to a detector instead of a risk score:
//!
//! - **Explainable** — every reported contribution names the feature, the
//!   value observed, what the training window looked like, and how far apart
//!   they are. A reader can check the claim against the block.
//! - **Versioned** — a contribution is only interpretable under the schema it
//!   was measured in, so the finding carries `feature_version`, the schema
//!   hash, and the baseline hash alongside (see [`crate::AnomalyDetail`]).
//! - **Nuanced** — a contribution is a *deviation*, not a cause. Tree
//!   ensembles decide on interactions, so the honest claim is "these features
//!   are what is unusual here", never "this feature made the model fire".
//!   [`FeatureContribution::share`] states how much of the total deviation the
//!   reported features account for, so a thin explanation reads as thin.
//!
//! Ranking is fully deterministic — magnitude descending, ties broken by
//! schema position — because the same block must explain itself identically on
//! replay and in a backtest (§18).

use ml_features::{FeatureBaseline, FeatureKind, FeatureVector};
use serde::{Deserialize, Serialize};

/// One feature's contribution to a finding: what was seen, what was normal,
/// and how far apart they are.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeatureContribution {
    /// The feature's name in the schema that produced the vector.
    pub feature: String,
    /// Its statistical kind — a reader (or a UI) needs it to render `0.87`
    /// correctly as a fraction rather than a magnitude.
    pub kind: FeatureKind,
    /// The value extracted from this block/transaction.
    pub value: f64,
    /// The training window's centre for this feature (a median).
    pub baseline: f64,
    /// The training window's spread (a σ-scaled MAD). Reported so a deviation
    /// can be re-derived rather than taken on trust.
    pub spread: f64,
    /// Signed robust z-score: how many spreads above (`+`) or below (`-`) the
    /// training centre the value sits. Bounded by
    /// [`ml_features::MAX_DEVIATION`].
    pub deviation: f64,
    /// This feature's fraction of the vector's **total** absolute deviation,
    /// in `[0, 1]`. The reported contributions' shares therefore sum to at
    /// most 1: what is missing is the deviation spread thinly across every
    /// other feature.
    pub share: f64,
}

/// The `top_k` most-deviating features of `features` against `baseline`,
/// ranked by `|deviation|`, keeping only those at or above `min_deviation`.
///
/// Returns empty when nothing deviates enough — the honest reading of a
/// finding driven by feature *interactions* rather than any single extreme
/// value, which is a real and common shape for a tree ensemble. Also empty
/// (rather than wrong) if `baseline` does not describe `features`; the
/// detector refuses that pairing at construction, so it cannot arise from
/// config.
pub fn top_contributions(
    features: &FeatureVector,
    baseline: &FeatureBaseline,
    top_k: usize,
    min_deviation: f64,
) -> Vec<FeatureContribution> {
    let Some(deviations) = baseline.deviations(features) else {
        return Vec::new();
    };

    // Denominator over *every* feature, not just the reported ones, so a
    // share says "this much of what is unusual here", not "this much of the
    // part we chose to show you".
    let total: f64 = deviations.iter().map(|d| d.magnitude()).sum();

    let mut ranked: Vec<_> = deviations
        .iter()
        .filter(|d| d.magnitude() >= min_deviation)
        .collect();
    // `total_cmp`, and the schema index as tie-breaker: two features that
    // deviate identically must rank identically on every run and platform.
    ranked.sort_by(|a, b| {
        b.magnitude()
            .total_cmp(&a.magnitude())
            .then(a.index.cmp(&b.index))
    });
    ranked.truncate(top_k);

    ranked
        .into_iter()
        .map(|d| FeatureContribution {
            feature: d.name().to_owned(),
            kind: d.kind(),
            value: d.value,
            baseline: d.stats.center,
            spread: d.stats.spread,
            deviation: d.deviation,
            share: if total > 0.0 {
                d.magnitude() / total
            } else {
                0.0
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_features::{Granularity, MAX_DEVIATION};

    /// A baseline over block vectors whose every feature has centre 0 and
    /// spread 1, so a raw value *is* its deviation and the ranking is
    /// readable in the test.
    fn unit_baseline() -> FeatureBaseline {
        let names: Vec<String> = ml_features::block_schema()
            .names()
            .map(str::to_owned)
            .collect();
        let stats = names
            .into_iter()
            .map(|n| {
                (
                    n,
                    ml_features::FeatureStats {
                        center: 0.0,
                        spread: 1.0,
                    },
                )
            })
            .collect();
        FeatureBaseline::new(ml_features::FEATURE_VERSION, Granularity::Block, stats)
            .expect("a full set of statistics for the current block schema")
    }

    /// A block vector whose `i`th value is `values[i]`, padded with zeros.
    fn vector(values: &[f64]) -> FeatureVector {
        let mut all = vec![0.0; ml_features::block_schema().len()];
        all[..values.len()].copy_from_slice(values);
        // Round-tripping through serde is the only way to build a vector from
        // outside `ml-features` (construction is the extractors' privilege) —
        // which is itself the property that keeps hand-made vectors out of
        // production.
        serde_json::from_value(serde_json::json!({
            "feature_version": ml_features::FEATURE_VERSION,
            "granularity": "block",
            "values": all,
        }))
        .expect("a well-formed block vector")
    }

    fn names(found: &[FeatureContribution]) -> Vec<&str> {
        found.iter().map(|c| c.feature.as_str()).collect()
    }

    #[test]
    fn ranks_by_magnitude_and_reports_both_sides() {
        let schema = ml_features::block_schema();
        // Feature 2 deviates most, then 0 (negative — just as interesting),
        // then 1.
        let found = top_contributions(&vector(&[-5.0, 3.0, 9.0]), &unit_baseline(), 3, 2.0);

        assert_eq!(
            names(&found),
            vec![
                schema.defs()[2].name,
                schema.defs()[0].name,
                schema.defs()[1].name
            ]
        );
        assert_eq!(found[0].deviation, 9.0);
        assert_eq!(
            found[1].deviation, -5.0,
            "a value *below* normal explains too"
        );
        assert_eq!(found[0].value, 9.0);
        assert_eq!(found[0].baseline, 0.0);
        assert_eq!(found[0].spread, 1.0);
        assert_eq!(found[0].kind, schema.defs()[2].kind);
    }

    #[test]
    fn shares_are_fractions_of_the_whole_vectors_deviation() {
        // Total |deviation| = 9 + 5 + 3 = 17, but only the top two are shown.
        let found = top_contributions(&vector(&[-5.0, 3.0, 9.0]), &unit_baseline(), 2, 2.0);
        assert_eq!(found.len(), 2);
        assert!((found[0].share - 9.0 / 17.0).abs() < 1e-12);
        assert!((found[1].share - 5.0 / 17.0).abs() < 1e-12);
        let explained: f64 = found.iter().map(|c| c.share).sum();
        assert!(
            explained < 1.0,
            "a truncated explanation must not claim 100%"
        );
    }

    #[test]
    fn a_finding_no_single_feature_explains_reports_nothing() {
        // Every feature mildly off, none past the floor: the honest answer is
        // an empty explanation, not the five least-boring features dressed up
        // as a cause.
        let found = top_contributions(&vector(&[1.0, 1.5, 0.5]), &unit_baseline(), 5, 2.0);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn ties_break_on_schema_position_not_iteration_order() {
        let schema = ml_features::block_schema();
        let found = top_contributions(&vector(&[4.0, -4.0, 4.0]), &unit_baseline(), 3, 2.0);
        assert_eq!(
            names(&found),
            vec![
                schema.defs()[0].name,
                schema.defs()[1].name,
                schema.defs()[2].name
            ]
        );
    }

    #[test]
    fn a_feature_constant_in_training_lands_at_the_clamp_not_at_infinity() {
        let mut stats: std::collections::BTreeMap<String, ml_features::FeatureStats> =
            ml_features::block_schema()
                .names()
                .map(|n| {
                    (
                        n.to_owned(),
                        ml_features::FeatureStats {
                            center: 0.0,
                            spread: 1.0,
                        },
                    )
                })
                .collect();
        let frozen = ml_features::block_schema().defs()[0].name;
        stats.insert(
            frozen.to_owned(),
            ml_features::FeatureStats {
                center: 0.0,
                spread: 0.0,
            },
        );
        let baseline =
            FeatureBaseline::new(ml_features::FEATURE_VERSION, Granularity::Block, stats).unwrap();

        let found = top_contributions(&vector(&[0.5, 3.0]), &baseline, 2, 2.0);
        assert_eq!(found[0].feature, frozen);
        assert_eq!(found[0].deviation, MAX_DEVIATION);
        // Bounded, so the *other* contribution still gets a visible share
        // instead of being rounded away by an infinite denominator.
        assert!(found[1].share > 0.0);
    }

    #[test]
    fn a_baseline_for_another_schema_explains_nothing_rather_than_lying() {
        let tx_stats = ml_features::tx_schema()
            .names()
            .map(|n| {
                (
                    n.to_owned(),
                    ml_features::FeatureStats {
                        center: 0.0,
                        spread: 1.0,
                    },
                )
            })
            .collect();
        let tx_baseline =
            FeatureBaseline::new(ml_features::FEATURE_VERSION, Granularity::Tx, tx_stats).unwrap();
        assert!(top_contributions(&vector(&[9.0]), &tx_baseline, 5, 2.0).is_empty());
    }

    #[test]
    fn a_contribution_round_trips_on_the_wire() {
        let found = top_contributions(&vector(&[9.0]), &unit_baseline(), 1, 2.0);
        let json = serde_json::to_string(&found).unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<FeatureContribution>>(&json).unwrap(),
            found
        );
        assert!(json.contains("\"kind\":"), "the statistical kind travels");
    }
}
