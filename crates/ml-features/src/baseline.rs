//! [`FeatureBaseline`] — what "normal" looked like in a model's training
//! window, per feature, under one frozen schema (§20.2, §20.5).
//!
//! A score on its own is not an explanation. §20.2 requires an anomaly
//! finding's evidence to carry its *top contributing features*, and §8.3
//! requires every reported delta to be explainable and versioned — both of
//! which need a reference distribution to measure "unusual" against. That
//! reference is this type: the per-feature centre and spread of the dataset a
//! model was trained on, exported alongside the ONNX artifact and loaded at
//! boot.
//!
//! It lives here, next to the schema, rather than in the detector that reads
//! it, because two subsystems key off the same numbers and must not each keep
//! their own: the serving-side explainer (the `anomaly-detector`, Sprint 18
//! t4) turns them into contributions, and the drift monitor (t5) compares a
//! live feature distribution against them. One owner of "what normal is for
//! feature version *N*", the same way this crate is the one owner of what the
//! features *are*.
//!
//! Three properties make it trustworthy:
//!
//! - **Schema-bound, link-or-fail.** A baseline is built against a resolved
//!   [`FeatureSchema`] — every feature named exactly once, no unknown names,
//!   every statistic finite. A snapshot for a version this build can no
//!   longer extract is refused at construction, like
//!   `inference::ModelDescriptor`'s skew check, so a mislabelled explanation
//!   is a refused boot rather than a plausible-looking lie in an alert.
//! - **Total at serving time.** [`deviations`](FeatureBaseline::deviations)
//!   cannot divide by zero, produce a `NaN`, or run away to infinity: the
//!   spread is floored ([`MIN_SPREAD`]) and the result clamped
//!   ([`MAX_DEVIATION`]). A feature that never varied in training and moved
//!   in production is *maximally* surprising, not infinitely so — and a
//!   finite number is what keeps the shares an explanation reports
//!   meaningful.
//! - **Identified by content.** [`content_hash`](FeatureBaseline::content_hash)
//!   digests the schema it binds to *and* every statistic, so a re-derived
//!   baseline changes the deployed detector's identity exactly as a retrain
//!   does (§20.2 — the explanation is part of what a deployment claims, not a
//!   cosmetic sidecar).
//!
//! # Robust statistics, deliberately
//!
//! The centre is the **median** and the spread is the **MAD** (median absolute
//! deviation, scaled by [`MAD_TO_SIGMA`] so it reads as a standard deviation
//! on normal data), not mean/σ. On-chain features are heavy-tailed by nature —
//! one $40M flashloan block moves a mean and inflates a σ enough to hide every
//! subsequent outlier behind it. The point of a baseline is to make outliers
//! *visible*, so the statistics must not be dominated by them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::schema::{FeatureDef, FeatureKind, FeatureSchema, FeatureVersion, Granularity};
use crate::stats::{mad, median};
use crate::vector::FeatureVector;

/// Scale factor turning a MAD into a σ-equivalent for normally distributed
/// data (`1 / Φ⁻¹(0.75)`), so a deviation reads on the familiar "how many
/// standard deviations" scale even though it is computed robustly.
pub const MAD_TO_SIGMA: f64 = 1.482_602_218_505_602;

/// Floor applied to every feature's spread before dividing by it.
///
/// A feature that is constant across the whole training window has a MAD of
/// exactly zero (`is_contract_creation` in a window with no deployments, say).
/// Without a floor the first production value that differs would divide by
/// zero; with one, it lands at [`MAX_DEVIATION`] — which is the honest
/// reading: training never saw this vary.
pub const MIN_SPREAD: f64 = 1e-6;

/// Clamp on `|deviation|`.
///
/// Not cosmetic: an explanation reports each contribution's *share* of the
/// total deviation, and one unbounded term would drive every other share to
/// zero, hiding the rest of the explanation behind a single constant-in-
/// training feature. Anything at the clamp is already "as surprising as this
/// baseline can express".
pub const MAX_DEVIATION: f64 = 32.0;

/// One feature's training-window distribution: where it sat and how much it
/// moved.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct FeatureStats {
    /// The centre — a median (see the module docs).
    pub center: f64,
    /// The spread — a σ-scaled MAD. Non-negative; zero means "constant in
    /// training", which [`MIN_SPREAD`] then handles.
    pub spread: f64,
}

/// A model's training-window feature distribution, bound to one
/// `(feature_version, granularity)` schema.
///
/// Deliberately **`Serialize` but not `Deserialize`** (the `ModelDescriptor`
/// discipline): it is derived from samples or parsed through
/// [`BaselineSnapshot`], never conjured from text. A `FeatureBaseline` that
/// exists has been checked against a live schema.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FeatureBaseline {
    feature_version: FeatureVersion,
    granularity: Granularity,
    /// The bound schema's own content hash — carried so a baseline can be
    /// shown to describe the schema it claims to, even in a log line.
    schema_hash: String,
    /// Statistics in schema order; `stats[i]` describes `values[i]`.
    stats: Vec<FeatureStats>,
}

impl FeatureBaseline {
    /// Build from per-feature statistics keyed by schema name.
    ///
    /// Errors on an unextractable version, a missing feature, an unknown name,
    /// or a non-finite/negative statistic — every one of which would otherwise
    /// surface as a silently wrong explanation.
    pub fn new(
        feature_version: FeatureVersion,
        granularity: Granularity,
        mut named: BTreeMap<String, FeatureStats>,
    ) -> Result<Self, BaselineError> {
        let schema = schema_for(feature_version, granularity)?;

        let mut stats = Vec::with_capacity(schema.len());
        for def in schema.defs() {
            let entry = named
                .remove(def.name)
                .ok_or(BaselineError::MissingFeature {
                    feature: def.name,
                    feature_version,
                    granularity,
                })?;
            check(def, entry)?;
            stats.push(entry);
        }
        // Anything left over names a feature this schema does not have — a
        // baseline exported against a *different* version, which the version
        // stamp alone would not have caught.
        if let Some(name) = named.keys().next() {
            return Err(BaselineError::UnknownFeature {
                feature: name.clone(),
                feature_version,
                granularity,
            });
        }

        Ok(Self {
            feature_version,
            granularity,
            schema_hash: schema.content_hash(),
            stats,
        })
    }

    /// Derive a baseline from extracted vectors — how a training run produces
    /// the snapshot it ships beside its artifact, and how a test builds one
    /// without a file.
    ///
    /// Every sample must carry the same `(version, granularity)` stamp, which
    /// is read from the first one; a mixed batch is a caller bug, not
    /// something to average over.
    pub fn from_samples(samples: &[FeatureVector]) -> Result<Self, BaselineError> {
        let first = samples.first().ok_or(BaselineError::NoSamples)?;
        let (feature_version, granularity) = (first.feature_version(), first.granularity());
        let schema = schema_for(feature_version, granularity)?;

        for sample in samples {
            if sample.feature_version() != feature_version
                || sample.granularity() != granularity
                || sample.values().len() != schema.len()
            {
                return Err(BaselineError::MixedSamples {
                    feature_version,
                    granularity,
                });
            }
        }

        // Column-wise: gather each feature's values across samples, then take
        // the robust pair. `median`/`mad` sort their input, so the result does
        // not depend on sample order (the same order-independence the
        // extractors themselves guarantee).
        let mut column = Vec::with_capacity(samples.len());
        let mut stats = Vec::with_capacity(schema.len());
        for i in 0..schema.len() {
            column.clear();
            column.extend(samples.iter().map(|s| s.values()[i]));
            let center = median(&mut column);
            let spread = mad(&mut column, center) * MAD_TO_SIGMA;
            stats.push(FeatureStats { center, spread });
        }

        Ok(Self {
            feature_version,
            granularity,
            schema_hash: schema.content_hash(),
            stats,
        })
    }

    pub fn feature_version(&self) -> FeatureVersion {
        self.feature_version
    }

    pub fn granularity(&self) -> Granularity {
        self.granularity
    }

    /// The bound schema's content hash (names + kinds, in order).
    pub fn schema_hash(&self) -> &str {
        &self.schema_hash
    }

    /// The schema this baseline describes. Always resolvable — construction
    /// refused a version this build cannot extract.
    pub fn schema(&self) -> &'static FeatureSchema {
        schema_for(self.feature_version, self.granularity)
            .expect("construction resolved this schema; versions are never unregistered")
    }

    /// One feature's statistics by schema position.
    pub fn stats(&self) -> &[FeatureStats] {
        &self.stats
    }

    /// Whether `features` is shaped like the vectors this baseline describes —
    /// the same check `inference::ModelDescriptor::accepts` makes of a model,
    /// asked of an explanation.
    pub fn accepts(&self, features: &FeatureVector) -> bool {
        features.feature_version() == self.feature_version
            && features.granularity() == self.granularity
            && features.values().len() == self.stats.len()
    }

    /// The bare clamped z-scores of `features`, in schema order, written into
    /// `out` — the allocation-free half of [`deviations`](Self::deviations).
    ///
    /// `false` (leaving `out` untouched) iff [`accepts`](Self::accepts) is
    /// false. `out` is cleared first, so a caller keeps one buffer for the
    /// process's life.
    ///
    /// This exists because the drift monitor observes *every* served vector
    /// and needs only the numbers, while an explanation is built rarely and
    /// wants the names and training statistics alongside them. Both go through
    /// the same [`deviation`] arithmetic — the buffer is the only difference,
    /// so there is still exactly one definition of "how far is this from
    /// normal" (which is the whole reason this type has two consumers).
    pub fn fill_deviations(&self, features: &FeatureVector, out: &mut Vec<f64>) -> bool {
        if !self.accepts(features) {
            return false;
        }
        out.clear();
        out.extend(
            features
                .values()
                .iter()
                .zip(&self.stats)
                .map(|(&value, &stats)| deviation(value, stats)),
        );
        true
    }

    /// How far each of `features`'s values sits from the training window, in
    /// schema order — the raw material an explanation ranks.
    ///
    /// `None` iff [`accepts`](Self::accepts) is false. Every yielded
    /// `deviation` is finite and within `±`[`MAX_DEVIATION`].
    ///
    /// Allocates. A caller on the per-vector hot path wants
    /// [`fill_deviations`](Self::fill_deviations) instead.
    pub fn deviations(&self, features: &FeatureVector) -> Option<Vec<Deviation>> {
        if !self.accepts(features) {
            return None;
        }
        let defs = self.schema().defs();
        Some(
            features
                .values()
                .iter()
                .zip(&self.stats)
                .zip(defs)
                .enumerate()
                .map(|(index, ((&value, &stats), &def))| Deviation {
                    index,
                    def,
                    value,
                    stats,
                    deviation: deviation(value, stats),
                })
                .collect(),
        )
    }

    /// SHA-256 over the bound schema and every statistic, hex-encoded.
    ///
    /// Floats are hashed by [`f64::to_bits`], not by their formatted form, so
    /// the digest is exact and platform-independent (the discipline the
    /// dataset manifests already use). This is what a deployed detector folds
    /// into its `config_hash`: re-deriving a baseline changes what its
    /// evidence *means*, so it must change the deployment's identity.
    pub fn content_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"ml-features/baseline/v1\n");
        hasher.update(self.schema_hash.as_bytes());
        for stat in &self.stats {
            hasher.update(stat.center.to_bits().to_be_bytes());
            hasher.update(stat.spread.to_bits().to_be_bytes());
        }
        alloy_primitives::hex::encode(hasher.finalize())
    }

    /// The serializable snapshot form — what a training run writes to disk.
    pub fn to_snapshot(&self) -> BaselineSnapshot {
        BaselineSnapshot {
            feature_version: self.feature_version,
            granularity: self.granularity,
            features: self
                .schema()
                .names()
                .map(str::to_owned)
                .zip(self.stats.iter().copied())
                .collect(),
        }
    }
}

/// One feature's position relative to the training window.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Deviation {
    /// Position in the schema (and in the vector) — the deterministic
    /// tie-breaker when two features deviate equally.
    pub index: usize,
    /// The feature's name and statistical kind.
    pub def: FeatureDef,
    /// The observed value.
    pub value: f64,
    /// What training saw.
    pub stats: FeatureStats,
    /// Signed, floored and clamped `(value - center) / spread`. Positive means
    /// "higher than the training window", negative "lower".
    pub deviation: f64,
}

impl Deviation {
    pub fn name(&self) -> &'static str {
        self.def.name
    }

    pub fn kind(&self) -> FeatureKind {
        self.def.kind
    }

    /// `|deviation|` — the magnitude a ranking sorts on.
    pub fn magnitude(&self) -> f64 {
        self.deviation.abs()
    }
}

/// The on-disk / on-wire form of a baseline: a training run writes this beside
/// its ONNX artifact, and a deployment loads it at boot.
///
/// Separate from [`FeatureBaseline`] on purpose (parse, don't validate): this
/// is untrusted text with a name-keyed map, and turning it into a baseline is
/// where the schema check happens.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineSnapshot {
    pub feature_version: FeatureVersion,
    pub granularity: Granularity,
    /// Per-feature statistics, keyed by the schema's feature name. A
    /// `BTreeMap` so a serialized snapshot is byte-stable.
    pub features: BTreeMap<String, FeatureStats>,
}

impl BaselineSnapshot {
    /// Resolve against the live schema registry, or explain why it can't be.
    pub fn into_baseline(self) -> Result<FeatureBaseline, BaselineError> {
        FeatureBaseline::new(self.feature_version, self.granularity, self.features)
    }
}

/// A baseline could not be bound to a schema. Every variant is a boot-time
/// wiring or export mistake, never a runtime data condition.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BaselineError {
    #[error(
        "baseline claims feature schema {feature_version}, which this build cannot extract \
         — no registered extractor (serving/training skew, §20.5)"
    )]
    UnknownVersion { feature_version: FeatureVersion },

    #[error("baseline for {feature_version}/{granularity:?} has no statistics for {feature:?}")]
    MissingFeature {
        feature: &'static str,
        feature_version: FeatureVersion,
        granularity: Granularity,
    },

    #[error(
        "baseline for {feature_version}/{granularity:?} carries {feature:?}, which is not a \
         feature of that schema — the snapshot was exported against a different version"
    )]
    UnknownFeature {
        feature: String,
        feature_version: FeatureVersion,
        granularity: Granularity,
    },

    #[error("baseline statistic for {feature:?} is not usable: {reason}")]
    InvalidStatistic {
        feature: &'static str,
        reason: &'static str,
    },

    #[error("a baseline needs at least one sample")]
    NoSamples,

    #[error(
        "samples disagree: expected every vector to be {feature_version}/{granularity:?} of the \
         schema's arity"
    )]
    MixedSamples {
        feature_version: FeatureVersion,
        granularity: Granularity,
    },
}

fn schema_for(
    feature_version: FeatureVersion,
    granularity: Granularity,
) -> Result<&'static FeatureSchema, BaselineError> {
    crate::registry::extractor_for(feature_version)
        .map(|e| e.schema(granularity))
        .ok_or(BaselineError::UnknownVersion { feature_version })
}

fn check(def: &FeatureDef, stats: FeatureStats) -> Result<(), BaselineError> {
    let reason = if !stats.center.is_finite() {
        Some("center is not finite")
    } else if !stats.spread.is_finite() {
        Some("spread is not finite")
    } else if stats.spread < 0.0 {
        Some("spread is negative")
    } else {
        None
    };
    match reason {
        Some(reason) => Err(BaselineError::InvalidStatistic {
            feature: def.name,
            reason,
        }),
        None => Ok(()),
    }
}

/// The floored, clamped robust z-score. Total over every finite input by
/// construction; a non-finite `value` cannot occur (a `FeatureVector`
/// sanitizes at construction) but collapses to `0.0` if it ever did.
fn deviation(value: f64, stats: FeatureStats) -> f64 {
    if !value.is_finite() {
        return 0.0;
    }
    let z = (value - stats.center) / stats.spread.max(MIN_SPREAD);
    if z.is_finite() {
        z.clamp(-MAX_DEVIATION, MAX_DEVIATION)
    } else {
        // Only reachable from a `center` so large the subtraction overflows;
        // the sign is still the honest answer.
        if value > stats.center {
            MAX_DEVIATION
        } else {
            -MAX_DEVIATION
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{v1, FEATURE_VERSION};

    fn vector(values: Vec<f64>) -> FeatureVector {
        FeatureVector::from_schema_values(v1::block_schema(), values)
    }

    /// Vectors whose every feature is `base + i * step`, so each column has a
    /// known, non-degenerate distribution.
    fn samples(offsets: &[f64]) -> Vec<FeatureVector> {
        offsets
            .iter()
            .map(|off| vector(vec![*off; v1::block_schema().len()]))
            .collect()
    }

    #[test]
    fn from_samples_takes_the_robust_pair() {
        // Median 2.0; absolute deviations {2,1,0,1,2} → MAD 1.0.
        let baseline = FeatureBaseline::from_samples(&samples(&[0.0, 1.0, 2.0, 3.0, 4.0])).unwrap();
        assert_eq!(baseline.feature_version(), FEATURE_VERSION);
        assert_eq!(baseline.granularity(), Granularity::Block);
        assert_eq!(baseline.stats().len(), v1::block_schema().len());
        assert_eq!(baseline.stats()[0].center, 2.0);
        assert!((baseline.stats()[0].spread - MAD_TO_SIGMA).abs() < 1e-12);
    }

    #[test]
    fn from_samples_is_order_independent() {
        let a = FeatureBaseline::from_samples(&samples(&[0.0, 1.0, 2.0, 3.0, 9.0])).unwrap();
        let b = FeatureBaseline::from_samples(&samples(&[9.0, 2.0, 0.0, 3.0, 1.0])).unwrap();
        assert_eq!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn a_heavy_tail_does_not_swallow_the_spread() {
        // The whole reason for median/MAD over mean/σ: one enormous sample
        // must not inflate the spread so far that ordinary outliers vanish.
        let robust = FeatureBaseline::from_samples(&samples(&[1.0, 2.0, 3.0, 4.0, 1e9])).unwrap();
        assert_eq!(robust.stats()[0].center, 3.0);
        assert!(robust.stats()[0].spread < 5.0, "{:?}", robust.stats()[0]);
    }

    #[test]
    fn deviations_are_signed_finite_and_in_schema_order() {
        let baseline = FeatureBaseline::from_samples(&samples(&[0.0, 1.0, 2.0, 3.0, 4.0])).unwrap();
        let mut values = vec![2.0; v1::block_schema().len()];
        values[0] = 2.0 + 3.0 * MAD_TO_SIGMA; // three robust sigmas high
        values[1] = 2.0 - MAD_TO_SIGMA; // one low
        let found = baseline.deviations(&vector(values)).unwrap();

        assert_eq!(found.len(), v1::block_schema().len());
        assert_eq!(found[0].index, 0);
        assert_eq!(found[0].name(), v1::block_schema().defs()[0].name);
        assert!((found[0].deviation - 3.0).abs() < 1e-9, "{found:?}");
        assert!((found[1].deviation + 1.0).abs() < 1e-9, "{found:?}");
        assert_eq!(found[2].deviation, 0.0);
        assert!(found.iter().all(|d| d.deviation.is_finite()));
    }

    #[test]
    fn a_feature_constant_in_training_pins_at_the_clamp_instead_of_dividing_by_zero() {
        // Every sample identical ⇒ MAD 0. A moved value must be maximally,
        // *finitely* surprising.
        let baseline = FeatureBaseline::from_samples(&samples(&[1.0, 1.0, 1.0])).unwrap();
        assert_eq!(baseline.stats()[0].spread, 0.0);

        let mut values = vec![1.0; v1::block_schema().len()];
        values[0] = 1.5;
        values[1] = 0.5;
        let found = baseline.deviations(&vector(values)).unwrap();
        assert_eq!(found[0].deviation, MAX_DEVIATION);
        assert_eq!(found[1].deviation, -MAX_DEVIATION);
        assert_eq!(found[2].deviation, 0.0);
    }

    #[test]
    fn a_vector_from_another_schema_is_refused() {
        let baseline = FeatureBaseline::from_samples(&samples(&[1.0, 2.0])).unwrap();
        let tx_vector =
            FeatureVector::from_schema_values(v1::tx_schema(), vec![0.0; v1::tx_schema().len()]);
        assert!(!baseline.accepts(&tx_vector));
        assert!(baseline.deviations(&tx_vector).is_none());
    }

    #[test]
    fn a_snapshot_round_trips_through_the_schema_check() {
        let baseline = FeatureBaseline::from_samples(&samples(&[1.0, 2.0, 3.0])).unwrap();
        let json = serde_json::to_string(&baseline.to_snapshot()).unwrap();
        let parsed: BaselineSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.into_baseline().unwrap(), baseline);
    }

    #[test]
    fn a_snapshot_missing_a_feature_is_refused() {
        let baseline = FeatureBaseline::from_samples(&samples(&[1.0, 2.0])).unwrap();
        let mut snapshot = baseline.to_snapshot();
        let dropped = v1::block_schema().defs()[3].name;
        snapshot.features.remove(dropped);

        let err = snapshot.into_baseline().unwrap_err();
        assert!(
            matches!(err, BaselineError::MissingFeature { feature, .. } if feature == dropped),
            "{err}"
        );
    }

    #[test]
    fn a_snapshot_carrying_a_foreign_feature_is_refused() {
        // The case a version stamp alone can't catch: right version number,
        // wrong feature set (a hand-edited or cross-version export).
        let baseline = FeatureBaseline::from_samples(&samples(&[1.0, 2.0])).unwrap();
        let mut snapshot = baseline.to_snapshot();
        snapshot.features.insert(
            "not_a_feature".to_owned(),
            FeatureStats {
                center: 0.0,
                spread: 1.0,
            },
        );

        let err = snapshot.into_baseline().unwrap_err();
        assert!(
            matches!(&err, BaselineError::UnknownFeature { feature, .. } if feature == "not_a_feature"),
            "{err}"
        );
    }

    #[test]
    fn a_snapshot_for_an_unshippable_version_is_refused_at_boot() {
        let err = FeatureBaseline::new(FeatureVersion(999), Granularity::Block, BTreeMap::new())
            .unwrap_err();
        assert!(matches!(err, BaselineError::UnknownVersion { .. }), "{err}");
    }

    #[test]
    fn non_finite_and_negative_statistics_are_refused() {
        let baseline = FeatureBaseline::from_samples(&samples(&[1.0, 2.0])).unwrap();
        let name = v1::block_schema().defs()[0].name;
        for bad in [
            FeatureStats {
                center: f64::NAN,
                spread: 1.0,
            },
            FeatureStats {
                center: 0.0,
                spread: f64::INFINITY,
            },
            FeatureStats {
                center: 0.0,
                spread: -1.0,
            },
        ] {
            let mut snapshot = baseline.to_snapshot();
            snapshot.features.insert(name.to_owned(), bad);
            assert!(
                matches!(
                    snapshot.into_baseline(),
                    Err(BaselineError::InvalidStatistic { .. })
                ),
                "{bad:?} should be refused"
            );
        }
    }

    #[test]
    fn mixed_or_empty_samples_are_refused() {
        assert!(matches!(
            FeatureBaseline::from_samples(&[]),
            Err(BaselineError::NoSamples)
        ));

        let mixed = vec![
            vector(vec![0.0; v1::block_schema().len()]),
            FeatureVector::from_schema_values(v1::tx_schema(), vec![0.0; v1::tx_schema().len()]),
        ];
        assert!(matches!(
            FeatureBaseline::from_samples(&mixed),
            Err(BaselineError::MixedSamples { .. })
        ));
    }

    #[test]
    fn content_hash_moves_with_the_statistics() {
        let a = FeatureBaseline::from_samples(&samples(&[1.0, 2.0, 3.0])).unwrap();
        let b = FeatureBaseline::from_samples(&samples(&[1.0, 5.0, 9.0])).unwrap();
        assert_ne!(a.content_hash(), b.content_hash());
        assert_eq!(a.content_hash(), a.content_hash());
        assert_eq!(a.content_hash().len(), 64);
    }
}
