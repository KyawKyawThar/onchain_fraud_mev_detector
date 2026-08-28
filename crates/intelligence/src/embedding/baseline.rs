//! Population baseline for behavior vectors (§20.3) — the per-feature centre
//! and spread that make two vectors *comparable*.
//!
//! ## Why a raw distance is the wrong distance
//!
//! The v1 families have deliberately different natural ranges
//! ([`FeatureKind`](super::FeatureKind)): a `Fraction` lives in `[0, 1]` while
//! a `LogMagnitude` reaches ~7. A cosine or Euclidean distance over that is
//! dominated by the log family, so "behaviorally similar" quietly degrades into
//! "similar transaction count" — the addresses a similarity search is *least*
//! useful for finding. Standardizing each feature against the population it
//! was drawn from is what restores the intent.
//!
//! ## Robust statistics, not mean/σ
//!
//! Median and MAD, for the same reason `ml_features::FeatureBaseline` uses
//! them: on-chain distributions are heavy-tailed, and the point of a baseline
//! is to make an unusual address *visible* rather than hide it behind one
//! router's inflated variance. MAD is scaled by `1.4826` so it estimates σ for
//! normally-distributed data, which keeps the standardized units readable as
//! "z-ish".
//!
//! ## Applied at comparison time, never at embed time
//!
//! Stored vectors stay in their raw, interpretable units — a stored
//! `is_sanctioned` reads as `1.0`, not as `4.7σ`. Standardization happens when
//! two vectors are compared, so a re-derived baseline changes *rankings*
//! without rewriting history, and one subsystem owns the answer to "why do
//! these two look alike?". This is the layering §20.2 uses to keep
//! explainability above the inference seam.
//!
//! A baseline is bound to the `(embedding_version, schema_hash)` it was
//! computed from and refuses to standardize anything else — a mismatched
//! baseline is a refused comparison, not an explanation quietly measured
//! against the wrong distribution.

use chrono::{DateTime, Utc};

use super::BehaviorSchema;

/// Scale factor making the MAD a consistent estimator of σ for normally
/// distributed data — the same constant `ml-features` uses, so a "spread" here
/// and there mean the same thing.
pub const MAD_TO_SIGMA: f64 = 1.4826;

/// Below this, a feature's spread is treated as *no spread at all*.
///
/// A constant feature (v1's `value_magnitude_known`, or `is_sanctioned` across
/// a population where nobody is sanctioned) has a MAD of exactly zero.
/// Dividing by it would turn the tiniest deviation into an infinite one and
/// poison every distance computed against the vector — so such a feature
/// contributes `0.0` instead: it carries no discriminating signal in this
/// population, which is the honest reading.
const MIN_SPREAD: f32 = 1e-9;

/// Why a baseline could not be used.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BaselineError {
    /// The baseline describes a different feature space than the vector.
    #[error(
        "baseline is for {baseline_version} ({baseline_hash}), \
         vector is {vector_version} ({vector_hash})"
    )]
    SchemaMismatch {
        baseline_version: String,
        baseline_hash: String,
        vector_version: String,
        vector_hash: String,
    },

    /// The baseline's arity disagrees with the vector's — a corrupt stored
    /// row, since a matching schema hash implies a matching dimension.
    #[error("baseline has {baseline} features, vector has {vector}")]
    DimensionMismatch { baseline: usize, vector: usize },

    /// Too few addresses went into it for the medians to mean anything.
    #[error("baseline was computed from {samples} vectors, below the minimum of {minimum}")]
    TooFewSamples { samples: u64, minimum: u64 },
}

/// The fewest vectors a baseline may be computed from before it is allowed to
/// standardize anything.
///
/// A median over a handful of addresses is not a population statistic, and a
/// similarity search built on one would rank confidently against noise. Small
/// enough that a dev/test chain still works, large enough that the number
/// means something.
pub const MIN_SAMPLES: u64 = 100;

/// Per-feature centre and spread for one `(embedding_version, schema_hash)`.
#[derive(Debug, Clone, PartialEq)]
pub struct BehaviorBaseline {
    pub embedding_version: String,
    pub schema_hash: String,
    /// Median per feature, in schema order.
    pub centre: Vec<f32>,
    /// Scaled MAD per feature, in schema order.
    pub spread: Vec<f32>,
    /// How many vectors it was computed from.
    pub sample_count: u64,
    pub computed_at: DateTime<Utc>,
}

impl BehaviorBaseline {
    /// Whether this baseline describes `schema`'s feature space.
    pub fn matches(&self, schema: &BehaviorSchema) -> bool {
        self.embedding_version == schema.version() && self.schema_hash == schema.content_hash()
    }

    /// A content fingerprint of the *numbers this baseline standardizes with*
    /// — version, schema hash, centre, spread and sample count.
    ///
    /// This is what makes a materialized ranking safe to reuse. §20.3's
    /// contract is that a **re-derived baseline changes rankings without
    /// rewriting history**; anything that caches a ranking therefore has to
    /// know which baseline produced it, or it silently serves yesterday's
    /// ordering forever and quietly repeals that contract. Stamping the
    /// fingerprint on a cached result turns "is this still valid" into an
    /// equality check.
    ///
    /// Hashes the float **bit patterns**, not their decimal forms: this is an
    /// identity check, and two baselines that differ in the last ulp
    /// standardize differently. `computed_at` is deliberately excluded — two
    /// recomputations that land on identical statistics *are* the same
    /// baseline, and invalidating on a timestamp would throw away every cached
    /// ranking on each harmless refresh.
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(self.embedding_version.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.schema_hash.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.sample_count.to_be_bytes());
        for value in self.centre.iter().chain(self.spread.iter()) {
            hasher.update(value.to_bits().to_be_bytes());
        }
        format!("{:x}", hasher.finalize())
    }

    /// Standardize `values` into robust z-units: `(x - median) / (1.4826 * MAD)`,
    /// with a zero-spread feature contributing `0.0`.
    ///
    /// Fallible on purpose. The alternative to a `Result` when the baseline
    /// doesn't match is a *plausible-looking* distance computed in the wrong
    /// units — a wrong answer that no downstream check can detect, which is the
    /// one output a similarity search must never produce.
    pub fn standardize(
        &self,
        schema: &BehaviorSchema,
        values: &[f32],
    ) -> Result<Vec<f32>, BaselineError> {
        if !self.matches(schema) {
            return Err(BaselineError::SchemaMismatch {
                baseline_version: self.embedding_version.clone(),
                baseline_hash: self.schema_hash.clone(),
                vector_version: schema.version().to_owned(),
                vector_hash: schema.content_hash().to_owned(),
            });
        }
        if self.centre.len() != values.len() || self.spread.len() != values.len() {
            return Err(BaselineError::DimensionMismatch {
                baseline: self.centre.len(),
                vector: values.len(),
            });
        }
        if self.sample_count < MIN_SAMPLES {
            return Err(BaselineError::TooFewSamples {
                samples: self.sample_count,
                minimum: MIN_SAMPLES,
            });
        }

        Ok(values
            .iter()
            .zip(self.centre.iter())
            .zip(self.spread.iter())
            .map(|((value, centre), spread)| {
                if *spread <= MIN_SPREAD {
                    0.0
                } else {
                    (value - centre) / spread
                }
            })
            .collect())
    }
}

/// Compute a baseline from a sample of vectors, all drawn from `schema`.
///
/// Two passes: medians, then the median of absolute deviations from them.
/// Pure, so the statistic is unit-testable without a database — the store just
/// supplies the sample (see
/// [`EmbeddingStore::sample_vectors`](crate::embedding_store::EmbeddingStore::sample_vectors)).
///
/// Returns `None` for an empty sample: a baseline over nothing is not a
/// baseline with zero spread, it is the absence of one.
pub fn compute(
    schema: &BehaviorSchema,
    sample: &[Vec<f32>],
    computed_at: DateTime<Utc>,
) -> Option<BehaviorBaseline> {
    if sample.is_empty() {
        return None;
    }
    let dimension = schema.dimension();

    let mut centre = Vec::with_capacity(dimension);
    let mut spread = Vec::with_capacity(dimension);

    let mut column: Vec<f32> = Vec::with_capacity(sample.len());
    for index in 0..dimension {
        column.clear();
        // A row shorter than the schema is a corrupt sample row; skipping the
        // missing cell keeps one bad row from shifting every median.
        column.extend(sample.iter().filter_map(|row| row.get(index).copied()));
        let centre_value = median(&mut column);
        centre.push(centre_value);

        for value in column.iter_mut() {
            *value = (*value - centre_value).abs();
        }
        let mad = median(&mut column);
        spread.push((f64::from(mad) * MAD_TO_SIGMA) as f32);
    }

    Some(BehaviorBaseline {
        embedding_version: schema.version().to_owned(),
        schema_hash: schema.content_hash().to_owned(),
        centre,
        spread,
        sample_count: sample.len() as u64,
        computed_at,
    })
}

/// Median of `values`, sorting in place. `0.0` for an empty slice — the caller
/// has already established the sample is non-empty, so this is the
/// corrupt-row path, not a statistic anyone reads.
///
/// The even case averages the two middles rather than taking the lower, so a
/// baseline over an even sample isn't biased downward.
fn median(values: &mut [f32]) -> f32 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = values.len() / 2;
    if values.len() % 2 == 1 {
        values[mid]
    } else {
        (f64::from(values[mid - 1]) + f64::from(values[mid])) as f32 / 2.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embedding::v1;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    /// A tiny two-feature stand-in so the statistics are checkable by hand;
    /// the v1 schema is exercised through [`baseline_matches_the_v1_schema`].
    fn schema() -> BehaviorSchema {
        use crate::embedding::{FeatureDef, FeatureKind};
        BehaviorSchema::new(
            "test-v1",
            vec![
                FeatureDef {
                    name: "a",
                    kind: FeatureKind::Ratio,
                },
                FeatureDef {
                    name: "b",
                    kind: FeatureKind::Indicator,
                },
            ],
        )
    }

    fn sample(rows: &[[f32; 2]]) -> Vec<Vec<f32>> {
        rows.iter().map(|row| row.to_vec()).collect()
    }

    fn with_samples(mut baseline: BehaviorBaseline, count: u64) -> BehaviorBaseline {
        baseline.sample_count = count;
        baseline
    }

    #[test]
    fn median_and_mad_are_computed_per_feature() {
        let schema = schema();
        // Feature a: 1,2,3,4,100 → median 3, deviations 2,1,0,1,97 → MAD 1.
        // Feature b is constant.
        let baseline = compute(
            &schema,
            &sample(&[[1.0, 1.0], [2.0, 1.0], [3.0, 1.0], [4.0, 1.0], [100.0, 1.0]]),
            at(0),
        )
        .expect("a non-empty sample yields a baseline");

        assert_eq!(baseline.centre, vec![3.0, 1.0]);
        assert_eq!(baseline.spread[0], MAD_TO_SIGMA as f32);
        assert_eq!(baseline.spread[1], 0.0, "a constant feature has no spread");
        assert_eq!(baseline.sample_count, 5);
    }

    /// The whole reason for robust statistics: one $40M router must not widen
    /// the spread until every other address looks average.
    #[test]
    fn an_extreme_outlier_does_not_move_the_centre_or_spread() {
        let schema = schema();
        let without = compute(
            &schema,
            &sample(&[[1.0, 0.0], [2.0, 0.0], [3.0, 0.0], [4.0, 0.0], [5.0, 0.0]]),
            at(0),
        )
        .unwrap();
        let with = compute(
            &schema,
            &sample(&[[1.0, 0.0], [2.0, 0.0], [3.0, 0.0], [4.0, 0.0], [1e9, 0.0]]),
            at(0),
        )
        .unwrap();

        assert_eq!(without.centre[0], with.centre[0]);
        assert_eq!(without.spread[0], with.spread[0]);
    }

    #[test]
    fn standardizing_puts_the_median_at_zero_and_scales_by_spread() {
        let schema = schema();
        let baseline = with_samples(
            compute(
                &schema,
                &sample(&[[1.0, 0.0], [2.0, 0.0], [3.0, 0.0], [4.0, 0.0], [5.0, 0.0]]),
                at(0),
            )
            .unwrap(),
            MIN_SAMPLES,
        );

        let z = baseline.standardize(&schema, &[3.0, 0.0]).unwrap();
        assert_eq!(z[0], 0.0, "the median standardizes to zero");
        // deviations 2,1,0,1,2 → MAD 1 → spread 1.4826
        let above = baseline.standardize(&schema, &[5.0, 0.0]).unwrap();
        assert!((above[0] - (2.0 / MAD_TO_SIGMA as f32)).abs() < 1e-5);
    }

    /// A zero-spread feature carries no discriminating signal in this
    /// population — it contributes nothing, rather than an infinity that
    /// would poison every distance computed against the vector.
    #[test]
    fn a_constant_feature_contributes_zero_not_infinity() {
        let schema = schema();
        let baseline = with_samples(
            compute(
                &schema,
                &sample(&[[1.0, 1.0], [2.0, 1.0], [3.0, 1.0]]),
                at(0),
            )
            .unwrap(),
            MIN_SAMPLES,
        );
        let z = baseline.standardize(&schema, &[2.0, 999.0]).unwrap();
        assert_eq!(z[1], 0.0);
        assert!(z.iter().all(|v| v.is_finite()));
    }

    /// A mismatched baseline is a refused comparison, never a plausible-looking
    /// distance in the wrong units.
    #[test]
    fn a_mismatched_schema_is_refused_rather_than_silently_applied() {
        let schema = schema();
        let mut baseline = with_samples(
            compute(&schema, &sample(&[[1.0, 1.0], [2.0, 1.0]]), at(0)).unwrap(),
            MIN_SAMPLES,
        );
        baseline.schema_hash = "a-different-schema".into();

        assert!(matches!(
            baseline.standardize(&schema, &[1.0, 1.0]),
            Err(BaselineError::SchemaMismatch { .. })
        ));
        assert!(!baseline.matches(&schema));
    }

    #[test]
    fn a_thin_sample_is_refused_rather_than_ranked_against_noise() {
        let schema = schema();
        let baseline = compute(&schema, &sample(&[[1.0, 1.0], [2.0, 1.0]]), at(0)).unwrap();
        assert!(matches!(
            baseline.standardize(&schema, &[1.0, 1.0]),
            Err(BaselineError::TooFewSamples { samples: 2, .. })
        ));
    }

    /// The fingerprint is what lets a materialized ranking be reused safely,
    /// so it must move exactly when the standardization does — and not when
    /// something irrelevant does.
    #[test]
    fn the_fingerprint_tracks_the_numbers_and_ignores_the_clock() {
        let schema = schema();
        let baseline = compute(
            &schema,
            &sample(&[[1.0, 1.0], [2.0, 1.0], [3.0, 1.0]]),
            at(0),
        )
        .expect("a baseline");

        // Same statistics, different time: the *same* baseline. Invalidating
        // on the clock would discard every cached ranking on each harmless
        // refresh.
        let mut later = baseline.clone();
        later.computed_at = at(999_999);
        assert_eq!(baseline.fingerprint(), later.fingerprint());

        // A moved centre is a different standardization.
        let mut shifted = baseline.clone();
        shifted.centre[0] += 0.5;
        assert_ne!(baseline.fingerprint(), shifted.fingerprint());

        // So is a moved spread, a different schema, and a different sample.
        let mut respread = baseline.clone();
        respread.spread[0] += 0.5;
        assert_ne!(baseline.fingerprint(), respread.fingerprint());

        let mut reschema = baseline.clone();
        reschema.schema_hash = "other".into();
        assert_ne!(baseline.fingerprint(), reschema.fingerprint());

        let mut resampled = baseline.clone();
        resampled.sample_count += 1;
        assert_ne!(baseline.fingerprint(), resampled.fingerprint());
    }

    /// An ulp of difference standardizes differently, so it must fingerprint
    /// differently — hence hashing bit patterns rather than decimal forms.
    #[test]
    fn the_fingerprint_separates_baselines_differing_by_one_ulp() {
        let schema = schema();
        let baseline =
            compute(&schema, &sample(&[[1.0, 1.0], [2.0, 1.0]]), at(0)).expect("a baseline");
        let mut nudged = baseline.clone();
        nudged.centre[0] = f32::from_bits(nudged.centre[0].to_bits() + 1);
        assert_ne!(baseline.fingerprint(), nudged.fingerprint());
    }

    #[test]
    fn an_empty_sample_is_no_baseline_at_all() {
        assert!(compute(&schema(), &[], at(0)).is_none());
    }

    #[test]
    fn a_corrupt_short_row_does_not_shift_every_median() {
        let schema = schema();
        let mut rows = sample(&[[1.0, 1.0], [1.0, 1.0], [1.0, 1.0]]);
        rows.push(vec![1.0]); // a row missing its second feature
        let baseline = compute(&schema, &rows, at(0)).unwrap();
        assert_eq!(baseline.centre, vec![1.0, 1.0]);
    }

    #[test]
    fn baseline_matches_the_v1_schema() {
        let schema = &*v1::SCHEMA;
        let rows = vec![vec![0.0; schema.dimension()]; 3];
        let baseline = compute(schema, &rows, at(0)).unwrap();
        assert!(baseline.matches(schema));
        assert_eq!(baseline.centre.len(), schema.dimension());
        assert_eq!(baseline.embedding_version, v1::VERSION);
    }
}
