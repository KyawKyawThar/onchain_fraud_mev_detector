//! [`FeatureVector`] — an extracted vector plus the [`FeatureVersion`] that
//! makes it interpretable.
//!
//! A bare `Vec<f64>` is meaningless without knowing which schema laid it out;
//! stamping the version *into* the value (rather than trusting surrounding
//! context) is what lets a dataset row, a Kafka payload, or a model card carry
//! its own provenance — the same discipline as `config_hash` on
//! `DetectorTriggered` (§6, §20.1).

use serde::{Deserialize, Serialize};

use crate::schema::{schema_for, FeatureSchema, FeatureVersion, Granularity, FEATURE_VERSION};

/// One extracted feature vector: the version + granularity that name its
/// layout, and the values in schema order.
///
/// Constructed only by this crate's extractors (via `from_pairs`, which
/// asserts the layout against the schema), so a vector that exists is
/// well-formed by construction. Every value is finite: the extractors guard
/// each division/log, and `from_pairs` sanitizes defensively — a `NaN` must
/// never reach a model input or a distance computation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeatureVector {
    feature_version: FeatureVersion,
    granularity: Granularity,
    values: Vec<f64>,
}

impl FeatureVector {
    /// Build from `(name, value)` pairs that must mirror `schema` exactly —
    /// same length, same names, same order. The names at the call site are
    /// what make an extractor readable *and* what pins its output layout to
    /// the schema: a drifted name or position is a `debug_assert` failure in
    /// every test/CI build.
    pub(crate) fn from_pairs(
        schema: &'static FeatureSchema,
        pairs: &[(&'static str, f64)],
    ) -> Self {
        debug_assert_eq!(
            pairs.len(),
            schema.len(),
            "extractor produced {} features, {} schema declares {}",
            pairs.len(),
            schema.granularity_label(),
            schema.len()
        );
        debug_assert!(
            pairs
                .iter()
                .zip(schema.names())
                .all(|((name, _), expected)| name == expected),
            "extractor feature order drifted from the {} schema",
            schema.granularity_label()
        );
        let values = pairs
            .iter()
            .map(|&(name, value)| {
                // Belt and braces: the invariant is "extractors only emit
                // finite values" (debug-asserted), and release builds still
                // sanitize rather than ship a NaN into a model.
                debug_assert!(value.is_finite(), "feature {name} is not finite: {value}");
                if value.is_finite() {
                    value
                } else {
                    0.0
                }
            })
            .collect();
        Self {
            feature_version: schema.version(),
            granularity: schema.granularity(),
            values,
        }
    }

    /// The schema version this vector was extracted under.
    pub fn feature_version(&self) -> FeatureVersion {
        self.feature_version
    }

    pub fn granularity(&self) -> Granularity {
        self.granularity
    }

    /// The values, in schema order. Model input as-is.
    pub fn values(&self) -> &[f64] {
        &self.values
    }

    /// The schema describing this vector's layout — `None` when the vector
    /// was produced under a different (older/newer) `FEATURE_VERSION` than
    /// this build knows, in which case its values must not be interpreted by
    /// name (the serving/training skew rule, §20.5).
    pub fn schema(&self) -> Option<&'static FeatureSchema> {
        let schema = schema_for(self.granularity);
        (self.feature_version == FEATURE_VERSION && self.values.len() == schema.len())
            .then_some(schema)
    }

    ///`(name, value)` pairs for explainability surfaces — the "top
    /// contributing features" an anomaly finding's evidence carries (§20.2,
    /// §8.3). `None` under the same version-mismatch condition as
    /// [`schema`](Self::schema).
    pub fn pairs(&self) -> Option<impl Iterator<Item = (&'static str, f64)> + '_> {
        self.schema()
            .map(|s| s.names().iter().copied().zip(self.values.iter().copied()))
    }
}

impl FeatureSchema {
    fn granularity_label(&self) -> &'static str {
        match self.granularity() {
            Granularity::Block => "block",
            Granularity::Tx => "tx",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::block_schema;

    fn well_formed() -> FeatureVector {
        let pairs: Vec<(&'static str, f64)> = block_schema()
            .names()
            .iter()
            .enumerate()
            .map(|(i, name)| (*name, i as f64))
            .collect();
        FeatureVector::from_pairs(block_schema(), &pairs)
    }

    #[test]
    fn from_pairs_stamps_version_and_keeps_order() {
        let v = well_formed();
        assert_eq!(v.feature_version(), FEATURE_VERSION);
        assert_eq!(v.granularity(), Granularity::Block);
        assert_eq!(v.values().len(), block_schema().len());
        assert_eq!(v.values()[3], 3.0);
    }

    #[test]
    fn pairs_zip_names_with_values() {
        let v = well_formed();
        let pairs: Vec<_> = v.pairs().expect("current version").collect();
        assert_eq!(pairs[0].0, block_schema().names()[0]);
        assert_eq!(pairs[1].1, 1.0);
        assert_eq!(pairs.len(), block_schema().len());
    }

    #[test]
    fn a_foreign_version_is_not_interpreted_by_name() {
        // Simulate a vector deserialized from a dataset written under a
        // different FEATURE_VERSION: schema()/pairs() must refuse, because
        // interpreting v2 values with v1 names is exactly the skew §20.5
        // exists to prevent.
        let json = serde_json::to_string(&well_formed()).unwrap();
        let bumped = json.replacen("\"feature_version\":1", "\"feature_version\":999", 1);
        let foreign: FeatureVector = serde_json::from_str(&bumped).unwrap();
        assert!(foreign.schema().is_none());
        assert!(foreign.pairs().is_none());
        // The values themselves survive untouched for version-aware consumers.
        assert_eq!(foreign.values().len(), block_schema().len());
    }

    #[test]
    fn serde_round_trips() {
        let v = well_formed();
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(serde_json::from_str::<FeatureVector>(&json).unwrap(), v);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "order drifted")]
    fn from_pairs_rejects_a_drifted_name() {
        let mut pairs: Vec<(&'static str, f64)> = block_schema()
            .names()
            .iter()
            .map(|name| (*name, 0.0))
            .collect();
        pairs.swap(0, 1);
        let _ = FeatureVector::from_pairs(block_schema(), &pairs);
    }
}
