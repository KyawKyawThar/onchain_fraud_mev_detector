//! [`FeatureVector`] — an extracted vector plus the [`FeatureVersion`] that
//! makes it interpretable.
//!
//! A bare `Vec<f64>` is meaningless without knowing which schema laid it out;
//! stamping the version *into* the value (rather than trusting surrounding
//! context) is what lets a dataset row, a Kafka payload, or a model card carry
//! its own provenance — the same discipline as `config_hash` on
//! `DetectorTriggered` (§6, §20.1).

use serde::{Deserialize, Serialize};

use crate::schema::{FeatureSchema, FeatureVersion, Granularity};

/// One extracted feature vector: the version + granularity that name its
/// layout, and the values in schema order.
///
/// Constructed only by a version module's extractor, whose feature enum fixes
/// the length and order at compile time — so a vector that exists is
/// well-formed by construction. Every value is finite: the extractors guard
/// each division/log, and construction sanitizes defensively — a `NaN` must
/// never reach a model input or a distance computation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeatureVector {
    feature_version: FeatureVersion,
    granularity: Granularity,
    values: Vec<f64>,
}

impl FeatureVector {
    /// Build from values already in `schema` order. The callers are the
    /// version modules, whose values come from iterating the same enum the
    /// schema itself is derived from — length or order can only disagree
    /// through a bug in that module, hence debug-asserted, not `Result`ed.
    pub(crate) fn from_schema_values(schema: &'static FeatureSchema, values: Vec<f64>) -> Self {
        debug_assert_eq!(
            values.len(),
            schema.len(),
            "extractor produced {} values, the {} schema declares {}",
            values.len(),
            schema.granularity().as_str(),
            schema.len()
        );
        let values = values
            .into_iter()
            .enumerate()
            .map(|(i, value)| {
                // Belt and braces: the invariant is "extractors only emit
                // finite values" (debug-asserted), and release builds still
                // sanitize rather than ship a NaN into a model.
                debug_assert!(
                    value.is_finite(),
                    "feature {} is not finite: {value}",
                    schema.defs().get(i).map_or("<beyond schema>", |d| d.name)
                );
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

    /// The schema describing this vector's layout, resolved through the
    /// version registry — so a vector deserialized from a historical dataset
    /// is interpretable as long as this build still ships its version's
    /// extractor. `None` for a version this build doesn't know (or a
    /// length-corrupted payload): its values must not be interpreted by name
    /// (the serving/training skew rule, §20.5).
    pub fn schema(&self) -> Option<&'static FeatureSchema> {
        let schema = crate::registry::extractor_for(self.feature_version)?.schema(self.granularity);
        (schema.len() == self.values.len()).then_some(schema)
    }

    /// `(name, value)` pairs for explainability surfaces — the "top
    /// contributing features" an anomaly finding's evidence carries (§20.2,
    /// §8.3). `None` under the same unknown-version condition as
    /// [`schema`](Self::schema).
    pub fn pairs(&self) -> Option<impl Iterator<Item = (&'static str, f64)> + '_> {
        self.schema()
            .map(|s| s.names().zip(self.values.iter().copied()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1;
    use crate::FEATURE_VERSION;

    fn well_formed() -> FeatureVector {
        let values: Vec<f64> = (0..v1::block_schema().len()).map(|i| i as f64).collect();
        FeatureVector::from_schema_values(v1::block_schema(), values)
    }

    #[test]
    fn construction_stamps_version_and_keeps_order() {
        let v = well_formed();
        assert_eq!(v.feature_version(), FEATURE_VERSION);
        assert_eq!(v.granularity(), Granularity::Block);
        assert_eq!(v.values().len(), v1::block_schema().len());
        assert_eq!(v.values()[3], 3.0);
    }

    #[test]
    fn pairs_zip_names_with_values() {
        let v = well_formed();
        let pairs: Vec<_> = v.pairs().expect("current version").collect();
        assert_eq!(pairs[0].0, v1::block_schema().defs()[0].name);
        assert_eq!(pairs[1].1, 1.0);
        assert_eq!(pairs.len(), v1::block_schema().len());
    }

    #[test]
    fn an_unknown_version_is_not_interpreted_by_name() {
        // Simulate a vector deserialized from a dataset written under a
        // FEATURE_VERSION this build has no extractor for: schema()/pairs()
        // must refuse, because interpreting v999 values with v1 names is
        // exactly the skew §20.5 exists to prevent.
        let json = serde_json::to_string(&well_formed()).unwrap();
        let bumped = json.replacen("\"feature_version\":1", "\"feature_version\":999", 1);
        let foreign: FeatureVector = serde_json::from_str(&bumped).unwrap();
        assert!(foreign.schema().is_none());
        assert!(foreign.pairs().is_none());
        // The values themselves survive untouched for version-aware consumers.
        assert_eq!(foreign.values().len(), v1::block_schema().len());
    }

    #[test]
    fn a_length_corrupted_payload_is_refused_by_name_lookup() {
        // Right version stamp, wrong arity (a truncated/corrupted row): the
        // registry knows the version but the layout can't be trusted.
        let mut json = serde_json::to_string(&well_formed()).unwrap();
        json = json.replacen("\"values\":[0.0,", "\"values\":[", 1);
        let corrupted: FeatureVector = serde_json::from_str(&json).unwrap();
        assert_eq!(corrupted.values().len(), v1::block_schema().len() - 1);
        assert!(corrupted.schema().is_none());
    }

    #[test]
    fn serde_round_trips() {
        let v = well_formed();
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(serde_json::from_str::<FeatureVector>(&json).unwrap(), v);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "schema declares")]
    fn wrong_arity_from_an_extractor_is_a_loud_bug() {
        let _ = FeatureVector::from_schema_values(v1::block_schema(), vec![0.0]);
    }
}
