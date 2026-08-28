//! Behavioral embeddings — the pure kernel and its **version registry**
//! (§20.3, Sprint 19 t1).
//!
//! A per-address **behavior vector**: activity cadence, counterparty-type
//! distribution, value-flow shape and incident history, computed from the
//! ClickHouse adjacency store plus the Postgres system of record. It is to
//! [`crate::embedding_job`] exactly what [`crate::risk`] is to
//! [`crate::risk_scorer`] — the decision, with no store dependency of its own,
//! so the interesting logic is `assert_eq!`-testable with plain structs.
//!
//! ## Versioned like a risk-score model — and *runnable* like one
//!
//! A frozen schema is only survivable if two versions can run side by side.
//! [`BehaviorEmbedder`] is that seam and [`EMBEDDERS`] is the roster: the job
//! computes every *enabled* version per address, so shipping v2 is
//! shadow → backfill → cut the read over → retire v1, rather than a flag day.
//! Without this seam a frozen schema is just a schema you cannot change, which
//! is the failure mode the version stamp was supposed to prevent.
//!
//! Every vector carries **both** its `version` and its schema
//! [`content_hash`](BehaviorSchema::content_hash). The hash is not redundant:
//! a version string cannot catch an edit made *underneath* it, and comparing
//! across such an edit computes distances between two different feature spaces
//! while looking entirely well-formed.
//!
//! ## What the adjacency store cannot say
//!
//! `address_adjacency` records *relations* (A funded B, in this tx, at this
//! block), never amounts. So "value-flow shape" here is the shape of the flow
//! — direction balance, which relation kinds carry it, how concentrated it is
//! across counterparties — and **not** its magnitude. Missing upstream data is
//! encoded, never imputed (the `ml-features` rule): v1's
//! `value_magnitude_known` is an explicit `0.0` rather than a plausible-looking
//! zero volume, so a consumer can tell "no value facts exist" from "value flow
//! was zero", and a later version that gains an amount column lights it up.
//!
//! ## Scale, and why comparison is not this module's job
//!
//! The feature families have deliberately different natural ranges
//! ([`FeatureKind`]), so a raw cosine over a stored vector is dominated by the
//! log-magnitude family — "behaviorally similar" would degrade into "similar
//! transaction count". Standardization belongs at **comparison** time, against
//! a population [`baseline`], not at embed time: stored vectors stay
//! interpretable, and one subsystem owns the answer to "why do these two look
//! alike?" — the same layering §20.2 uses to keep explainability above the
//! inference seam.
//!
//! ## What a vector does *not* survive
//!
//! `address_adjacency` has no reorg reversal — a reverted block's edges stay in
//! the graph. The incident-history family rolls back correctly (the job
//! consumes `AttributionRetracted`, §15), but the cadence and flow families do
//! not: they describe every observation ever appended, canonical or not. Do
//! not read a behavior vector as reorg-safe.

pub mod baseline;
pub mod v1;

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use events::intelligence::{AddressEmbeddingUpdated, BehaviorFactor};
use events::primitives::{AccountAddress, EntityId};
use sha2::{Digest, Sha256};
use strum::IntoStaticStr;

use crate::model::{
    AttributionRecord, EdgeHistory, EntityRecord, LabelKind, LabelRecord, SanctionEntry,
};

/// How many factors [`BehaviorVector::top_factors`] surfaces. The full vector
/// travels with the event, so this is the *explanation*, not the record —
/// bounded on the same "explainable past a screenful means bounded" reasoning
/// as `risk::MAX_VISIBLE_FACTORS`.
pub const MAX_VISIBLE_FACTORS: usize = 8;

/// The statistical shape of a feature's values — the scaling convention a
/// reader needs to interpret one number, and part of the schema hash.
///
/// Deliberately a local enum rather than `ml_features::FeatureKind`: this
/// crate must not take a dependency on the ML feature pipeline to describe its
/// own schema (they are versioned on different clocks, and the conformance
/// rules keep `ml-features` unaware of `intelligence` in the other direction).
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum FeatureKind {
    /// `[0, 1]` — a share of some total.
    Fraction,
    /// Exactly `0.0` or `1.0`.
    Indicator,
    /// `log10(1 + x)` of a non-negative count/duration.
    LogMagnitude,
    /// Unbounded non-negative.
    Ratio,
}

/// One feature's identity in a schema: its stable wire name and its scaling
/// convention. Both are hashed, so reclassifying a feature is as visible as
/// renaming one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureDef {
    pub name: &'static str,
    pub kind: FeatureKind,
}

/// One version's frozen feature layout: declaration order *is* vector order.
///
/// Built once per version at first use and never mutated — the `content_hash`
/// is computed at construction so it cannot drift from the list it describes.
#[derive(Debug)]
pub struct BehaviorSchema {
    version: &'static str,
    features: Vec<FeatureDef>,
    content_hash: String,
}

impl BehaviorSchema {
    /// Freeze a feature list into a schema, hashing it in the same step.
    ///
    /// Panics on a duplicate feature name: two features sharing a wire name
    /// would make the explanation view ambiguous and the hash a liar, and this
    /// runs once at first use from a `const` list, so failing loudly at boot is
    /// strictly better than shipping it.
    pub fn new(version: &'static str, features: Vec<FeatureDef>) -> Self {
        let mut names: Vec<&str> = features.iter().map(|f| f.name).collect();
        names.sort_unstable();
        let total = names.len();
        names.dedup();
        assert_eq!(
            names.len(),
            total,
            "behavior schema {version} has two features with the same name"
        );

        let mut hasher = Sha256::new();
        for feature in &features {
            let kind: &'static str = feature.kind.into();
            hasher.update(feature.name.as_bytes());
            hasher.update(b":");
            hasher.update(kind.as_bytes());
            hasher.update(b"\n");
        }
        Self {
            version,
            content_hash: format!("{:x}", hasher.finalize()),
            features,
        }
    }

    /// The version string stamped on every vector this schema produces.
    pub fn version(&self) -> &'static str {
        self.version
    }

    /// Hex SHA-256 over every feature's `name:kind`, in order — what makes
    /// "same version" mean "same schema".
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }

    /// The features, in vector order.
    pub fn features(&self) -> &[FeatureDef] {
        &self.features
    }

    /// The vector length — derived from the feature list, never a hand-kept
    /// constant that could disagree with it.
    pub fn dimension(&self) -> usize {
        self.features.len()
    }

    /// The vector index a feature name occupies, if this schema has it.
    pub fn index_of(&self, name: &str) -> Option<usize> {
        self.features.iter().position(|f| f.name == name)
    }
}

/// One embeddable schema version. Object-safe: the roster is
/// `&'static [&'static dyn BehaviorEmbedder]`, and the job holds whichever
/// versions are enabled without knowing what they are.
pub trait BehaviorEmbedder: Send + Sync {
    /// This version's frozen layout.
    fn schema(&self) -> &'static BehaviorSchema;

    /// Compute the vector for one address from already-fetched inputs,
    /// `as_of` a given instant — an explicit input, not an ambient clock, so
    /// replaying the same inputs yields the same bits (§18).
    fn embed(
        &self,
        address: AccountAddress,
        entity_id: Option<EntityId>,
        inputs: &BehaviorInputs,
        as_of: DateTime<Utc>,
    ) -> BehaviorVector;

    /// Convenience: this version's name.
    fn version(&self) -> &'static str {
        self.schema().version()
    }
}

/// Every version this build ships, **newest last**. Append-only: removing an
/// entry orphans every stored vector stamped with it, and every downstream
/// comparison that assumed it.
static EMBEDDERS: &[&dyn BehaviorEmbedder] = &[&v1::Embedder];

/// The versions this build can compute.
pub fn embedders() -> &'static [&'static dyn BehaviorEmbedder] {
    EMBEDDERS
}

/// The embedder for a named version, or `None` if this build doesn't ship it —
/// a *typed miss*, not a fallback to the default: silently embedding under a
/// different version than the operator asked for is exactly the drift the
/// version stamp exists to prevent.
pub fn embedder_for(version: &str) -> Option<&'static dyn BehaviorEmbedder> {
    EMBEDDERS
        .iter()
        .copied()
        .find(|embedder| embedder.version() == version)
}

/// The newest version — what a caller that hasn't been told otherwise should
/// compute and read.
pub fn default_embedder() -> &'static dyn BehaviorEmbedder {
    *EMBEDDERS
        .last()
        .expect("the embedder roster is never empty — v1 is linked unconditionally")
}

/// Every input an embedder needs for one address — assembled by the caller
/// from the adjacency store and the Sprint 7 t1 store seams (see
/// [`crate::embedding_job::load_behavior_inputs`]). Bundled so `embed` takes
/// one argument and a caller cannot mix two addresses' facts, and shared
/// across versions so a multi-version pass loads them **once**.
#[derive(Debug, Clone, Default)]
pub struct BehaviorInputs {
    /// The address's own observations, most recent first, already capped.
    pub history: EdgeHistory,
    /// Active labels for each counterparty that has any. A counterparty absent
    /// from the map is *unlabeled*, not unknown — the caller reads labels for
    /// the whole counterparty set, so an absence is a fact.
    pub counterparty_labels: BTreeMap<AccountAddress, Vec<LabelKind>>,
    /// The address's own active labels.
    pub labels: Vec<LabelRecord>,
    /// Sanctions-list matches for the address (§8.5).
    pub sanctions: Vec<SanctionEntry>,
    /// Incidents attributed to the address's resolved entity.
    pub attributions: Vec<AttributionRecord>,
    /// That entity, if any (drives the cluster-size feature).
    pub entity: Option<EntityRecord>,
}

/// One address's computed behavior vector, stamped with the schema that
/// produced it. `values` is in schema order and always has
/// [`BehaviorSchema::dimension`] entries.
#[derive(Debug, Clone)]
pub struct BehaviorVector {
    pub address: AccountAddress,
    pub entity_id: Option<EntityId>,
    /// The schema behind `values` — carried by reference so the vector can
    /// name its own features without a lookup table beside it.
    pub schema: &'static BehaviorSchema,
    pub values: Vec<f32>,
    /// The input history was capped — this describes a recent activity window
    /// rather than the address's whole life (§8.2's hub rule at edge
    /// granularity).
    pub observations_truncated: bool,
    /// When this vector was computed, `as_of` the caller's instant.
    pub computed_at: DateTime<Utc>,
}

/// Compares by *value*, deliberately ignoring the `schema` pointer identity:
/// two vectors are the same vector when they say the same thing about the same
/// address under the same schema version, which is what change-detection and
/// tests both mean by equality.
impl PartialEq for BehaviorVector {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
            && self.entity_id == other.entity_id
            && self.schema.version() == other.schema.version()
            && self.schema.content_hash() == other.schema.content_hash()
            && self.values == other.values
            && self.observations_truncated == other.observations_truncated
            && self.computed_at == other.computed_at
    }
}

impl BehaviorVector {
    /// The version stamped on this vector.
    pub fn embedding_version(&self) -> &'static str {
        self.schema.version()
    }

    /// The schema hash stamped on this vector.
    pub fn schema_hash(&self) -> &str {
        self.schema.content_hash()
    }

    /// One feature's value by name, or `None` when this schema has no such
    /// feature — the version-agnostic accessor. A caller that knows the
    /// version uses that version's typed index instead (see
    /// [`v1::BehaviorFeature::index`]).
    pub fn get(&self, name: &str) -> Option<f32> {
        self.schema.index_of(name).map(|index| self.values[index])
    }

    /// The features paired with their values, in schema order.
    pub fn features(&self) -> impl Iterator<Item = (&FeatureDef, f32)> {
        self.schema
            .features()
            .iter()
            .zip(self.values.iter().copied())
    }

    /// A stable digest of what this vector *says* — see [`content_digest`].
    pub fn content_digest(&self) -> u64 {
        content_digest(
            &self.address,
            self.schema.version(),
            self.schema.content_hash(),
            self.observations_truncated,
            &self.values,
        )
    }

    /// The largest-magnitude features, most significant first, each with its
    /// **share** of the vector's total squared magnitude — the same "a thin
    /// explanation must read as thin" contract as the anomaly detector's
    /// contributions: a vector no single feature dominates reports small
    /// shares rather than padding itself with its least-boring dimensions.
    ///
    /// An all-zero vector (an address with no recorded behavior at all) has no
    /// factors, not an arbitrary tie-break ordering.
    pub fn top_factors(&self, limit: usize) -> Vec<BehaviorFactor> {
        let total: f64 = self
            .values
            .iter()
            .map(|v| f64::from(*v) * f64::from(*v))
            .sum();
        if total <= 0.0 {
            return Vec::new();
        }
        let mut factors: Vec<(&'static str, f32, f64)> = self
            .schema
            .features()
            .iter()
            .zip(self.values.iter().copied())
            .filter(|(_, value)| *value != 0.0)
            .map(|(def, value)| {
                let share = f64::from(value) * f64::from(value) / total;
                (def.name, value, share)
            })
            .collect();
        // Descending share, ties broken by schema name so the order never
        // depends on iteration accidents.
        factors.sort_by(|a, b| {
            b.2.partial_cmp(&a.2)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(b.0))
        });
        factors
            .into_iter()
            .take(limit)
            .map(|(name, value, share)| BehaviorFactor {
                feature: name.to_owned(),
                value,
                share: share as f32,
            })
            .collect()
    }

    /// The wire form (§20.3) — the vector plus its bounded explanation.
    pub fn to_event(&self) -> AddressEmbeddingUpdated {
        AddressEmbeddingUpdated {
            address: self.address,
            entity_id: self.entity_id,
            embedding_version: self.schema.version().to_owned(),
            schema_hash: self.schema.content_hash().to_owned(),
            vector: self.values.clone(),
            top_factors: self.top_factors(MAX_VISIBLE_FACTORS),
            observations_truncated: self.observations_truncated,
        }
    }
}

// ── Shared numeric helpers ───────────────────────────────────────────────────
// Every version computes different features, but they must agree on what
// "no data" and "a log magnitude" mean — otherwise two versions of the *same*
// feature name would silently differ in their empty case.

/// A stable digest of what a vector *says* — address, version, schema and
/// values, deliberately **excluding when it was computed**.
///
/// This is the change-detection key: two recomputations of a dormant address
/// differ only in when they ran, and republishing that difference forever is
/// noise on the bus and rows in the event store that no consumer can act on.
/// Excluding `computed_at` is the whole point.
///
/// A free function rather than a method so a *stored* vector
/// ([`crate::embedding_store::StoredEmbedding`]) and a freshly computed one
/// hash identically by construction — the two are compared against each other
/// on every page, and two nearly-identical hashers would be a bug that
/// manifests as "everything always looks changed".
pub fn content_digest(
    address: &AccountAddress,
    version: &str,
    schema_hash: &str,
    observations_truncated: bool,
    values: &[f32],
) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(address.as_slice());
    hasher.update(version.as_bytes());
    hasher.update(schema_hash.as_bytes());
    hasher.update([u8::from(observations_truncated)]);
    for value in values {
        // The bit pattern, not the decimal form: this is an identity check,
        // and `to_bits` is exactly the "same bits" the kernel's determinism
        // contract promises.
        hasher.update(value.to_bits().to_be_bytes());
    }
    let digest = hasher.finalize();
    u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 is 32 bytes"))
}

/// `log10(1 + x)` through the pure-Rust `libm` rather than the host C library:
/// C libms differ in the last ulp across platforms, and a vector that differs
/// by an ulp between a replay and the original is not the same vector (§18).
pub(crate) fn log_magnitude(x: f64) -> f64 {
    if x <= 0.0 {
        0.0
    } else {
        libm::log10(1.0 + x)
    }
}

/// `numerator / denominator`, or `0.0` when there is nothing to divide — the
/// one place "no observations" turns into a value, so no feature invents its
/// own convention for an empty history.
pub(crate) fn ratio(numerator: f64, denominator: f64) -> f64 {
    if denominator <= 0.0 {
        0.0
    } else {
        numerator / denominator
    }
}

/// Elapsed days between two instants, clamped at zero (clock skew, or an
/// observation stamped microscopically in the future, is not negative time).
pub(crate) fn days_between(from: DateTime<Utc>, to: DateTime<Utc>) -> f64 {
    ((to - from).num_seconds() as f64 / 86_400.0).max(0.0)
}

/// Normalize negative zero and narrow to the stored width.
///
/// `f64`'s `Sum` folds from `-0.0`, so an empty sum lands on `-0.0` —
/// numerically identical to `0.0` but a different bit pattern, and this
/// vector's contract is that the same inputs produce the same *bits* (§18),
/// which `content_digest` then depends on.
pub(crate) fn store_value(value: f64) -> f32 {
    let value = if value == 0.0 { 0.0 } else { value };
    value as f32
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    fn vector() -> BehaviorVector {
        default_embedder().embed(
            Address::repeat_byte(1),
            None,
            &BehaviorInputs::default(),
            at(1_000),
        )
    }

    // ── The version registry ─────────────────────────────────────────

    /// The roster is what makes a *frozen* schema survivable: v2 ships beside
    /// v1 and the two run through a rollout together.
    #[test]
    fn every_registered_version_is_unique_and_reachable_by_name() {
        let mut versions: Vec<&str> = embedders().iter().map(|e| e.version()).collect();
        assert!(!versions.is_empty());
        let total = versions.len();
        versions.sort_unstable();
        versions.dedup();
        assert_eq!(versions.len(), total, "two embedders share a version name");

        for embedder in embedders() {
            let found = embedder_for(embedder.version()).expect("registered versions resolve");
            assert_eq!(
                found.schema().content_hash(),
                embedder.schema().content_hash()
            );
        }
    }

    /// A typed miss, never a fallback: silently embedding under a different
    /// version than the operator asked for is exactly the drift the version
    /// stamp exists to prevent.
    #[test]
    fn an_unknown_version_is_a_miss_not_a_fallback() {
        assert!(embedder_for("behavior-v99").is_none());
    }

    #[test]
    fn the_default_embedder_is_the_newest_registered_one() {
        assert_eq!(
            default_embedder().version(),
            embedders().last().unwrap().version()
        );
        assert_eq!(default_embedder().version(), v1::VERSION);
    }

    // ── Schema construction ──────────────────────────────────────────

    #[test]
    fn the_hash_covers_the_kind_not_only_the_name() {
        let a = BehaviorSchema::new(
            "t",
            vec![FeatureDef {
                name: "x",
                kind: FeatureKind::Fraction,
            }],
        );
        let b = BehaviorSchema::new(
            "t",
            vec![FeatureDef {
                name: "x",
                kind: FeatureKind::Ratio,
            }],
        );
        assert_ne!(
            a.content_hash(),
            b.content_hash(),
            "reclassifying a feature must be as visible as renaming one"
        );
    }

    #[test]
    fn the_hash_covers_the_order() {
        let defs = |first: &'static str, second: &'static str| {
            vec![
                FeatureDef {
                    name: first,
                    kind: FeatureKind::Fraction,
                },
                FeatureDef {
                    name: second,
                    kind: FeatureKind::Fraction,
                },
            ]
        };
        assert_ne!(
            BehaviorSchema::new("t", defs("a", "b")).content_hash(),
            BehaviorSchema::new("t", defs("b", "a")).content_hash(),
        );
    }

    #[test]
    #[should_panic(expected = "two features with the same name")]
    fn a_duplicate_feature_name_fails_loudly_at_construction() {
        let dup = FeatureDef {
            name: "x",
            kind: FeatureKind::Fraction,
        };
        BehaviorSchema::new("t", vec![dup, dup]);
    }

    // ── Change detection ─────────────────────────────────────────────

    /// The whole point: a dormant address recomputed an hour later differs
    /// only in `computed_at`, and republishing that forever is noise on the
    /// bus and rows no consumer can act on.
    #[test]
    fn the_content_digest_ignores_when_the_vector_was_computed() {
        let embedder = default_embedder();
        let address = Address::repeat_byte(1);
        let earlier = embedder.embed(address, None, &BehaviorInputs::default(), at(0));
        let later = embedder.embed(address, None, &BehaviorInputs::default(), at(9_999));

        assert_ne!(earlier.computed_at, later.computed_at);
        assert_eq!(earlier.content_digest(), later.content_digest());
    }

    #[test]
    fn the_content_digest_changes_with_the_address_or_any_value() {
        let embedder = default_embedder();
        let base = vector();
        let other_address = embedder.embed(
            Address::repeat_byte(2),
            None,
            &BehaviorInputs::default(),
            at(1_000),
        );
        assert_ne!(base.content_digest(), other_address.content_digest());

        let mut moved = base.clone();
        moved.values[0] = 0.5;
        assert_ne!(base.content_digest(), moved.content_digest());

        let mut hubbed = base.clone();
        hubbed.observations_truncated = true;
        assert_ne!(base.content_digest(), hubbed.content_digest());
    }

    // ── The version-agnostic accessors ───────────────────────────────

    #[test]
    fn features_are_readable_by_name_without_knowing_the_version() {
        let vector = vector();
        for (def, value) in vector.features() {
            assert_eq!(vector.get(def.name), Some(value));
        }
        assert_eq!(vector.get("not_a_feature"), None);
    }

    #[test]
    fn equality_is_by_value_not_by_schema_pointer() {
        let a = vector();
        let b = vector();
        assert_eq!(a, b);
        assert_eq!(a.embedding_version(), v1::VERSION);
        assert_eq!(a.schema_hash(), v1::SCHEMA.content_hash());
    }
}
