//! The schema *vocabulary* (§20.1): the version, granularity, kind, and
//! layout types every feature-extraction version is described with.
//!
//! The concrete feature lists do **not** live here — each shipped version owns
//! its layout as a frozen module ([`crate::v1`], one day `v2`, …) whose enums
//! *are* the schema: variant order is vector order, variant names (via strum)
//! are feature names, and an exhaustive `match` is what computes each value.
//! That makes the three failure modes of a parallel name-list design —
//! a missing feature, a duplicated one, a reordered one — unrepresentable at
//! compile time rather than debug-asserted at run time.
//!
//! A version, once shipped, is frozen forever: any observable change to a
//! feature's name, position, kind, or extraction semantics is a new version
//! module and a new [`FeatureVersion`], never an edit (§20.5's
//! serving/training skew check compares exactly this stamp). The snapshot
//! tests pin the current schema so accidental drift fails CI.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A feature-schema version. Plain monotonic counter — semantic versioning
/// buys nothing here because *any* observable change (a renamed feature, a
/// reordered column, a changed formula) breaks a trained model equally.
///
/// The current version is [`crate::FEATURE_VERSION`]; historical versions
/// stay resolvable through [`crate::extractor_for`] so a dataset defined by
/// `(window, feature_version, label rule)` remains reproducible without a
/// checkout of old code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FeatureVersion(pub u32);

impl std::fmt::Display for FeatureVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// What one vector describes: a whole block, or a single transaction within
/// its block. The two granularities carry different feature sets (the block
/// schema aggregates; the tx schema positions one tx against its block).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Granularity {
    Block,
    Tx,
}

impl Granularity {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Granularity::Block => "block",
            Granularity::Tx => "tx",
        }
    }
}

/// The statistical shape of one feature — metadata that lives *in* the schema
/// (and in its [`content_hash`](FeatureSchema::content_hash)) rather than
/// being re-derived by consumers from naming conventions.
///
/// Three places key off it: the invariant tests derive each feature's legal
/// range from its kind instead of string-matching names; the drift monitor
/// (Sprint 18 t5) picks a population-stability statistic appropriate to the
/// kind (a bounded fraction and an unbounded ratio need different tests); and
/// training-side normalization can be driven from the schema instead of a
/// hand-maintained sidecar list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureKind {
    /// A count fraction or share in `[0, 1]`.
    Fraction,
    /// A boolean encoded as exactly `0.0` or `1.0`.
    Indicator,
    /// A `log10(1 + x)`-compressed non-negative magnitude (count, USD, gas).
    LogMagnitude,
    /// An unbounded non-negative ratio of two quantities (premiums,
    /// per-pool densities).
    Ratio,
}

impl FeatureKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            FeatureKind::Fraction => "fraction",
            FeatureKind::Indicator => "indicator",
            FeatureKind::LogMagnitude => "log_magnitude",
            FeatureKind::Ratio => "ratio",
        }
    }

    /// Whether values of this kind are confined to `[0, 1]` by contract.
    pub fn unit_bounded(self) -> bool {
        matches!(self, FeatureKind::Fraction | FeatureKind::Indicator)
    }
}

/// One feature's schema entry: its wire name and statistical kind. Index `i`
/// of a schema's [`defs`](FeatureSchema::defs) describes `values[i]` of every
/// vector extracted under it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureDef {
    pub name: &'static str,
    pub kind: FeatureKind,
}

/// One granularity's frozen feature layout under one [`FeatureVersion`].
/// Obtained from a version module (e.g. [`crate::v1::block_schema`]) or from
/// a vector via [`crate::FeatureVector::schema`].
#[derive(Debug, PartialEq, Eq)]
pub struct FeatureSchema {
    version: FeatureVersion,
    granularity: Granularity,
    defs: &'static [FeatureDef],
}

impl FeatureSchema {
    /// Only version modules construct schemas — the layout is their enum's.
    pub(crate) fn new(
        version: FeatureVersion,
        granularity: Granularity,
        defs: &'static [FeatureDef],
    ) -> Self {
        Self {
            version,
            granularity,
            defs,
        }
    }

    pub fn version(&self) -> FeatureVersion {
        self.version
    }

    pub fn granularity(&self) -> Granularity {
        self.granularity
    }

    /// The feature definitions in vector order.
    pub fn defs(&self) -> &'static [FeatureDef] {
        self.defs
    }

    /// Feature names in vector order.
    pub fn names(&self) -> impl ExactSizeIterator<Item = &'static str> + '_ {
        self.defs.iter().map(|d| d.name)
    }

    pub fn len(&self) -> usize {
        self.defs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.defs.is_empty()
    }

    /// SHA-256 over the canonical schema text (version, granularity, and the
    /// ordered `name:kind` entries), hex-encoded. This is the digest a model
    /// artifact folds into its registry `config_hash` (§20.2), so a schema
    /// change is a new registry triple exactly like a weight change — and the
    /// serving/training skew check (§20.5) can compare digests, not trust
    /// labels. Kinds are part of the contract, hence part of the hash.
    pub fn content_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.version.to_string().as_bytes());
        hasher.update(b":");
        hasher.update(self.granularity.as_str().as_bytes());
        for def in self.defs {
            hasher.update(b"\n");
            hasher.update(def.name.as_bytes());
            hasher.update(b":");
            hasher.update(def.kind.as_str().as_bytes());
        }
        alloy_primitives::hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_displays_and_round_trips() {
        assert_eq!(FeatureVersion(1).to_string(), "v1");
        // `transparent`: the version serializes as a bare number, so it embeds
        // cleanly in dataset rows and model cards.
        assert_eq!(serde_json::to_string(&FeatureVersion(1)).unwrap(), "1");
        assert_eq!(
            serde_json::from_str::<FeatureVersion>("1").unwrap(),
            FeatureVersion(1)
        );
    }

    #[test]
    fn unit_boundedness_follows_the_kind() {
        assert!(FeatureKind::Fraction.unit_bounded());
        assert!(FeatureKind::Indicator.unit_bounded());
        assert!(!FeatureKind::LogMagnitude.unit_bounded());
        assert!(!FeatureKind::Ratio.unit_bounded());
    }

    #[test]
    fn content_hash_covers_kinds_not_just_names() {
        // Reclassifying a feature (same name, different kind) changes the
        // contract consumers key off — the digest must move.
        static A: &[FeatureDef] = &[FeatureDef {
            name: "x",
            kind: FeatureKind::Fraction,
        }];
        static B: &[FeatureDef] = &[FeatureDef {
            name: "x",
            kind: FeatureKind::Ratio,
        }];
        let sa = FeatureSchema::new(FeatureVersion(9), Granularity::Block, A);
        let sb = FeatureSchema::new(FeatureVersion(9), Granularity::Block, B);
        assert_ne!(sa.content_hash(), sb.content_hash());
    }
}
