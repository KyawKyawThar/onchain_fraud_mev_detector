//! The versioned feature schema (§20.1): which features exist, in what order,
//! under which [`FeatureVersion`].
//!
//! The schema is the contract between dataset export, offline training, and
//! serving-side inference — three places that never share a process. It is
//! therefore **append-only per version and frozen forever once shipped**: any
//! change to a feature's name, position, or extraction semantics is a new
//! [`FEATURE_VERSION`], never an edit to an existing one. A model trained on
//! v1 vectors must be served v1 vectors; the boot-time skew check (§20.5)
//! compares exactly this version.
//!
//! The name lists below are the single source of truth for vector layout —
//! the extractors build `(name, value)` pairs against them and
//! [`FeatureVector::from_pairs`](crate::FeatureVector) asserts the order
//! matches, so code and schema cannot drift silently. A snapshot test pins
//! the whole schema (names + [`content_hash`](FeatureSchema::content_hash));
//! changing it without bumping the version fails CI.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The feature-extraction contract version stamped into every
/// [`FeatureVector`](crate::FeatureVector), every exported dataset, and every
/// deployed model's registry card (§20.1, §20.5).
pub const FEATURE_VERSION: FeatureVersion = FeatureVersion(1);

/// A feature-schema version. Plain monotonic counter — semantic versioning
/// buys nothing here because *any* observable change (a renamed feature, a
/// reordered column, a changed formula) breaks a trained model equally.
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
    fn as_str(self) -> &'static str {
        match self {
            Granularity::Block => "block",
            Granularity::Tx => "tx",
        }
    }
}

/// Block-level feature names, in vector order. Four families (§20.1): tx
/// structure, gas dynamics, value flows, pool interactions. `*_log` features
/// are `log10(1 + x)`-scaled; `*_fraction`/`*_share` are `[0, 1]`;
/// `*_known_fraction` features encode missing upstream data explicitly (a
/// header-only source yields honest zeros plus a zero known-fraction, never a
/// guess).
pub(crate) const BLOCK_FEATURES: &[&str] = &[
    // — tx structure —
    "tx_count_log",
    "enriched_tx_fraction",
    "contract_creation_fraction",
    "distinct_sender_fraction",
    "top_sender_tx_share",
    "repeat_sender_tx_fraction",
    // — gas dynamics —
    "gas_known_fraction",
    "gas_price_gwei_log_mean",
    "gas_price_gwei_log_std",
    "head_gas_premium",
    "gas_used_log_mean",
    // — value flows —
    "swap_count_log",
    "transfer_count_log",
    "swap_usd_volume_log",
    "priced_swap_fraction",
    "transfer_usd_volume_log",
    "priced_transfer_fraction",
    "max_transfer_usd_log",
    "flow_concentration",
    // — pool interactions —
    "distinct_pool_count_log",
    "swaps_per_pool",
    "top_pool_swap_share",
    "pool_round_trip_fraction",
    "max_pool_impact_log",
];

/// Per-transaction feature names, in vector order. Same four families and the
/// same scaling conventions as [`BLOCK_FEATURES`]; block-relative features
/// (`position_in_block`, `gas_price_vs_block_median`, …) place the tx against
/// the block it rode in.
pub(crate) const TX_FEATURES: &[&str] = &[
    // — tx structure —
    "position_in_block",
    "is_enriched",
    "is_contract_creation",
    "swap_count_log",
    "transfer_count_log",
    "sender_block_tx_share",
    // — gas dynamics —
    "gas_known",
    "gas_price_gwei_log",
    "gas_price_vs_block_median",
    "gas_used_log",
    // — value flows —
    "swap_in_usd_log",
    "priced_swap_fraction",
    "transfer_usd_log",
    "max_transfer_usd_log",
    // — pool interactions —
    "distinct_pool_count_log",
    "distinct_token_count_log",
    "swap_chain_overlap",
    "self_pool_round_trip",
    "max_pool_impact_log",
];

/// One granularity's frozen feature layout under one [`FeatureVersion`].
#[derive(Debug, PartialEq, Eq)]
pub struct FeatureSchema {
    version: FeatureVersion,
    granularity: Granularity,
    names: &'static [&'static str],
}

/// The current block-level schema.
pub fn block_schema() -> &'static FeatureSchema {
    static SCHEMA: FeatureSchema = FeatureSchema {
        version: FEATURE_VERSION,
        granularity: Granularity::Block,
        names: BLOCK_FEATURES,
    };
    &SCHEMA
}

/// The current per-transaction schema.
pub fn tx_schema() -> &'static FeatureSchema {
    static SCHEMA: FeatureSchema = FeatureSchema {
        version: FEATURE_VERSION,
        granularity: Granularity::Tx,
        names: TX_FEATURES,
    };
    &SCHEMA
}

/// The schema a vector of `granularity` under the **current**
/// [`FEATURE_VERSION`] follows.
pub fn schema_for(granularity: Granularity) -> &'static FeatureSchema {
    match granularity {
        Granularity::Block => block_schema(),
        Granularity::Tx => tx_schema(),
    }
}

impl FeatureSchema {
    pub fn version(&self) -> FeatureVersion {
        self.version
    }

    pub fn granularity(&self) -> Granularity {
        self.granularity
    }

    /// Feature names in vector order — index `i` names `values[i]`.
    pub fn names(&self) -> &'static [&'static str] {
        self.names
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// SHA-256 over the canonical schema text (version, granularity, ordered
    /// names), hex-encoded. This is the digest a model artifact folds into its
    /// registry `config_hash` (§20.2), so a schema change is a new registry
    /// triple exactly like a weight change — and the serving/training skew
    /// check (§20.5) can compare digests, not trust labels.
    pub fn content_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.version.to_string().as_bytes());
        hasher.update(b":");
        hasher.update(self.granularity.as_str().as_bytes());
        for name in self.names {
            hasher.update(b"\n");
            hasher.update(name.as_bytes());
        }
        alloy_primitives::hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique_within_each_schema() {
        for schema in [block_schema(), tx_schema()] {
            let mut seen = std::collections::HashSet::new();
            for name in schema.names() {
                assert!(seen.insert(name), "duplicate feature name {name:?}");
            }
        }
    }

    #[test]
    fn content_hash_distinguishes_the_granularities() {
        // Same version, different name lists — the digest must differ, or a
        // tx-schema model could pass the skew check against block vectors.
        assert_ne!(block_schema().content_hash(), tx_schema().content_hash());
    }

    #[test]
    fn schema_for_routes_by_granularity() {
        assert_eq!(schema_for(Granularity::Block), block_schema());
        assert_eq!(schema_for(Granularity::Tx), tx_schema());
    }

    #[test]
    fn version_displays_and_round_trips() {
        assert_eq!(FEATURE_VERSION.to_string(), "v1");
        // `transparent`: the version serializes as a bare number, so it embeds
        // cleanly in dataset rows and model cards.
        assert_eq!(serde_json::to_string(&FEATURE_VERSION).unwrap(), "1");
        assert_eq!(
            serde_json::from_str::<FeatureVersion>("1").unwrap(),
            FEATURE_VERSION
        );
    }
}
