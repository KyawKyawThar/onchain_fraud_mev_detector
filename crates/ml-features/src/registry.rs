//! The version registry: every feature-schema version this build can still
//! extract, resolvable by [`FeatureVersion`].
//!
//! §20.1 defines a dataset by `(time window, feature_version, label rule)` —
//! so reproducing a historical dataset (to retrain, audit, or investigate a
//! model) needs the *exact* extractor that version shipped with, not the
//! current one. The decision, made while v1 is the only version: **shipped
//! extractors are kept linkable forever** as frozen version modules behind
//! this registry — the same stance the model registry takes on historical
//! evidence (attributable to the exact config that produced it), and the same
//! link-don't-lookup discipline as `DetectionPlan` (§6). The alternative
//! ("reproduce old versions by checking out the git tag") was rejected: it
//! makes cross-version backfills a source-control exercise and leaves the
//! dataset-export binary able to speak only one version.
//!
//! When v2 lands: freeze it as `crate::v2`, point `FEATURE_VERSION` at it,
//! append `&v2::Extractor` here — and leave `v1` untouched.

use alloy_primitives::B256;
use detector_api::DetectionCtx;

use crate::schema::{FeatureSchema, FeatureVersion, Granularity};
use crate::vector::FeatureVector;
use crate::FEATURE_VERSION;

/// One shipped feature-schema version's extraction surface — what the
/// dataset-export binary (t2) programs against so it can materialize a window
/// under *any* version the registry knows, not just the current one.
///
/// Object-safe on purpose (the `EventSink` seam discipline): consumers hold
/// `&'static dyn VersionedExtractor` resolved once at boot, link-or-fail.
pub trait VersionedExtractor: Send + Sync {
    /// The version every vector this extractor produces is stamped with.
    fn version(&self) -> FeatureVersion;

    /// This version's frozen layout for `granularity`.
    fn schema(&self, granularity: Granularity) -> &'static FeatureSchema;

    /// The block-level vector for `ctx`.
    fn extract_block(&self, ctx: &DetectionCtx) -> FeatureVector;

    /// The per-tx vector for `tx_hash` within `ctx`; `None` iff the hash is
    /// not in the block's bundle.
    fn extract_tx(&self, ctx: &DetectionCtx, tx_hash: B256) -> Option<FeatureVector>;

    /// Per-tx vectors for every transaction in the block, in block order.
    fn extract_all_txs(&self, ctx: &DetectionCtx) -> Vec<(B256, FeatureVector)>;
}

/// Every version this build ships, newest last. Append-only: removing an
/// entry orphans every dataset and model card stamped with its version.
static EXTRACTORS: &[&dyn VersionedExtractor] = &[&crate::v1::Extractor];

/// The extractor for `version`, if this build still ships it.
pub fn extractor_for(version: FeatureVersion) -> Option<&'static dyn VersionedExtractor> {
    EXTRACTORS.iter().copied().find(|e| e.version() == version)
}

/// The current version's extractor — what serving-side consumers (the
/// anomaly detector, t4) use. The crate-root `extract_*` free functions are
/// this, statically dispatched.
pub fn current() -> &'static dyn VersionedExtractor {
    extractor_for(FEATURE_VERSION)
        .expect("the current FEATURE_VERSION is always registered — a wiring bug otherwise")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_current_version_is_always_resolvable() {
        assert_eq!(current().version(), FEATURE_VERSION);
        assert!(extractor_for(FEATURE_VERSION).is_some());
    }

    #[test]
    fn an_unshipped_version_resolves_to_none() {
        assert!(extractor_for(FeatureVersion(999)).is_none());
    }

    #[test]
    fn registered_versions_are_unique() {
        // Two extractors claiming one version would make extractor_for
        // order-dependent — the registry must stay a function.
        let mut seen = std::collections::HashSet::new();
        for e in EXTRACTORS {
            assert!(
                seen.insert(e.version()),
                "duplicate version {}",
                e.version()
            );
        }
    }
}
