//! The model registry (§6, task 2): the catalogue of *what we know* about each
//! detector build — its `config_hash`, when it was `deployed_at`, its measured
//! `performance`, and where it sits in the rollout lifecycle.
//!
//! This is deliberately **separate** from [`crate::registry::Registry`], which is
//! the live roster of plugin *instances* the scheduler fans out over.
//! Registration answers "does this detector exist and is it linked?"; the model
//! registry answers "what is this detector's track record, and is it the version
//! we trust?". Keeping them apart means a detector can be linked and running
//! (`Registry`) while still being shadow/deprecated in the catalogue
//! (`ModelRegistry`) — the two evolve on different clocks.
//!
//! Its payoff is the [`DetectorRef`] each [`ModelCard`] yields: the exact
//! `(id, version, config_hash)` triple stamped onto every `DetectorTriggered`
//! (task 5), so historical evidence is reproducible against one specific build
//! (§6, §22, §18).

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use chrono::{DateTime, Utc};
use events::primitives::{Confidence, DetectorRef};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::registry::DetectorKey;
use detector_api::{DetectorId, DetectorPlugin, ModelKind, Scope, SemVer};

/// A stable content hash of a detector's active configuration — the third
/// component of the [`DetectorRef`] triple (§6).
///
/// Two detector builds with the same `(id, version)` but different thresholds
/// must be distinguishable when replaying historical evidence, and the config
/// is what differs — so the hash is taken over the config, not the code. A real
/// SHA-256 digest (audit identifier; collision-resistance matters), held as the
/// raw 32 bytes and rendered as lowercase hex at the edges ([`to_hex`](Self::to_hex),
/// `Display`, serde). Storing the digest, not a `String`, keeps a `ConfigHash`
/// *always* a valid 32-byte hash — it can't be constructed from arbitrary text.
///
/// Hashing is **deterministic by construction**: [`of`](Self::of) routes through
/// [`serde_json::Value`], whose maps are sorted, so a config with a `HashMap`
/// can't hash two different ways from one logical value — the caller doesn't
/// have to remember to use ordered containers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConfigHash([u8; 32]);

/// A detector's config could not be serialized for hashing.
#[derive(Debug, thiserror::Error)]
#[error("failed to serialize detector config for hashing: {source}")]
pub struct ConfigHashError {
    #[source]
    source: serde_json::Error,
}

impl ConfigHash {
    /// Hash a serializable config value, deterministically (see the type docs).
    pub fn of<T: Serialize>(config: &T) -> Result<Self, ConfigHashError> {
        // Round-trip through `Value` so map keys are canonically ordered before
        // hashing — robust by construction, not by caller discipline. The cost
        // (one allocation) is on the cold deploy path, never the detect hot path.
        let canonical =
            serde_json::to_value(config).map_err(|source| ConfigHashError { source })?;
        let bytes = serde_json::to_vec(&canonical)
            .expect("re-serializing an in-memory serde_json::Value is infallible");
        Ok(Self::of_bytes(&bytes))
    }

    /// Hash raw bytes directly — for a detector that already has a canonical
    /// byte encoding of its config and wants to skip the JSON round-trip.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// The **boot-placeholder** config hash for a detector, derived from its
    /// `(id, version)` identity alone.
    ///
    /// Detectors don't yet expose their serialised config for a real
    /// [`of`](Self::of), so until per-detector config hashing lands (Sprint 10 t4)
    /// the boot path stamps this stable, identity-seeded stand-in. Both the `Block`
    /// catalogue (`main::catalogue`) and the cross-block roster
    /// ([`register_cross_block_builtins`](crate::registry::register_cross_block_builtins))
    /// route through *this one function* so the placeholder can't drift between the
    /// two paths — a detector's emitted triple is the same however it was linked.
    pub fn boot_placeholder(id: DetectorId, version: SemVer) -> Self {
        Self::of_bytes(format!("{id}-{version}").as_bytes())
    }

    /// The raw 32-byte digest.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The lowercase-hex rendering, as it lands in [`DetectorRef::config_hash`].
    pub fn to_hex(&self) -> String {
        alloy_primitives::hex::encode(self.0)
    }
}

impl std::fmt::Display for ConfigHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for ConfigHash {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ConfigHash {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let hex = String::deserialize(deserializer)?;
        let bytes = alloy_primitives::hex::decode(&hex).map_err(D::Error::custom)?;
        let digest: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            D::Error::custom(format!(
                "config hash must be 32 bytes (64 hex chars), got {}",
                bytes.len()
            ))
        })?;
        Ok(Self(digest))
    }
}

/// Where a detector build sits in the rollout lifecycle (§6 — safe rollout / A-B).
///
/// Orthogonal to the runtime [`crate::flags::FeatureFlags`] (which is the coarse
/// per-*id* on/off): the status picks, among the linked *versions* of one id,
/// which one's output is trusted. Two versions coexist in the live `Registry`,
/// but only one is normally `Active`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleStatus {
    /// Live: its evidence feeds alerts. The normal state.
    Active,
    /// Runs and is scored, but its output is recorded, not alerted on — a canary
    /// compared against the `Active` version before promotion (§6, §18).
    Shadow,
    /// Superseded by a newer version; kept catalogued so historical events that
    /// name it stay resolvable on replay (§18).
    Deprecated,
}

impl std::fmt::Display for LifecycleStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LifecycleStatus::Active => "active",
            LifecycleStatus::Shadow => "shadow",
            LifecycleStatus::Deprecated => "deprecated",
        })
    }
}

/// A detector build's track record (§6) — either unscored or fully scored,
/// never half.
///
/// Modelled as an enum so "measured" and its numbers can't disagree: a
/// [`Measured`](Self::Measured) build *has* precision/recall/hit-rate over a
/// `NonZeroU64` sample at a known time, and [`Unmeasured`](Self::Unmeasured) has
/// none of them — there is no way to represent "measured over zero samples" or
/// "has a sample count but no precision". **Measurement lands later** (the
/// backtest harness, Sprint 10 §18; per-detector live metrics, Sprint 4 t3 §19);
/// the type exists from task 2 so those jobs have a typed home to write, every
/// card starting `Unmeasured`.
///
/// Rates reuse [`Confidence`] (a validated `[0.0, 1.0]`) so a precision of `1.7`
/// can't be recorded.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum Performance {
    /// No metrics job has scored this build yet — the starting state.
    #[default]
    Unmeasured,
    /// Scored over a non-empty sample.
    Measured {
        /// Of the alerts this build raised, the fraction that were true positives.
        precision: Confidence,
        /// Of the real incidents in the window, the fraction this build caught.
        recall: Confidence,
        /// Fraction of blocks on which the detector fired at all (volume/noise).
        hit_rate: Confidence,
        /// How many samples the rates were computed over — a precision over 3
        /// blocks is not the precision over 30k. Non-zero by construction.
        sample_size: NonZeroU64,
        /// When these numbers were computed.
        measured_at: DateTime<Utc>,
    },
}

impl Performance {
    /// Has this build been scored? `false` only for [`Unmeasured`](Self::Unmeasured).
    pub fn is_measured(&self) -> bool {
        matches!(self, Self::Measured { .. })
    }
}

/// One detector build's full record in the model registry: its identity (from
/// the plugin) plus the catalogue metadata (§6).
#[derive(Debug, Clone, PartialEq)]
pub struct ModelCard {
    pub id: DetectorId,
    pub version: SemVer,
    pub kind: ModelKind,
    pub scope: Scope,
    pub config_hash: ConfigHash,
    pub deployed_at: DateTime<Utc>,
    pub performance: Performance,
    pub status: LifecycleStatus,
}

impl ModelCard {
    /// Build a card for a plugin, pulling `id`/`version`/`kind`/`scope` straight
    /// from it (one source of truth — they can't drift from the live detector)
    /// and attaching the catalogue metadata. Starts [`Active`](LifecycleStatus::Active)
    /// with [`Unmeasured`](Performance::Unmeasured) performance; layer the
    /// builder methods to change either.
    pub fn for_plugin(
        plugin: &dyn DetectorPlugin,
        config_hash: ConfigHash,
        deployed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: plugin.id(),
            version: plugin.version(),
            kind: plugin.kind(),
            scope: plugin.scope(),
            config_hash,
            deployed_at,
            performance: Performance::Unmeasured,
            status: LifecycleStatus::Active,
        }
    }

    /// Override the lifecycle status (e.g. mark this build `Shadow` or
    /// `Deprecated`). Chainable.
    #[must_use]
    pub fn with_status(mut self, status: LifecycleStatus) -> Self {
        self.status = status;
        self
    }

    /// Attach measured performance. Chainable.
    #[must_use]
    pub fn with_performance(mut self, performance: Performance) -> Self {
        self.performance = performance;
        self
    }

    /// This card's `(id, version)` registry key.
    pub fn key(&self) -> DetectorKey {
        (self.id, self.version)
    }

    /// The wire [`DetectorRef`] — the exact `(id, version, config_hash)` triple
    /// stamped onto every `DetectorTriggered` this build produces (§6, task 5).
    pub fn detector_ref(&self) -> DetectorRef {
        DetectorRef {
            id: self.id.as_str().to_owned(),
            version: self.version.to_string(),
            config_hash: self.config_hash.to_hex(),
        }
    }
}

/// Something went wrong assembling the model registry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModelRegistryError {
    /// Two cards for the same `(id, version)` — a build that can't have two
    /// distinct config hashes / deployment records. Mirrors
    /// [`crate::registry::RegistryError::Duplicate`].
    #[error("duplicate model card: {id} v{version} catalogued more than once")]
    Duplicate { id: DetectorId, version: SemVer },
}

/// The catalogue of detector builds known to this binary, keyed by
/// `(id, version)` (§6).
///
/// Parallel to [`crate::registry::Registry`] but holding *metadata*, not plugin
/// instances. Lookups are by the exact `(id, version)` an event names so its
/// `config_hash` and provenance can be recovered on replay; [`versions_of`](Self::versions_of)
/// walks the builds of one id for rollout decisions.
#[derive(Debug, Clone)]
pub struct ModelRegistry {
    by_key: BTreeMap<DetectorKey, ModelCard>,
}

impl ModelRegistry {
    /// Start assembling a catalogue.
    pub fn builder() -> ModelRegistryBuilder {
        ModelRegistryBuilder::default()
    }

    /// Number of catalogued builds.
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    /// The card for one exact build, if catalogued.
    pub fn card(&self, id: DetectorId, version: SemVer) -> Option<&ModelCard> {
        self.by_key.get(&(id, version))
    }

    /// The `(id, version, config_hash)` ref for one build — the convenience the
    /// emission path (task 5) calls to stamp `DetectorTriggered`.
    pub fn detector_ref(&self, id: DetectorId, version: SemVer) -> Option<DetectorRef> {
        self.card(id, version).map(ModelCard::detector_ref)
    }

    /// Every catalogued build, in deterministic `(id, version)` order.
    pub fn cards(&self) -> impl ExactSizeIterator<Item = &ModelCard> {
        self.by_key.values()
    }

    /// The catalogued builds of one detector id, ascending by version — the
    /// rollout view (compare an old `Active` against a new `Shadow`).
    pub fn versions_of(&self, id: DetectorId) -> impl Iterator<Item = &ModelCard> {
        self.by_key
            .range((id, SemVer::new(0, 0, 0))..)
            .take_while(move |((card_id, _), _)| *card_id == id)
            .map(|(_, card)| card)
    }
}

/// Accumulates [`ModelCard`]s, then validates and freezes them into a
/// [`ModelRegistry`]. Order-independent; a duplicate `(id, version)` fails
/// [`build`](Self::build) loudly rather than silently overwriting — same
/// discipline as [`crate::registry::RegistryBuilder`].
#[derive(Default)]
pub struct ModelRegistryBuilder {
    cards: Vec<ModelCard>,
}

impl ModelRegistryBuilder {
    /// Catalogue one build. Chainable.
    pub fn record(&mut self, card: ModelCard) -> &mut Self {
        self.cards.push(card);
        self
    }

    // NOTE: this dedupe-by-`(id, version)` mirrors `registry::RegistryBuilder::build`.
    // Two instances isn't enough to abstract over (rule of three) — and the two
    // error vocabularies are deliberately distinct — so it's left duplicated.
    // Unify into a shared keyed-builder helper if a third keyed registry appears.
    /// Validate uniqueness of `(id, version)` and freeze.
    pub fn build(&self) -> Result<ModelRegistry, ModelRegistryError> {
        let mut by_key: BTreeMap<DetectorKey, ModelCard> = BTreeMap::new();
        for card in &self.cards {
            let key = card.key();
            if by_key.contains_key(&key) {
                return Err(ModelRegistryError::Duplicate {
                    id: key.0,
                    version: key.1,
                });
            }
            by_key.insert(key, card.clone());
        }
        Ok(ModelRegistry { by_key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use detector_api::test_util::MockDetector;
    use serde::Serialize;

    /// A stand-in detector config to hash in the `ConfigHash` tests.
    #[derive(Serialize)]
    struct Cfg {
        min_profit_wei: u64,
        pools: Vec<&'static str>,
    }

    fn a_card(id: &'static str, version: SemVer) -> ModelCard {
        ModelCard::for_plugin(
            &MockDetector::new(id, version),
            ConfigHash::of_bytes(b"cfg"),
            Utc::now(),
        )
    }

    #[test]
    fn config_hash_is_stable_and_distinguishes_configs() {
        let a = Cfg {
            min_profit_wei: 1,
            pools: vec!["uniswap"],
        };
        let b = Cfg {
            min_profit_wei: 2,
            pools: vec!["uniswap"],
        };
        // Same config → same hash (the reproducibility contract).
        assert_eq!(ConfigHash::of(&a).unwrap(), ConfigHash::of(&a).unwrap());
        // Different config → different hash.
        assert_ne!(ConfigHash::of(&a).unwrap(), ConfigHash::of(&b).unwrap());
        // SHA-256 is 32 bytes / 64 hex chars.
        assert_eq!(ConfigHash::of(&a).unwrap().as_bytes().len(), 32);
        assert_eq!(ConfigHash::of(&a).unwrap().to_hex().len(), 64);
    }

    #[test]
    fn config_hash_canonicalizes_key_order() {
        // Deterministic proof that `of` hashes the *sorted* JSON, not the raw
        // field/iteration order — the whole point of routing through `Value`.
        // Fields are declared out of alphabetical order on purpose.
        #[derive(Serialize)]
        struct Unsorted {
            zebra: u8,
            alpha: u8,
        }
        let cfg = Unsorted { zebra: 1, alpha: 2 };

        // Raw serde order is declaration order: `{"zebra":1,"alpha":2}`.
        let raw = serde_json::to_vec(&cfg).unwrap();
        // The canonical (sorted-key) form serde_json::Value produces.
        let canonical = br#"{"alpha":2,"zebra":1}"#;

        // `of` matches the canonical form …
        assert_eq!(
            ConfigHash::of(&cfg).unwrap(),
            ConfigHash::of_bytes(canonical)
        );
        // … and is *not* the naive hash of raw declaration order. If this passed,
        // canonicalization would be a no-op and the test above a coincidence.
        assert_ne!(ConfigHash::of(&cfg).unwrap(), ConfigHash::of_bytes(&raw));
    }

    #[test]
    fn measured_performance_cannot_have_zero_samples() {
        // The `NonZeroU64` on `Performance::Measured.sample_size` makes "measured
        // over zero samples" unrepresentable: the metrics job cannot even build
        // the value (the constructor returns None), so the type — not a runtime
        // check — is what guarantees it.
        assert!(NonZeroU64::new(0).is_none());
        assert!(NonZeroU64::new(1).is_some());
    }

    #[test]
    fn config_hash_round_trips_through_serde() {
        let h = ConfigHash::of_bytes(b"thresholds");
        let json = serde_json::to_string(&h).unwrap();
        // Wire form is the hex string.
        assert_eq!(json, format!("\"{}\"", h.to_hex()));
        assert_eq!(serde_json::from_str::<ConfigHash>(&json).unwrap(), h);
        // A non-32-byte hex string is rejected, not silently accepted.
        assert!(serde_json::from_str::<ConfigHash>("\"abcd\"").is_err());
    }

    #[test]
    fn performance_states_are_either_unmeasured_or_fully_measured() {
        assert!(!Performance::Unmeasured.is_measured());
        let measured = Performance::Measured {
            precision: Confidence::new(0.9),
            recall: Confidence::new(0.8),
            hit_rate: Confidence::new(0.05),
            sample_size: NonZeroU64::new(30_000).unwrap(),
            measured_at: Utc::now(),
        };
        assert!(measured.is_measured());
    }

    #[test]
    fn card_yields_the_detector_ref_triple() {
        let card = ModelCard::for_plugin(
            &MockDetector::new("sandwich", SemVer::new(1, 2, 0)),
            ConfigHash::of_bytes(b"thresholds"),
            Utc::now(),
        );
        let r = card.detector_ref();
        assert_eq!(r.id, "sandwich");
        assert_eq!(r.version, "1.2.0");
        assert_eq!(r.config_hash, card.config_hash.to_hex());
    }

    #[test]
    fn card_pulls_identity_from_the_plugin() {
        let card = ModelCard::for_plugin(
            &MockDetector::new("arb", SemVer::new(1, 0, 0))
                .with_kind(ModelKind::Hybrid)
                .with_scope(Scope::CrossBlock { window_blocks: 5 }),
            ConfigHash::of_bytes(b""),
            Utc::now(),
        );
        assert_eq!(card.kind, ModelKind::Hybrid);
        assert_eq!(card.scope, Scope::CrossBlock { window_blocks: 5 });
        assert_eq!(card.status, LifecycleStatus::Active);
        assert!(!card.performance.is_measured());
    }

    #[test]
    fn lookup_recovers_a_card_by_exact_build() {
        let reg = ModelRegistry::builder()
            .record(a_card("sandwich", SemVer::new(1, 2, 0)))
            .record(a_card("arb", SemVer::new(1, 0, 0)))
            .build()
            .unwrap();

        assert_eq!(reg.len(), 2);
        assert!(reg
            .card(DetectorId::new("sandwich"), SemVer::new(1, 2, 0))
            .is_some());
        assert!(reg
            .detector_ref(DetectorId::new("arb"), SemVer::new(1, 0, 0))
            .is_some());
        // A version that isn't catalogued is absent, not a default.
        assert!(reg
            .card(DetectorId::new("sandwich"), SemVer::new(9, 9, 9))
            .is_none());
    }

    #[test]
    fn versions_of_walks_one_ids_builds_in_order() {
        let reg = ModelRegistry::builder()
            .record(a_card("sandwich", SemVer::new(1, 2, 0)))
            .record(a_card("sandwich", SemVer::new(1, 3, 0)).with_status(LifecycleStatus::Shadow))
            .record(a_card("arb", SemVer::new(1, 0, 0)))
            .build()
            .unwrap();

        let sandwich: Vec<_> = reg
            .versions_of(DetectorId::new("sandwich"))
            .map(|c| (c.version, c.status))
            .collect();
        assert_eq!(
            sandwich,
            vec![
                (SemVer::new(1, 2, 0), LifecycleStatus::Active),
                (SemVer::new(1, 3, 0), LifecycleStatus::Shadow),
            ]
        );
        // Doesn't bleed into the neighbouring id.
        assert_eq!(reg.versions_of(DetectorId::new("arb")).count(), 1);
    }

    #[test]
    fn duplicate_id_and_version_is_rejected() {
        let err = ModelRegistry::builder()
            .record(a_card("sandwich", SemVer::new(1, 2, 0)))
            .record(a_card("sandwich", SemVer::new(1, 2, 0)))
            .build()
            .unwrap_err();
        assert_eq!(
            err,
            ModelRegistryError::Duplicate {
                id: DetectorId::new("sandwich"),
                version: SemVer::new(1, 2, 0),
            }
        );
    }
}
