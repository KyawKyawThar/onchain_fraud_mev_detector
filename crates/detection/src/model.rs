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
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use events::primitives::{Confidence, ConfidenceOutOfRange, DetectorRef};
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

/// Per-detector rollout-stage overrides (§6, §18) — the model-registry analogue
/// of [`crate::flags::FeatureFlags`]: `FeatureFlags` decides whether a detector
/// *runs at all*; this decides, for a detector that runs, whether its evidence
/// is live (`Active`) or canary-only (`Shadow`). Every id defaults to `Active`
/// unless overridden, so a policy only has to name the detectors being staged.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RolloutPolicy {
    overrides: BTreeMap<DetectorId, LifecycleStatus>,
}

impl RolloutPolicy {
    /// Every detector `Active` unless overridden below.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stage `id` as [`Shadow`](LifecycleStatus::Shadow): it still runs and is
    /// scored, but [`PreliminaryAlertCreated`](events::detection::PreliminaryAlertCreated)
    /// is suppressed for it until promoted. Chainable.
    #[must_use]
    pub fn shadow(mut self, id: DetectorId) -> Self {
        self.overrides.insert(id, LifecycleStatus::Shadow);
        self
    }

    /// Mark `id` [`Deprecated`](LifecycleStatus::Deprecated). Chainable.
    #[must_use]
    pub fn deprecated(mut self, id: DetectorId) -> Self {
        self.overrides.insert(id, LifecycleStatus::Deprecated);
        self
    }

    /// The status `id` should be catalogued at: an explicit override, or
    /// `Active` by default.
    pub fn status_of(&self, id: DetectorId) -> LifecycleStatus {
        self.overrides
            .get(&id)
            .copied()
            .unwrap_or(LifecycleStatus::Active)
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

/// The wire form of one detector's measured performance (§18, Sprint 10 t4) — the
/// bridge between the backtest harness's offline scoring
/// ([`backtest::performance::from_report`](../../backtest/performance/index.html))
/// and a live boot's [`ModelCard`].
///
/// Rates are plain `f64`, not [`Confidence`], on purpose: `Confidence`'s derived
/// `Deserialize` doesn't range-check (it's `#[serde(transparent)]` over a bare
/// `f64`), so validating a value from outside the process — this is read from a
/// checked-in JSON file — has to happen explicitly, in [`into_performance`]
/// (Self::into_performance), not silently inside serde.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceRecord {
    pub precision: f64,
    pub recall: f64,
    pub hit_rate: f64,
    pub sample_size: NonZeroU64,
    pub measured_at: DateTime<Utc>,
}

impl PerformanceRecord {
    /// Validate the rates into a [`Performance::Measured`], or the first
    /// out-of-range field's error.
    pub fn into_performance(self) -> Result<Performance, ConfidenceOutOfRange> {
        Ok(Performance::Measured {
            precision: Confidence::try_new(self.precision)?,
            recall: Confidence::try_new(self.recall)?,
            hit_rate: Confidence::try_new(self.hit_rate)?,
            sample_size: self.sample_size,
            measured_at: self.measured_at,
        })
    }
}

/// Every detector's persisted measured performance, keyed by [`DetectorId`]
/// string — the same keying convention as
/// [`backtest::baseline::Baseline`](../../backtest/baseline/type.Baseline.html).
pub type PerformanceStore = BTreeMap<String, PerformanceRecord>;

/// Something went wrong loading the committed performance store.
#[derive(Debug, thiserror::Error)]
pub enum PerformanceStoreError {
    #[error("reading performance store at {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing performance store at {path}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("performance store at {path} has an out-of-range rate for {id}")]
    InvalidRecord {
        path: PathBuf,
        id: String,
        #[source]
        source: ConfidenceOutOfRange,
    },
    #[error("serializing performance store")]
    Serialize(#[source] serde_json::Error),
    #[error("writing performance store to {path}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// `crates/detection/model_performance.json`, resolved at compile time (so it's
/// correct regardless of which crate/cwd calls it — `backtest` writes here via
/// this same function, `detection`'s boot reads it) — the committed bridge from
/// the backtest harness's measured precision/recall/hit_rate into every
/// [`ModelCard::performance`] at boot.
pub fn default_performance_store_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("model_performance.json")
}

/// Load the committed performance store. A missing file is `Ok`-empty — a
/// legitimate state before the backtest harness has ever run
/// (`--update-model-cards`) or for a brand-new detector with no history yet;
/// every card just stays [`Performance::Unmeasured`]. Malformed JSON or an
/// out-of-range rate is a typed error: a checked-in artifact drifting from its
/// schema is a wiring bug, not a runtime condition to paper over.
pub fn load_performance_store(path: &Path) -> Result<PerformanceStore, PerformanceStoreError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PerformanceStore::new())
        }
        Err(source) => {
            return Err(PerformanceStoreError::Read {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    let raw: BTreeMap<String, PerformanceRecord> =
        serde_json::from_str(&text).map_err(|source| PerformanceStoreError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
    // Validate every record eagerly (rather than lazily on first read) so a bad
    // artifact fails at boot, not on whichever detector happens to be looked up
    // first.
    for (id, record) in &raw {
        record.clone().into_performance().map_err(|source| {
            PerformanceStoreError::InvalidRecord {
                path: path.to_path_buf(),
                id: id.clone(),
                source,
            }
        })?;
    }
    Ok(raw)
}

/// Write `store` back to `path` as pretty JSON — the artifact
/// `backtest --update-model-cards` commits.
pub fn save_performance_store(
    store: &PerformanceStore,
    path: &Path,
) -> Result<(), PerformanceStoreError> {
    let mut json = serde_json::to_string_pretty(store).map_err(PerformanceStoreError::Serialize)?;
    json.push('\n');
    std::fs::write(path, json).map_err(|source| PerformanceStoreError::Write {
        path: path.to_path_buf(),
        source,
    })
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
    /// Build a card from its identity fields directly. Starts
    /// [`Active`](LifecycleStatus::Active) with [`Unmeasured`](Performance::Unmeasured)
    /// performance; layer the builder methods to change either. The general
    /// constructor — used both for `Block` plugins (via
    /// [`for_plugin`](Self::for_plugin)) and `CrossBlockDetector`s, which have no
    /// `&dyn DetectorPlugin` to pull identity from.
    pub fn new(
        id: DetectorId,
        version: SemVer,
        kind: ModelKind,
        scope: Scope,
        config_hash: ConfigHash,
        deployed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            version,
            kind,
            scope,
            config_hash,
            deployed_at,
            performance: Performance::Unmeasured,
            status: LifecycleStatus::Active,
        }
    }

    /// Build a card for a plugin, pulling `id`/`version`/`kind`/`scope` straight
    /// from it (one source of truth — they can't drift from the live detector)
    /// and attaching the catalogue metadata. See [`new`](Self::new).
    pub fn for_plugin(
        plugin: &dyn DetectorPlugin,
        config_hash: ConfigHash,
        deployed_at: DateTime<Utc>,
    ) -> Self {
        Self::new(
            plugin.id(),
            plugin.version(),
            plugin.kind(),
            plugin.scope(),
            config_hash,
            deployed_at,
        )
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

/// Build one detector's [`ModelCard`], layering the rollout status and any
/// measured performance from `performance` on top of a fresh boot-placeholder
/// card (§18, Sprint 10 t4). Shared by the `Block` catalogue
/// ([`crate::boot`]) and cross-block registration
/// ([`crate::registry::register_cross_block_builtins`]) so both stamp a
/// detector's card the same way regardless of which roster it lives in.
pub(crate) fn card_for(
    id: DetectorId,
    version: SemVer,
    kind: ModelKind,
    scope: Scope,
    rollout: &RolloutPolicy,
    performance: &PerformanceStore,
) -> ModelCard {
    let mut card = ModelCard::new(
        id,
        version,
        kind,
        scope,
        ConfigHash::boot_placeholder(id, version),
        Utc::now(),
    )
    .with_status(rollout.status_of(id));

    if let Some(record) = performance.get(id.as_str()) {
        let perf = record
            .clone()
            .into_performance()
            .expect("load_performance_store already validated every record");
        card = card.with_performance(perf);
    }

    card
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

    // ── RolloutPolicy ──────────────────────────────────────────────────

    #[test]
    fn rollout_policy_defaults_every_id_to_active() {
        let policy = RolloutPolicy::new();
        assert_eq!(
            policy.status_of(DetectorId::new("sandwich")),
            LifecycleStatus::Active
        );
    }

    #[test]
    fn rollout_policy_override_wins_and_is_scoped_to_its_id() {
        let policy = RolloutPolicy::new()
            .shadow(DetectorId::new("flashloan"))
            .deprecated(DetectorId::new("arb"));
        assert_eq!(
            policy.status_of(DetectorId::new("flashloan")),
            LifecycleStatus::Shadow
        );
        assert_eq!(
            policy.status_of(DetectorId::new("arb")),
            LifecycleStatus::Deprecated
        );
        assert_eq!(
            policy.status_of(DetectorId::new("sandwich")),
            LifecycleStatus::Active
        );
    }

    // ── PerformanceRecord ─────────────────────────────────────────────

    fn valid_record() -> PerformanceRecord {
        PerformanceRecord {
            precision: 0.9,
            recall: 0.8,
            hit_rate: 0.05,
            sample_size: NonZeroU64::new(1_000).unwrap(),
            measured_at: Utc::now(),
        }
    }

    #[test]
    fn performance_record_converts_into_measured() {
        let perf = valid_record().into_performance().unwrap();
        assert!(perf.is_measured());
        match perf {
            Performance::Measured {
                precision, recall, ..
            } => {
                assert_eq!(precision, Confidence::new(0.9));
                assert_eq!(recall, Confidence::new(0.8));
            }
            Performance::Unmeasured => panic!("expected Measured"),
        }
    }

    #[test]
    fn performance_record_rejects_an_out_of_range_rate() {
        let mut record = valid_record();
        record.precision = 1.7;
        assert!(record.into_performance().is_err());
    }

    #[test]
    fn performance_record_round_trips_through_json() {
        let record = valid_record();
        let json = serde_json::to_string(&record).unwrap();
        let reloaded: PerformanceRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, reloaded);
    }

    // ── performance store I/O ────────────────────────────────────────

    #[test]
    fn a_missing_performance_store_loads_as_empty() {
        let path = Path::new("/nonexistent/does-not-exist/model_performance.json");
        let store = load_performance_store(path).unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn malformed_performance_store_is_a_typed_parse_error() {
        let path = std::env::temp_dir().join(format!("model-perf-test-{}-bad", std::process::id()));
        std::fs::write(&path, b"not json").unwrap();
        let result = load_performance_store(&path);
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(result, Err(PerformanceStoreError::Parse { .. })));
    }

    #[test]
    fn an_out_of_range_record_is_a_typed_error_not_a_silent_clamp() {
        let path = std::env::temp_dir().join(format!("model-perf-test-{}-oor", std::process::id()));
        std::fs::write(
            &path,
            br#"{"sandwich":{"precision":1.7,"recall":0.5,"hit_rate":0.1,"sample_size":10,"measured_at":"2024-01-01T00:00:00Z"}}"#,
        )
        .unwrap();
        let result = load_performance_store(&path);
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(
            result,
            Err(PerformanceStoreError::InvalidRecord { .. })
        ));
    }

    #[test]
    fn performance_store_save_then_load_round_trips() {
        let path = std::env::temp_dir().join(format!("model-perf-test-{}-ok", std::process::id()));
        let store = PerformanceStore::from([("sandwich".to_string(), valid_record())]);

        save_performance_store(&store, &path).unwrap();
        let reloaded = load_performance_store(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(store, reloaded);
    }

    // ── card_for ─────────────────────────────────────────────────────

    #[test]
    fn card_for_applies_rollout_status_and_measured_performance() {
        let rollout = RolloutPolicy::new().shadow(DetectorId::new("flashloan"));
        let performance = PerformanceStore::from([("flashloan".to_string(), valid_record())]);

        let card = card_for(
            DetectorId::new("flashloan"),
            SemVer::new(2, 1, 0),
            ModelKind::Rule,
            Scope::Block,
            &rollout,
            &performance,
        );

        assert_eq!(card.status, LifecycleStatus::Shadow);
        assert!(card.performance.is_measured());
    }

    #[test]
    fn card_for_defaults_to_active_and_unmeasured_without_overrides() {
        let card = card_for(
            DetectorId::new("sandwich"),
            SemVer::new(1, 2, 0),
            ModelKind::Rule,
            Scope::Block,
            &RolloutPolicy::default(),
            &PerformanceStore::new(),
        );

        assert_eq!(card.status, LifecycleStatus::Active);
        assert!(!card.performance.is_measured());
    }
}
