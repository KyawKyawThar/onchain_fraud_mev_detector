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

use crate::measured::{canonical_json, Build, BuildKeyed, Lookup};
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
/// Hashing is **deterministic by construction**: [`of`](Self::of) and
/// [`for_build`](Self::for_build) hash [`canonical_json`], which sorts object
/// keys itself, so a config with a `HashMap` can't hash two different ways from
/// one logical value, and no cargo feature elsewhere in the build can change
/// the bytes.
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
        let value = serde_json::to_value(config).map_err(|source| ConfigHashError { source })?;
        Ok(Self::of_bytes(&canonical_json(&value)))
    }

    /// Hash raw bytes directly — for a detector that already has a canonical
    /// byte encoding of its config and wants to skip the JSON round-trip.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// The config hash of one detector build: its `(id, version)` plus the
    /// configuration it reports through
    /// [`DetectorPlugin::config_value`](detector_api::DetectorPlugin::config_value).
    ///
    /// This is what makes the triple mean something to the backtest gate
    /// (§18): a threshold change moves the hash while the version stays put,
    /// so a committed measurement can say which build it was taken from, and a
    /// precision drop under a *new* hash reads as "we changed it" rather than
    /// "it broke". The `Block` catalogue, the cross-block roster and the ML
    /// bundle check all route through this one function, so a detector's
    /// triple is the same however it was linked.
    ///
    /// Canonical by construction ([`canonical_json`] sorts keys itself), and
    /// domain-separated so it can never collide with [`of`](Self::of) over
    /// bytes that happen to spell the same thing.
    pub fn for_build(id: DetectorId, version: SemVer, config: &serde_json::Value) -> Self {
        let config = canonical_json(config);
        let mut hasher = Sha256::new();
        hasher.update(b"config-hash/detector-build/v1\n");
        hasher.update(id.as_str().as_bytes());
        hasher.update(b"\n");
        hasher.update(version.to_string().as_bytes());
        hasher.update(b"\n");
        hasher.update(&config);
        Self(hasher.finalize().into())
    }

    /// The raw 32-byte digest.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Fold a deployed ML model's identity into this config hash — **weights
    /// are config** (§20.2).
    ///
    /// `model_digest` is a `inference::ModelDescriptor::content_hash()`: a
    /// digest over the ONNX artifact's SHA-256, the `feature_version` it was
    /// trained on, and that schema's own content hash. Folding it in means a
    /// retrain, a re-export, or a feature-schema change each produce a new
    /// `(id, version, config_hash)` triple, exactly as a threshold change
    /// does — so historical evidence stays attributable to the precise weights
    /// that produced it and rollback is the registry's existing
    /// `deprecated_at`, not an archaeology exercise.
    ///
    /// Taken as raw bytes rather than a typed descriptor deliberately: the
    /// serving seam (`inference`) stays off this crate's dependency edge, and
    /// this stays the *one* fold, so a detector's hash can't be composed two
    /// different ways (the same reason [`for_build`](Self::for_build)
    /// is a single function).
    ///
    /// Domain-separated, so folding a model into a config hash can never
    /// collide with hashing a config that happens to contain those bytes.
    #[must_use]
    pub fn with_model_artifact(self, model_digest: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"config-hash/model-artifact/v1\n");
        hasher.update(self.0);
        hasher.update(model_digest);
        Self(hasher.finalize().into())
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

/// A [`ConfigHash`] could not be read back from its hex rendering.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("config hash must be 64 hex chars (32 bytes): {reason}")]
pub struct ConfigHashParseError {
    reason: String,
}

impl std::str::FromStr for ConfigHash {
    type Err = ConfigHashParseError;

    /// Parse the lowercase-hex form [`to_hex`](Self::to_hex) writes — the
    /// inverse the backtest harness needs to turn a wire [`DetectorRef`] back
    /// into a typed build.
    fn from_str(hex: &str) -> Result<Self, Self::Err> {
        let bytes = alloy_primitives::hex::decode(hex).map_err(|e| ConfigHashParseError {
            reason: e.to_string(),
        })?;
        let digest: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| ConfigHashParseError {
                reason: format!("got {} bytes", bytes.len()),
            })?;
        Ok(Self(digest))
    }
}

impl<'de> Deserialize<'de> for ConfigHash {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        String::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
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

    /// [`status_of`](Self::status_of) for a detector named by a wire string.
    ///
    /// A [`DetectorId`] wraps a `&'static str` — a detector *build* names
    /// itself with a compile-time constant — but a `DetectorTriggered`'s
    /// `detector.id` came off the wire, and so does a backtest report's key.
    /// This is the one adapter, so a consumer holding a `String` does not
    /// have to leak the `'static` requirement (or, worse, `Box::leak` its way
    /// around it).
    pub fn status_of_name(&self, id: &str) -> LifecycleStatus {
        self.overrides
            .iter()
            .find(|(key, _)| key.as_str() == id)
            .map_or(LifecycleStatus::Active, |(_, status)| *status)
    }

    /// Every detector this policy stages away from `Active`, in id order.
    ///
    /// The rollout gate reads this: "which detectors are currently held back,
    /// and have they earned promotion?" is a question about the *overrides*,
    /// and enumerating them beats asking [`status_of`](Self::status_of) about
    /// a roster the caller would have to already know.
    pub fn staged(&self) -> impl Iterator<Item = (DetectorId, LifecycleStatus)> + '_ {
        self.overrides.iter().map(|(id, status)| (*id, *status))
    }

    /// **The** shipped rollout staging (§6, §18, §20.2) — the one place the
    /// live service's Shadow list is declared.
    ///
    /// It lives here rather than in `main.rs` for the same reason
    /// [`link_builtin_roster`](crate::boot::link_builtin_roster) does: a
    /// second reader arrived. The backtest harness's promotion gate (§18,
    /// Sprint 18 t5) reports whether a *staged* detector has earned its way
    /// to `Active`, which is meaningless if it is reading a different staging
    /// than the service applies. Two hand-maintained lists would agree right
    /// up until the release where it mattered.
    ///
    /// A detector on this list runs and is scored, and its `DetectorTriggered`
    /// is recorded so backtests and metrics see it, but no customer-facing
    /// alert is raised. **Promote one by deleting its line**, once
    /// `cargo run -p backtest` reports it as clearing the committed gate.
    ///
    /// `anomaly` (§20.2) is on this list for the same reason as the rest, and
    /// that sameness is deliberate: an ML detector walks Shadow → backtest
    /// gate → Live like any heuristic change, with no special path around the
    /// gates. It is also the detector where shadowing matters most — its
    /// evidence names no known pattern, so a false positive is expensive to
    /// explain.
    pub fn builtin() -> Self {
        Self::new()
            .shadow(DetectorId::new("flashloan"))
            .shadow(DetectorId::new("liquidation"))
            .shadow(DetectorId::new("rugpull"))
            .shadow(DetectorId::new("wash-trading"))
            .shadow(DetectorId::new("address-poisoning"))
            .shadow(DetectorId::new("anomaly"))
    }

    /// Apply **demotion-only** overrides from `DETECTION_SHADOW_DETECTORS`
    /// (comma-separated detector ids) on top of this policy.
    ///
    /// # Why only demotions
    ///
    /// The obvious design is a general per-environment override — promote in
    /// staging, shadow in prod, no rebuild. It is the wrong one, and the
    /// asymmetry is the entire point:
    ///
    /// - **Demotion is an incident response.** A detector melting down at 03:00
    ///   should be shadowable by whoever is awake, from a config change, in
    ///   seconds. Requiring a merge and a rebuild for that is how a bad
    ///   detector stays live for an hour.
    /// - **Promotion is a claim about evidence.** §20.2's rollout is Shadow →
    ///   *backtest gate* → Live. An env var that could promote would be a path
    ///   around the gate — exactly the thing "ML gets no special path" forbids,
    ///   and it would be available to every heuristic detector too. So the only
    ///   way to make something customer-facing stays a reviewed diff to
    ///   [`builtin`](Self::builtin), with `cargo run -p backtest` in the PR.
    ///
    /// A safety valve that can only make the system quieter, never louder.
    /// Unknown ids are accepted rather than rejected: this is an emergency
    /// lever, and refusing to boot because someone shadowed a detector that
    /// this build does not link would turn a typo into an outage. It is logged.
    #[must_use]
    pub fn with_env_demotions(self) -> Self {
        match std::env::var(SHADOW_DETECTORS_ENV) {
            Ok(raw) => self.with_demotions(&raw),
            Err(_) => self,
        }
    }

    /// The pure half of [`with_env_demotions`](Self::with_env_demotions), so
    /// the parsing is testable without touching the process environment.
    #[must_use]
    pub fn with_demotions(mut self, raw: &str) -> Self {
        for id in raw.split(',').map(str::trim).filter(|id| !id.is_empty()) {
            // Leaked because `DetectorId` wraps a `&'static str` — a detector
            // build names itself with a compile-time constant. This runs once
            // at boot over a handful of operator-supplied ids, so the leak is
            // bounded by the config file and lives as long as the process would
            // have kept the string anyway.
            let id = DetectorId::new(String::leak(id.to_owned()));
            tracing::warn!(
                detector = %id,
                "{SHADOW_DETECTORS_ENV} demotes this detector to Shadow — its evidence is \
                 recorded but raises no customer-facing alert (§6). Promotion is not \
                 available here: it is a reviewed change to RolloutPolicy::builtin, gated \
                 on the backtest (§20.2)."
            );
            self.overrides.insert(id, LifecycleStatus::Shadow);
        }
        self
    }
}

/// Comma-separated detector ids to force to `Shadow` at boot — the
/// demotion-only safety valve. See
/// [`RolloutPolicy::with_env_demotions`].
pub const SHADOW_DETECTORS_ENV: &str = "DETECTION_SHADOW_DETECTORS";

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

/// One detector's measured performance, as the backtest harness writes it
/// ([`backtest::performance::from_report`](../../backtest/performance/index.html))
/// and a boot shows it on a [`ModelCard`] (§18, Sprint 10 t4).
///
/// **Validated inside `Deserialize`** (`try_from` a raw record), so an
/// out-of-range rate cannot be parsed at all — the invariant is the type's,
/// not a `validate()` call a reader must remember. The same family as
/// `UsdAmount` and `loadtest::slo::LatencyBudget`.
///
/// It carries no build: the [`PerformanceStore`] around it does, and only
/// hands a record out for the exact build it was measured on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "RawPerformanceRecord")]
pub struct PerformanceRecord {
    precision: Confidence,
    recall: Confidence,
    hit_rate: Confidence,
    sample_size: NonZeroU64,
    measured_at: DateTime<Utc>,
}

/// The unvalidated wire shape of a [`PerformanceRecord`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPerformanceRecord {
    precision: f64,
    recall: f64,
    hit_rate: f64,
    sample_size: NonZeroU64,
    measured_at: DateTime<Utc>,
}

impl TryFrom<RawPerformanceRecord> for PerformanceRecord {
    type Error = ConfidenceOutOfRange;

    fn try_from(raw: RawPerformanceRecord) -> Result<Self, Self::Error> {
        Self::try_new(
            raw.precision,
            raw.recall,
            raw.hit_rate,
            raw.sample_size,
            raw.measured_at,
        )
    }
}

impl PerformanceRecord {
    /// A record, or the first out-of-range rate's error.
    pub fn try_new(
        precision: f64,
        recall: f64,
        hit_rate: f64,
        sample_size: NonZeroU64,
        measured_at: DateTime<Utc>,
    ) -> Result<Self, ConfidenceOutOfRange> {
        Ok(Self {
            precision: Confidence::try_new(precision)?,
            recall: Confidence::try_new(recall)?,
            hit_rate: Confidence::try_new(hit_rate)?,
            sample_size,
            measured_at,
        })
    }

    /// The card's view of this record. Infallible: the rates were checked
    /// when the record was built.
    pub fn performance(&self) -> Performance {
        Performance::Measured {
            precision: self.precision,
            recall: self.recall,
            hit_rate: self.hit_rate,
            sample_size: self.sample_size,
            measured_at: self.measured_at,
        }
    }

    pub fn precision(&self) -> f64 {
        self.precision.get()
    }

    pub fn recall(&self) -> f64 {
        self.recall.get()
    }

    pub fn hit_rate(&self) -> f64 {
        self.hit_rate.get()
    }

    pub fn sample_size(&self) -> NonZeroU64 {
        self.sample_size
    }
}

/// Every detector's measured performance, each entry naming the build it was
/// measured on (see [`crate::measured`]). A card shows a record only through
/// [`BuildKeyed::lookup`] → `Current`.
pub type PerformanceStore = BuildKeyed<PerformanceRecord>;

/// Something went wrong loading or writing a performance store.
#[derive(Debug, thiserror::Error)]
pub enum PerformanceStoreError {
    #[error("reading performance store at {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Includes an out-of-range rate: records validate while parsing.
    #[error("parsing performance store at {path}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
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

/// `crates/detection/model_performance.json` in the source tree — where
/// `backtest --update-model-cards` **writes**. Never a runtime read path: a
/// deployed image has no source tree (see [`committed_performance_store`]).
pub fn default_performance_store_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("model_performance.json")
}

/// The committed store, compiled into the binary.
///
/// Embedded rather than read from [`default_performance_store_path`]: that is
/// a path on the *build* machine, so a container image (which ships only the
/// binary) would find nothing, and a missing file used to mean "every card
/// unmeasured", silently. It also belongs with the binary for a better
/// reason: every record is keyed on a build triple, and the triple is fixed
/// when the binary is compiled, so the measurement ships with the build it
/// describes. `tests/committed_builds.rs` in the backtest crate keeps the two
/// in step.
pub const COMMITTED_PERFORMANCE_STORE: &str = include_str!("../model_performance.json");

/// Environment variable naming a performance store file to use **instead of**
/// the embedded one — an operator override, e.g. numbers from a larger
/// corpus. A missing or malformed file then fails boot.
pub const PERFORMANCE_STORE_ENV: &str = "DETECTION_PERFORMANCE_STORE";

/// Parse the store compiled into this binary.
pub fn committed_performance_store() -> Result<PerformanceStore, PerformanceStoreError> {
    serde_json::from_str(COMMITTED_PERFORMANCE_STORE).map_err(|source| {
        PerformanceStoreError::Parse {
            path: PathBuf::from("<embedded model_performance.json>"),
            source,
        }
    })
}

/// Where a boot's performance store came from — logged, so an operator
/// override is never invisible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PerformanceSource {
    Embedded,
    File(PathBuf),
}

impl std::fmt::Display for PerformanceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Embedded => f.write_str("embedded"),
            Self::File(path) => write!(f, "{}", path.display()),
        }
    }
}

/// The store a service boot should use: the file [`PERFORMANCE_STORE_ENV`]
/// names, or else the embedded one. Read once at boot; fail-fast either way.
pub fn performance_store_from_env(
) -> Result<(PerformanceStore, PerformanceSource), PerformanceStoreError> {
    match std::env::var_os(PERFORMANCE_STORE_ENV) {
        Some(path) => {
            let path = PathBuf::from(path);
            Ok((
                load_performance_store(&path)?,
                PerformanceSource::File(path),
            ))
        }
        None => Ok((committed_performance_store()?, PerformanceSource::Embedded)),
    }
}

/// Load a store from `path`. A missing file is an error: the embedded store
/// is always available, so a path someone named and that is not there is a
/// deployment mistake, not an empty store.
pub fn load_performance_store(path: &Path) -> Result<PerformanceStore, PerformanceStoreError> {
    let text = std::fs::read_to_string(path).map_err(|source| PerformanceStoreError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&text).map_err(|source| PerformanceStoreError::Parse {
        path: path.to_path_buf(),
        source,
    })
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

    /// This card's typed `(id, version, config_hash)` build.
    pub fn build(&self) -> Build {
        Build::new(self.id.as_str(), self.version, self.config_hash.clone())
    }

    /// The wire [`DetectorRef`] — the exact `(id, version, config_hash)` triple
    /// stamped onto every `DetectorTriggered` this build produces (§6, task 5).
    pub fn detector_ref(&self) -> DetectorRef {
        self.build().to_ref()
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

/// Build one detector's [`ModelCard`], layering the rollout status, any
/// measured performance from `performance`, and any served model's identity
/// on top of the build's own [`ConfigHash::for_build`] (§18, Sprint 10 t4;
/// §20.2). Shared by the `Block` catalogue ([`crate::boot`]) and cross-block
/// registration ([`crate::registry::register_cross_block_builtins`]) so both
/// stamp a detector's card the same way regardless of which roster it lives in.
///
/// A stored measurement is applied only when it names this exact
/// `(id, version, config_hash)`. One taken from another build leaves the card
/// [`Performance::Unmeasured`]: the card must not advertise a precision the
/// running configuration was never scored at.
// One argument per identity component plus the two policy inputs; bundling
// them would just rename the list.
#[allow(clippy::too_many_arguments)]
pub(crate) fn card_for(
    id: DetectorId,
    version: SemVer,
    kind: ModelKind,
    scope: Scope,
    config: &serde_json::Value,
    model_digest: Option<[u8; 32]>,
    rollout: &RolloutPolicy,
    performance: &PerformanceStore,
) -> ModelCard {
    // Weights are config (§20.2): a detector serving a learned model folds its
    // model identity — artifact SHA-256 + trained `feature_version` + schema
    // digest — into the same hash a threshold change moves, so a retrain is a
    // new `(id, version, config_hash)` triple and rollback stays
    // `deprecated_at`. A rule detector returns `None` and is unaffected.
    let build = ConfigHash::for_build(id, version, config);
    let config_hash = match model_digest {
        Some(digest) => build.with_model_artifact(&digest),
        None => build,
    };
    let mut card = ModelCard::new(id, version, kind, scope, config_hash, Utc::now())
        .with_status(rollout.status_of(id));

    // Only a measurement of exactly this build reaches the card. A stale one
    // is reported by the caller's shell (`PerformanceStore::stale_against`),
    // which keeps this function pure.
    if let Lookup::Current(record) = performance.lookup(&card.build()) {
        card = card.with_performance(record.performance());
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
    fn folding_a_model_artifact_versions_the_weights_like_config() {
        // §20.2: a retrain must be a new `(id, version, config_hash)` triple,
        // so evidence stays attributable to the weights that produced it.
        let config = ConfigHash::of(&Cfg {
            min_profit_wei: 1,
            pools: vec!["uniswap"],
        })
        .unwrap();

        let march = [7u8; 32];
        let april = [8u8; 32];

        assert_eq!(
            config.clone().with_model_artifact(&march),
            config.clone().with_model_artifact(&march),
            "the same config + weights is the same triple across boots"
        );
        assert_ne!(
            config.clone().with_model_artifact(&march),
            config.clone().with_model_artifact(&april),
            "a weight change must move the config hash"
        );
        assert_ne!(
            config.clone().with_model_artifact(&march),
            config.clone(),
            "an ML detector's triple is not its unfolded config's"
        );

        // A *config* change still moves it, with the weights held fixed —
        // both halves are live, neither shadows the other.
        let other_config = ConfigHash::of(&Cfg {
            min_profit_wei: 2,
            pools: vec!["uniswap"],
        })
        .unwrap();
        assert_ne!(
            config.with_model_artifact(&march),
            other_config.with_model_artifact(&march)
        );
    }

    #[test]
    fn the_model_fold_is_domain_separated_from_plain_hashing() {
        // Without the domain prefix, folding a model into a config hash would
        // be indistinguishable from hashing a config whose bytes happen to be
        // that concatenation — a collision between two different meanings.
        let config = ConfigHash::of_bytes(b"cfg");
        let digest = [3u8; 32];

        let mut naive = Vec::new();
        naive.extend_from_slice(config.as_bytes());
        naive.extend_from_slice(&digest);

        assert_ne!(
            config.with_model_artifact(&digest),
            ConfigHash::of_bytes(&naive)
        );
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
        PerformanceRecord::try_new(0.9, 0.8, 0.05, NonZeroU64::new(1_000).unwrap(), Utc::now())
            .unwrap()
    }

    fn flashloan_build(config: &serde_json::Value) -> Build {
        let (id, version) = (DetectorId::new("flashloan"), SemVer::new(2, 1, 0));
        Build::new(
            id.as_str(),
            version,
            ConfigHash::for_build(id, version, config),
        )
    }

    fn flashloan_store() -> PerformanceStore {
        [(flashloan_build(&serde_json::Value::Null), valid_record())]
            .into_iter()
            .collect()
    }

    #[test]
    fn performance_record_converts_into_measured() {
        match valid_record().performance() {
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
        let n = NonZeroU64::new(1).unwrap();
        assert!(PerformanceRecord::try_new(1.7, 0.5, 0.1, n, Utc::now()).is_err());
        assert!(PerformanceRecord::try_new(0.5, f64::NAN, 0.1, n, Utc::now()).is_err());
    }

    #[test]
    fn performance_record_round_trips_through_json() {
        let record = valid_record();
        let json = serde_json::to_string(&record).unwrap();
        let reloaded: PerformanceRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, reloaded);
    }

    #[test]
    fn an_out_of_range_rate_does_not_parse() {
        // Validation lives in `Deserialize`: there is no parsed-but-invalid
        // record for a reader to forget to check.
        let bad = r#"{"precision":1.7,"recall":0.5,"hit_rate":0.1,"sample_size":10,"measured_at":"2024-01-01T00:00:00Z"}"#;
        assert!(serde_json::from_str::<PerformanceRecord>(bad).is_err());
        let extra = r#"{"precision":0.7,"recall":0.5,"hit_rate":0.1,"sample_size":10,"measured_at":"2024-01-01T00:00:00Z","note":1}"#;
        assert!(serde_json::from_str::<PerformanceRecord>(extra).is_err());
    }

    // ── performance store I/O ────────────────────────────────────────

    #[test]
    fn the_embedded_store_parses() {
        // It is compiled in, so a malformed committed file must fail here
        // rather than at a production boot.
        committed_performance_store().expect("the committed model_performance.json parses");
    }

    #[test]
    fn a_missing_named_store_is_an_error_not_an_empty_store() {
        let path = Path::new("/nonexistent/does-not-exist/model_performance.json");
        assert!(matches!(
            load_performance_store(path),
            Err(PerformanceStoreError::Read { .. })
        ));
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
    fn an_out_of_range_record_in_a_file_fails_the_load() {
        let path = std::env::temp_dir().join(format!("model-perf-test-{}-oor", std::process::id()));
        let hash = "00".repeat(32);
        std::fs::write(
            &path,
            format!(
                r#"{{"sandwich":{{"version":"1.2.0","config_hash":"{hash}","metrics":{{"precision":1.7,"recall":0.5,"hit_rate":0.1,"sample_size":10,"measured_at":"2024-01-01T00:00:00Z"}}}}}}"#
            ),
        )
        .unwrap();
        let result = load_performance_store(&path);
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(result, Err(PerformanceStoreError::Parse { .. })));
    }

    #[test]
    fn performance_store_save_then_load_round_trips() {
        let path = std::env::temp_dir().join(format!("model-perf-test-{}-ok", std::process::id()));
        let store = flashloan_store();

        save_performance_store(&store, &path).unwrap();
        let reloaded = load_performance_store(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(store, reloaded);
    }

    // ── card_for ─────────────────────────────────────────────────────

    #[test]
    fn card_for_applies_rollout_status_and_measured_performance() {
        let rollout = RolloutPolicy::new().shadow(DetectorId::new("flashloan"));

        let card = card_for(
            DetectorId::new("flashloan"),
            SemVer::new(2, 1, 0),
            ModelKind::Rule,
            Scope::Block,
            &serde_json::Value::Null,
            None,
            &rollout,
            &flashloan_store(),
        );

        assert_eq!(card.status, LifecycleStatus::Shadow);
        assert!(card.performance.is_measured());
    }

    #[test]
    fn card_for_ignores_a_measurement_taken_on_another_build() {
        // The record was measured under `Null` config; the running build has a
        // threshold. Same id, same version — still not the detector that was
        // scored, so its numbers must not reach this card.
        let performance = flashloan_store();
        let rebuilt = card_for(
            DetectorId::new("flashloan"),
            SemVer::new(2, 1, 0),
            ModelKind::Rule,
            Scope::Block,
            &serde_json::json!({ "min_loan_usd": 500.0 }),
            None,
            &RolloutPolicy::default(),
            &performance,
        );
        assert!(!rebuilt.performance.is_measured());
        assert_eq!(
            performance.stale_against([&rebuilt.build()]).len(),
            1,
            "the shell can report it"
        );

        let bumped = card_for(
            DetectorId::new("flashloan"),
            SemVer::new(2, 2, 0),
            ModelKind::Rule,
            Scope::Block,
            &serde_json::Value::Null,
            None,
            &RolloutPolicy::default(),
            &performance,
        );
        assert!(!bumped.performance.is_measured());
    }

    #[test]
    fn a_card_build_is_its_wire_ref() {
        let card = a_card("sandwich", SemVer::new(1, 2, 0));
        assert_eq!(Build::from_ref(&card.detector_ref()).unwrap(), card.build());
    }

    #[test]
    fn for_build_moves_with_each_component_of_the_triple() {
        let id = DetectorId::new("sandwich");
        let v = SemVer::new(1, 2, 0);
        let cfg = serde_json::json!({ "min_profit_usd": 10.0 });
        let base = ConfigHash::for_build(id, v, &cfg);

        assert_eq!(base, ConfigHash::for_build(id, v, &cfg), "deterministic");
        assert_ne!(
            base,
            ConfigHash::for_build(id, v, &serde_json::json!({ "min_profit_usd": 5.0 })),
            "a threshold change is a new identity at the same version"
        );
        assert_ne!(base, ConfigHash::for_build(id, SemVer::new(1, 3, 0), &cfg));
        assert_ne!(base, ConfigHash::for_build(DetectorId::new("arb"), v, &cfg));
        // Key order is not identity.
        let ab: serde_json::Value = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
        let ba: serde_json::Value = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
        assert_eq!(
            ConfigHash::for_build(id, v, &ab),
            ConfigHash::for_build(id, v, &ba)
        );
    }

    #[test]
    fn card_for_defaults_to_active_and_unmeasured_without_overrides() {
        let card = card_for(
            DetectorId::new("sandwich"),
            SemVer::new(1, 2, 0),
            ModelKind::Rule,
            Scope::Block,
            &serde_json::Value::Null,
            None,
            &RolloutPolicy::default(),
            &PerformanceStore::new(),
        );

        assert_eq!(card.status, LifecycleStatus::Active);
        assert!(!card.performance.is_measured());
    }

    #[test]
    fn card_for_folds_a_served_models_identity_into_the_config_hash() {
        let card = |digest: Option<[u8; 32]>| {
            card_for(
                DetectorId::new("anomaly"),
                SemVer::new(1, 0, 0),
                ModelKind::Ml,
                Scope::Block,
                &serde_json::Value::Null,
                digest,
                &RolloutPolicy::default(),
                &PerformanceStore::new(),
            )
            .config_hash
        };
        // The fold is `with_model_artifact` and nothing else — stated as an
        // equality so the two can't drift into different compositions of the
        // same inputs (§20.2: one fold, one way).
        assert_eq!(
            card(Some([0x11; 32])),
            ConfigHash::for_build(
                DetectorId::new("anomaly"),
                SemVer::new(1, 0, 0),
                &serde_json::Value::Null
            )
            .with_model_artifact(&[0x11; 32])
        );
        assert_ne!(card(Some([0x11; 32])), card(Some([0x22; 32])));
        assert_ne!(card(Some([0x11; 32])), card(None));
    }
}
