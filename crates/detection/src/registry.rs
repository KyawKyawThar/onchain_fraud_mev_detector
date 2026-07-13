//! Compile-time detector registration (§6).
//!
//! > "No dynamic loading — Rust has no stable ABI. Each detector is an
//! > independent crate implementing `DetectorPlugin`, registered at compile
//! > time." (§6)
//!
//! The mechanism is deliberately explicit rather than `inventory`/`linkme`
//! life-before-main magic — in keeping with the rest of this codebase, where the
//! topology is wired by hand and greppable (cf. the ingestion service's explicit
//! topic provisioning, not broker auto-create). [`register_builtins`] is the one
//! place the linked detector set is named; each detector is gated behind a Cargo
//! feature, so **which** detectors a binary contains is fixed at compile time
//! and chosen per build — premium detectors simply aren't linked into an
//! open/free build (§6: "selective open-sourcing, premium detectors stay
//! closed").
//!
//! The [`Registry`] this produces is the *live roster* of plugin instances. The
//! richer model-registry metadata (`config_hash`, `deployed_at`, `performance`,
//! deprecation — for safe rollouts and A/B comparison) lives separately in
//! [`crate::model`] (task 2); registration (a detector exists and is linked) is
//! kept apart from cataloguing (what we know about a detector's track record), so
//! the two evolve independently. The runtime on/off switch — [`crate::flags`] —
//! gates this roster through [`RegistryBuilder::register_if`].

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::flags::FeatureFlags;
use detector_api::{DetectorId, DetectorPlugin, SemVer};

/// The unique key a detector occupies in a [`Registry`]: its id and version.
/// Two builds of the same detector (`sandwich` v1.2 and v1.3) coexist for safe
/// rollout/A-B (§6); two registrations of the *same* `(id, version)` are a
/// wiring bug, caught by [`RegistryBuilder::build`].
pub type DetectorKey = (DetectorId, SemVer);

/// Something went wrong assembling the registry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// The same `(id, version)` was registered twice — almost always a
    /// copy-paste in [`register_builtins`] or a detector crate shipping two
    /// instances of itself.
    #[error("duplicate detector registered: {id} v{version} appears more than once")]
    Duplicate { id: DetectorId, version: SemVer },
}

/// The live roster of detectors a binary was built with (§6).
///
/// Immutable once built: detectors are compile-time plugins, so the set is fixed
/// for the process's life. Keyed by `(id, version)` for O(log n) lookup when an
/// event names the exact build that produced it (replay/backtest, §18).
#[derive(Clone)]
pub struct Registry {
    by_key: BTreeMap<DetectorKey, Arc<dyn DetectorPlugin>>,
}

impl Registry {
    /// Start assembling a registry. Prefer [`register_builtins`] for the real
    /// roster; this is for tests and bespoke wiring.
    pub fn builder() -> RegistryBuilder {
        RegistryBuilder::default()
    }

    /// Number of registered detectors.
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    /// Look up the exact build that produced an event, by `(id, version)`.
    pub fn get(&self, id: DetectorId, version: SemVer) -> Option<&Arc<dyn DetectorPlugin>> {
        self.by_key.get(&(id, version))
    }

    /// Every registered detector, in deterministic `(id, version)` order — the
    /// roster the scheduler fans out over (§17).
    pub fn detectors(&self) -> impl ExactSizeIterator<Item = &Arc<dyn DetectorPlugin>> {
        self.by_key.values()
    }
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `dyn DetectorPlugin` isn't `Debug`; show the roster by key instead.
        f.debug_struct("Registry")
            .field("detectors", &self.by_key.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Accumulates detector registrations, then validates and freezes them into a
/// [`Registry`]. Registration is order-independent; duplicates are reported by
/// [`build`](Self::build), not silently last-wins, so a wiring mistake fails
/// loudly instead of dropping a detector.
#[derive(Default)]
pub struct RegistryBuilder {
    // `Vec`, not a map: collect first so `build` can *detect* a duplicate rather
    // than have an insert silently overwrite it.
    registered: Vec<Arc<dyn DetectorPlugin>>,
}

impl RegistryBuilder {
    /// Register a detector. Takes the concrete plugin and boxes it behind the
    /// trait object the registry stores.
    pub fn register<P: DetectorPlugin + 'static>(&mut self, plugin: P) -> &mut Self {
        self.registered.push(Arc::new(plugin));
        self
    }

    /// Register only when `enabled`. The seam the per-detector feature flags
    /// (`[detectors.*] enabled`, task 2) plug into at runtime, complementing the
    /// compile-time `#[cfg(feature)]` gate: a detector can be linked yet turned
    /// off by config without recompiling.
    pub fn register_if<P: DetectorPlugin + 'static>(
        &mut self,
        enabled: bool,
        plugin: P,
    ) -> &mut Self {
        if enabled {
            self.register(plugin);
        }
        self
    }

    /// Validate uniqueness and freeze. Errors on a duplicate `(id, version)`.
    ///
    /// Borrows `&self` (cloning the cheap `Arc` handles) so it reads naturally
    /// both fluently — `builder().register(a).register(b).build()` — and from
    /// the incremental, `#[cfg]`-gated style [`register_builtins`] uses.
    pub fn build(&self) -> Result<Registry, RegistryError> {
        let mut by_key: BTreeMap<DetectorKey, Arc<dyn DetectorPlugin>> = BTreeMap::new();
        for plugin in &self.registered {
            let key = (plugin.id(), plugin.version());
            if by_key.contains_key(&key) {
                return Err(RegistryError::Duplicate {
                    id: key.0,
                    version: key.1,
                });
            }
            by_key.insert(key, Arc::clone(plugin));
        }
        Ok(Registry { by_key })
    }
}

/// Assemble the registry of detectors this binary was compiled with (§6),
/// gated by the runtime [`FeatureFlags`].
///
/// This is the single, greppable place the linked detector roster is declared.
/// Two gates compose here, answering different questions (see [`crate::flags`]):
/// the **compile-time** `#[cfg(feature = "…")]` decides whether a detector is in
/// the binary at all (premium detectors aren't linked into an open build); the
/// **runtime** `flags.is_enabled(...)` then decides whether a linked detector is
/// turned on, without a recompile. The detectors are optional dependencies of
/// this crate (depending on the small `detector-api` seam, not on `detection`, so
/// there's no cycle); a build that doesn't enable a feature never links it.
///
/// Panics on a duplicate `(id, version)`: the built-in roster is statically
/// known, so a duplicate is a build-time wiring bug to surface at boot, not a
/// recoverable runtime condition (fail fast, mirroring the service's config
/// loading).
pub fn register_builtins(flags: &FeatureFlags) -> Registry {
    // `flags` goes unread only in a build that links *no* detector feature; each
    // `#[cfg]` arm below consumes it via `register_if`.
    let _ = flags;
    #[allow(unused_mut)] // stays `mut`-free only when no detector feature is on.
    let mut b = Registry::builder();

    // ── built-in detectors plug in here (task 4) ──
    #[cfg(feature = "sandwich")]
    b.register_if(
        flags.is_enabled(sandwich_detector::SandwichDetector::ID),
        sandwich_detector::plugin(), // sandwich-v1.2
    );
    #[cfg(feature = "arb")]
    b.register_if(
        flags.is_enabled(arb_detector::ArbDetector::ID),
        arb_detector::plugin(), // arb-v1.0
    );
    // ── Phase-3 `Scope::Block` detectors (§22, Sprint 10 t1) ──
    // `washtrading` is `Scope::CrossBlock` and is wired separately, through
    // `register_cross_block_builtins`, not here.
    #[cfg(feature = "flashloan")]
    b.register_if(
        flags.is_enabled(flashloan_detector::FlashloanDetector::ID),
        flashloan_detector::plugin(), // flashloan-v2.1
    );
    #[cfg(feature = "liquidation")]
    b.register_if(
        flags.is_enabled(liquidation_detector::LiquidationDetector::ID),
        liquidation_detector::plugin(), // liquidation-v1.0
    );
    #[cfg(feature = "rugpull")]
    b.register_if(
        flags.is_enabled(rugpull_detector::RugpullDetector::ID),
        rugpull_detector::plugin(), // rugpull-v1.0
    );
    #[cfg(feature = "poisoning")]
    b.register_if(
        flags.is_enabled(poisoning_detector::PoisoningDetector::ID),
        poisoning_detector::plugin(), // address-poisoning-v1.0
    );
    // Dev/demo only (§19): synthetic detector that fires on a fixed schedule so
    // the per-detector metrics + emit path light up on a header-only source.
    #[cfg(feature = "demo")]
    b.register_if(
        flags.is_enabled(demo_detector::DemoDetector::ID),
        demo_detector::plugin(), // demo-v0.1
    );

    b.build()
        .expect("built-in detector roster has a duplicate (id, version) — fix register_builtins")
}

/// Assemble the roster of `Scope::CrossBlock` detectors this binary was compiled
/// with (§6, §15), gated by the runtime [`FeatureFlags`] — the cross-block analogue
/// of [`register_builtins`].
///
/// A [`CrossBlockDetector`](detector_api::CrossBlockDetector) can't live in the
/// `Block` [`Registry`] (its `detect` threads `&mut State`, so it runs serially, not
/// on the parallel fan-out), so it registers into a separate
/// [`CrossBlockStates`](crate::reorg::CrossBlockStates) roster. Each slot is paired
/// with its resolved [`DetectorRef`] once here, the same fail-fast link-time pairing
/// [`DetectionPlan`](crate::emit::DetectionPlan) does for `Block` detectors, so the
/// per-block emit path never fabricates a triple. The `config_hash` is the same boot
/// placeholder `main::catalogue` stamps on the `Block` roster (real per-detector
/// config hashing is the Sprint 10 t4 follow-up).
///
/// In a build with no cross-block detector feature the roster is empty — the case
/// until `washtrading` is linked.
pub fn register_cross_block_builtins(flags: &FeatureFlags) -> crate::reorg::CrossBlockStates {
    let _ = flags; // read only by a linked cross-block feature's arm below.
    #[allow(unused_mut)]
    let mut roster = crate::reorg::CrossBlockStates::new();

    // ── built-in cross-block detectors plug in here ──
    #[cfg(feature = "washtrading")]
    if flags.is_enabled(washtrading_detector::WashTradingDetector::ID) {
        let detector = washtrading_detector::plugin(); // wash-trading-v1.0
        roster.insert_detector(boot_detector_ref(&detector), detector);
    }

    roster
}

/// The boot-placeholder [`DetectorRef`] for a cross-block detector, mirroring the
/// `(id, version)`-seeded `config_hash` `main::catalogue` computes for the `Block`
/// roster — so a cross-block detector's emitted triple matches what a model card
/// would yield, until real config hashing lands (Sprint 10 t4).
#[cfg(feature = "washtrading")]
fn boot_detector_ref<D: detector_api::CrossBlockDetector>(
    detector: &D,
) -> events::primitives::DetectorRef {
    let (id, version) = (detector.id(), detector.version());
    events::primitives::DetectorRef {
        id: id.as_str().to_owned(),
        version: version.to_string(),
        config_hash: crate::model::ConfigHash::boot_placeholder(id, version).to_hex(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use detector_api::test_util::{dummy_evidence, MockDetector};
    use detector_api::{BlockBundle, DetectionCtx};
    use events::primitives::{BlockRef, Chain};

    #[test]
    fn collects_registered_detectors_in_key_order() {
        let reg = Registry::builder()
            .register(MockDetector::new("arb", SemVer::new(1, 0, 0)))
            .register(MockDetector::new("sandwich", SemVer::new(1, 2, 0)))
            .build()
            .unwrap();

        assert_eq!(reg.len(), 2);
        let ids: Vec<_> = reg.detectors().map(|d| d.id().as_str()).collect();
        // BTreeMap order: "arb" sorts before "sandwich".
        assert_eq!(ids, ["arb", "sandwich"]);
    }

    #[test]
    fn same_id_different_versions_coexist() {
        // Safe rollout: v1.2 alongside v1.3 (§6).
        let reg = Registry::builder()
            .register(MockDetector::new("sandwich", SemVer::new(1, 2, 0)))
            .register(MockDetector::new("sandwich", SemVer::new(1, 3, 0)))
            .build()
            .unwrap();

        assert_eq!(reg.len(), 2);
        assert!(reg
            .get(DetectorId::new("sandwich"), SemVer::new(1, 2, 0))
            .is_some());
        assert!(reg
            .get(DetectorId::new("sandwich"), SemVer::new(1, 3, 0))
            .is_some());
    }

    #[test]
    fn duplicate_id_and_version_is_rejected() {
        let err = Registry::builder()
            .register(MockDetector::new("sandwich", SemVer::new(1, 2, 0)))
            .register(MockDetector::new("sandwich", SemVer::new(1, 2, 0)))
            .build()
            .unwrap_err();

        assert_eq!(
            err,
            RegistryError::Duplicate {
                id: DetectorId::new("sandwich"),
                version: SemVer::new(1, 2, 0),
            }
        );
    }

    #[test]
    fn register_if_gates_on_the_flag() {
        let reg = Registry::builder()
            .register_if(true, MockDetector::new("sandwich", SemVer::new(1, 2, 0)))
            .register_if(false, MockDetector::new("rugpull", SemVer::new(0, 1, 0)))
            .build()
            .unwrap();

        assert_eq!(reg.len(), 1);
        assert_eq!(reg.detectors().next().unwrap().id().as_str(), "sandwich");
    }

    #[test]
    fn lookup_dispatches_to_the_right_plugin() {
        let reg = Registry::builder()
            .register(
                MockDetector::new("sandwich", SemVer::new(1, 2, 0))
                    .returning(vec![dummy_evidence(); 3]),
            )
            .register(MockDetector::new("arb", SemVer::new(1, 0, 0)))
            .build()
            .unwrap();

        let ctx = DetectionCtx::new(BlockBundle::new(
            Chain::ETHEREUM,
            BlockRef::new(1, Default::default()),
            vec![],
        ));

        let sandwich = reg
            .get(DetectorId::new("sandwich"), SemVer::new(1, 2, 0))
            .unwrap();
        assert_eq!(sandwich.detect(&ctx).len(), 3);

        let arb = reg
            .get(DetectorId::new("arb"), SemVer::new(1, 0, 0))
            .unwrap();
        assert!(arb.detect(&ctx).is_empty());
    }

    #[test]
    fn register_builtins_assembles_without_duplicates_and_honours_disable() {
        // The load-bearing contract for any feature build: assembling the roster
        // never panics on a duplicate `(id, version)` …
        let _ = register_builtins(&FeatureFlags::all_enabled());
        // … and a flags-all-off policy yields an empty roster no matter which
        // detector features are compiled in (the runtime gate beats the link).
        assert!(register_builtins(&FeatureFlags::all_disabled()).is_empty());
    }

    #[test]
    fn register_cross_block_builtins_honours_the_disable_flag() {
        // Same contract for the cross-block roster: a flags-all-off policy yields an
        // empty roster regardless of which cross-block detector features are linked.
        assert!(register_cross_block_builtins(&FeatureFlags::all_disabled()).is_empty());
    }

    #[cfg(feature = "washtrading")]
    #[test]
    fn washtrading_cross_block_detector_is_registered_when_feature_and_flag_are_on() {
        // The first `Scope::CrossBlock` writer lands in the cross-block roster (not
        // the `Block` `Registry`), paired with its resolved `DetectorRef`.
        let roster = register_cross_block_builtins(&FeatureFlags::all_enabled());
        assert!(roster.contains(&(DetectorId::new("wash-trading"), SemVer::new(1, 0, 0))));
    }

    #[cfg(feature = "sandwich")]
    #[test]
    fn sandwich_is_registered_when_feature_and_flag_are_on() {
        let reg = register_builtins(&FeatureFlags::all_enabled());
        assert!(reg
            .get(DetectorId::new("sandwich"), SemVer::new(1, 2, 0))
            .is_some());
    }

    #[cfg(feature = "arb")]
    #[test]
    fn arb_is_registered_when_feature_and_flag_are_on() {
        let reg = register_builtins(&FeatureFlags::all_enabled());
        assert!(reg
            .get(DetectorId::new("arb"), SemVer::new(1, 0, 0))
            .is_some());
    }
}
