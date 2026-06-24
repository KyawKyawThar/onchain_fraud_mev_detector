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

    b.build()
        .expect("built-in detector roster has a duplicate (id, version) — fix register_builtins")
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
