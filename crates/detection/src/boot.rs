//! Shared boot-time roster linking (§6, §18) — the **one** place a binary
//! derives a linked [`DetectionPlan`] from [`FeatureFlags`].
//!
//! Originally this lived only in the service binary's `main.rs`. A second
//! caller arrived — the backtest harness (Sprint 10 t2), which must link the
//! *identical* roster the live service would, or its measured precision/recall
//! is scored against a build that never runs in production — and it now also
//! reads back the `(id, version, config_hash)` triples this derives, to key its
//! committed baseline and model cards on them (§18). So the outcome is shared
//! here; the cataloguing itself (`catalogue`) stays private.
//!
//! [`DetectionPlan`]: crate::emit::DetectionPlan
//! [`FeatureFlags`]: crate::flags::FeatureFlags

use crate::emit::{DetectionPlan, UnlinkedDetector};
use crate::flags::FeatureFlags;
use crate::measured::{Build, BuildParseError};
use crate::model::{card_for, ModelRegistry, PerformanceStore, RolloutPolicy};
use crate::registry::{register_builtins, Registry};
use crate::reorg::CrossBlockStates;

/// Build the `Block` roster `register_builtins` compiles in, gated by `flags`,
/// and link it to a model registry — failing fast (`Err`) if a live detector is
/// uncatalogued, the same link-or-fail discipline [`DetectionPlan::link`]
/// enforces everywhere else. Every binary that needs a linked plan — the live
/// service and the backtest harness alike — calls this, so neither can
/// silently diverge in how a build's `config_hash` is derived at boot.
///
/// `rollout` and `performance` decide each card's [`LifecycleStatus`](crate::model::LifecycleStatus)
/// and [`Performance`](crate::model::Performance) (§18, Sprint 10 t4) — a pure
/// function of its inputs, so loading `performance` from disk is the caller's
/// job (the effectful shell), not this function's.
pub fn link_builtin_roster(
    flags: &FeatureFlags,
    rollout: &RolloutPolicy,
    performance: &PerformanceStore,
) -> Result<DetectionPlan, UnlinkedDetector> {
    link_roster(&register_builtins(flags), rollout, performance)
}

/// [`link_builtin_roster`] over an already-assembled [`Registry`] — for a
/// binary whose roster includes a detector it had to *construct* at boot
/// rather than one `register_builtins` compiles in.
///
/// The ML detector (§20.2) is the case: it holds a loaded model artifact and a
/// training-window baseline, so the binary builds it, adds it through
/// [`register_builtins_with`](crate::registry::register_builtins_with), and
/// links the result here. Cataloguing is identical either way — same
/// `config_hash` derivation, same rollout status, same link-or-fail — which is
/// exactly the property §20.2 asks for: ML walks the same gates as a heuristic
/// change, with no path around them.
pub fn link_roster(
    registry: &Registry,
    rollout: &RolloutPolicy,
    performance: &PerformanceStore,
) -> Result<DetectionPlan, UnlinkedDetector> {
    let models = catalogue(registry, rollout, performance);
    DetectionPlan::link(registry, &models)
}

/// Every build a binary linked, `Block` and cross-block, typed — what the
/// boot shell checks the performance store against, and what the backtest
/// keys its measurements on. Read from the linked rosters, never recomputed,
/// so these are exactly the triples the service stamps on its events.
pub fn linked_builds(
    plan: &DetectionPlan,
    cross_block: &CrossBlockStates,
) -> Result<Vec<Build>, BuildParseError> {
    plan.detector_refs()
        .chain(cross_block.detector_refs())
        .map(Build::from_ref)
        .collect()
}

/// Catalogue every live detector into a [`ModelRegistry`] so the plan can `link`.
///
/// Each card's `config_hash` is [`ConfigHash::for_build`](crate::model::ConfigHash::for_build)
/// over the detector's own [`config_value`](detector_api::DetectorPlugin::config_value),
/// with an ML detector's [`model_digest`](detector_api::DetectorPlugin::model_digest)
/// folded on top (§20.2) — so a threshold change and a retrain each produce a
/// new `(id, version, config_hash)` triple.
fn catalogue(
    registry: &Registry,
    rollout: &RolloutPolicy,
    performance: &PerformanceStore,
) -> ModelRegistry {
    let mut builder = ModelRegistry::builder();
    for plugin in registry.detectors() {
        builder.record(card_for(
            plugin.id(),
            plugin.version(),
            plugin.kind(),
            plugin.scope(),
            &plugin.config_value(),
            // `None` for every rule detector; an ML detector returns the
            // digest of the weights + feature contract it serves, which is
            // folded into its `config_hash` (§20.2).
            plugin.model_digest(),
            rollout,
            performance,
        ));
    }
    builder
        .build()
        .expect("one card per live detector — keys are unique by construction")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::LifecycleStatus;
    use detector_api::test_util::MockDetector;
    use detector_api::{DetectorId, SemVer};

    #[test]
    fn links_every_compiled_in_detector_without_drift() {
        let plan = link_builtin_roster(
            &FeatureFlags::all_enabled(),
            &RolloutPolicy::default(),
            &PerformanceStore::new(),
        )
        .expect("register_builtins's roster is exactly what catalogue covers");
        assert_eq!(
            plan.len(),
            register_builtins(&FeatureFlags::all_enabled()).len(),
            "the linked plan covers every detector this build compiled in"
        );
    }

    #[test]
    fn an_all_disabled_policy_links_an_empty_plan() {
        let plan = link_builtin_roster(
            &FeatureFlags::all_disabled(),
            &RolloutPolicy::default(),
            &PerformanceStore::new(),
        )
        .expect("an empty roster has nothing to fail linking");
        assert!(plan.is_empty());
    }

    #[test]
    fn a_served_models_identity_lands_in_the_detectors_config_hash() {
        // "Weights are config" (§20.2), end to end through the boot path: two
        // deployments of the same detector build that differ *only* in the
        // model they serve must emit different `(id, version, config_hash)`
        // triples, or historical evidence cannot be attributed to the weights
        // that produced it.
        let card_for = |plugin: MockDetector| {
            let registry = Registry::builder().register(plugin).build().unwrap();
            catalogue(
                &registry,
                &RolloutPolicy::default(),
                &PerformanceStore::new(),
            )
            .card(DetectorId::new("anomaly"), SemVer::new(1, 0, 0))
            .expect("catalogued")
            .clone()
        };
        let plain = MockDetector::new("anomaly", SemVer::new(1, 0, 0));
        let march = card_for(plain.with_model_digest(0x11));
        let april =
            card_for(MockDetector::new("anomaly", SemVer::new(1, 0, 0)).with_model_digest(0x22));
        let redeploy =
            card_for(MockDetector::new("anomaly", SemVer::new(1, 0, 0)).with_model_digest(0x11));
        let rule_only = card_for(MockDetector::new("anomaly", SemVer::new(1, 0, 0)));

        assert_ne!(
            march.config_hash, april.config_hash,
            "a retrain is a new triple"
        );
        assert_eq!(
            march.config_hash, redeploy.config_hash,
            "an unchanged redeploy is not"
        );
        assert_ne!(
            march.config_hash, rule_only.config_hash,
            "serving a model is itself part of the identity"
        );
        // A detector serving no model is untouched by the fold.
        assert_eq!(
            rule_only.config_hash,
            crate::model::ConfigHash::for_build(
                DetectorId::new("anomaly"),
                SemVer::new(1, 0, 0),
                &serde_json::Value::Null
            )
        );
    }

    #[test]
    fn a_boot_constructed_detector_is_staged_by_the_same_rollout_policy() {
        // §20.2's "ML gets no special path around the gates", as a test: a
        // detector the *binary* built is registered, catalogued and staged
        // exactly like a compiled-in one.
        let ml: std::sync::Arc<dyn detector_api::DetectorPlugin> = std::sync::Arc::new(
            MockDetector::new("anomaly", SemVer::new(1, 0, 0))
                .with_kind(detector_api::ModelKind::Ml)
                .with_model_digest(0x11),
        );
        let registry =
            crate::registry::register_builtins_with(&FeatureFlags::all_enabled(), vec![ml]);
        let rollout = RolloutPolicy::new().shadow(DetectorId::new("anomaly"));

        let models = catalogue(&registry, &rollout, &PerformanceStore::new());
        let card = models
            .card(DetectorId::new("anomaly"), SemVer::new(1, 0, 0))
            .expect("the boot-constructed detector is catalogued like any other");
        assert_eq!(card.status, LifecycleStatus::Shadow);
        assert!(link_roster(&registry, &rollout, &PerformanceStore::new()).is_ok());
    }

    #[cfg(feature = "sandwich")]
    #[test]
    fn catalogue_applies_rollout_status_and_measured_performance() {
        let rollout = RolloutPolicy::new().shadow(DetectorId::new("sandwich"));
        let registry = register_builtins(&FeatureFlags::all_enabled());
        let sandwich = registry
            .detectors()
            .find(|d| d.id() == DetectorId::new("sandwich"))
            .expect("sandwich is a built-in Block detector");
        let build = crate::measured::Build::new(
            sandwich.id().as_str(),
            sandwich.version(),
            crate::model::ConfigHash::for_build(
                sandwich.id(),
                sandwich.version(),
                &sandwich.config_value(),
            ),
        );
        let record = crate::model::PerformanceRecord::try_new(
            0.9,
            0.8,
            0.05,
            std::num::NonZeroU64::new(1_000).unwrap(),
            chrono::Utc::now(),
        )
        .unwrap();
        let performance: PerformanceStore = [(build, record)].into_iter().collect();

        let models = catalogue(&registry, &rollout, &performance);
        let card = models
            .card(
                DetectorId::new("sandwich"),
                sandwich_detector::SandwichDetector::VERSION,
            )
            .expect("sandwich is a built-in Block detector");

        assert_eq!(card.status, LifecycleStatus::Shadow);
        assert!(card.performance.is_measured());
    }

    #[cfg(feature = "sandwich")]
    #[test]
    fn a_threshold_change_links_as_a_new_triple_at_the_same_version() {
        // Epic E: the backtest gate can only tell "we changed it" from "it
        // broke" if a config change reaches the emitted `config_hash`.
        use sandwich_detector::{SandwichConfig, SandwichDetector};

        let link = |detector: SandwichDetector| {
            let registry = Registry::builder().register(detector).build().unwrap();
            link_roster(
                &registry,
                &RolloutPolicy::default(),
                &PerformanceStore::new(),
            )
            .unwrap()
            .detector_ref(SandwichDetector::ID)
            .cloned()
            .expect("linked")
        };
        let default = link(SandwichDetector::new(SandwichConfig::default()));
        let lowered = link(SandwichDetector::new(SandwichConfig {
            min_profit_usd: detector_api::UsdPrice::try_new(1.0).unwrap(),
        }));

        assert_eq!(default.version, lowered.version);
        assert_ne!(default.config_hash, lowered.config_hash);
        assert_eq!(
            default,
            link(SandwichDetector::new(SandwichConfig::default())),
            "an unchanged config is the same triple"
        );
    }

    /// Every compiled-in detector's `(id, version, config_hash)`, as a stable
    /// list for the golden and conformance tests below.
    #[cfg(feature = "detectors")]
    fn builtin_builds() -> Vec<crate::measured::Build> {
        let flags = FeatureFlags::all_enabled();
        let plan = link_builtin_roster(&flags, &RolloutPolicy::default(), &PerformanceStore::new())
            .unwrap();
        let cross = crate::registry::register_cross_block_builtins(
            &flags,
            &RolloutPolicy::default(),
            &PerformanceStore::new(),
        );
        linked_builds(&plan, &cross)
            .unwrap()
            .into_iter()
            .filter(|b| b.id != "demo")
            .collect()
    }

    /// The config hash of every shipped detector at its default config, pinned.
    ///
    /// This fails when a detector's version or defaults change, which is
    /// intended: update the table in the same diff as the re-baseline. It also
    /// fails when *nothing* about a detector changed but the hash did — a
    /// canonicalisation change, a serde feature unified in from elsewhere in
    /// the build — which would otherwise silently orphan every committed
    /// measurement and every historical event's triple.
    #[cfg(feature = "detectors")]
    #[test]
    fn builtin_config_hashes_are_pinned() {
        const GOLDEN: &[(&str, &str, &str)] = &[
            (
                "address-poisoning",
                "1.0.0",
                "4138542f29a26b2ee2cf9b6d39f569af24c065c73a24bc69a817020d88b12ddb",
            ),
            (
                "arb",
                "1.0.0",
                "59c146ba06899bd81551c32e91f0d77009013e09dd8ca75986c36493986bd045",
            ),
            (
                "flashloan",
                "2.1.0",
                "c31483efd3d14b43ccedd6724598dde48b20e4d0284bf2a1fa88b66f6800b800",
            ),
            (
                "liquidation",
                "1.0.0",
                "3ba1bf8192a565fa86f9d0211cfb8a1a653c36eb5448a143521567573495f576",
            ),
            (
                "rugpull",
                "1.0.0",
                "380fc479515c9ff2ba5e0f1fc9bfdeeb7f3d9b31a5a5c2dbf3044d31088c666f",
            ),
            (
                "sandwich",
                "1.2.0",
                "410e44c54bb005acb2307121f52680206a286c5ecce75728b7774b703da9e208",
            ),
            (
                "wash-trading",
                "1.0.0",
                "10ad57c57db6dea2235803bf839cc3fbe67e58e7f195b9f912953a8c6b6d36af",
            ),
        ];
        let mut actual: Vec<_> = builtin_builds()
            .into_iter()
            .map(|b| (b.id, b.version.to_string(), b.config_hash.to_hex()))
            .collect();
        actual.sort();
        let golden: Vec<_> = GOLDEN
            .iter()
            .map(|(i, v, h)| (i.to_string(), v.to_string(), h.to_string()))
            .collect();
        assert_eq!(
            actual, golden,
            "a detector's triple moved: if intended, update this table, then run \
             `just backtest-update-baseline`"
        );
    }

    /// `config_value` is a required method, but "required" only means a
    /// detector returned *something*. This checks what it returned: a real
    /// config (only `demo` has nothing tunable) that rebuilds a detector
    /// reporting the same config — so the hash covers the whole config type,
    /// not a hand-picked subset of it.
    #[cfg(feature = "detectors")]
    #[test]
    fn every_builtin_config_value_is_the_whole_config() {
        use detector_api::{CrossBlockDetector as _, DetectorPlugin as _};

        const NOTHING_TUNABLE: &[&str] = &["demo"];
        let registry = register_builtins(&FeatureFlags::all_enabled());
        for d in registry.detectors() {
            if NOTHING_TUNABLE.contains(&d.id().as_str()) {
                continue;
            }
            assert!(
                d.config_value().is_object(),
                "{} reports no config; a threshold change would not move its hash",
                d.id()
            );
        }

        fn round_trips<C, D>(
            detector: &D,
            rebuild: impl Fn(C) -> D,
            report: impl Fn(&D) -> serde_json::Value,
        ) where
            C: serde::de::DeserializeOwned,
        {
            let value = report(detector);
            let config: C = serde_json::from_value(value.clone())
                .expect("config_value deserializes back into the detector's config type");
            assert_eq!(report(&rebuild(config)), value);
        }

        round_trips(
            &sandwich_detector::plugin(),
            sandwich_detector::SandwichDetector::new,
            |d| d.config_value(),
        );
        round_trips(
            &arb_detector::plugin(),
            arb_detector::ArbDetector::new,
            |d| d.config_value(),
        );
        round_trips(
            &flashloan_detector::plugin(),
            flashloan_detector::FlashloanDetector::new,
            |d| d.config_value(),
        );
        round_trips(
            &liquidation_detector::plugin(),
            liquidation_detector::LiquidationDetector::new,
            |d| d.config_value(),
        );
        round_trips(
            &poisoning_detector::plugin(),
            poisoning_detector::PoisoningDetector::new,
            |d| d.config_value(),
        );
        round_trips(
            &rugpull_detector::plugin(),
            rugpull_detector::RugpullDetector::new,
            |d| d.config_value(),
        );
        round_trips(
            &washtrading_detector::plugin(),
            washtrading_detector::WashTradingDetector::new,
            |d| d.config_value(),
        );

        // Cross-block detectors are held to the same rule.
        assert!(washtrading_detector::plugin().config_value().is_object());
    }

    #[test]
    fn the_roster_passes_config_to_the_hash() {
        // A mock with a config and one without must link as different builds.
        let link = |d: MockDetector| {
            let registry = Registry::builder().register(d).build().unwrap();
            link_roster(
                &registry,
                &RolloutPolicy::default(),
                &PerformanceStore::new(),
            )
            .unwrap()
            .detector_ref(DetectorId::new("m"))
            .cloned()
            .unwrap()
        };
        let plain = link(MockDetector::new("m", SemVer::new(1, 0, 0)));
        let tuned = link(
            MockDetector::new("m", SemVer::new(1, 0, 0))
                .with_config(serde_json::json!({ "threshold": 1 })),
        );
        assert_ne!(plain.config_hash, tuned.config_hash);
    }
}
