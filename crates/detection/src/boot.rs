//! Shared boot-time roster linking (§6, §18) — the **one** place a binary
//! derives a linked [`DetectionPlan`] from [`FeatureFlags`].
//!
//! Originally this lived only in the service binary's `main.rs`, on the theory
//! that the boot-placeholder `config_hash` derivation (see
//! [`catalogue`]'s docs below) shouldn't leak into the lib as something a
//! caller could come to depend on ahead of real per-detector config hashing
//! landing (Sprint 10 t4). That held while there was exactly one caller. A
//! second one arrived — the backtest harness (Sprint 10 t2), which must link
//! the *identical* roster the live service would, or its measured
//! precision/recall is scored against a build that never runs in production.
//! So the outcome is shared here (the one function below); the placeholder
//! hash *mechanism* (`catalogue`) stays private to this module, not
//! re-exported, so a caller can depend on "give me a linked plan for these
//! flags" without depending on how today's stand-in `config_hash` is derived.
//!
//! [`DetectionPlan`]: crate::emit::DetectionPlan
//! [`FeatureFlags`]: crate::flags::FeatureFlags

use crate::emit::{DetectionPlan, UnlinkedDetector};
use crate::flags::FeatureFlags;
use crate::model::{card_for, ModelRegistry, PerformanceStore, RolloutPolicy};
use crate::registry::{register_builtins, Registry};

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

/// Catalogue every live detector into a [`ModelRegistry`] so the plan can `link`.
///
/// The `config_hash` here is derived from the detector's `(id, version)` as a
/// **boot placeholder** — detectors don't yet expose their serialized config for a
/// real [`ConfigHash::of`](crate::model::ConfigHash::of), and a fabricated-but-stable
/// hash is enough to make the link total. Computing the real config hash (the §18
/// reproducibility identifier) remains a follow-up; kept private to this module in
/// the meantime (see the module docs).
///
/// The one part that is *not* a placeholder is a detector's
/// [`model_digest`](detector_api::DetectorPlugin::model_digest): an ML detector
/// (§20.2) folds the identity of the weights and feature contract it serves
/// into the hash, so a retrain is already a new `(id, version, config_hash)`
/// triple today, ahead of the general config-hashing follow-up.
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
    use crate::model::{LifecycleStatus, PerformanceRecord};
    use detector_api::test_util::MockDetector;
    use detector_api::{DetectorId, SemVer};
    use std::num::NonZeroU64;

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
            crate::model::ConfigHash::boot_placeholder(
                DetectorId::new("anomaly"),
                SemVer::new(1, 0, 0)
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
        let performance = PerformanceStore::from([(
            "sandwich".to_string(),
            PerformanceRecord {
                precision: 0.9,
                recall: 0.8,
                hit_rate: 0.05,
                sample_size: NonZeroU64::new(1_000).unwrap(),
                measured_at: chrono::Utc::now(),
            },
        )]);

        let registry = register_builtins(&FeatureFlags::all_enabled());
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
}
