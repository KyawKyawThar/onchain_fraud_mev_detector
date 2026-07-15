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
    let registry = register_builtins(flags);
    let models = catalogue(&registry, rollout, performance);
    DetectionPlan::link(&registry, &models)
}

/// Catalogue every live detector into a [`ModelRegistry`] so the plan can `link`.
///
/// The `config_hash` here is derived from the detector's `(id, version)` as a
/// **boot placeholder** — detectors don't yet expose their serialized config for a
/// real [`ConfigHash::of`](crate::model::ConfigHash::of), and a fabricated-but-stable
/// hash is enough to make the link total. Computing the real config hash (the §18
/// reproducibility identifier) remains a follow-up; kept private to this module in
/// the meantime (see the module docs).
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
    use detector_api::DetectorId;
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
