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

use chrono::Utc;

use crate::emit::{DetectionPlan, UnlinkedDetector};
use crate::flags::FeatureFlags;
use crate::model::{ConfigHash, ModelCard, ModelRegistry};
use crate::registry::{register_builtins, Registry};

/// Build the `Block` roster `register_builtins` compiles in, gated by `flags`,
/// and link it to a model registry — failing fast (`Err`) if a live detector is
/// uncatalogued, the same link-or-fail discipline [`DetectionPlan::link`]
/// enforces everywhere else. Every binary that needs a linked plan — the live
/// service and the backtest harness alike — calls this, so neither can
/// silently diverge in how a build's `config_hash` is derived at boot.
pub fn link_builtin_roster(flags: &FeatureFlags) -> Result<DetectionPlan, UnlinkedDetector> {
    let registry = register_builtins(flags);
    let models = catalogue(&registry);
    DetectionPlan::link(&registry, &models)
}

/// Catalogue every live detector into a [`ModelRegistry`] so the plan can `link`.
///
/// The `config_hash` here is derived from the detector's `(id, version)` as a
/// **boot placeholder** — detectors don't yet expose their serialized config for a
/// real [`ConfigHash::of`], and a fabricated-but-stable hash is enough to make the
/// link total. Computing the real config hash (the §18 reproducibility identifier)
/// is a model-registry follow-up (Sprint 10 t4); kept private to this module in
/// the meantime (see the module docs).
fn catalogue(registry: &Registry) -> ModelRegistry {
    let mut builder = ModelRegistry::builder();
    for plugin in registry.detectors() {
        builder.record(ModelCard::for_plugin(
            plugin.as_ref(),
            ConfigHash::boot_placeholder(plugin.id(), plugin.version()),
            Utc::now(),
        ));
    }
    builder
        .build()
        .expect("one card per live detector — keys are unique by construction")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_every_compiled_in_detector_without_drift() {
        let plan = link_builtin_roster(&FeatureFlags::all_enabled())
            .expect("register_builtins's roster is exactly what catalogue covers");
        assert_eq!(
            plan.len(),
            register_builtins(&FeatureFlags::all_enabled()).len(),
            "the linked plan covers every detector this build compiled in"
        );
    }

    #[test]
    fn an_all_disabled_policy_links_an_empty_plan() {
        let plan = link_builtin_roster(&FeatureFlags::all_disabled())
            .expect("an empty roster has nothing to fail linking");
        assert!(plan.is_empty());
    }
}
