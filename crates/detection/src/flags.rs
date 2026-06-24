//! Per-detector feature flags (§6, task 2) — the runtime on/off switch for a
//! linked detector.
//!
//! Two independent gates decide whether a detector runs, and they answer
//! different questions:
//!
//! - The **compile-time** `#[cfg(feature = "…")]` in
//!   [`register_builtins`](crate::registry::register_builtins) decides whether a
//!   detector is *in the binary at all* — premium detectors simply aren't linked
//!   into an open build (§6: "selective open-sourcing").
//! - These **runtime** flags decide whether a linked detector is *turned on*,
//!   without a recompile — operations can dark-launch a detector, or disable a
//!   noisy one in production, by config alone.
//!
//! Flags are keyed by [`DetectorId`], not `(id, version)`: a flag is the coarse
//! "do we run the sandwich detector?" switch. Picking *which* version is live is
//! the model registry's job ([`crate::model::LifecycleStatus`]) — two versions
//! of one id coexist for safe rollout, and the flag turns the whole family on or
//! off. They feed [`RegistryBuilder::register_if`](crate::registry::RegistryBuilder::register_if).

use std::collections::BTreeMap;

use detector_api::DetectorId;

/// Which detectors are enabled at runtime (§6).
///
/// A `default_enabled` policy plus per-id overrides, so config can express
/// either "everything on except these" (`all_enabled().disable(...)`) or
/// "everything off except these" (`all_disabled().enable(...)`) without
/// listing every detector. Resolved by [`is_enabled`](Self::is_enabled).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureFlags {
    /// What to answer for an id with no explicit override.
    default_enabled: bool,
    /// Per-detector overrides of the default policy.
    overrides: BTreeMap<DetectorId, bool>,
}

impl FeatureFlags {
    /// Every linked detector on unless explicitly disabled — the production
    /// default (a detector compiled in is meant to run).
    pub fn all_enabled() -> Self {
        Self::with_default(true)
    }

    /// Every linked detector off unless explicitly enabled — for dark-launching
    /// a new detector against live traffic one id at a time.
    pub fn all_disabled() -> Self {
        Self::with_default(false)
    }

    /// Start from an explicit default policy.
    pub fn with_default(default_enabled: bool) -> Self {
        Self {
            default_enabled,
            overrides: BTreeMap::new(),
        }
    }

    /// Force `id` on, overriding the default. Chainable.
    #[must_use]
    pub fn enable(mut self, id: DetectorId) -> Self {
        self.overrides.insert(id, true);
        self
    }

    /// Force `id` off, overriding the default. Chainable.
    #[must_use]
    pub fn disable(mut self, id: DetectorId) -> Self {
        self.overrides.insert(id, false);
        self
    }

    /// Set `id`'s flag in place (the mutating form config loaders use while
    /// folding over env/file entries).
    pub fn set(&mut self, id: DetectorId, enabled: bool) -> &mut Self {
        self.overrides.insert(id, enabled);
        self
    }

    /// Is `id` enabled? An explicit override wins; otherwise the default policy.
    /// This is what [`register_if`](crate::registry::RegistryBuilder::register_if)
    /// is handed per detector.
    pub fn is_enabled(&self, id: DetectorId) -> bool {
        self.overrides
            .get(&id)
            .copied()
            .unwrap_or(self.default_enabled)
    }
}

impl Default for FeatureFlags {
    /// All detectors enabled — see [`all_enabled`](Self::all_enabled).
    fn default() -> Self {
        Self::all_enabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_applies_without_an_override() {
        assert!(FeatureFlags::all_enabled().is_enabled(DetectorId::new("sandwich")));
        assert!(!FeatureFlags::all_disabled().is_enabled(DetectorId::new("sandwich")));
    }

    #[test]
    fn an_override_wins_over_the_default() {
        let flags = FeatureFlags::all_enabled().disable(DetectorId::new("arb"));
        assert!(!flags.is_enabled(DetectorId::new("arb")));
        // Untouched ids still follow the default.
        assert!(flags.is_enabled(DetectorId::new("sandwich")));

        let flags = FeatureFlags::all_disabled().enable(DetectorId::new("arb"));
        assert!(flags.is_enabled(DetectorId::new("arb")));
        assert!(!flags.is_enabled(DetectorId::new("sandwich")));
    }

    #[test]
    fn set_mutates_in_place_and_last_write_wins() {
        let mut flags = FeatureFlags::all_disabled();
        flags
            .set(DetectorId::new("sandwich"), true)
            .set(DetectorId::new("sandwich"), false);
        assert!(!flags.is_enabled(DetectorId::new("sandwich")));
    }
}
