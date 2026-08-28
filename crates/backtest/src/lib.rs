//! The backtest harness (§18, Sprint 10 t2) — replays labeled ground-truth
//! fixtures for known incidents through the pure detection core, no Kafka, and
//! reports each detector's precision/recall.
//!
//! # Why this is possible at all
//!
//! Every detector's [`detect`](detector_api::DetectorPlugin::detect) is a pure
//! function of a [`DetectionCtx`](detector_api::DetectionCtx) — no I/O, no
//! clock, no labels (§6) — and [`DetectionPlan::detection_events`] and
//! `CrossBlockStates::observe_and_detect` are the identical, Kafka-free mapping
//! the live scheduler's `Assembled` branch runs per block (§17). So replaying a
//! fixture is exactly two calls per block, no broker, no envelopes:
//!
//! ```text
//! for each block, in order:
//!     events  = plan.detection_events(&ctx)                // Block roster
//!     events += cross_block.observe_and_detect(&ctx)        // CrossBlock roster
//! ```
//!
//! [`fixture`] defines the scenario shape ([`Fixture`]/[`ExpectedIncident`]);
//! [`fixtures`] is the ground truth itself — one known-incident scenario per
//! built-in detector, plus a clean block, built with the same [`CtxBuilder`]
//! helper the detectors' own regression tests use; [`scoring`] replays a
//! fixture and rolls the outcomes up into per-detector precision/recall/hit_rate;
//! [`baseline`] compares that roll-up against the committed reference numbers
//! and is the CI gate (§18, Sprint 10 t3); [`gate`] compares it against the
//! committed *promotion* floor and is the Shadow → Live rollout gate (§18,
//! §20.2, Sprint 18 t5); [`performance`] derives a
//! [`detection::PerformanceStore`] from a [`Report`] — the artifact
//! `detection`'s boot reads to fill `ModelCard::Performance` (§18, Sprint 10 t4).
//!
//! [`CtxBuilder`]: detector_api::test_util::CtxBuilder

pub mod baseline;
pub mod fixture;
pub mod fixtures;
pub mod gate;
pub mod performance;
pub mod scoring;

pub use fixture::{ExpectedIncident, Fixture};
pub use scoring::{run_backtest, run_fixture, DetectorStats, Finding, FixtureResult, Report};

use std::sync::Arc;

use detection::{
    link_roster, register_builtins_with, DetectionPlan, DetectorId, DetectorPlugin, FeatureFlags,
    PerformanceStore, RolloutPolicy,
};

/// The linked `Block` roster plus the flags it was built from — bundled
/// because every replay needs both together (a plan without the flags that
/// produced it can't rebuild the matching cross-block roster per fixture, see
/// [`scoring::run_fixture`]), and passing the pair as one value keeps that and
/// [`run_backtest`] from growing a third parameter every time boot needs to
/// hand across one more thing.
#[derive(Debug)]
pub struct Roster {
    pub plan: DetectionPlan,
    pub flags: FeatureFlags,
}

/// Build the full built-in `Block` roster the same way the live service's
/// binary does at boot (§6), via `detection`'s own [`link_builtin_roster`] —
/// so the backtest harness and the live service can't silently link two
/// different rosters and call them the same build.
///
/// `demo` is disabled by flag regardless of whether its Cargo feature happens
/// to be linked: it's dev/test-only scaffolding that fires on a fixed schedule
/// "regardless of tx content" (its own module docs — never a real build), so a
/// `--all-features` build (CI's own invocation) must not let it poison a
/// detector's measured precision/recall.
///
/// Links with [`RolloutPolicy::default`] (every detector `Active`) and an empty
/// [`PerformanceStore`], regardless of the live service's current staging or
/// prior measurements: the backtest harness exists to measure a detector's true
/// detection capability so it can *inform* a Shadow→Active promotion (§18,
/// Sprint 10 t4), so it can't itself be gated — or seeded — by that decision.
pub fn boot() -> anyhow::Result<Roster> {
    boot_with(Vec::new())
}

/// [`boot`] plus detectors the *caller* constructed — the ML detector (§20.2),
/// whose weights and training-window baselines are files a deployment mounts
/// and so cannot be a compile-time constant.
///
/// Routed through `detection`'s own
/// [`register_builtins_with`](detection::register_builtins_with) +
/// [`link_roster`](detection::link_roster) — the identical pair the service
/// binary's boot calls — so a model scored here is registered, catalogued and
/// linked exactly as it would be in production. Measuring a detector through a
/// different wiring than the one that runs it is the one thing a rollout gate
/// must not do.
pub fn boot_with(extra: Vec<Arc<dyn DetectorPlugin>>) -> anyhow::Result<Roster> {
    let flags = FeatureFlags::all_enabled().disable(DetectorId::new("demo"));
    let registry = register_builtins_with(&flags, extra);
    let plan = link_roster(
        &registry,
        &RolloutPolicy::default(),
        &PerformanceStore::new(),
    )?;
    Ok(Roster { plan, flags })
}
