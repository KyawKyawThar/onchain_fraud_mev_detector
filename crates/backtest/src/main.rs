//! `backtest` — replay the ground-truth fixtures through the pure detection
//! core (no Kafka), print each detector's precision/recall, and gate on both
//! committed thresholds (§18, Sprint 10 t2/t3; §20.2, Sprint 18 t5).
//!
//! Default (no args, what CI runs via `just backtest`): replay, print the
//! report, then fail with a non-zero exit if either gate says so —
//!
//! - the **regression** gate ([`baseline`]): a baselined detector's precision
//!   or recall dropped below `crates/backtest/baseline.json`. Answers "did this
//!   change make something worse?"
//! - the **promotion** gate ([`gate`]): a `LifecycleStatus::Active` detector is
//!   below `crates/backtest/promotion_gate.json`, or has no measurement at all.
//!   Answers "is what we ship still good enough?" — and, for the shadowed
//!   detectors, reports which have earned a promotion.
//!
//! Both, because neither subsumes the other: a detector can regress without
//! falling under the promotion bar, and one can sit *at* its baseline forever
//! while never having been good enough to ship.
//!
//! `--update-baseline` overwrites the baseline with this run's numbers — the
//! deliberate step a change that intentionally moves a detector's measured
//! performance takes before it can merge. `--update-model-cards` overwrites
//! `crates/detection/model_performance.json`, the artifact `detection`'s boot
//! reads to fill `ModelCard::Performance` (§18, Sprint 10 t4), separately,
//! since it carries a `measured_at` timestamp and so isn't itself a
//! CI-diffable golden file. There is deliberately **no** `--update-gate`: the
//! promotion floor is policy, and moving it is a hand edit (see [`gate`]).
//!
//! # Scoring the ML detector
//!
//! `--anomaly-config <path>` loads a model bundle through `detection`'s own
//! boot path and scores it alongside the heuristics, adding the ML fixtures
//! ([`fixtures::ml`]) to the replay:
//!
//! ```text
//! cargo run -p backtest --features anomaly -- --anomaly-config /models/anomaly.json
//! ```
//!
//! Without it the ML detector simply isn't in the roster and reports as
//! `UNMEASURED` — which is the honest state of a model this machine has no
//! weights for, not a failure.

use anyhow::Context;
use backtest::{baseline, fixtures, gate, performance};
use clap::Parser;
use detection::RolloutPolicy;

#[derive(Parser)]
#[command(
    about = "Replay the backtest fixtures and gate on the committed precision/recall thresholds (§18, §20.2)"
)]
struct Cli {
    /// Overwrite the committed baseline with this run's numbers instead of
    /// gating on it.
    #[arg(long)]
    update_baseline: bool,
    /// Overwrite `crates/detection/model_performance.json` with this run's
    /// measured precision/recall/hit_rate, the artifact detection's boot reads
    /// to fill `ModelCard::Performance` (§18, Sprint 10 t4).
    #[arg(long)]
    update_model_cards: bool,
    /// Score the ML detector (§20.2) too, loading the model bundle this JSON
    /// config names — the same file `DETECTION_ANOMALY_CONFIG` points at in a
    /// deployment. Requires a build with the `anomaly` feature.
    #[arg(long, value_name = "PATH")]
    anomaly_config: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let ml = ml_detectors(cli.anomaly_config.as_deref())?;
    let scoring_ml = !ml.is_empty();
    let roster =
        backtest::boot_with(ml).context("linking the detector roster to its model cards")?;

    let mut fixtures = fixtures::all();
    if scoring_ml {
        fixtures.extend(fixtures::ml());
    }
    let report = backtest::run_backtest(&fixtures, &roster);
    print!("{report}");

    // The committed artifacts are derived from `fixtures::all()` alone. A run
    // that replayed more blocks than they were measured over would rewrite
    // every detector's hit rate against a different denominator — silently
    // making the golden files unreproducible on a machine with no model
    // bundle. Refuse rather than produce a file nobody else can regenerate.
    if scoring_ml && (cli.update_baseline || cli.update_model_cards) {
        anyhow::bail!(
            "--anomaly-config replays extra ML fixtures, so this run's numbers are measured over \
             a different block set than the committed baseline/model cards — re-run without it \
             to update them"
        );
    }

    if cli.update_model_cards {
        let store = performance::from_report(&report);
        let path = detection::default_performance_store_path();
        detection::save_performance_store(&store, &path)
            .context("updating the committed model performance store")?;
        println!("\nmodel performance updated: {}", path.display());
    }

    if cli.update_baseline {
        let path = baseline::default_path();
        baseline::save(&baseline::from_report(&report), &path)
            .context("updating the committed precision/recall baseline")?;
        println!("\nbaseline updated: {}", path.display());
        return Ok(());
    }

    // Both gates run before either can fail the process, so one invocation
    // reports everything wrong rather than a fix-and-rerun cycle per gate.
    let regressions = check_regressions(&report)?;
    let promotion = check_promotion(&report)?;

    if regressions == 0 && promotion == 0 {
        println!("\nall gates clear (§18, §20.2)");
        return Ok(());
    }
    anyhow::bail!(
        "{regressions} regression(s) and {promotion} promotion-gate failure(s) — fix the \
         detector/config change, or run `cargo run -p backtest -- --update-baseline` if a \
         measured drop is intended"
    )
}

/// The regression gate: nothing may drop below the committed baseline.
fn check_regressions(report: &backtest::Report) -> anyhow::Result<usize> {
    let base = baseline::load(&baseline::default_path())
        .context("loading the committed precision/recall baseline")?;
    let regressions = baseline::check(report, &base);

    println!();
    if regressions.is_empty() {
        println!("no regressions against baseline (§18)");
    }
    for r in &regressions {
        println!("REGRESSION  {r}");
    }
    Ok(regressions.len())
}

/// The promotion gate: nothing `Active` may sit below the committed floor, and
/// shadowed detectors that clear it are reported as promotable.
fn check_promotion(report: &backtest::Report) -> anyhow::Result<usize> {
    let thresholds =
        gate::load(&gate::default_path()).context("loading the committed promotion gate")?;
    // The *live* staging, read from `detection` rather than restated here — a
    // gate reporting on a rollout the service doesn't apply would be worse
    // than no gate.
    let report = gate::GateReport::new(report, &thresholds, &RolloutPolicy::builtin());

    println!("\n{report}");
    let promotable: Vec<&str> = report.promotable().map(|o| o.detector.as_str()).collect();
    if !promotable.is_empty() {
        println!(
            "{} shadowed detector(s) clear the gate and could be promoted: {}\n  \
             Promotion is a deliberate step, not this harness's: delete the matching \
             `.shadow(...)` line in `RolloutPolicy::builtin`.",
            promotable.len(),
            promotable.join(", ")
        );
    }

    let failures = report.failures().count();
    for o in report.failures() {
        // `headline` already carries the "GATE FAIL" prefix for these; what
        // this line adds is *why*, spelled out per shortfall.
        println!("GATE FAIL   {} ({}) — {}", o.detector, o.status, reason(o));
    }
    Ok(failures)
}

/// Why a live detector failed its gate, in one clause.
fn reason(outcome: &gate::GateOutcome) -> String {
    match &outcome.verdict {
        gate::Verdict::Held(shortfalls) => shortfalls
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        gate::Verdict::Unmeasured => format!(
            "no measurement: {} ground-truthed incident(s), the gate needs {}. A detector that \
             ships with nothing verified about it is the case this gate exists for — add a \
             fixture for it, or stage it back to Shadow in `RolloutPolicy::builtin`",
            outcome.incidents, outcome.thresholds.min_incidents
        ),
        // Unreachable: `blocks_release` is false for a clearing detector.
        gate::Verdict::Clears => "clears (nothing to report)".to_owned(),
    }
}

/// The ML detector, loaded from the bundle `--anomaly-config` names.
#[cfg(feature = "anomaly")]
fn ml_detectors(
    config: Option<&str>,
) -> anyhow::Result<Vec<std::sync::Arc<dyn detection::DetectorPlugin>>> {
    let Some(path) = config else {
        return Ok(Vec::new());
    };
    // The service's own loader: digests, pinned-digest check, §20.5 skew,
    // graph conformance, the probe inference, baseline/schema pairing. A
    // bundle scored here is a bundle that would boot.
    let detector = detection::ml::load_anomaly_detector(std::path::Path::new(path))
        .with_context(|| format!("loading the ML deployment at {path}"))?;
    println!("scoring the ML detector from {path}\n");
    Ok(vec![std::sync::Arc::new(detector)])
}

#[cfg(not(feature = "anomaly"))]
fn ml_detectors(
    config: Option<&str>,
) -> anyhow::Result<Vec<std::sync::Arc<dyn detection::DetectorPlugin>>> {
    // Say so rather than replaying without it: a silent no-op here would print
    // a gate report claiming the ML detector is unmeasured when the operator
    // just told us where its weights are.
    anyhow::ensure!(
        config.is_none(),
        "--anomaly-config needs a build with the `anomaly` feature: \
         cargo run -p backtest --features anomaly -- --anomaly-config <path>"
    );
    Ok(Vec::new())
}
