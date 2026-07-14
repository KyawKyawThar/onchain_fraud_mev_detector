//! `backtest` — replay the ground-truth fixtures through the pure detection
//! core (no Kafka), print each detector's precision/recall, and gate on the
//! committed baseline (§18, Sprint 10 t2/t3).
//!
//! Default (no args, what CI runs via `just backtest`): replay, print the
//! report, then fail with a non-zero exit if any baselined detector's
//! precision or recall dropped below `crates/backtest/baseline.json`.
//! `--update-baseline` instead overwrites that file with this run's numbers —
//! the deliberate step a change that intentionally moves a detector's
//! measured performance takes before it can merge.

use anyhow::Context;
use backtest::baseline;
use clap::Parser;

#[derive(Parser)]
#[command(
    about = "Replay the backtest fixtures and gate on the committed precision/recall baseline (§18)"
)]
struct Cli {
    /// Overwrite the committed baseline with this run's numbers instead of
    /// gating on it.
    #[arg(long)]
    update_baseline: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let roster = backtest::boot().context("linking the detector roster to its model cards")?;
    let fixtures = backtest::fixtures::all();
    let report = backtest::run_backtest(&fixtures, &roster);
    print!("{report}");

    let path = baseline::default_path();

    if cli.update_baseline {
        baseline::save(&baseline::from_report(&report), &path)
            .context("updating the committed precision/recall baseline")?;
        println!("\nbaseline updated: {}", path.display());
        return Ok(());
    }

    let base = baseline::load(&path).context("loading the committed precision/recall baseline")?;
    let regressions = baseline::check(&report, &base);
    if regressions.is_empty() {
        println!("\nno regressions against baseline (§18)");
        return Ok(());
    }

    println!();
    for r in &regressions {
        println!("REGRESSION  {r}");
    }
    anyhow::bail!(
        "{} detector metric(s) regressed below baseline (§18) — fix the detector/config change, \
         or run `cargo run -p backtest -- --update-baseline` if this drop is intended",
        regressions.len()
    )
}
