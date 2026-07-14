//! `backtest` — replay the ground-truth fixtures through the pure detection
//! core (no Kafka) and print each detector's precision/recall (§18, Sprint 10 t2).

use anyhow::Context;

fn main() -> anyhow::Result<()> {
    let roster = backtest::boot().context("linking the detector roster to its model cards")?;
    let fixtures = backtest::fixtures::all();
    let report = backtest::run_backtest(&fixtures, &roster);
    print!("{report}");
    Ok(())
}
