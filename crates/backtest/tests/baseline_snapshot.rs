//! Full-report snapshot (§18) — a *dev-review* signal distinct from the
//! merge-blocking gate in `baseline.rs`/`main.rs`. That gate only fails on a
//! *regression*, so an improvement passes silently and `baseline.json` can
//! drift stale without anyone noticing. This test fails on *any* change to
//! the full report — improvement included — via `cargo insta`'s committed
//! `.snap` file, so a detector/config change that moves the numbers always
//! gets a reviewable diff, whether or not it's bad enough to fail the gate.
//!
//! A mismatch here doesn't block a merge by itself; accepting the new
//! snapshot (`just backtest-accept-snapshot`, or `cargo insta accept`) is the
//! reviewer's acknowledgement that the change was seen, same spirit as
//! `--update-baseline` is for the gate itself.

#[test]
fn full_report_matches_its_committed_snapshot() {
    let roster = backtest::boot().expect("the built-in roster links cleanly");
    let fixtures = backtest::fixtures::all();
    let report = backtest::run_backtest(&fixtures, &roster);
    insta::assert_snapshot!(report.to_string());
}
