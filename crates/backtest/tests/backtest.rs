//! The harness's own regression check (§18, Sprint 10 t2): every built-in
//! detector catches its ground-truth incident and raises nothing on any other
//! fixture — perfect precision and recall over the shipped fixture set. A
//! detector/threshold change that regresses this is exactly what a future CI
//! gate (Sprint 10 t3) would block on.

#[test]
fn seven_detectors_score_perfect_precision_and_recall_with_no_cross_triggers() {
    let roster = backtest::boot().expect("the built-in roster links cleanly");
    let fixtures = backtest::fixtures::all();
    let report = backtest::run_backtest(&fixtures, &roster);

    assert_eq!(
        report.detectors.len(),
        7,
        "all seven built-in detectors should have scored: {:?}",
        report.detectors.keys().collect::<Vec<_>>()
    );

    for (id, stats) in &report.detectors {
        assert_eq!(
            stats.false_positives, 0,
            "{id} raised an alert no fixture expected"
        );
        assert_eq!(
            stats.false_negatives, 0,
            "{id} missed its own ground-truth incident"
        );
        assert_eq!(stats.precision(), Some(1.0), "{id} precision");
        assert_eq!(stats.recall(), Some(1.0), "{id} recall");
    }
}

#[test]
fn the_clean_fixture_raises_nothing() {
    let roster = backtest::boot().expect("the built-in roster links cleanly");
    let clean = backtest::fixtures::clean_block();
    let result = backtest::run_fixture(&clean, &roster);

    assert!(result.caught.is_empty());
    assert!(result.missed.is_empty());
    assert!(
        result.unexpected.is_empty(),
        "an ordinary block should raise no alerts: {:?}",
        result.unexpected
    );
}
