//! The ML detector's rollout path, end to end through the harness (§20.2,
//! §18, Sprint 18 t5).
//!
//! What this covers that no unit test can: that a *boot-constructed* detector
//! reaches the backtest roster at all, that the anomaly fixture scores against
//! it, and that the committed promotion gate reaches the right verdict about
//! it. Those three are separately tested elsewhere and could each be right
//! while the wiring between them was wrong — which is exactly the failure a
//! rollout gate cannot have.
//!
//! **No ONNX Runtime is involved, on purpose.** The engine is
//! `inference::test_util::StubEngine`, which enforces the same skew contract
//! the real backend does. A test that needed a native library would either be
//! skipped in CI (green while checking nothing) or make the harness
//! undeployable on a machine with no model bundle — and the property under
//! test here is about *wiring*, which a stub exercises identically.

use std::sync::Arc;

use anomaly_detector::{AnomalyConfig, AnomalyDetector, ModelSlot};
use backtest::gate::{self, GateThresholds, PromotionGate, Verdict};
use backtest::{fixtures, DetectorStats};
use detection::{DetectorId, DetectorPlugin, LifecycleStatus, RolloutPolicy};
use inference::test_util::{block_descriptor, StubEngine};
use inference::Score;
use ml_features::FeatureBaseline;

/// An ML detector that scores every block at `score` — a stand-in for a
/// deployed bundle, wired exactly as `detection::ml` wires a real one.
fn ml_detector(score: f64) -> Arc<dyn DetectorPlugin> {
    let ctx = detector_api::test_util::CtxBuilder::new()
        .tx(
            detector_api::test_util::b256(1),
            detector_api::test_util::addr(1),
            vec![],
        )
        .build();
    let baseline = FeatureBaseline::from_samples(&[ml_features::extract_block(&ctx)])
        .expect("a one-sample baseline over the current block schema");
    let engine = Arc::new(StubEngine::constant(
        block_descriptor("anomaly-iforest"),
        Score::new(score).expect("a valid score"),
    ));
    let detector = AnomalyDetector::new(
        AnomalyConfig::default(),
        vec![ModelSlot::novelty(engine, baseline).expect("baseline matches the block schema")],
    )
    .expect("one model is a valid deployment");
    Arc::new(detector)
}

fn stats(report: &backtest::Report, id: &str) -> DetectorStats {
    report.detectors.get(id).copied().unwrap_or_default()
}

/// A gate whose only difference from the committed one is that a single
/// incident counts as evidence — so the *verdict logic* can be exercised on
/// the one-fixture ML corpus that exists today.
fn gate_accepting_one_incident() -> PromotionGate {
    let mut gate = gate::load(&gate::default_path()).expect("the committed gate");
    gate.detectors.insert(
        "anomaly".to_string(),
        GateThresholds {
            min_incidents: 1,
            ..gate.thresholds("anomaly")
        },
    );
    gate
}

#[test]
fn a_boot_constructed_ml_detector_joins_the_roster_and_scores_its_fixture() {
    // The §20.2 deliverable: "an anomalous bundle no heuristic has a signature
    // for produces a DetectorTriggered with feature-level evidence."
    let roster = backtest::boot_with(vec![ml_detector(0.99)]).expect("the roster links");

    let mut all = fixtures::all();
    all.extend(fixtures::ml());
    let report = backtest::run_backtest(&all, &roster);

    let anomaly = stats(&report, "anomaly");
    assert_eq!(
        anomaly.true_positives, 1,
        "the anomalous bundle is ground truth for the ML detector: {report}"
    );
    assert_eq!(anomaly.false_negatives, 0);
}

#[test]
fn a_model_that_never_fires_is_held_in_shadow_on_recall() {
    // A bundle that misses its own ground truth must not promote. This is the
    // gate doing its job on the case it exists for.
    let roster = backtest::boot_with(vec![ml_detector(0.01)]).expect("the roster links");
    let mut all = fixtures::all();
    all.extend(fixtures::ml());
    let report = backtest::run_backtest(&all, &roster);

    let outcomes = gate::evaluate(
        &report,
        &gate_accepting_one_incident(),
        &RolloutPolicy::builtin(),
    );
    let anomaly = outcomes
        .iter()
        .find(|o| o.detector == "anomaly")
        .expect("the ML detector is reported");

    assert_eq!(anomaly.status, LifecycleStatus::Shadow);
    assert_eq!(anomaly.recall, Some(0.0));
    assert!(matches!(anomaly.verdict, Verdict::Held(_)), "{anomaly:?}");
    assert!(!anomaly.eligible_for_promotion());
    assert!(
        !anomaly.blocks_release(),
        "a shadowed detector that isn't ready is not a broken build"
    );
}

#[test]
fn a_model_that_fires_on_everything_is_held_on_precision() {
    // The other failure mode, and the reason `anomaly`'s committed
    // `min_precision` is *above* the default: an unexplained-anomaly alert on
    // every ordinary block costs an analyst an investigation each time.
    let roster = backtest::boot_with(vec![ml_detector(1.0)]).expect("the roster links");
    let mut all = fixtures::all();
    all.extend(fixtures::ml());
    let report = backtest::run_backtest(&all, &roster);

    let anomaly = stats(&report, "anomaly");
    assert!(
        anomaly.false_positives > 0,
        "scoring every block at 1.0 fires on the clean block too: {report}"
    );

    let outcomes = gate::evaluate(
        &report,
        &gate_accepting_one_incident(),
        &RolloutPolicy::builtin(),
    );
    let anomaly = outcomes
        .iter()
        .find(|o| o.detector == "anomaly")
        .expect("the ML detector is reported");
    assert!(matches!(anomaly.verdict, Verdict::Held(_)), "{anomaly:?}");
    assert!(!anomaly.eligible_for_promotion());
}

#[test]
fn one_lucky_fixture_does_not_promote_a_model_under_the_committed_gate() {
    // Driven through the *committed* `promotion_gate.json`, not a test-local
    // one: `anomaly` requires three ground-truthed incidents, and the shipped
    // ML corpus has one. A model that catches its fixture must therefore still
    // read `Unmeasured` — a model can be fit to a single fixture, and a gate
    // that promoted on one would be measuring memorisation.
    let roster = backtest::boot_with(vec![ml_detector(0.99)]).expect("the roster links");
    let mut all = fixtures::all();
    all.extend(fixtures::ml());
    let report = backtest::run_backtest(&all, &roster);

    let committed = gate::load(&gate::default_path()).expect("the committed gate");
    let outcomes = gate::evaluate(&report, &committed, &RolloutPolicy::builtin());
    let anomaly = outcomes
        .iter()
        .find(|o| o.detector == "anomaly")
        .expect("the ML detector is reported");

    assert_eq!(anomaly.incidents, 1, "one ML fixture, one ground truth");
    assert_eq!(
        anomaly.verdict,
        Verdict::Unmeasured,
        "too few incidents outranks any shortfall: the numbers aren't evidence yet"
    );
    assert!(!anomaly.eligible_for_promotion());
}

#[test]
fn the_ml_detector_is_shadowed_in_the_shipped_rollout() {
    // §20.2: ML walks Shadow → backtest gate → Live like any detector change.
    // If someone promotes it, this test is the reminder that the promotion was
    // a deliberate act — update it along with `RolloutPolicy::builtin`.
    assert_eq!(
        RolloutPolicy::builtin().status_of(DetectorId::new("anomaly")),
        LifecycleStatus::Shadow
    );
}

#[test]
fn the_ml_fixtures_are_not_part_of_the_committed_corpus() {
    // The committed baseline and `model_performance.json` are measured over
    // `fixtures::all()`. If an ML fixture leaked into it, every run on a
    // machine with no model bundle would score a false negative for `anomaly`
    // — turning "not deployed here" into "broken".
    assert!(
        fixtures::all()
            .iter()
            .all(|f| f.expected.iter().all(|e| e.detector.as_str() != "anomaly")),
        "no ML ground truth may appear in the default fixture set"
    );
    assert!(!fixtures::ml().is_empty());
}
