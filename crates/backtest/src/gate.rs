//! The **promotion gate** (§18, §20.2, Sprint 18 t5) — the committed
//! precision/recall floor a detector must clear before it leaves `Shadow`, and
//! must keep clearing to stay `Active`.
//!
//! # This is not the baseline
//!
//! [`crate::baseline`] and this module answer different questions and are
//! deliberately not merged:
//!
//! | | baseline.json | promotion_gate.json |
//! |---|---|---|
//! | asks | "did this change make a detector *worse*?" | "is this detector *good enough to ship*?" |
//! | moves | with every intentional change, via `--update-baseline` | only by deliberate policy decision |
//! | scope | whatever happens to be measured | every detector, including ones with no entry |
//!
//! A baseline that a change is allowed to rewrite cannot also be a promotion
//! bar — a detector could ratchet its own floor down one merge at a time and
//! arrive at `Active` with a precision of 0.2, each step "no regression". So
//! the gate is a separate file with **no `--update` flag**: moving it is a
//! hand edit, which is exactly the friction a governance threshold should have.
//!
//! # What the verdict means
//!
//! §20.2's rollout is `Shadow → backtest gate (precision/recall ≥ committed
//! baseline) → Live`, and §6 makes `LifecycleStatus` the thing that changes.
//! So the gate reads the *live* staging
//! ([`RolloutPolicy::builtin`](detection::RolloutPolicy::builtin)) and reports
//! per detector:
//!
//! - **`Shadow` + clears** — eligible for promotion. Informational: promoting
//!   is a human decision (delete its line in `RolloutPolicy::builtin`), and a
//!   harness that promoted detectors by itself would be a rollout with no
//!   rollout in it.
//! - **`Shadow` + held** — still shadowed, working as intended. Also
//!   informational: a detector being not-yet-good-enough is the normal state
//!   of a detector under development, not a broken build.
//! - **`Active` + held, or `Active` + unmeasured** — a **gate failure**, and
//!   the only outcome that fails the build. Something customer-facing is
//!   either below the bar it was promoted against, or has no evidence behind
//!   it at all. Both are release blockers; "we promoted it and then stopped
//!   measuring it" is the exact governance hole §20.5 asks to close.
//! - **`Deprecated`** — skipped. It is catalogued so historical events stay
//!   resolvable (§18), not because anyone expects it to perform.
//!
//! Note the asymmetry is the whole design: the gate can *block a release*, but
//! it can only *recommend* a promotion.
//!
//! # The committed numbers
//!
//! `promotion_gate.json` ships one `default` bar (0.8 / 0.8 over ≥ 1
//! ground-truthed incident) and one override, for `anomaly`:
//!
//! ```json
//! "anomaly": { "min_precision": 0.9, "min_recall": 0.5, "min_incidents": 3 }
//! ```
//!
//! That is **not** a path around the gate (§20.2 forbids one) — it is a
//! stricter bar where the cost is higher and a looser one where the claim is
//! weaker, argued rather than assumed:
//!
//! - *Precision 0.9, above the default.* An `AlertKind::Anomaly` names no
//!   known pattern, so a false positive costs an analyst a full investigation
//!   to dismiss. A signature detector's false positive at least says what it
//!   thought it saw.
//! - *Recall 0.5, below the default.* The novelty model is a net for attacks
//!   with no signature yet, not the primary detector for anything. Holding it
//!   to a signature detector's recall would be demanding it catch things it
//!   was never the mechanism for.
//! - *Three incidents, above the default one.* A model's measurement over a
//!   single block is noise, and unlike a heuristic it can be *fit* to one
//!   fixture. Until the ML fixture set has three, `anomaly` reads `UNMEASURED`
//!   — which is the honest state of a model nobody has scored yet, and the
//!   reason it stays in `Shadow`.
//!
//! The `default` `min_incidents` of 1 is likewise honest rather than
//! aspirational: the shipped fixture corpus ground-truths exactly one incident
//! per heuristic detector, so 1 is the floor that corpus can support. It is
//! the first number to raise as fixtures land — a bar nothing can fail is a
//! bar in name only.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use detection::{LifecycleStatus, RolloutPolicy};
use serde::{Deserialize, Serialize};

use crate::baseline::BaselineError;
use crate::{DetectorStats, Report};

/// Float noise from the tp/fp/fn ratios' own arithmetic — a detector sitting
/// exactly on its floor must not be held back by an ulp.
const EPSILON: f64 = 1e-9;

/// The bar one detector has to clear.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateThresholds {
    /// Of the alerts it raised, the minimum fraction that must be true.
    pub min_precision: f64,
    /// Of the incidents ground-truthed for it, the minimum fraction it must
    /// catch.
    pub min_recall: f64,
    /// Minimum ground-truthed incidents behind those numbers.
    ///
    /// A precision of 1.0 over one incident is not evidence, and §6's
    /// `Performance::Measured` already carries a `sample_size` for exactly
    /// this reason ("a precision over 3 blocks is not the precision over
    /// 30k"). The committed value is small because the shipped fixture set is
    /// small — it is an honest floor for the corpus that exists, and the
    /// number to raise as fixtures are added, not a target to design fixtures
    /// around.
    pub min_incidents: u64,
}

/// The committed gate: one bar every detector is held to, plus per-detector
/// overrides.
///
/// A `default` rather than a map of every id, so a **new detector is gated
/// from the day it lands**. The alternative — a bare map — would leave an
/// unlisted detector silently ungated, which is the same "absent means
/// exempt" failure the model registry's link-or-fail discipline exists to
/// prevent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionGate {
    /// Applied to any detector with no entry in [`detectors`](Self::detectors).
    pub default: GateThresholds,
    /// Per-detector overrides, keyed the same way [`Report::detectors`] is.
    #[serde(default)]
    pub detectors: BTreeMap<String, GateThresholds>,
}

impl PromotionGate {
    /// The bar `id` is held to.
    pub fn thresholds(&self, id: &str) -> GateThresholds {
        self.detectors.get(id).copied().unwrap_or(self.default)
    }
}

/// `crates/backtest/promotion_gate.json`, resolved at compile time so the gate
/// works from any CWD.
pub fn default_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("promotion_gate.json")
}

/// Load the committed gate. A missing or malformed file is an error, never a
/// skipped check — reusing [`BaselineError`] because the failure modes and the
/// message an operator needs are identical, and a second near-identical error
/// enum would be two things to keep in step.
pub fn load(path: &Path) -> Result<PromotionGate, BaselineError> {
    let text = std::fs::read_to_string(path).map_err(|source| BaselineError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&text).map_err(|source| BaselineError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

/// Which requirement a detector fell short of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    Precision,
    Recall,
    Incidents,
}

impl std::fmt::Display for Requirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Requirement::Precision => "precision",
            Requirement::Recall => "recall",
            Requirement::Incidents => "incidents",
        })
    }
}

/// One requirement a detector did not meet.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Shortfall {
    pub requirement: Requirement,
    pub required: f64,
    pub measured: f64,
}

impl std::fmt::Display for Shortfall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {:.3} < {:.3}",
            self.requirement, self.measured, self.required
        )
    }
}

/// How a detector stands against its gate.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Meets every requirement.
    Clears,
    /// Measured, but short on at least one requirement.
    Held(Vec<Shortfall>),
    /// Nothing to judge: the fixture set ground-truths no incident for it, so
    /// it has no recall to measure. Distinct from [`Held`](Self::Held) on
    /// purpose — "we looked and it wasn't good enough" and "we never looked"
    /// call for different responses, and collapsing them would let an
    /// unmeasured detector read as a merely-underperforming one.
    Unmeasured,
}

impl Verdict {
    pub fn clears(&self) -> bool {
        matches!(self, Verdict::Clears)
    }
}

/// One detector's standing: where it is staged, what it measured, and whether
/// that clears the bar.
#[derive(Debug, Clone, PartialEq)]
pub struct GateOutcome {
    pub detector: String,
    pub status: LifecycleStatus,
    pub thresholds: GateThresholds,
    pub precision: Option<f64>,
    pub recall: Option<f64>,
    /// Ground-truthed incidents behind the numbers (`tp + fn`) — the recall
    /// denominator, and what [`GateThresholds::min_incidents`] is checked
    /// against.
    pub incidents: u64,
    pub verdict: Verdict,
}

impl GateOutcome {
    /// Whether this outcome fails the build: a live detector that is below its
    /// bar, or one that was promoted and has no measurement behind it.
    ///
    /// A `Shadow` detector never blocks — being not-yet-good-enough is what
    /// `Shadow` *means*.
    pub fn blocks_release(&self) -> bool {
        self.status == LifecycleStatus::Active && !self.verdict.clears()
    }

    /// Whether this outcome is a promotion recommendation: shadowed, and
    /// clearing its bar.
    pub fn eligible_for_promotion(&self) -> bool {
        self.status == LifecycleStatus::Shadow && self.verdict.clears()
    }

    /// The one-line summary the CLI prints.
    pub fn headline(&self) -> &'static str {
        match (&self.verdict, self.status) {
            (_, LifecycleStatus::Deprecated) => "SKIP        deprecated",
            (Verdict::Clears, LifecycleStatus::Shadow) => "PROMOTABLE  clears its gate",
            (Verdict::Clears, LifecycleStatus::Active) => "OK          clears its gate",
            (Verdict::Held(_), LifecycleStatus::Shadow) => "HELD        below its gate",
            (Verdict::Held(_), LifecycleStatus::Active) => "GATE FAIL   live and below its gate",
            (Verdict::Unmeasured, LifecycleStatus::Shadow) => "UNMEASURED  no ground truth",
            (Verdict::Unmeasured, LifecycleStatus::Active) => "GATE FAIL   live and unmeasured",
        }
    }
}

/// Evaluate every detector the run knows about against `gate`, in id order.
///
/// The universe is the union of the detectors that appear in `report` and the
/// ones `rollout` explicitly stages — so a staged detector that produced no
/// measurement at all (an ML deployment with no model loaded, say) is still
/// *reported*, as `Unmeasured`, rather than vanishing from the output. A
/// detector that silently disappears from a governance report is the one thing
/// this must not do.
///
/// `Deprecated` detectors are dropped: they are catalogued for replay, not
/// judged.
pub fn evaluate(
    report: &Report,
    gate: &PromotionGate,
    rollout: &RolloutPolicy,
) -> Vec<GateOutcome> {
    let mut ids: BTreeSet<&str> = report.detectors.keys().map(String::as_str).collect();
    for (id, _) in rollout.staged() {
        ids.insert(id.as_str());
    }

    ids.into_iter()
        .filter_map(|id| {
            let status = rollout.status_of_name(id);
            (status != LifecycleStatus::Deprecated)
                .then(|| outcome(id, status, report.detectors.get(id).copied(), gate))
        })
        .collect()
}

fn outcome(
    id: &str,
    status: LifecycleStatus,
    stats: Option<DetectorStats>,
    gate: &PromotionGate,
) -> GateOutcome {
    let thresholds = gate.thresholds(id);
    let stats = stats.unwrap_or_default();
    let incidents = stats.true_positives + stats.false_negatives;
    let (precision, recall) = (stats.precision(), stats.recall());

    // Order matters: too few incidents means the precision/recall that *are*
    // present don't count as evidence yet, so it reports as unmeasured rather
    // than as a shortfall against numbers nobody should be reading.
    let verdict = match (precision, recall) {
        _ if incidents < thresholds.min_incidents => Verdict::Unmeasured,
        (Some(precision), Some(recall)) => {
            let mut short = Vec::new();
            if precision + EPSILON < thresholds.min_precision {
                short.push(Shortfall {
                    requirement: Requirement::Precision,
                    required: thresholds.min_precision,
                    measured: precision,
                });
            }
            if recall + EPSILON < thresholds.min_recall {
                short.push(Shortfall {
                    requirement: Requirement::Recall,
                    required: thresholds.min_recall,
                    measured: recall,
                });
            }
            if short.is_empty() {
                Verdict::Clears
            } else {
                Verdict::Held(short)
            }
        }
        // A detector with ground truth but no raised alert has a recall (0)
        // and no precision — measured, and failing.
        (None, Some(recall)) if recall + EPSILON < thresholds.min_recall => {
            Verdict::Held(vec![Shortfall {
                requirement: Requirement::Recall,
                required: thresholds.min_recall,
                measured: recall,
            }])
        }
        _ => Verdict::Unmeasured,
    };

    GateOutcome {
        detector: id.to_owned(),
        status,
        thresholds,
        precision,
        recall,
        incidents,
        verdict,
    }
}

/// The printable roll-up: every outcome plus the two counts a caller acts on.
#[derive(Debug)]
pub struct GateReport {
    pub outcomes: Vec<GateOutcome>,
    /// The evidence these verdicts were reached over.
    pub corpus: Corpus,
}

impl GateReport {
    pub fn new(report: &Report, gate: &PromotionGate, rollout: &RolloutPolicy) -> Self {
        Self {
            outcomes: evaluate(report, gate, rollout),
            corpus: Corpus::of(report),
        }
    }

    /// Outcomes that fail the build (see [`GateOutcome::blocks_release`]).
    pub fn failures(&self) -> impl Iterator<Item = &GateOutcome> {
        self.outcomes.iter().filter(|o| o.blocks_release())
    }

    /// Shadowed detectors that have earned a promotion.
    pub fn promotable(&self) -> impl Iterator<Item = &GateOutcome> {
        self.outcomes.iter().filter(|o| o.eligible_for_promotion())
    }
}

/// How much evidence the run that produced a [`GateReport`] was built on.
///
/// Printed with the verdicts because a verdict is only as good as its corpus,
/// and this one is small: the shipped fixture set is a handful of hand-built
/// scenarios with one ground-truthed incident per detector. `PROMOTABLE` over
/// that means "not disqualified by the evidence we have", not "proven" — and a
/// report that showed the verdict without the sample size would let the first
/// read at a glance as the second.
///
/// The number to grow is the corpus, not the thresholds: §20.1's flywheel
/// already produces labeled ground truth from `SimulationCompleted` confirming
/// or refuting a `DetectorTriggered`, so replay over a production window is the
/// real gate this mechanism is waiting for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Corpus {
    pub fixtures: usize,
    pub blocks: u64,
    pub incidents: u64,
}

impl Corpus {
    fn of(report: &Report) -> Self {
        Self {
            fixtures: report.fixtures.len(),
            blocks: report.total_blocks,
            incidents: report
                .detectors
                .values()
                .map(|s| s.true_positives + s.false_negatives)
                .sum(),
        }
    }
}

impl std::fmt::Display for Corpus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} fixtures / {} blocks / {} ground-truthed incidents",
            self.fixtures, self.blocks, self.incidents
        )
    }
}

impl std::fmt::Display for GateReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "promotion gate (§18, §20.2) over {corpus}\n  \
             A verdict is only as good as its corpus: at this size PROMOTABLE means \"not \
             disqualified\", not \"proven\". The corpus is the number to grow (§20.1 replay), \
             not the thresholds.",
            corpus = self.corpus,
        )?;
        for o in &self.outcomes {
            writeln!(
                f,
                "  {id:<20} {status:<10} {headline}  (precision {p} ≥ {mp:.2}, recall {r} ≥ {mr:.2}, incidents {n} ≥ {mn})",
                id = o.detector,
                status = o.status.to_string(),
                headline = o.headline(),
                p = fmt_rate(o.precision),
                mp = o.thresholds.min_precision,
                r = fmt_rate(o.recall),
                mr = o.thresholds.min_recall,
                n = o.incidents,
                mn = o.thresholds.min_incidents,
            )?;
            if let Verdict::Held(short) = &o.verdict {
                for s in short {
                    writeln!(f, "  {:<20} {:<10}   ↳ {s}", "", "")?;
                }
            }
        }
        Ok(())
    }
}

fn fmt_rate(rate: Option<f64>) -> String {
    match rate {
        Some(r) => format!("{r:.3}"),
        None => "  n/a".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use detection::DetectorId;

    fn gate() -> PromotionGate {
        PromotionGate {
            default: GateThresholds {
                min_precision: 0.8,
                min_recall: 0.8,
                min_incidents: 1,
            },
            detectors: BTreeMap::new(),
        }
    }

    fn report_of(entries: &[(&str, DetectorStats)]) -> Report {
        Report {
            fixtures: Vec::new(),
            detectors: entries
                .iter()
                .map(|(id, stats)| (id.to_string(), *stats))
                .collect(),
            total_blocks: 10,
        }
    }

    fn perfect() -> DetectorStats {
        DetectorStats {
            true_positives: 2,
            false_positives: 0,
            false_negatives: 0,
            blocks_hit: 2,
        }
    }

    fn only(outcomes: Vec<GateOutcome>, id: &str) -> GateOutcome {
        outcomes
            .into_iter()
            .find(|o| o.detector == id)
            .unwrap_or_else(|| panic!("{id} must appear in the gate report"))
    }

    #[test]
    fn the_report_states_the_corpus_its_verdicts_rest_on() {
        // A verdict printed without its sample size reads as stronger than it
        // is, and this corpus is small enough that the difference matters.
        let report = report_of(&[("anomaly", perfect())]);
        let rendered = GateReport::new(&report, &gate(), &RolloutPolicy::new()).to_string();

        assert!(rendered.contains("10 blocks"), "{rendered}");
        assert!(
            rendered.contains("2 ground-truthed incidents"),
            "{rendered}"
        );
        assert!(rendered.contains("not disqualified"), "{rendered}");
    }

    #[test]
    fn a_shadowed_detector_that_clears_is_promotable_and_does_not_fail_the_build() {
        let rollout = RolloutPolicy::new().shadow(DetectorId::new("anomaly"));
        let report = report_of(&[("anomaly", perfect())]);
        let outcome = only(evaluate(&report, &gate(), &rollout), "anomaly");

        assert_eq!(outcome.verdict, Verdict::Clears);
        assert!(outcome.eligible_for_promotion());
        assert!(
            !outcome.blocks_release(),
            "a shadow detector never blocks a release"
        );
    }

    #[test]
    fn a_shadowed_detector_below_the_bar_is_held_not_a_failure() {
        // The normal state of a detector under development. If this failed the
        // build, nobody could land a detector before it was already finished.
        let rollout = RolloutPolicy::new().shadow(DetectorId::new("anomaly"));
        let report = report_of(&[(
            "anomaly",
            DetectorStats {
                true_positives: 1,
                false_positives: 4,
                false_negatives: 0,
                blocks_hit: 5,
            },
        )]);
        let outcome = only(evaluate(&report, &gate(), &rollout), "anomaly");

        assert!(matches!(&outcome.verdict, Verdict::Held(s)
            if s.len() == 1 && s[0].requirement == Requirement::Precision));
        assert!(!outcome.blocks_release());
        assert!(!outcome.eligible_for_promotion());
    }

    #[test]
    fn a_live_detector_below_the_bar_fails_the_build() {
        // The teeth: promoting a detector and then letting it decay is the
        // governance hole this closes.
        let report = report_of(&[(
            "sandwich",
            DetectorStats {
                true_positives: 1,
                false_positives: 4,
                false_negatives: 0,
                blocks_hit: 5,
            },
        )]);
        let outcome = only(
            evaluate(&report, &gate(), &RolloutPolicy::new()),
            "sandwich",
        );

        assert_eq!(outcome.status, LifecycleStatus::Active);
        assert!(outcome.blocks_release());
    }

    #[test]
    fn a_live_detector_with_no_ground_truth_at_all_fails_the_build() {
        // "Promoted, then stopped measuring" must not read as passing.
        let report = report_of(&[(
            "sandwich",
            DetectorStats {
                true_positives: 0,
                false_positives: 0,
                false_negatives: 0,
                blocks_hit: 0,
            },
        )]);
        let outcome = only(
            evaluate(&report, &gate(), &RolloutPolicy::new()),
            "sandwich",
        );

        assert_eq!(outcome.verdict, Verdict::Unmeasured);
        assert!(outcome.blocks_release());
    }

    #[test]
    fn a_staged_detector_absent_from_the_report_is_still_reported() {
        // The ML detector with no bundle loaded. It must appear as
        // `Unmeasured`, not silently vanish from a governance report.
        let rollout = RolloutPolicy::new().shadow(DetectorId::new("anomaly"));
        let outcomes = evaluate(&report_of(&[]), &gate(), &rollout);

        let outcome = only(outcomes, "anomaly");
        assert_eq!(outcome.verdict, Verdict::Unmeasured);
        assert_eq!(outcome.incidents, 0);
        assert!(!outcome.blocks_release());
    }

    #[test]
    fn too_few_incidents_reads_as_unmeasured_not_as_a_pass() {
        // A precision of 1.0 over one incident is not evidence. Without this,
        // a single lucky fixture would promote a detector.
        let gate = PromotionGate {
            default: GateThresholds {
                min_precision: 0.8,
                min_recall: 0.8,
                min_incidents: 5,
            },
            detectors: BTreeMap::new(),
        };
        let rollout = RolloutPolicy::new().shadow(DetectorId::new("anomaly"));
        let outcome = only(
            evaluate(&report_of(&[("anomaly", perfect())]), &gate, &rollout),
            "anomaly",
        );

        assert_eq!(outcome.verdict, Verdict::Unmeasured);
        assert!(
            !outcome.eligible_for_promotion(),
            "a perfect score over too few samples must not promote anything"
        );
    }

    #[test]
    fn a_deprecated_detector_is_not_judged() {
        let rollout = RolloutPolicy::new().deprecated(DetectorId::new("sandwich"));
        let outcomes = evaluate(&report_of(&[("sandwich", perfect())]), &gate(), &rollout);
        assert!(outcomes.iter().all(|o| o.detector != "sandwich"));
    }

    #[test]
    fn a_per_detector_override_wins_over_the_default() {
        let gate = PromotionGate {
            default: GateThresholds {
                min_precision: 0.9,
                min_recall: 0.9,
                min_incidents: 1,
            },
            detectors: BTreeMap::from([(
                "anomaly".to_string(),
                GateThresholds {
                    min_precision: 0.4,
                    min_recall: 0.4,
                    min_incidents: 1,
                },
            )]),
        };
        assert_eq!(gate.thresholds("anomaly").min_precision, 0.4);
        assert_eq!(gate.thresholds("sandwich").min_precision, 0.9);
    }

    #[test]
    fn a_detector_that_stopped_firing_is_held_on_recall_not_reported_unmeasured() {
        // It has ground truth and caught none of it: precision is `None`
        // (nothing raised) but recall is a measured 0. Reading that as
        // "unmeasured" would let a totally broken detector look untested.
        let rollout = RolloutPolicy::new().shadow(DetectorId::new("rugpull"));
        let report = report_of(&[(
            "rugpull",
            DetectorStats {
                true_positives: 0,
                false_positives: 0,
                false_negatives: 3,
                blocks_hit: 0,
            },
        )]);
        let outcome = only(evaluate(&report, &gate(), &rollout), "rugpull");

        assert!(matches!(&outcome.verdict, Verdict::Held(s)
            if s.len() == 1 && s[0].requirement == Requirement::Recall && s[0].measured == 0.0));
    }

    #[test]
    fn the_committed_gate_parses_and_covers_every_shipped_detector_by_default() {
        let gate = load(&default_path()).expect("the committed promotion gate");
        // The `default` entry is what makes a brand-new detector gated rather
        // than exempt; assert it exists and is a real bar, not a rubber stamp.
        assert!(gate.default.min_precision > 0.0);
        assert!(gate.default.min_recall > 0.0);
        assert!(gate.default.min_incidents >= 1);
    }

    #[test]
    fn a_typo_in_the_committed_gate_is_a_parse_error_not_a_silent_default() {
        let path = std::env::temp_dir().join(format!("backtest-gate-{}.json", std::process::id()));
        std::fs::write(&path, r#"{"default": {"min_precisions": 0.8}}"#).unwrap();
        let result = load(&path);
        std::fs::remove_file(&path).unwrap();
        assert!(
            matches!(result, Err(BaselineError::Parse { .. })),
            "{result:?}"
        );
    }
}
