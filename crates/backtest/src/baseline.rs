//! Per-detector precision/recall baseline (§18, Sprint 10 t3) — the committed
//! reference [`run_backtest`](crate::run_backtest) results a change must not
//! regress below to merge.
//!
//! The baseline lives at `crates/backtest/baseline.json`, one `DetectorBaseline`
//! per [`DetectorId`](detection::DetectorId) string, keyed the same way
//! [`Report::detectors`](crate::Report) is. It's data, not code, so reviewing a
//! change to it is reviewing a number, not a diff of assertions — the same
//! reason a snapshot-tested golden file beats a pile of `assert_eq!`s.
//!
//! # Keyed on the build, not the id
//!
//! Every entry names the `version` and `config_hash` it was measured on (Epic
//! E). Without them a lowered threshold that costs precision reads exactly
//! like a bug that costs precision, and the gate cannot say which happened.
//! [`check`] now separates the two:
//!
//! - **same build, lower number** — a [`Regression`]: the detector did not
//!   change, so something under it did (decoding, enrichment, the corpus).
//!   "It broke."
//! - **different build** — [`Rebuilt`]: the baseline describes a detector
//!   that no longer runs, whatever the numbers did. "We changed it." The fix
//!   is to review the movement it lists and re-baseline, so the committed
//!   file names the new build.
//!
//! Both fail the gate. A stale entry would otherwise sit in the file claiming
//! numbers for a build nobody runs, and the *next* change to that detector
//! would be judged against it.

use std::path::{Path, PathBuf};

use detection::{Build, BuildKeyed, Lookup};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::Report;

/// Everything that can go wrong loading or writing the committed baseline —
/// typed so a caller (or a test) can match on *which* failure mode this is
/// instead of parsing an opaque `anyhow` string. `main.rs` still wraps these
/// in `anyhow::Context` for the human-facing CLI message; the type itself
/// stays precise for anyone calling into this module as a library.
#[derive(Debug, Error)]
pub enum BaselineError {
    #[error("reading baseline at {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing baseline at {path}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("serializing baseline")]
    Serialize(#[source] serde_json::Error),
    #[error("writing baseline to {path}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// A regression is only real once it clears float noise from the TP/FP/FN
/// ratios' own arithmetic — not a threshold anyone should tune.
const EPSILON: f64 = 1e-9;

/// One detector's committed precision/recall reference point.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorBaseline {
    pub precision: f64,
    pub recall: f64,
}

/// The committed baseline: one [`DetectorBaseline`] per detector, each naming
/// the build it was measured on ([`detection::measured`]). Serialized as
/// `{ "<id>": { "version", "config_hash", "metrics": { "precision", "recall" } } }`.
pub type Baseline = BuildKeyed<DetectorBaseline>;

/// What [`check`] found wrong with one detector.
#[derive(Debug, Clone, PartialEq)]
pub enum Finding {
    /// Same build as the baseline, and a metric dropped: it broke.
    Regressed(Regression),
    /// A different build from the baseline's: we changed it.
    Rebuilt(Rebuilt),
}

impl Finding {
    pub fn detector(&self) -> &str {
        match self {
            Finding::Regressed(r) => &r.detector,
            Finding::Rebuilt(r) => &r.current.id,
        }
    }
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Finding::Regressed(r) => write!(f, "REGRESSION  {r}"),
            Finding::Rebuilt(r) => write!(f, "REBUILT     {r}"),
        }
    }
}

/// One detector's metric dropping below its committed baseline, on the same
/// build the baseline was measured on.
#[derive(Debug, Clone, PartialEq)]
pub struct Regression {
    pub detector: String,
    pub metric: Metric,
    pub baseline: f64,
    pub current: f64,
}

/// A detector whose running build is not the one its baseline was measured
/// on, with every metric that moved in between (up or down).
#[derive(Debug, Clone, PartialEq)]
pub struct Rebuilt {
    /// What the baseline was measured on.
    pub baseline: Build,
    /// What this run measured.
    pub current: Build,
    /// Metrics that differ from the baseline. Empty when the change did not
    /// move the numbers — still stale, but a one-line re-baseline.
    pub moves: Vec<Move>,
}

/// One metric's movement across a rebuild. `current` is `None` when the new
/// build has no measurement for it at all (it stopped raising alerts, say).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Move {
    pub metric: Metric,
    pub baseline: f64,
    pub current: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metric {
    Precision,
    Recall,
}

impl std::fmt::Display for Metric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Metric::Precision => "precision",
            Metric::Recall => "recall",
        })
    }
}

impl std::fmt::Display for Regression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} regressed on an unchanged build: baseline {:.3}, now {:.3} (§18)",
            self.detector, self.metric, self.baseline, self.current
        )
    }
}

impl std::fmt::Display for Rebuilt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} changed: baseline measured {}, running {}",
            self.current.id, self.baseline, self.current,
        )?;
        if self.moves.is_empty() {
            f.write_str("; numbers unchanged")?;
        }
        for m in &self.moves {
            match m.current {
                Some(now) => write!(f, "; {} {:.3} -> {:.3}", m.metric, m.baseline, now)?,
                None => write!(f, "; {} {:.3} -> unmeasured", m.metric, m.baseline)?,
            }
        }
        f.write_str(" — review, then re-baseline for the new build")
    }
}

/// `crates/backtest/baseline.json`, resolved at compile time so the gate
/// works from any CWD `cargo run`/`cargo test` happens to be invoked from.
pub fn default_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("baseline.json")
}

/// Load the committed baseline. Errors (missing file, bad JSON) are the
/// caller's to surface — there is no "no baseline" default, since silently
/// skipping the gate is exactly the failure mode it exists to prevent.
pub fn load(path: &Path) -> Result<Baseline, BaselineError> {
    let text = std::fs::read_to_string(path).map_err(|source| BaselineError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&text).map_err(|source| BaselineError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

/// Write `baseline` back to `path` as pretty JSON, one committed source of
/// truth — the deliberate step a change that intentionally moves a
/// detector's measured performance takes before it can merge.
pub fn save(baseline: &Baseline, path: &Path) -> Result<(), BaselineError> {
    let mut json = serde_json::to_string_pretty(baseline).map_err(BaselineError::Serialize)?;
    json.push('\n');
    std::fs::write(path, json).map_err(|source| BaselineError::Write {
        path: path.to_path_buf(),
        source,
    })
}

/// Derive a baseline from a fresh [`Report`] — used by `--update-baseline`.
/// A detector with no measured precision or recall (raised nothing, or has
/// no ground-truthed incident) is left out entirely rather than baselined at
/// a fabricated 0, mirroring [`DetectorStats`](crate::DetectorStats)'s own
/// `None`-over-zero-samples rule. So is one the run did not link: a number
/// that cannot say which build produced it is not a baseline.
pub fn from_report(report: &Report) -> Baseline {
    report
        .linked()
        .filter_map(|(_, build, stats)| {
            Some((
                build.clone(),
                DetectorBaseline {
                    precision: stats.precision()?,
                    recall: stats.recall()?,
                },
            ))
        })
        .collect()
}

/// Compare a fresh [`Report`] against the committed `baseline`.
///
/// For each detector this run linked, [`BuildKeyed::lookup`] decides:
///
/// - `Stale`: one [`Finding::Rebuilt`], whatever the numbers did (see the
///   module docs);
/// - `Current`: a [`Finding::Regressed`] per dropped metric;
/// - `Missing`: nothing — a new detector is gated by the promotion floor, not
///   by a baseline it does not have yet.
///
/// A detector that stops firing entirely still gets caught: its ground-truth
/// incidents fall through to `missed` in [`crate::run_fixture`], so its recall
/// is measured (and low). A baselined detector this build does not link at all
/// (retired, or an ML model with no bundle mounted) is not flagged: nothing is
/// running to compare.
pub fn check(report: &Report, baseline: &Baseline) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (id, build, current) in report.linked() {
        let base = match baseline.lookup(build) {
            Lookup::Missing => continue,
            Lookup::Current(base) => base,
            Lookup::Stale { measured } => {
                let base = baseline
                    .get(id)
                    .expect("a stale lookup has an entry")
                    .metrics;
                let moves = metrics(&base, current)
                    .into_iter()
                    .filter(|(_, was, now)| now.is_none_or(|now| (now - was).abs() > EPSILON))
                    .map(|(metric, baseline, current)| Move {
                        metric,
                        baseline,
                        current,
                    })
                    .collect();
                findings.push(Finding::Rebuilt(Rebuilt {
                    baseline: measured,
                    current: build.clone(),
                    moves,
                }));
                continue;
            }
        };

        for (metric, was, now) in metrics(base, current) {
            if let Some(now) = now {
                if now + EPSILON < was {
                    findings.push(Finding::Regressed(Regression {
                        detector: id.to_owned(),
                        metric,
                        baseline: was,
                        current: now,
                    }));
                }
            }
        }
    }
    findings
}

/// Each gated metric: its baseline value and this run's measurement.
fn metrics(
    base: &DetectorBaseline,
    current: &crate::DetectorStats,
) -> [(Metric, f64, Option<f64>); 2] {
    [
        (Metric::Precision, base.precision, current.precision()),
        (Metric::Recall, base.recall, current.recall()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_build, test_report, DetectorStats};

    fn report_of(entries: &[(&str, DetectorStats)]) -> Report {
        test_report(0, entries)
    }

    fn stats(tp: u64, fp: u64, fn_: u64) -> DetectorStats {
        DetectorStats {
            true_positives: tp,
            false_positives: fp,
            false_negatives: fn_,
            blocks_hit: 0,
            unadjudicated: 0,
        }
    }

    fn perfect() -> DetectorStats {
        stats(1, 0, 0)
    }

    /// A baseline holding `id` at `precision`/1.0, measured on the build
    /// [`test_report`] links it as.
    fn baselined(entries: &[(&str, f64)]) -> Baseline {
        entries
            .iter()
            .map(|(id, precision)| {
                (
                    test_build(id, "1.0.0", "cfg"),
                    DetectorBaseline {
                        precision: *precision,
                        recall: 1.0,
                    },
                )
            })
            .collect()
    }

    /// `report`, but with `id` running under a different config.
    fn rebuilt(mut report: Report, id: &str) -> Report {
        report.detectors.get_mut(id).unwrap().build = Some(test_build(id, "1.0.0", "lowered"));
        report
    }

    #[test]
    fn no_regressions_against_itself() {
        let report = report_of(&[("sandwich", perfect())]);
        assert!(check(&report, &from_report(&report)).is_empty());
    }

    #[test]
    fn from_report_records_the_build_it_measured() {
        let report = report_of(&[("sandwich", perfect())]);
        let baseline = from_report(&report);
        assert!(matches!(
            baseline.lookup(&test_build("sandwich", "1.0.0", "cfg")),
            Lookup::Current(_)
        ));
        assert!(matches!(
            baseline.lookup(&test_build("sandwich", "1.0.0", "other")),
            Lookup::Stale { .. }
        ));
    }

    #[test]
    fn from_report_skips_a_detector_with_no_build() {
        let mut report = report_of(&[("sandwich", perfect())]);
        report.detectors.get_mut("sandwich").unwrap().build = None;
        assert!(from_report(&report).is_empty());
    }

    #[test]
    fn precision_drop_on_the_same_build_is_a_regression() {
        let baseline = baselined(&[("sandwich", 1.0)]);
        // Same true positive, but now one extra false positive: precision 0.5.
        let report = report_of(&[("sandwich", stats(1, 1, 0))]);
        let findings = check(&report, &baseline);
        let [Finding::Regressed(r)] = findings.as_slice() else {
            panic!("an unchanged build dropping is a regression: {findings:?}");
        };
        assert_eq!(r.metric, Metric::Precision);
        assert_eq!(r.current, 0.5);
    }

    #[test]
    fn the_same_drop_on_a_changed_build_is_a_rebuild_not_a_regression() {
        // The whole point of keying on the triple: identical numbers, but the
        // config moved, so the gate reports what was changed rather than
        // what broke.
        let baseline = baselined(&[("sandwich", 1.0)]);
        let report = rebuilt(report_of(&[("sandwich", stats(1, 1, 0))]), "sandwich");
        let findings = check(&report, &baseline);
        let [Finding::Rebuilt(r)] = findings.as_slice() else {
            panic!("a changed build is a rebuild: {findings:?}");
        };
        assert_eq!(r.baseline, test_build("sandwich", "1.0.0", "cfg"));
        assert_eq!(r.current, test_build("sandwich", "1.0.0", "lowered"));
        assert_eq!(
            r.moves,
            vec![Move {
                metric: Metric::Precision,
                baseline: 1.0,
                current: Some(0.5),
            }]
        );
        let line = findings[0].to_string();
        assert!(line.starts_with("REBUILT"), "{line}");
        assert!(line.contains("precision 1.000 -> 0.500"), "{line}");
    }

    #[test]
    fn a_rebuild_that_moved_nothing_is_still_stale() {
        let baseline = baselined(&[("sandwich", 1.0)]);
        let report = rebuilt(report_of(&[("sandwich", perfect())]), "sandwich");
        let findings = check(&report, &baseline);
        let [Finding::Rebuilt(r)] = findings.as_slice() else {
            panic!("expected one rebuild: {findings:?}");
        };
        assert!(r.moves.is_empty());
        assert!(findings[0].to_string().contains("numbers unchanged"));
    }

    #[test]
    fn a_rebuild_that_improved_lists_the_improvement() {
        let baseline = baselined(&[("sandwich", 0.5)]);
        let report = rebuilt(report_of(&[("sandwich", perfect())]), "sandwich");
        let findings = check(&report, &baseline);
        let [Finding::Rebuilt(r)] = findings.as_slice() else {
            panic!("expected one rebuild: {findings:?}");
        };
        assert_eq!(r.moves[0].current, Some(1.0));
    }

    #[test]
    fn a_rebuild_that_stopped_measuring_reports_unmeasured() {
        let baseline = baselined(&[("sandwich", 1.0)]);
        // Nothing raised and nothing ground-truthed: both rates are `None`.
        let report = rebuilt(report_of(&[("sandwich", stats(0, 0, 0))]), "sandwich");
        let findings = check(&report, &baseline);
        let [Finding::Rebuilt(r)] = findings.as_slice() else {
            panic!("expected one rebuild: {findings:?}");
        };
        assert_eq!(r.moves.len(), 2);
        assert!(r.moves.iter().all(|m| m.current.is_none()));
        assert!(findings[0].to_string().contains("-> unmeasured"));
    }

    #[test]
    fn a_baselined_detector_this_build_does_not_link_is_not_flagged() {
        // Retired, or an ML model with no bundle: nothing is running to
        // compare against the entry.
        let baseline = baselined(&[("wash-trading", 1.0)]);
        let findings = check(&report_of(&[]), &baseline);
        assert!(findings.is_empty(), "nothing linked: {findings:?}");
    }

    #[test]
    fn a_detector_that_stopped_firing_still_regresses_via_its_recorded_miss() {
        let baseline = baselined(&[("wash-trading", 1.0)]);
        let report = report_of(&[("wash-trading", stats(0, 0, 1))]);
        let findings = check(&report, &baseline);
        let [Finding::Regressed(r)] = findings.as_slice() else {
            panic!("expected one regression: {findings:?}");
        };
        assert_eq!(r.metric, Metric::Recall);
        assert_eq!(r.current, 0.0);
    }

    #[test]
    fn an_unbaselined_detector_is_never_flagged() {
        let report = report_of(&[("brand-new-detector", stats(0, 5, 3))]);
        assert!(check(&report, &Baseline::new()).is_empty());
    }

    #[test]
    fn a_legacy_id_only_entry_is_refused() {
        // A baseline that does not say which build it measured is exactly the
        // ambiguity this file exists to remove, so it does not parse.
        let legacy = r#"{"sandwich":{"precision":1.0,"recall":1.0}}"#;
        assert!(serde_json::from_str::<Baseline>(legacy).is_err());
    }

    #[test]
    fn baseline_round_trips_through_json() {
        let baseline = from_report(&report_of(&[("sandwich", perfect())]));
        let json = serde_json::to_string_pretty(&baseline).unwrap();
        let reloaded: Baseline = serde_json::from_str(&json).unwrap();
        assert_eq!(baseline, reloaded);
    }

    #[test]
    fn load_of_a_missing_file_is_a_typed_read_error() {
        let path = Path::new("/nonexistent/does-not-exist/baseline.json");
        match load(path) {
            Err(BaselineError::Read { path: p, .. }) => assert_eq!(p, path),
            other => panic!("expected BaselineError::Read, got {other:?}"),
        }
    }

    #[test]
    fn load_of_malformed_json_is_a_typed_parse_error() {
        let dir =
            std::env::temp_dir().join(format!("backtest-baseline-test-{}", std::process::id()));
        std::fs::write(&dir, b"not json").unwrap();
        let result = load(&dir);
        std::fs::remove_file(&dir).unwrap();
        match result {
            Err(BaselineError::Parse { path: p, .. }) => assert_eq!(p, dir),
            other => panic!("expected BaselineError::Parse, got {other:?}"),
        }
    }

    #[test]
    fn save_then_load_round_trips_through_the_filesystem() {
        let path =
            std::env::temp_dir().join(format!("backtest-baseline-test-{}-ok", std::process::id()));
        let baseline = from_report(&report_of(&[("sandwich", perfect())]));

        save(&baseline, &path).expect("save should succeed");
        let reloaded = load(&path).expect("load should succeed");
        std::fs::remove_file(&path).unwrap();

        assert_eq!(baseline, reloaded);
    }
}
