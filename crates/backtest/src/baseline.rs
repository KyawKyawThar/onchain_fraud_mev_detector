//! Per-detector precision/recall baseline (§18, Sprint 10 t3) — the committed
//! reference [`run_backtest`](crate::run_backtest) results a change must not
//! regress below to merge.
//!
//! The baseline lives at `crates/backtest/baseline.json`, one `DetectorBaseline`
//! per [`DetectorId`](detection::DetectorId) string, keyed the same way
//! [`Report::detectors`](crate::Report) is. It's data, not code, so reviewing a
//! change to it is reviewing a number, not a diff of assertions — the same
//! reason a snapshot-tested golden file beats a pile of `assert_eq!`s.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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
pub struct DetectorBaseline {
    pub precision: f64,
    pub recall: f64,
}

/// Keyed by the same `DetectorId` string [`Report::detectors`](crate::Report)
/// uses. A `BTreeMap` so the committed JSON diffs one detector at a time,
/// never a reshuffle of unrelated entries.
pub type Baseline = BTreeMap<String, DetectorBaseline>;

/// One detector's metric dropping below its committed baseline.
#[derive(Debug, Clone, PartialEq)]
pub struct Regression {
    pub detector: String,
    pub metric: Metric,
    pub baseline: f64,
    pub current: f64,
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
            "{} {} regressed: baseline {:.3}, now {:.3} (§18)",
            self.detector, self.metric, self.baseline, self.current
        )
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
/// `None`-over-zero-samples rule.
pub fn from_report(report: &Report) -> Baseline {
    report
        .detectors
        .iter()
        .filter_map(|(id, stats)| {
            Some((
                id.clone(),
                DetectorBaseline {
                    precision: stats.precision()?,
                    recall: stats.recall()?,
                },
            ))
        })
        .collect()
}

/// Compare a fresh [`Report`] against the committed `baseline`, one entry per
/// regressed metric. In practice a detector that stops firing entirely still
/// gets caught here: its ground-truth incidents fall through to `missed` in
/// [`crate::run_fixture`], which still records a `DetectorStats` entry with a
/// measured (low) recall — so the recall check fires even though the
/// detector raised nothing. Only a detector truly absent from `report` *and*
/// its baseline (no ground truth defined for it at all, an edge case the
/// shipped fixture set doesn't hit) compares as "nothing measured" and is
/// left unflagged, same as a brand-new detector with no baseline entry yet.
pub fn check(report: &Report, baseline: &Baseline) -> Vec<Regression> {
    let mut regressions = Vec::new();
    for (id, base) in baseline {
        let current = report.detectors.get(id).copied().unwrap_or_default();

        if let Some(precision) = current.precision() {
            if precision + EPSILON < base.precision {
                regressions.push(Regression {
                    detector: id.clone(),
                    metric: Metric::Precision,
                    baseline: base.precision,
                    current: precision,
                });
            }
        }

        if let Some(recall) = current.recall() {
            if recall + EPSILON < base.recall {
                regressions.push(Regression {
                    detector: id.clone(),
                    metric: Metric::Recall,
                    baseline: base.recall,
                    current: recall,
                });
            }
        }
    }
    regressions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DetectorStats;

    fn report_of(entries: &[(&str, DetectorStats)]) -> Report {
        Report {
            fixtures: Vec::new(),
            detectors: entries
                .iter()
                .map(|(id, stats)| (id.to_string(), *stats))
                .collect(),
        }
    }

    fn perfect() -> DetectorStats {
        DetectorStats {
            true_positives: 1,
            false_positives: 0,
            false_negatives: 0,
        }
    }

    #[test]
    fn no_regressions_against_itself() {
        let report = report_of(&[("sandwich", perfect())]);
        let baseline = from_report(&report);
        assert!(check(&report, &baseline).is_empty());
    }

    #[test]
    fn precision_drop_is_flagged() {
        let baseline = Baseline::from([(
            "sandwich".to_string(),
            DetectorBaseline {
                precision: 1.0,
                recall: 1.0,
            },
        )]);
        // Same true positive, but now one extra false positive: precision 0.5.
        let report = report_of(&[(
            "sandwich",
            DetectorStats {
                true_positives: 1,
                false_positives: 1,
                false_negatives: 0,
            },
        )]);
        let regressions = check(&report, &baseline);
        assert_eq!(regressions.len(), 1);
        assert_eq!(regressions[0].metric, Metric::Precision);
        assert_eq!(regressions[0].current, 0.5);
    }

    #[test]
    fn a_detector_with_no_entry_at_all_in_the_report_is_not_flagged() {
        // Truly absent — no ground truth for this id in the current fixture
        // set, so there's nothing measured to compare against the baseline.
        let baseline = Baseline::from([(
            "wash-trading".to_string(),
            DetectorBaseline {
                precision: 1.0,
                recall: 1.0,
            },
        )]);
        let report = report_of(&[]);
        let regressions = check(&report, &baseline);
        assert!(
            regressions.is_empty(),
            "no measured recall, nothing to compare: {regressions:?}"
        );
    }

    #[test]
    fn a_detector_that_stopped_firing_still_regresses_via_its_recorded_miss() {
        let baseline = Baseline::from([(
            "wash-trading".to_string(),
            DetectorBaseline {
                precision: 1.0,
                recall: 1.0,
            },
        )]);
        let report = report_of(&[(
            "wash-trading",
            DetectorStats {
                true_positives: 0,
                false_positives: 0,
                false_negatives: 1,
            },
        )]);
        let regressions = check(&report, &baseline);
        assert_eq!(regressions.len(), 1);
        assert_eq!(regressions[0].metric, Metric::Recall);
        assert_eq!(regressions[0].current, 0.0);
    }

    #[test]
    fn an_unbaselined_detector_is_never_flagged() {
        let baseline = Baseline::new();
        let report = report_of(&[(
            "brand-new-detector",
            DetectorStats {
                true_positives: 0,
                false_positives: 5,
                false_negatives: 3,
            },
        )]);
        assert!(check(&report, &baseline).is_empty());
    }

    #[test]
    fn baseline_round_trips_through_json() {
        let report = report_of(&[("sandwich", perfect())]);
        let baseline = from_report(&report);
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
        let report = report_of(&[("sandwich", perfect())]);
        let baseline = from_report(&report);

        save(&baseline, &path).expect("save should succeed");
        let reloaded = load(&path).expect("load should succeed");
        std::fs::remove_file(&path).unwrap();

        assert_eq!(baseline, reloaded);
    }
}
