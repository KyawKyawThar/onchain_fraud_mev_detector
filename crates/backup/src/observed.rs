//! §19 metrics for backups, drills and the recovery objectives.
//!
//! ## Why these are gauges of *age*, not counters of runs
//!
//! "Backups ran 24 times today" is a number that stays healthy while every one
//! of those runs writes an empty file. The signal an operator actually needs
//! is the one that degrades on its own when nothing happens:
//! `backup_artifact_age_seconds` climbs the moment snapshots stop, whether
//! they stopped by crashing, by being scaled to zero, or by never having been
//! deployed. Alerting on an age against the RPO budget is therefore alerting
//! on the objective itself rather than on a proxy for it.
//!
//! The same argument decides where these are produced. A `CronJob` cannot
//! export "I did not run" — an absent job exports nothing at all, which looks
//! exactly like a healthy one to a dashboard. So the scheduled snapshots and
//! drills live in a long-running process (`backup serve`) that holds the
//! gauges, and `up{job="backup"}` plus `absent()` cover the case where *it* is
//! the thing that died.
//!
//! | metric | type | labels | what it says |
//! |---|---|---|---|
//! | `backup_artifact_age_seconds` | gauge | `target` | seconds since the newest artifact's **cut** — the measured RPO |
//! | `backup_last_success_timestamp_seconds` | gauge | `target` | when the last snapshot completed |
//! | `backup_snapshot_duration_seconds` | histogram | `target` | how long taking one costs |
//! | `backup_artifact_bytes` | gauge | `target` | size of the newest artifact; a cliff here is a truncated backup |
//! | `backup_artifact_rows` | gauge | `target` | rows in the newest artifact |
//! | `backup_runs_total` | counter | `target`, `outcome` | `success` / `failure` |
//! | `backup_drill_runs_total` | counter | `target`, `outcome` | `passed` / `failed` |
//! | `backup_drill_duration_seconds` | histogram | `target` | measured restore + verify — the RTO input |
//! | `backup_drill_age_seconds` | gauge | `target` | seconds since the last **passing** drill |
//! | `backup_drill_divergence_tables` | gauge | `target`, `class` | `missing` / `unexpected` / `changed` |
//! | `backup_objective_seconds` | gauge | `target`, `objective`, `kind` | `budget` vs `measured`, so an alert rule needs no hard-coded threshold |
//!
//! Every gauge is written on every cycle, including to zero. A gauge only
//! written when non-zero holds its last value forever, so a target that
//! started passing would keep alerting — the same "monitoring the monitor"
//! trap the conventions name.

use std::time::Duration;

use crate::drill::DrillReport;
use crate::error::BackupError;
use crate::manifest::BackupManifest;
use crate::objective::{Objective, Report};

/// Metric names as constants, so a dashboard or alert rule greps back to the
/// code that produces it.
pub mod names {
    pub const ARTIFACT_AGE: &str = "backup_artifact_age_seconds";
    pub const LAST_SUCCESS: &str = "backup_last_success_timestamp_seconds";
    pub const SNAPSHOT_DURATION: &str = "backup_snapshot_duration_seconds";
    pub const ARTIFACT_BYTES: &str = "backup_artifact_bytes";
    pub const ARTIFACT_ROWS: &str = "backup_artifact_rows";
    pub const RUNS: &str = "backup_runs_total";
    pub const DRILL_RUNS: &str = "backup_drill_runs_total";
    pub const DRILL_DURATION: &str = "backup_drill_duration_seconds";
    pub const DRILL_AGE: &str = "backup_drill_age_seconds";
    pub const DRILL_DIVERGENCE: &str = "backup_drill_divergence_tables";
    pub const OBJECTIVE: &str = "backup_objective_seconds";
    pub const ARTIFACT_INCOMPLETE: &str = "backup_artifact_incomplete_objects";
    pub const SCRATCH_SWEPT: &str = "backup_scratch_swept_total";
    pub const CYCLES_SKIPPED: &str = "backup_cycles_skipped_total";
}

/// Record a completed snapshot.
pub fn record_snapshot(target: &str, manifest: &BackupManifest, elapsed: Duration) {
    let target = target.to_owned();
    metrics::counter!(names::RUNS, "target" => target.clone(), "outcome" => "success").increment(1);
    metrics::histogram!(names::SNAPSHOT_DURATION, "target" => target.clone())
        .record(elapsed.as_secs_f64());
    metrics::gauge!(names::LAST_SUCCESS, "target" => target.clone())
        .set(manifest.finished_at.timestamp() as f64);
    metrics::gauge!(names::ARTIFACT_BYTES, "target" => target.clone()).set(manifest.bytes() as f64);
    metrics::gauge!(names::ARTIFACT_ROWS, "target" => target.clone()).set(manifest.rows() as f64);
    // Always written, including zero: an artifact that stops being incomplete
    // must stop alerting, and a gauge only written when non-zero never comes
    // back down.
    metrics::gauge!(names::ARTIFACT_INCOMPLETE, "target" => target)
        .set(manifest.incompleteness().len() as f64);
}

/// Record a snapshot that never produced an artifact.
///
/// The `outcome` label carries the **classification**, not just "failure".
/// That is the difference between "ClickHouse blipped, it will retry" and "no
/// backup has been possible since the Postgres upgrade" — two states that used
/// to render identically here, and only one of which should wake anybody.
pub fn record_snapshot_failure(target: &str, err: &BackupError) {
    metrics::counter!(names::RUNS, "target" => target.to_owned(), "outcome" => err.outcome())
        .increment(1);
}

/// Record stale scratch databases removed by a sweep. Non-zero means an
/// earlier run leaked one — worth trending, never worth paging.
pub fn record_sweep(target: &str, swept: usize) {
    if swept > 0 {
        metrics::counter!(names::SCRATCH_SWEPT, "target" => target.to_owned())
            .increment(swept as u64);
    }
}

/// Record a scheduled cycle skipped because the previous one is still running.
///
/// A steady stream of these means the job no longer fits its interval — the
/// early warning that a snapshot has grown past its cadence, which would
/// otherwise surface only as an RPO breach.
pub fn record_skipped_cycle(target: &str, job: &'static str) {
    metrics::counter!(names::CYCLES_SKIPPED, "target" => target.to_owned(), "job" => job)
        .increment(1);
}

/// Record a completed drill, including a failing one.
pub fn record_drill(report: &DrillReport) {
    let target = report.target.clone();
    let outcome = if report.passed() { "passed" } else { "failed" };
    metrics::counter!(names::DRILL_RUNS, "target" => target.clone(), "outcome" => outcome)
        .increment(1);
    metrics::histogram!(names::DRILL_DURATION, "target" => target.clone())
        .record(report.elapsed.as_secs_f64());
    // Always all three, always including zero — see the module docs.
    for (class, count) in [
        ("missing", report.diff.missing.len()),
        ("unexpected", report.diff.unexpected.len()),
        ("changed", report.diff.changed.len()),
    ] {
        metrics::gauge!(names::DRILL_DIVERGENCE, "target" => target.clone(), "class" => class)
            .set(count as f64);
    }
}

/// Record a drill that could not be attempted (no artifact, unreachable
/// server), classified the same way a snapshot failure is. The *age* gauge is
/// what alerts either way, so a run that never happened cannot hide.
pub fn record_drill_failure(target: &str, err: &BackupError) {
    metrics::counter!(names::DRILL_RUNS, "target" => target.to_owned(), "outcome" => err.outcome())
        .increment(1);
}

/// Publish the objective report: for every target, the budget and the
/// measurement side by side.
///
/// Exporting the *budget* as a series is what keeps the alert rule free of a
/// hard-coded threshold — the rule compares two series, so changing the
/// commitment in config changes the alert, and the two can never drift.
pub fn record_report(report: &Report) {
    for measurement in &report.measurements {
        let target = measurement.target.clone();

        metrics::gauge!(names::ARTIFACT_AGE, "target" => target.clone())
            .set(measurement.rpo.map(seconds).unwrap_or(f64::INFINITY));
        metrics::gauge!(names::DRILL_AGE, "target" => target.clone()).set(
            measurement
                .verification_age
                .map(seconds)
                .unwrap_or(f64::INFINITY),
        );

        for (objective, budget, measured) in [
            (Objective::Rpo, report.objective.rpo, measurement.rpo),
            (
                Objective::Rto,
                report.objective.rto,
                measurement.rto(&report.objective),
            ),
            (
                Objective::Verification,
                report.objective.drill_max_age,
                measurement.verification_age,
            ),
        ] {
            metrics::gauge!(
                names::OBJECTIVE,
                "target" => target.clone(),
                "objective" => objective.as_str(),
                "kind" => "budget"
            )
            .set(seconds(budget));
            metrics::gauge!(
                names::OBJECTIVE,
                "target" => target.clone(),
                "objective" => objective.as_str(),
                "kind" => "measured"
            )
            .set(measured.map(seconds).unwrap_or(f64::INFINITY));
        }
    }
}

fn seconds(d: Duration) -> f64 {
    d.as_secs_f64()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use metrics_util::debugging::{DebuggingRecorder, Snapshotter};

    use super::*;
    use crate::manifest::FingerprintDiff;
    use crate::objective::{Measurement, RecoveryObjective};

    fn drain(snapshotter: &Snapshotter) -> Vec<String> {
        snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .map(|(key, _, _, value)| format!("{}|{:?}", key.key().name(), value))
            .collect()
    }

    fn measurement(rpo: Option<u64>, verified: Option<u64>) -> Measurement {
        Measurement {
            target: "postgres".to_owned(),
            rpo: rpo.map(Duration::from_secs),
            verification_age: verified.map(Duration::from_secs),
            measured_restore: Some(Duration::from_secs(30)),
            artifact_bytes: 1,
            artifact_rows: 1,
            holds_system_of_record: true,
        }
    }

    #[test]
    fn the_report_exports_both_the_budget_and_the_measurement() {
        // The alert rule compares two series instead of hard-coding a
        // threshold, so it cannot drift from the configured commitment.
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            record_report(&Report {
                objective: RecoveryObjective::default(),
                measurements: vec![measurement(Some(600), Some(3_600))],
            });
        });
        let recorded = drain(&snapshotter);
        let objectives: Vec<_> = recorded
            .iter()
            .filter(|line| line.starts_with(names::OBJECTIVE))
            .collect();
        // three objectives x {budget, measured}
        assert_eq!(objectives.len(), 6, "{recorded:?}");
        assert!(recorded.iter().any(|l| l.starts_with(names::ARTIFACT_AGE)));
        assert!(recorded.iter().any(|l| l.starts_with(names::DRILL_AGE)));
    }

    #[test]
    fn a_target_that_has_never_been_backed_up_reports_an_infinite_age() {
        // Not a missing series: a missing series looks identical to a healthy
        // one on a dashboard.
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            record_report(&Report {
                objective: RecoveryObjective::default(),
                measurements: vec![measurement(None, None)],
            });
        });
        let age = drain(&snapshotter)
            .into_iter()
            .find(|line| line.starts_with(names::ARTIFACT_AGE))
            .expect("age gauge");
        assert!(age.contains("inf"), "{age}");
    }

    #[test]
    fn a_clean_drill_still_writes_every_divergence_class() {
        // A gauge only written when non-zero never comes back down.
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let report = DrillReport {
            target: "postgres".to_owned(),
            artifact_id: "postgres-1".to_owned(),
            artifact_cut_at: chrono::Utc::now(),
            artifact_bytes: 1,
            artifact_rows: 1,
            elapsed: Duration::from_secs(3),
            restore_elapsed: Duration::from_secs(2),
            verify_elapsed: Duration::from_secs(1),
            integrity_problems: Vec::new(),
            incompleteness: Vec::new(),
            diff: FingerprintDiff::default(),
            swept: Vec::new(),
            scratch_kept: None,
        };
        metrics::with_local_recorder(&recorder, || record_drill(&report));
        let divergence: Vec<_> = drain(&snapshotter)
            .into_iter()
            .filter(|line| line.starts_with(names::DRILL_DIVERGENCE))
            .collect();
        assert_eq!(divergence.len(), 3, "{divergence:?}");
    }

    #[test]
    fn a_snapshot_records_size_and_row_count_so_a_truncated_backup_is_visible() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let manifest = crate::manifest::BackupManifest {
            format: crate::manifest::MANIFEST_FORMAT,
            artifact_id: "postgres-1".to_owned(),
            target: "postgres".to_owned(),
            kind: crate::manifest::TargetKind::Postgres,
            source_database: "detector".to_owned(),
            cut_at: chrono::Utc::now(),
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
            tables: BTreeMap::new(),
            files: Vec::new(),
            schema: Vec::new(),
            tool: "t".to_owned(),
            writer_version: "t".to_owned(),
            notes: Vec::new(),
        };
        metrics::with_local_recorder(&recorder, || {
            record_snapshot("postgres", &manifest, Duration::from_secs(1));
        });
        let recorded = drain(&snapshotter);
        assert!(recorded
            .iter()
            .any(|l| l.starts_with(names::ARTIFACT_BYTES)));
        assert!(recorded.iter().any(|l| l.starts_with(names::ARTIFACT_ROWS)));
    }
}
