//! **RPO and RTO** — defined here, measured by [`crate::drill`], and enforced
//! by `backup report`'s exit code.
//!
//! Readiness Epic B asks to *define and measure* both. The definitions matter
//! because both terms are routinely used to mean the thing that is easy to
//! say rather than the thing that is true:
//!
//! **RPO — Recovery Point Objective.** How much recent data an incident is
//! allowed to destroy. Measured here as **`now − cut_at` of the newest
//! artifact that a drill has shown to be restorable**, per target. Three
//! things about that definition are deliberate:
//!
//! * It is measured from the artifact's **cut**, not from when the dump
//!   finished. A dump that starts at 01:00 and lands at 03:00 protects you to
//!   01:00. Reporting 03:00 would understate the loss by the dump's duration —
//!   exactly the amount that grows as the data grows.
//! * An **unverified** artifact does not count. A backup nobody has restored
//!   is a belief, so [`Measurement::verdict`] breaches when the drill itself
//!   has gone stale, even if snapshots are landing on schedule. This is the
//!   whole point of the epic: the control is the restore, not the dump.
//! * It is **per target**. The pipeline's real exposure is the *worst* of
//!   them, and [`Report::worst_rpo`] is what a dashboard should show.
//!
//! One nuance worth holding: for the event store, events already accepted by
//! Kafka but not yet appended are *not* inside this window — they are
//! replayable from the broker for as long as `KAFKA_RETENTION_MS` (7 days by
//! default) and the brokers survive. So the measured RPO is the bound on
//! *unrecoverable* loss given a total ClickHouse loss, which is the number
//! that belongs in a customer commitment.
//!
//! **RTO — Recovery Time Objective.** How long a recovery is allowed to take.
//! Measured as the drill's own wall clock — integrity check, provision,
//! restore, verify — against the *real, current-sized* artifact, plus a
//! **declared** orchestration overhead for the parts a drill cannot execute:
//! deciding to fail over, getting hands on a terminal, repointing services,
//! draining caches. The overhead is a number a human wrote down; it is
//! reported separately and labelled as such, because a measured number and an
//! estimate added together and presented as one measurement is how RTOs come
//! to be wrong by an order of magnitude.
//!
//! A derived store has a second, usually slower recovery path — rebuild it
//! from the log (`docs/runbooks/projection-rebuild.md`). The RTO here is the
//! restore path only; the runbook says when to prefer which.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Default data-loss budget: one hour.
pub const DEFAULT_RPO: Duration = Duration::from_secs(60 * 60);
/// Default recovery-time budget: four hours.
pub const DEFAULT_RTO: Duration = Duration::from_secs(4 * 60 * 60);
/// Default declared, un-measured orchestration overhead added to every
/// measured restore: thirty minutes.
pub const DEFAULT_ORCHESTRATION_OVERHEAD: Duration = Duration::from_secs(30 * 60);
/// Default staleness budget for the proof itself: a drill older than this
/// makes every artifact it was supposed to vouch for unverified.
pub const DEFAULT_DRILL_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// The commitment, as configured. Not a measurement — the thing measurements
/// are held against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryObjective {
    pub rpo: Duration,
    pub rto: Duration,
    /// Added to every measured restore before comparing against `rto`.
    /// Declared by a human, never measured. See the module docs.
    pub orchestration_overhead: Duration,
    /// How old the newest passing drill may be before the backups it vouches
    /// for stop counting as verified.
    pub drill_max_age: Duration,
}

impl Default for RecoveryObjective {
    fn default() -> Self {
        Self {
            rpo: DEFAULT_RPO,
            rto: DEFAULT_RTO,
            orchestration_overhead: DEFAULT_ORCHESTRATION_OVERHEAD,
            drill_max_age: DEFAULT_DRILL_MAX_AGE,
        }
    }
}

/// Which commitment a breach is against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Objective {
    Rpo,
    Rto,
    /// Not an RPO/RTO number itself — the age of the *evidence* for them.
    Verification,
}

impl Objective {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rpo => "rpo",
            Self::Rto => "rto",
            Self::Verification => "verification",
        }
    }
}

/// One commitment, missed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Breach {
    pub target: String,
    pub objective: Objective,
    pub budget: Duration,
    /// `None` means "there is no measurement at all" — no artifact has ever
    /// been taken, or no drill has ever passed. That is a breach of unbounded
    /// size, and is reported as one rather than as a missing row somebody has
    /// to notice is missing.
    pub measured: Option<Duration>,
}

impl std::fmt::Display for Breach {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.measured {
            Some(measured) => write!(
                f,
                "{}: {} is {} against a budget of {}",
                self.target,
                self.objective.as_str(),
                humanize(measured),
                humanize(self.budget)
            ),
            None => write!(
                f,
                "{}: {} has never been measured (budget {}) — there is no evidence, \
                 which is a breach, not a gap in the report",
                self.target,
                self.objective.as_str(),
                humanize(self.budget)
            ),
        }
    }
}

/// What is actually true about one target right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measurement {
    pub target: String,
    /// `now − cut_at` of the newest artifact. `None` when there is none.
    pub rpo: Option<Duration>,
    /// Age of the newest *passing* drill.
    pub verification_age: Option<Duration>,
    /// Wall clock of that drill's restore-and-verify.
    pub measured_restore: Option<Duration>,
    /// Bytes and rows of the artifact the RPO figure came from, so a reader
    /// can tell a fast restore from a restore of nothing.
    pub artifact_bytes: u64,
    pub artifact_rows: u64,
    /// Whether this target holds anything the event store cannot re-derive.
    pub holds_system_of_record: bool,
}

impl Measurement {
    /// Measured restore plus the declared overhead — the number to compare
    /// against the RTO budget.
    pub fn rto(&self, objective: &RecoveryObjective) -> Option<Duration> {
        self.measured_restore
            .map(|measured| measured + objective.orchestration_overhead)
    }

    /// Every commitment this target currently misses.
    ///
    /// A stale drill breaches `Verification` *and* leaves the RPO figure
    /// unsupported — the RPO is still reported (an operator needs the number),
    /// but the verdict is not clean, which is what stops "backups are running"
    /// from being mistaken for "restores work".
    pub fn breaches(&self, objective: &RecoveryObjective) -> Vec<Breach> {
        let mut out = Vec::new();
        let mut check = |kind: Objective, budget: Duration, measured: Option<Duration>| {
            let missed = measured.is_none_or(|m| m > budget);
            if missed {
                out.push(Breach {
                    target: self.target.clone(),
                    objective: kind,
                    budget,
                    measured,
                });
            }
        };
        check(Objective::Rpo, objective.rpo, self.rpo);
        check(
            Objective::Verification,
            objective.drill_max_age,
            self.verification_age,
        );
        check(Objective::Rto, objective.rto, self.rto(objective));
        out
    }

    /// A single line for a terminal or a ticket.
    pub fn summarize(&self, objective: &RecoveryObjective) -> String {
        let rpo = self.rpo.map(humanize).unwrap_or_else(|| "never".to_owned());
        let rto = self
            .rto(objective)
            .map(humanize)
            .unwrap_or_else(|| "never".to_owned());
        let verified = self
            .verification_age
            .map(|age| format!("{} ago", humanize(age)))
            .unwrap_or_else(|| "never".to_owned());
        let role = if self.holds_system_of_record {
            "system of record"
        } else {
            "derived (also rebuildable)"
        };
        format!(
            "{:<12} rpo {:>10} (budget {})  rto {:>10} (budget {})  last verified {}  [{}]",
            self.target,
            rpo,
            humanize(objective.rpo),
            rto,
            humanize(objective.rto),
            verified,
            role,
        )
    }
}

/// Every target's measurement, and the verdict over all of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub objective: RecoveryObjective,
    pub measurements: Vec<Measurement>,
}

impl Report {
    /// The pipeline's exposure is its worst target, not its average.
    pub fn worst_rpo(&self) -> Option<Duration> {
        self.measurements.iter().filter_map(|m| m.rpo).max()
    }

    pub fn worst_rto(&self) -> Option<Duration> {
        self.measurements
            .iter()
            .filter_map(|m| m.rto(&self.objective))
            .max()
    }

    pub fn breaches(&self) -> Vec<Breach> {
        self.measurements
            .iter()
            .flat_map(|m| m.breaches(&self.objective))
            .collect()
    }

    pub fn is_met(&self) -> bool {
        self.breaches().is_empty()
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        for measurement in &self.measurements {
            out.push_str(&measurement.summarize(&self.objective));
            out.push('\n');
        }
        out.push_str(&format!(
            "\ndeclared orchestration overhead (not measured): {}\n",
            humanize(self.objective.orchestration_overhead)
        ));
        let breaches = self.breaches();
        if breaches.is_empty() {
            out.push_str("VERDICT: recovery objectives met\n");
        } else {
            out.push_str(&format!("VERDICT: {} breach(es)\n", breaches.len()));
            for breach in breaches {
                out.push_str(&format!("  ! {breach}\n"));
            }
        }
        out
    }
}

/// Coarse, human-readable duration — the units an operator thinks in.
pub fn humanize(d: Duration) -> String {
    let secs = d.as_secs();
    match secs {
        0..=99 => format!("{secs}s"),
        100..=3_599 => format!("{}m{}s", secs / 60, secs % 60),
        3_600..=172_799 => format!("{}h{}m", secs / 3_600, (secs % 3_600) / 60),
        _ => format!("{}d{}h", secs / 86_400, (secs % 86_400) / 3_600),
    }
}

/// Parse `30s` / `15m` / `4h` / `7d` (and a bare number as seconds).
///
/// Objectives are configured by humans in a manifest or a `.env`; "4h" is
/// legible where `14400` is a number nobody re-derives when reviewing it.
pub fn parse_duration(raw: &str) -> Result<Duration, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("empty duration".to_owned());
    }
    let (value, multiplier) = match raw.chars().last() {
        Some('s') => (&raw[..raw.len() - 1], 1_u64),
        Some('m') => (&raw[..raw.len() - 1], 60),
        Some('h') => (&raw[..raw.len() - 1], 3_600),
        Some('d') => (&raw[..raw.len() - 1], 86_400),
        _ => (raw, 1),
    };
    let value: u64 = value
        .trim()
        .parse()
        .map_err(|_| format!("{raw:?} is not a duration like 30s / 15m / 4h / 7d"))?;
    value
        .checked_mul(multiplier)
        .map(Duration::from_secs)
        .ok_or_else(|| format!("{raw:?} overflows"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn measurement(rpo: Option<u64>, verified: Option<u64>, restore: Option<u64>) -> Measurement {
        Measurement {
            target: "postgres".to_owned(),
            rpo: rpo.map(Duration::from_secs),
            verification_age: verified.map(Duration::from_secs),
            measured_restore: restore.map(Duration::from_secs),
            artifact_bytes: 1_024,
            artifact_rows: 10,
            holds_system_of_record: true,
        }
    }

    #[test]
    fn fresh_backups_with_a_recent_passing_drill_meet_the_objectives() {
        let objective = RecoveryObjective::default();
        let m = measurement(Some(600), Some(3_600), Some(120));
        assert_eq!(m.breaches(&objective), Vec::new());
    }

    #[test]
    fn a_stale_drill_breaches_even_when_backups_are_current() {
        // The epic's whole thesis, as an assertion: snapshots landing every
        // ten minutes prove nothing if the last successful restore was a
        // month ago.
        let objective = RecoveryObjective::default();
        let m = measurement(Some(600), Some(30 * 86_400), Some(120));
        let breaches = m.breaches(&objective);
        assert_eq!(breaches.len(), 1);
        assert_eq!(breaches[0].objective, Objective::Verification);
    }

    #[test]
    fn never_measured_is_a_breach_not_a_blank() {
        let objective = RecoveryObjective::default();
        let breaches = measurement(None, None, None).breaches(&objective);
        assert_eq!(breaches.len(), 3);
        assert!(breaches.iter().all(|b| b.measured.is_none()));
        assert!(breaches[0].to_string().contains("never been measured"));
    }

    #[test]
    fn the_declared_overhead_is_added_to_the_measured_restore() {
        let objective = RecoveryObjective {
            rto: Duration::from_secs(1_000),
            orchestration_overhead: Duration::from_secs(900),
            ..RecoveryObjective::default()
        };
        // 200s of measured restore is comfortably inside a 1000s budget — until
        // the declared 900s of human orchestration is counted, which is the
        // number that actually reaches a customer.
        let m = measurement(Some(60), Some(60), Some(200));
        assert_eq!(m.rto(&objective), Some(Duration::from_secs(1_100)));
        let breaches = m.breaches(&objective);
        assert_eq!(breaches.len(), 1);
        assert_eq!(breaches[0].objective, Objective::Rto);
    }

    #[test]
    fn the_report_takes_the_worst_target_not_the_average() {
        let objective = RecoveryObjective::default();
        let report = Report {
            objective,
            measurements: vec![
                measurement(Some(60), Some(60), Some(10)),
                Measurement {
                    target: "clickhouse".to_owned(),
                    ..measurement(Some(9_000), Some(60), Some(4_000))
                },
            ],
        };
        assert_eq!(report.worst_rpo(), Some(Duration::from_secs(9_000)));
        assert!(!report.is_met());
        assert!(report.render().contains("clickhouse"));
    }

    #[test]
    fn durations_parse_in_the_units_operators_write() {
        assert_eq!(parse_duration("45s"), Ok(Duration::from_secs(45)));
        assert_eq!(parse_duration("15m"), Ok(Duration::from_secs(900)));
        assert_eq!(parse_duration("4h"), Ok(Duration::from_secs(14_400)));
        assert_eq!(parse_duration("7d"), Ok(Duration::from_secs(604_800)));
        assert_eq!(parse_duration("90"), Ok(Duration::from_secs(90)));
        assert!(parse_duration("soon").is_err());
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn humanize_reaches_for_the_unit_a_human_would() {
        assert_eq!(humanize(Duration::from_secs(45)), "45s");
        assert_eq!(humanize(Duration::from_secs(900)), "15m0s");
        // The unit has to turn over at the hour, not somewhere past it: an RPO
        // budget of "1h" that reads back as "60m0s" is the same number written
        // so that nobody compares it to the budget at a glance.
        assert_eq!(humanize(Duration::from_secs(3_599)), "59m59s");
        assert_eq!(humanize(Duration::from_secs(3_600)), "1h0m");
        assert_eq!(humanize(Duration::from_secs(604_800)), "7d0h");
    }
}
