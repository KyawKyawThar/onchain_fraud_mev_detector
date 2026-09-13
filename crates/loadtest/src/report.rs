//! The run's result: what load was offered, what was measured, and what that
//! does or does not prove.
//!
//! ## Gates and observations are different types
//!
//! A [`Gate`] can change the exit code; an [`Observation`] structurally cannot,
//! because it has no [`Verdict`] to give the fold. They were one struct with a
//! `gating: bool`, which made the exit code depend on every caller remembering
//! `.filter(|c| c.gating)` — a `bool` selecting a code path, the anti-pattern
//! the engineering conventions call out by name. The old test that asserted
//! "folding all of them would give the wrong answer" documented the footgun
//! instead of removing it; splitting the types removes it.
//!
//! The distinction is not bookkeeping. `queue_wait_p99` is *attribution* — it
//! says which half of the fast path grew — and it must never be a second budget
//! nobody agreed to. An observation with no samples is context that is missing,
//! not a run that failed.
//!
//! ## Everything is printed next to the load it was measured under
//!
//! A load-test report that prints only a p99 is the thing this crate replaces.
//! The `limits` section states, in the artifact itself, what a green run does
//! not establish; a caveat that lives only in a runbook is a caveat nobody reads
//! next to the number.

use serde::Serialize;

use crate::gates::Category;
use crate::profile::Profile;
use crate::run::{Drain, FastPathWindow};
use crate::slo::{Measured, Outcome, Slo, Verdict};
use crate::source::Offered;

/// A judged property of the run. Contributes to the exit code.
#[derive(Debug, Clone, Serialize)]
pub struct Gate {
    /// Stable id, so a CI job can grep for one result without parsing prose.
    pub id: &'static str,
    /// What was being asked.
    pub description: String,
    pub verdict: Verdict,
    /// Whether this validates the run or judges the platform. Stamped by
    /// [`crate::gates::evaluate`] from the rule's own declaration, never by the
    /// constructor — a rule cannot ship mis-filed.
    pub category: Category,
}

impl Gate {
    /// A gate, provisionally a [`Category::Claim`] until the registry stamps it.
    pub fn new(id: &'static str, description: impl Into<String>, verdict: Verdict) -> Self {
        Self {
            id,
            description: description.into(),
            verdict,
            category: Category::Claim,
        }
    }

    #[must_use]
    pub fn in_category(mut self, category: Category) -> Self {
        self.category = category;
        self
    }
}

/// A measured number with no budget attached: attribution for a breach, never a
/// pass/fail of its own.
#[derive(Debug, Clone, Serialize)]
pub struct Observation {
    pub id: &'static str,
    pub description: String,
    /// `None` where the run produced no samples for it — missing context, not a
    /// failure.
    pub value: Option<Measured>,
}

impl Observation {
    pub fn new(id: &'static str, description: impl Into<String>, value: Option<Measured>) -> Self {
        Self {
            id,
            description: description.into(),
            value,
        }
    }

    /// A latency observation from a histogram's p99 bound, in seconds.
    pub fn p99(
        id: &'static str,
        description: impl Into<String>,
        histogram: &crate::scrape::Histogram,
    ) -> Self {
        Self::new(
            id,
            description,
            histogram.quantile_upper_bound(0.99).map(Measured::Seconds),
        )
    }
}

/// The whole run.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub profile: Profile,
    pub slo: Slo,
    pub offered: Vec<Offered>,
    pub measured: Measurements,
    /// The rules that decide the exit code.
    pub gates: Vec<Gate>,
    /// Context for reading them. Never an exit code.
    pub observations: Vec<Observation>,
    /// Whether every precondition held — i.e. whether the claim verdicts above
    /// describe the run they were meant to. Serialized so a job that archives
    /// reports can filter on it without re-deriving the rule.
    pub preconditions_hold: bool,
    /// What a green run here does *not* establish.
    pub limits: Vec<&'static str>,
}

/// The subject's own numbers over the measurement window.
#[derive(Debug, Clone, Serialize)]
pub struct Measurements {
    pub alerting_samples: u64,
    pub quiet_samples: u64,
    /// The tightest bound the histogram puts on the fast path's p99, in
    /// seconds. `None` means it overflowed the top of the ladder.
    pub fast_path_p99_upper_bound: Option<f64>,
    pub fast_path_mean_seconds: Option<f64>,
    pub drain: String,
    pub drain_settled: bool,
}

impl Report {
    pub fn new(
        profile: Profile,
        slo: Slo,
        offered: Vec<Offered>,
        window: &FastPathWindow,
        drain: &Drain,
        gates: Vec<Gate>,
        observations: Vec<Observation>,
    ) -> Self {
        Self {
            measured: Measurements {
                alerting_samples: window.alerting.count,
                quiet_samples: window.quiet.count,
                fast_path_p99_upper_bound: window.alerting.quantile_upper_bound(0.99),
                fast_path_mean_seconds: window.alerting.mean(),
                drain: format!("{drain:?}"),
                drain_settled: matches!(drain, Drain::Settled { .. }),
            },
            profile,
            slo,
            offered,
            preconditions_hold: gates
                .iter()
                .filter(|g| g.category == Category::Precondition)
                .all(|g| matches!(g.verdict, Verdict::Held { .. })),
            gates,
            observations,
            limits: LIMITS.to_vec(),
        }
    }

    /// The run's exit code.
    ///
    /// Reads `gates` and nothing else — and there is no longer a way to hand
    /// this an observation by mistake, because an [`Observation`] has no
    /// [`Verdict`].
    pub fn outcome(&self) -> Outcome {
        Outcome::of(self.gates.iter().map(|gate| &gate.verdict))
    }

    fn gates_in(&self, category: Category) -> impl Iterator<Item = &Gate> {
        self.gates.iter().filter(move |g| g.category == category)
    }

    /// Did every precondition hold?
    ///
    /// When it did not, the claim verdicts below describe a run that did not
    /// measure what it set out to — they are not *wrong*, they are **about
    /// something else**, and the report says so rather than printing a green
    /// line a skim-reader will take home. The exit code already accounts for
    /// this (a failed precondition is at least inconclusive); this is about the
    /// artifact people read.
    pub fn preconditions_hold(&self) -> bool {
        self.gates_in(Category::Precondition)
            .all(|gate| matches!(gate.verdict, Verdict::Held { .. }))
    }
}

/// What a green run does not prove. Printed with every report.
const LIMITS: &[&str] = &[
    "Blocks are header-only (§6): `BlockAssembled` carries a tx count, not \
     transactions. This measures the pipeline at chain rate, not the per-tx cost \
     of a full bundle — the detectors do near-zero work per block.",
    "The alerting share is produced by `demo-v0.1`'s firing schedule \
     (`demo_detector::fires_on`), not by real evidence. It exercises the emit and \
     publish path at volume; it does not exercise any real detector's analysis.",
    "The fast path is measured from `BlockAssembled.occurred_at` to publication. \
     It excludes ingestion's own source→emit time, and it is a cross-process \
     wall-clock comparison: run the generator and detection against one clock, or \
     the number carries the skew between them.",
    "The p99 is a bucketed bound, not a point estimate: the verdict is `≥99% of \
     samples landed at or below the budget`, which the ladder decides exactly, \
     and the reported figure is the containing bucket's upper bound.",
];

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "load test — profile `{}`", self.profile.name)?;
        writeln!(f, "  {}", self.profile.rationale)?;
        writeln!(f)?;

        writeln!(f, "OFFERED")?;
        for load in &self.offered {
            let lateness = match load.max_lateness {
                Some(d) => format!("{:.3}s", d.as_secs_f64()),
                None => "—".to_owned(),
            };
            writeln!(
                f,
                "  {:<10} {:.2} {} — {} of {} delivered, {} failed, max lateness {lateness}",
                load.source,
                load.achieved_rate(),
                load.unit,
                load.delivered,
                load.scheduled,
                load.failed,
            )?;
            if let Some(o) = load.outcomes {
                writeln!(
                    f,
                    "             {} 2xx / {} 4xx / {} 5xx",
                    o.succeeded, o.client_errors, o.server_errors
                )?;
            }
        }
        writeln!(f)?;

        writeln!(f, "MEASURED (over the load window, warmup subtracted)")?;
        writeln!(
            f,
            "  fast path  p99 ≤ {}  mean {}  over {} alerting samples ({} quiet)",
            fmt_seconds(self.measured.fast_path_p99_upper_bound),
            fmt_seconds(self.measured.fast_path_mean_seconds),
            self.measured.alerting_samples,
            self.measured.quiet_samples,
        )?;
        writeln!(f)?;

        let supported = self.preconditions_hold();

        writeln!(
            f,
            "PRECONDITIONS (did this run measure what it claims to have measured?)"
        )?;
        for gate in self.gates_in(Category::Precondition) {
            writeln!(f, "  {:<22} {}", gate.id, gate.verdict)?;
            writeln!(f, "  {:<22} {}", "", gate.description)?;
        }
        writeln!(f)?;

        writeln!(f, "CLAIMS (the published budgets)")?;
        if !supported {
            writeln!(
                f,
                "  ⚠ a precondition above did not hold, so the verdicts below describe a \
                 run that did not offer, deliver or drain the load it set out to. Read \
                 them as UNSUPPORTED, not as results."
            )?;
        }
        for gate in self.gates_in(Category::Claim) {
            let suffix = if supported { "" } else { "  [UNSUPPORTED]" };
            writeln!(f, "  {:<22} {}{suffix}", gate.id, gate.verdict)?;
            writeln!(f, "  {:<22} {}", "", gate.description)?;
        }
        writeln!(f)?;

        writeln!(f, "OBSERVATIONS (context; never an exit code)")?;
        for observation in &self.observations {
            let value = match &observation.value {
                Some(v) => v.to_string(),
                None => "— (no samples)".to_owned(),
            };
            writeln!(f, "  {:<22} {value}", observation.id)?;
            writeln!(f, "  {:<22} {}", "", observation.description)?;
        }
        writeln!(f)?;

        writeln!(f, "WHAT THIS RUN DOES NOT PROVE")?;
        for limit in &self.limits {
            writeln!(f, "  · {limit}")?;
        }
        writeln!(f)?;
        writeln!(
            f,
            "outcome: {:?} (exit {})",
            self.outcome(),
            self.outcome() as i32
        )
    }
}

/// A duration, or `—` where the histogram could not bound it (every finite
/// bucket below the quantile). Never a fabricated number.
fn fmt_seconds(value: Option<f64>) -> String {
    match value {
        Some(v) => Measured::Seconds(v).to_string(),
        None => "— (above the ladder / no samples)".to_owned(),
    }
}

/// Convenience for the CLI's `--json-out`.
pub fn to_json(report: &Report) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slo::LatencyBudget;

    /// The property the type split buys: there is no way to pass an
    /// observation to the fold, so context cannot become an exit code. Under
    /// the old `Check { gating: bool }` this was a test asserting that the
    /// *wrong* fold gave the wrong answer; now it is a statement about what
    /// compiles.
    #[test]
    fn observations_have_no_verdict_to_give_the_exit_code() {
        let held = Outcome::of(&[Verdict::Held {
            measured: Measured::Share(1.0),
        }]);
        assert_eq!(held, Outcome::Held);

        // An observation with nothing to report is missing context, and the
        // only thing it can contribute to a report is a printed dash.
        let missing = Observation::new("queue_wait_p99", "context", None);
        assert!(missing.value.is_none());
    }

    /// The misleading-report failure: a claim that "held" over a run which
    /// never offered its load is not a result, and must not read like one.
    #[test]
    fn a_failed_precondition_marks_every_claim_unsupported() {
        let gates = vec![
            Gate::new(
                "chain_load_achieved",
                "load arrived",
                Verdict::inconclusive("52% of target"),
            )
            .in_category(Category::Precondition),
            Gate::new(
                "fast_path_p99",
                "the claim",
                Verdict::Held {
                    measured: Measured::Share(1.0),
                },
            )
            .in_category(Category::Claim),
        ];
        let report = report_with(gates);

        assert!(!report.preconditions_hold);
        let rendered = report.to_string();
        assert!(rendered.contains("[UNSUPPORTED]"), "{rendered}");
        assert!(rendered.contains("Read them as UNSUPPORTED"), "{rendered}");
        // …and the exit code was already right; this is about the artifact.
        assert_eq!(report.outcome(), Outcome::Inconclusive);
    }

    #[test]
    fn a_clean_run_does_not_shout_unsupported_at_its_own_results() {
        let gates = vec![
            Gate::new(
                "chain_load_achieved",
                "load arrived",
                Verdict::Held {
                    measured: Measured::Share(1.0),
                },
            )
            .in_category(Category::Precondition),
            Gate::new(
                "fast_path_p99",
                "the claim",
                Verdict::Held {
                    measured: Measured::Share(1.0),
                },
            )
            .in_category(Category::Claim),
        ];
        let report = report_with(gates);

        assert!(report.preconditions_hold);
        assert!(!report.to_string().contains("UNSUPPORTED"));
        assert_eq!(report.outcome(), Outcome::Held);
    }

    fn report_with(gates: Vec<Gate>) -> Report {
        Report::new(
            crate::profile::Profile {
                name: "t".into(),
                rationale: "t".into(),
                chain: 1,
                blocks_per_second: 1.0,
                txs_per_block: 1,
                alerting_block_fraction: 1.0,
                api_qps: 0.0,
                api_routes: vec![],
                warmup: std::time::Duration::from_secs(1),
                duration: std::time::Duration::from_secs(1),
                drain_timeout: std::time::Duration::from_secs(1),
            },
            crate::slo::Slo {
                fast_path_p99_seconds: LatencyBudget::try_from(1.0).unwrap(),
                api_p99_seconds: LatencyBudget::try_from(0.5).unwrap(),
                min_alert_samples: 1,
                min_achieved_ratio: 0.95,
                min_api_success_ratio: 0.99,
            },
            vec![],
            &FastPathWindow::default(),
            &Drain::Settled {
                waited: std::time::Duration::from_secs(1),
            },
            gates,
            vec![],
        )
    }

    #[test]
    fn an_unbounded_quantile_prints_as_unknown_not_as_the_top_bucket() {
        assert!(fmt_seconds(None).contains("above the ladder"));
        assert_eq!(fmt_seconds(Some(0.05)), "50.0ms");
        assert_eq!(fmt_seconds(Some(2.5)), "2.500s");
    }
}
