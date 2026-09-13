//! The thresholds, what a measurement *is*, and the three-way verdict.
//!
//! Three rules shape this module, and each exists because the obvious version
//! is wrong here:
//!
//! **A measured number carries its unit.** [`Measured`] is an enum, not an
//! `f64`. The run reports a share of samples, a latency, an achieved rate and a
//! yes/no all through the same verdict type, and an undifferentiated float made
//! `HELD (1.0000)` mean "100% of samples were in budget" in one row and "yes,
//! the pipeline drained" in the next. The unit belonged in the type; it had been
//! living in the prose of a description string, which is not a type.
//!
//! **A run that proved nothing must not exit like a run that proved
//! everything.** A load test has more ways to be uninformative than to fail: the
//! generator could not reach the target rate, the pipeline never drained, the
//! detector roster produced no alerts to time, the histogram's ladder has no
//! boundary at the threshold. Every one of those yields a clean-looking p99 over
//! a handful of samples. They are [`Verdict::Inconclusive`] and exit `2` — the
//! same distinction `copilot audit` draws.
//!
//! **The threshold is committed, and moving it is a reviewed diff.** `slo.json`
//! sits beside this file for the same reason `backtest/baseline.json` does; but
//! unlike a baseline there is deliberately no `--update` flag, because the < 1s
//! fast path is a published claim about the product, not a measurement of what
//! the code currently does. A run that cannot meet it is a failing run, never a
//! reason to write down a larger number.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
// The exporter's own ladder, not a copy of it: a budget is only decidable if a
// bucket boundary sits exactly on it, and a private copy here would go stale
// the first time the ladder gains a bucket.
use telemetry::metrics::LATENCY_BUCKETS_SECONDS;

/// A latency budget that is **known** to sit exactly on a boundary of the
/// shared latency ladder.
///
/// The invariant was previously enforced by [`Slo::validate`], one call away
/// from the field it guards. That works until someone adds a budget and
/// forgets the line — the same failure mode as the `DraftKind` whose
/// answer-check fell through a `match` arm and reached a customer. Here the
/// check moved into `Deserialize` itself (`#[serde(try_from)]`), so an
/// unaligned budget cannot be *parsed*, and the only way to build one in Rust
/// is through the same fallible conversion.
///
/// Why the invariant matters: a bucketed quantile is a bound, not a point. With
/// a boundary exactly on the budget, "99% at or below 1.0s" is decidable
/// without interpolating; a budget between two rungs is a question the
/// histogram cannot answer, and the gate would report *undecided* on every run
/// forever — which looks like a passing pipeline, not a broken gate.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "f64", into = "f64")]
pub struct LatencyBudget(f64);

impl LatencyBudget {
    /// The budget in seconds.
    pub fn seconds(self) -> f64 {
        self.0
    }
}

impl TryFrom<f64> for LatencyBudget {
    type Error = String;

    fn try_from(seconds: f64) -> std::result::Result<Self, Self::Error> {
        if LATENCY_BUCKETS_SECONDS.contains(&seconds) {
            Ok(Self(seconds))
        } else {
            Err(format!(
                "{seconds} is not a bucket boundary of the shared latency ladder, so no \
                 histogram can decide it — pick one of {LATENCY_BUCKETS_SECONDS:?}, or add \
                 the boundary to telemetry::metrics::LATENCY_BUCKETS_SECONDS"
            ))
        }
    }
}

impl From<LatencyBudget> for f64 {
    fn from(budget: LatencyBudget) -> Self {
        budget.0
    }
}

impl std::fmt::Display for LatencyBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The committed budgets a load run is judged against.
///
/// Every field here must be read by some [`crate::gates::GateRule`], and a test
/// enforces that — see [`crate::gates::RULES`]. A budget nobody reads is worse
/// than no budget: it looks enforced in review and does nothing at run time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Slo {
    /// §6's headline: the fast path's p99, in seconds.
    ///
    /// Must land on a bucket boundary of the shared latency ladder
    /// (`telemetry::metrics`), or no histogram can decide it — validated at
    /// load, so an unmeasurable threshold fails at startup rather than turning
    /// every future run inconclusive.
    pub fast_path_p99_seconds: LatencyBudget,
    /// Client-observed API p99, in seconds (§19's API panel).
    pub api_p99_seconds: LatencyBudget,
    /// The minimum number of *alerting* fast-path samples a run must collect
    /// before its p99 is allowed to mean anything.
    ///
    /// A p99 over 40 samples is the 99th percentile of nothing: one sample
    /// moves it a full bucket. This is the guard against the failure mode where
    /// a misconfigured roster fires no detector and the SLO series is
    /// technically green.
    pub min_alert_samples: u64,
    /// The share of the offered load a driver must actually have delivered for
    /// the result to count.
    ///
    /// The load test's own throughput is a precondition of its verdict, not a
    /// nice-to-have: a harness that managed 30% of target has measured a system
    /// at 30% of target, whatever its p99 says.
    pub min_achieved_ratio: f64,
    /// The share of API requests that must have succeeded (2xx). Errors are
    /// cheap and fast; a run that 429s or 500s its way to a good p99 has
    /// measured the error path.
    pub min_api_success_ratio: f64,
}

/// A measurement, with its unit.
///
/// The variants are the four shapes this harness actually produces. Keeping
/// them apart is what stops a share being compared against a latency, and what
/// lets [`Verdict`]'s `Display` render each correctly without the description
/// string having to explain what the number means.
/// `Serialize` only, deliberately. A report is an artifact this crate *writes*
/// — nothing reads one back — and `Rate`'s `unit` is a `&'static str` from a
/// closed set rather than an owned string precisely because it is a label, not
/// data. Deriving `Deserialize` would force that to a `String` to satisfy a
/// round-trip nobody performs.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(tag = "unit", content = "value", rename_all = "snake_case")]
pub enum Measured {
    /// A fraction of samples, `0..=1` — e.g. "99.92% landed at or below one
    /// second". This is what a bucketed latency verdict is: see
    /// [`crate::scrape::Histogram::share_at_most`].
    Share(f64),
    /// A duration in seconds.
    Seconds(f64),
    /// Delivered against offered load.
    Rate {
        achieved: f64,
        target: f64,
        unit: &'static str,
    },
    /// A plain count of things observed.
    Count(u64),
    /// A yes/no property of the run.
    Settled(bool),
}

impl std::fmt::Display for Measured {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Just the percentage: what it is a share *of* differs per gate
            // (samples within a budget, responses that succeeded, blocks that
            // came back out), and each gate's description already says so.
            Self::Share(v) => write!(f, "{:.2}%", v * 100.0),
            Self::Seconds(v) if *v >= 1.0 => write!(f, "{v:.3}s"),
            Self::Seconds(v) => write!(f, "{:.1}ms", v * 1000.0),
            Self::Rate {
                achieved,
                target,
                unit,
            } => {
                let share = if *target > 0.0 {
                    achieved / target * 100.0
                } else {
                    0.0
                };
                write!(f, "{achieved:.2}/{target:.2} {unit} ({share:.0}%)")
            }
            Self::Count(n) => write!(f, "{n}"),
            Self::Settled(true) => write!(f, "settled"),
            Self::Settled(false) => write!(f, "never settled"),
        }
    }
}

/// How a single check came out.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// Measured, and within budget.
    Held { measured: Measured },
    /// Measured, and over budget.
    Breached {
        measured: Measured,
        budget: Measured,
    },
    /// Not measured well enough to say. Carries why, because "inconclusive"
    /// without a reason is indistinguishable from a bug in the harness.
    Inconclusive { reason: String },
}

impl Verdict {
    pub fn inconclusive(reason: impl Into<String>) -> Self {
        Self::Inconclusive {
            reason: reason.into(),
        }
    }

    /// The common latency shape: a share of samples that must reach `floor`.
    ///
    /// One constructor rather than the same three-armed `match` at every
    /// latency gate — the arms are easy to get subtly different (`>` for `>=`,
    /// a budget recorded as the threshold instead of the required share), and
    /// a gate that is wrong in that direction reports green.
    pub fn share_at_least(
        measured: Option<f64>,
        floor: f64,
        undecidable: impl Into<String>,
    ) -> Self {
        match measured {
            Some(share) if share >= floor => Self::Held {
                measured: Measured::Share(share),
            },
            Some(share) => Self::Breached {
                measured: Measured::Share(share),
                budget: Measured::Share(floor),
            },
            None => Self::inconclusive(undecidable),
        }
    }

    pub fn is_breach(&self) -> bool {
        matches!(self, Self::Breached { .. })
    }

    pub fn is_inconclusive(&self) -> bool {
        matches!(self, Self::Inconclusive { .. })
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Held { measured } => write!(f, "HELD    ({measured})"),
            Self::Breached { measured, budget } => {
                write!(f, "BREACH  ({measured}, budget {budget})")
            }
            Self::Inconclusive { reason } => write!(f, "UNKNOWN ({reason})"),
        }
    }
}

/// The exit code a whole run reports. The deliverable of a CI job, so the three
/// states are distinct integers rather than a boolean plus a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Every gate held.
    Held = 0,
    /// At least one budget was breached.
    Breached = 1,
    /// Nothing was breached, but at least one gate could not be decided.
    Inconclusive = 2,
}

impl Outcome {
    /// Fold a run's **gate** verdicts into one exit code. A breach outranks an
    /// inconclusive: a run that proved a breach *and* failed to measure
    /// something else has still proved the breach.
    ///
    /// Takes verdicts, and `crate::report::Report` only ever hands it the
    /// gates' — an [`crate::report::Observation`] has no verdict to give it, so
    /// context cannot leak into the exit code by being passed to the wrong
    /// fold.
    pub fn of<'a>(verdicts: impl IntoIterator<Item = &'a Verdict>) -> Self {
        let mut outcome = Self::Held;
        for verdict in verdicts {
            match verdict {
                Verdict::Breached { .. } => return Self::Breached,
                Verdict::Inconclusive { .. } => outcome = Self::Inconclusive,
                Verdict::Held { .. } => {}
            }
        }
        outcome
    }
}

impl Slo {
    /// Read the committed budgets.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading the SLO at {}", path.display()))?;
        let slo: Self = serde_json::from_str(&raw)
            .with_context(|| format!("parsing the SLO at {}", path.display()))?;
        slo.validate()?;
        Ok(slo)
    }

    /// The path of the committed SLO, relative to this crate.
    pub fn committed_path() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("slo.json")
    }

    /// A latency budget is only checkable if the exporter's ladder has a bucket
    /// boundary exactly on it (see [`crate::scrape`]). Catching that here turns
    /// a silently-always-inconclusive gate into a startup error.
    pub(crate) fn validate(&self) -> Result<()> {
        // The bucket-boundary check that used to live here is now
        // [`LatencyBudget`]'s, enforced during deserialization — an unaligned
        // budget never reaches this function, and a newly added budget gets the
        // check by its type rather than by someone remembering to add a line.
        anyhow::ensure!(
            (0.0..=1.0).contains(&self.min_achieved_ratio),
            "min_achieved_ratio is a fraction"
        );
        anyhow::ensure!(
            self.min_alert_samples > 0,
            "min_alert_samples must be positive — with zero, a run in which no \
             detector fired would report a green p99 over an empty series"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_slo() -> Slo {
        Slo {
            fast_path_p99_seconds: LatencyBudget::try_from(1.0).expect("on the ladder"),
            api_p99_seconds: LatencyBudget::try_from(0.5).expect("on the ladder"),
            min_alert_samples: 100,
            min_achieved_ratio: 0.95,
            min_api_success_ratio: 0.99,
        }
    }

    #[test]
    fn a_breach_outranks_an_inconclusive() {
        let verdicts = vec![
            Verdict::inconclusive("no samples"),
            Verdict::Breached {
                measured: Measured::Share(0.5),
                budget: Measured::Share(0.99),
            },
        ];
        assert_eq!(Outcome::of(&verdicts), Outcome::Breached);
    }

    #[test]
    fn one_undecided_gate_makes_the_whole_run_inconclusive() {
        let verdicts = vec![
            Verdict::Held {
                measured: Measured::Share(1.0),
            },
            Verdict::inconclusive("generator fell short of target"),
        ];
        assert_eq!(Outcome::of(&verdicts), Outcome::Inconclusive);
        assert_eq!(Outcome::Inconclusive as i32, 2);
    }

    #[test]
    fn an_all_held_run_exits_zero() {
        assert_eq!(
            Outcome::of(&[Verdict::Held {
                measured: Measured::Seconds(0.1)
            }]) as i32,
            0
        );
    }

    /// The reason [`Measured`] is an enum: these two rendered identically as
    /// `1.0000` when every measurement was a bare `f64`, and the only thing
    /// telling them apart was a sentence in a description string.
    #[test]
    fn a_share_and_a_settled_flag_do_not_render_alike() {
        assert_eq!(Measured::Share(1.0).to_string(), "100.00%");
        assert_eq!(Measured::Settled(true).to_string(), "settled");
    }

    #[test]
    fn a_latency_renders_in_the_unit_a_human_reads_it_in() {
        assert_eq!(Measured::Seconds(0.05).to_string(), "50.0ms");
        assert_eq!(Measured::Seconds(1.0).to_string(), "1.000s");
    }

    #[test]
    fn a_rate_carries_both_sides_so_a_shortfall_is_legible() {
        let rate = Measured::Rate {
            achieved: 3.0,
            target: 4.0,
            unit: "blocks/s",
        };
        assert_eq!(rate.to_string(), "3.00/4.00 blocks/s (75%)");
    }

    #[test]
    fn the_share_constructor_gets_the_boundary_right() {
        // Exactly at the floor holds; a hair under breaches.
        assert!(matches!(
            Verdict::share_at_least(Some(0.99), 0.99, "x"),
            Verdict::Held { .. }
        ));
        assert!(Verdict::share_at_least(Some(0.9899), 0.99, "x").is_breach());
        assert!(Verdict::share_at_least(None, 0.99, "x").is_inconclusive());
    }

    /// The invariant is now the type's, so it is enforced where the value
    /// enters the program rather than by a `validate` call someone has to
    /// remember. Note what this test can no longer do: build an `Slo` with an
    /// unaligned budget at all — that is the improvement, and it is why this
    /// asserts on JSON rather than on a struct literal.
    #[test]
    fn a_budget_off_the_bucket_ladder_cannot_be_parsed() {
        let json = r#"{
            "fast_path_p99_seconds": 0.75,
            "api_p99_seconds": 0.5,
            "min_alert_samples": 100,
            "min_achieved_ratio": 0.95,
            "min_api_success_ratio": 0.99
        }"#;
        let err = serde_json::from_str::<Slo>(json)
            .expect_err("0.75 is between the 0.5 and 1.0 rungs")
            .to_string();
        assert!(err.contains("bucket boundary"), "got: {err}");
        assert!(
            err.contains("0.5") && err.contains("1"),
            "the error must name the usable rungs: {err}"
        );
    }

    /// A boundary value still parses — otherwise the check above could be
    /// passing because nothing parses.
    #[test]
    fn a_budget_on_the_ladder_parses() {
        assert_eq!(
            serde_json::from_str::<LatencyBudget>("0.25")
                .unwrap()
                .seconds(),
            0.25
        );
    }

    #[test]
    fn zero_required_samples_is_rejected() {
        let slo = Slo {
            min_alert_samples: 0,
            ..a_slo()
        };
        assert!(slo.validate().is_err());
    }

    #[test]
    fn the_committed_slo_parses_and_states_the_published_claim() {
        let slo = Slo::load(&Slo::committed_path()).expect("slo.json must be valid");
        assert_eq!(
            slo.fast_path_p99_seconds.seconds(),
            1.0,
            "§6's < 1s is a published claim; changing it here changes the product"
        );
    }
}
