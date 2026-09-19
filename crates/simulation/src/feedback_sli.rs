//! The §19 false-positive SLI (production-readiness Epic E) — the number, the
//! window it is measured over, and the conditions under which it is allowed to
//! page anybody.
//!
//! ```text
//!   POST /v1/incidents/{id}/feedback   (server::feedback)
//!            │  AlertFeedbackRecorded
//!            ▼
//!   projection_consumer ──► incident_feedback  ─┐
//!                            (ledger)           ├─► this module ──► gauges ──► §19 panel
//!                           incident_analytics ─┘                              + SLO alert
//!                            (population)
//! ```
//!
//! Everything here is pure except [`run_exporter`]: [`Evidence`] in, an [`Sli`]
//! out, unit-tested without a database. The store returns *facts* — a
//! contingency table of at most fourteen rows, a concentration pair, two
//! quantiles — and this module decides what they mean. That split is the whole
//! design: the meaning is **policy**, and policy inside a SQL string cannot be
//! named in a type, cannot be swapped, and cannot be tested without a
//! container.
//!
//! # Four decisions worth arguing about
//!
//! **The window lags.** Feedback arrives days after the incident it judges, so
//! the most recent days are always under-adjudicated. Measuring them would
//! produce a rate computed from whichever handful of verdicts happened to
//! arrive fastest — and the fast ones are not a random sample, since an
//! obvious false positive gets reported the same afternoon. The window
//! therefore ends [`Settle`] before now, and that delay is a *property of the
//! measurement*, not a tuning knob to minimise. It is no longer asserted
//! either: [`Evidence::lag_p95_seconds`] measures the real distribution, and
//! `FeedbackSettleTooShort` fires when the settle delay is shorter than it.
//!
//! **`unclear` is neither.** A verdict that could not decide counts in no half
//! of the rate (see `events::feedback::FeedbackVerdict`).
//!
//! **Cohorts are never merged.** A volunteered verdict is self-selected —
//! people report what annoyed them — so its rate is a fine product signal and
//! a poor accuracy claim. A solicited verdict comes from an incident the
//! platform picked without looking at the finding. They are separate series
//! (`sample="volunteered"` / `sample="solicited"`), because merging them lets
//! volume from the volunteered path silently dominate the number a README
//! quotes.
//!
//! **The SLO refuses to judge a sample it should not trust.** Too few
//! adjudications, or too many of them from one customer, and it disarms and
//! says so through its own gauge rather than through a missing series
//! (engineering conventions §15b). [`SloPolicy::arm`] is the whole rule.
//!
//! # Why concentration disarms rather than reweights
//!
//! One tenant can adjudicate thousands of incidents; a competitor on a trial
//! account can do it deliberately. The tempting fix is to winsorize — cap each
//! customer's contribution and scale the rest. This module does not, because a
//! reweighted rate is a number nobody can reproduce from the ledger, and the
//! honest response to "this sample is dominated by one opinion" is to stop
//! quoting it, not to launder it. [`Arming::Concentrated`] is that refusal,
//! and `detection_feedback_top_customer_share` is the evidence for it.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use events::feedback::FeedbackCohort;
use tokio_util::sync::CancellationToken;

use crate::store::FeedbackSliStore;

/// Gauge: the §19 false-positive rate — false positives over adjudicated
/// incidents, in the settled window, **labelled by cohort**. Absent, not zero,
/// when nothing in that cohort was adjudicated: an unmeasured rate is not a
/// perfect one, and a zero here would be the most flattering possible lie
/// about a platform nobody is reviewing.
pub const FEEDBACK_FALSE_POSITIVE_RATE: &str = "detection_feedback_false_positive_rate";
/// Gauge: the target the rate is held to, exported so the alert rule compares
/// two *series* and the deployment's own configuration is the threshold
/// (`deploy/prometheus-rules.yml`'s category 2). Carries the same `sample`
/// label as the rate so the rules are one-to-one matches rather than `on()`
/// joins, which fail — silently, as evaluation errors — the moment two
/// instances are scraped at once.
pub const FEEDBACK_FALSE_POSITIVE_TARGET: &str = "detection_feedback_false_positive_rate_target";
/// Gauge: incidents created in the window — the SLI's population. Cohort-free:
/// the population is a property of the platform's output, not of who was asked.
pub const FEEDBACK_WINDOW_INCIDENTS: &str = "detection_feedback_window_incidents";
/// Gauge: how many of them that cohort adjudicated either way.
pub const FEEDBACK_WINDOW_ADJUDICATED: &str = "detection_feedback_window_adjudicated";
/// Gauge: adjudicated over incidents, per cohort — what fraction of the
/// platform's output anybody actually looked at. The rate's own quality
/// measure: a false-positive rate at 2% coverage is a statement about 2% of
/// the platform.
pub const FEEDBACK_COVERAGE: &str = "detection_feedback_coverage";
/// Gauge: `1` when that cohort's SLO is armed, `0` when the window holds too
/// small or too concentrated a sample to judge — §15b's declare-your-arming-state
/// rule.
pub const FEEDBACK_SLO_ARMED: &str = "detection_feedback_slo_armed";
/// Gauge: the sample size the SLO arms at, exported for the same reason the
/// target is.
pub const FEEDBACK_MIN_ADJUDICATIONS: &str = "detection_feedback_min_adjudications";
/// Gauge: the largest single customer's share of the window's verdicts. No
/// customer label — an unbounded id set has no business in a time series
/// (§19); `just feedback-sli` names the customer when an operator needs it.
pub const FEEDBACK_TOP_CUSTOMER_SHARE: &str = "detection_feedback_top_customer_share";
/// Gauge: the share above which [`Arming::Concentrated`] disarms the SLO.
pub const FEEDBACK_CONCENTRATION_CAP: &str = "detection_feedback_concentration_cap";
/// Gauge: median incident-to-verdict lag, seconds. A **gauge**, not a
/// histogram: this is measured in days, and the shared `_seconds` bucket
/// ladder tops out at 10s, where `histogram_quantile` would report the ceiling
/// as though it were an answer (the §19b defect class).
pub const FEEDBACK_LAG_P50_SECONDS: &str = "detection_feedback_lag_p50_seconds";
/// Gauge: p95 incident-to-verdict lag, seconds — the number the settle delay
/// must exceed for the window to be settled in fact rather than by assertion.
pub const FEEDBACK_LAG_P95_SECONDS: &str = "detection_feedback_lag_p95_seconds";
/// Gauge: the window's width in seconds, exported so a dashboard can say
/// *which* span a rate describes. A retune silently changes the series'
/// meaning otherwise.
pub const FEEDBACK_WINDOW_SPAN_SECONDS: &str = "detection_feedback_window_span_seconds";
/// Gauge: the settle delay in seconds — how far before now the window ends.
pub const FEEDBACK_WINDOW_SETTLE_SECONDS: &str = "detection_feedback_window_settle_seconds";
/// Gauge: the window's end as a unix timestamp. Window provenance: a rate with
/// no visible window is a number whose meaning can change without anything
/// looking different.
pub const FEEDBACK_WINDOW_END_TIMESTAMP: &str = "detection_feedback_window_end_timestamp_seconds";
/// Gauge: seconds since the exporter last read the ledger successfully. A
/// stalled exporter leaves every gauge above frozen at its last value, which
/// looks exactly like a healthy, unchanging platform.
pub const FEEDBACK_SLI_AGE_SECONDS: &str = "detection_feedback_sli_age_seconds";
/// Gauge: the exporter's configured refresh interval, in seconds. Exported so
/// the staleness alert can be written as a multiple of *this deployment's*
/// cadence instead of carrying a second copy of it.
pub const FEEDBACK_SLI_REFRESH_SECONDS: &str = "detection_feedback_sli_refresh_seconds";

/// The metric label every per-cohort series carries.
const SAMPLE_LABEL: &str = "sample";

/// The settled window the SLI is measured over: incidents **created** between
/// `from` (inclusive) and `to` (exclusive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

/// How long after an incident is created its verdicts are still expected to
/// arrive — the lag between the end of the window and now.
///
/// A newtype rather than a bare `Duration` because it is the parameter most
/// likely to be "simplified" away by someone who notices the dashboard is a
/// day behind, and the type gives that instinct something to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settle(pub Duration);

/// The window's width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span(pub Duration);

impl Window {
    /// The settled window ending `settle` before `now` and spanning `span`.
    ///
    /// Saturates rather than panicking on an absurd configuration: a span so
    /// large it would run off the calendar yields a window starting at the
    /// earliest representable instant, which reads as "everything" — the
    /// answer the operator who typed it was asking for.
    pub fn settled(now: DateTime<Utc>, span: Span, settle: Settle) -> Self {
        let to = now - delta(settle.0);
        let from = to - delta(span.0);
        Self { from, to }
    }
}

/// `Duration` as a `TimeDelta`, saturating at the representable maximum.
fn delta(d: Duration) -> TimeDelta {
    TimeDelta::from_std(d).unwrap_or(TimeDelta::MAX)
}

/// One contingency cell: how many adjudicated incidents in one cohort carry
/// this exact combination of verdicts.
///
/// The booleans are *across customers*: `any_fp` means at least one customer
/// called this incident noise, not that all of them did. Resolving that
/// disagreement is [`DisagreementPolicy`]'s job, which is why the cell keeps
/// all three flags rather than a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    pub cohort: FeedbackCohort,
    pub any_fp: bool,
    pub any_tp: bool,
    pub any_unclear: bool,
    /// Incidents in this cell.
    pub incidents: u64,
}

/// What one [`FeedbackSliStore::feedback_evidence`] read found in the window.
/// Facts only — no rate, no verdict on whether the sample is usable.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Evidence {
    /// Incidents created in the window, adjudicated or not.
    pub incidents: u64,
    /// The contingency table, at most fourteen rows.
    pub cells: Vec<Cell>,
    /// Verdicts behind those cells (one per incident per customer).
    pub verdicts: u64,
    /// How many of them came from the single most active customer.
    pub top_customer_verdicts: u64,
    /// Median incident-to-verdict lag in seconds; `None` when nothing in the
    /// window has been adjudicated.
    pub lag_p50_seconds: Option<f64>,
    /// p95 of the same.
    pub lag_p95_seconds: Option<f64>,
}

impl Evidence {
    /// The largest single customer's share of the sample — `None` when there
    /// is no sample to be concentrated in.
    pub fn top_customer_share(&self) -> Option<f64> {
        (self.verdicts > 0).then(|| self.top_customer_verdicts as f64 / self.verdicts as f64)
    }
}

/// How an incident two customers disagree about is resolved.
///
/// Both variants are decidable from a [`Cell`]'s three booleans, which is what
/// keeps the store's aggregate tiny. A *majority* rule is deliberately absent:
/// it needs per-incident verdict counts, and that is an unbounded aggregate —
/// a policy whose cost is a full scan is not a policy this module will offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DisagreementPolicy {
    /// Any false-positive call makes the incident a false positive.
    ///
    /// The pessimistic fold, and the default. This number exists to find
    /// detectors that annoy people, and "somebody else thought it was fine" is
    /// not an answer to "this was noise to me".
    #[default]
    AnyFalsePositive,
    /// An incident counts only when the customers who looked at it agree; a
    /// contested incident is excluded from both halves.
    ///
    /// The conservative reading for a *published* claim: it will not call
    /// something a false positive on one dissenting voice, at the cost of a
    /// smaller sample.
    RequireUnanimous,
}

/// What a policy made of one cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resolved {
    FalsePositive,
    TruePositive,
    /// Adjudicated by nobody decisively (only `unclear`), or contested under a
    /// policy that refuses to break ties. Counts in neither half.
    Undecided,
}

impl DisagreementPolicy {
    fn resolve(self, cell: &Cell) -> Resolved {
        match self {
            Self::AnyFalsePositive => {
                if cell.any_fp {
                    Resolved::FalsePositive
                } else if cell.any_tp {
                    Resolved::TruePositive
                } else {
                    Resolved::Undecided
                }
            }
            Self::RequireUnanimous => match (cell.any_fp, cell.any_tp) {
                (true, false) => Resolved::FalsePositive,
                (false, true) => Resolved::TruePositive,
                _ => Resolved::Undecided,
            },
        }
    }

    /// The stable name for logs and the CLI.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AnyFalsePositive => "any_false_positive",
            Self::RequireUnanimous => "require_unanimous",
        }
    }
}

/// One cohort's counts, after the policy has resolved every cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counts {
    /// Incidents created in the window (cohort-independent population).
    pub incidents: u64,
    /// Of those, how many this cohort decided either way.
    pub adjudicated: u64,
    /// Of those, how many resolved to a false positive.
    pub false_positives: u64,
    /// Of those, how many resolved to a true positive.
    pub true_positives: u64,
}

impl Counts {
    /// False positives over adjudicated incidents — `None` when nothing was
    /// adjudicated, which is the whole point (see
    /// [`FEEDBACK_FALSE_POSITIVE_RATE`]).
    pub fn false_positive_rate(&self) -> Option<f64> {
        (self.adjudicated > 0).then(|| self.false_positives as f64 / self.adjudicated as f64)
    }

    /// Adjudicated over incidents — `None` when the window holds no incidents
    /// at all (a quiet week is not zero coverage).
    pub fn coverage(&self) -> Option<f64> {
        (self.incidents > 0).then(|| self.adjudicated as f64 / self.incidents as f64)
    }
}

/// The SLO's arming rules and the target it holds the rate to.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SloPolicy {
    /// The published false-positive target (the README's number, as a
    /// fraction).
    pub target: f64,
    /// The smallest adjudicated sample the rate may be judged on.
    pub min_adjudications: u64,
    /// The largest share of the window's verdicts one customer may contribute
    /// before the SLO stops trusting the sample.
    pub max_customer_share: f64,
    /// How two customers who disagree about one incident are reconciled.
    pub disagreement: DisagreementPolicy,
}

/// Why the SLO is or is not armed. An enum rather than a bool so the log line,
/// the CLI and the test all name the reason; the gauge carries only
/// [`Arming::is_armed`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Arming {
    /// Enough adjudications, spread widely enough, to judge the rate.
    Armed,
    /// Too few. Carries what was found, which is what an operator asks next.
    TooFewAdjudications { found: u64, needed: u64 },
    /// One customer dominates the sample, so the "platform" rate would be one
    /// customer's opinion wearing a platform's name.
    Concentrated { share: f64, cap: f64 },
}

impl Arming {
    /// The gauge's value: armed is `1`.
    pub fn is_armed(self) -> bool {
        matches!(self, Self::Armed)
    }
}

impl SloPolicy {
    /// Whether this cohort's counts may be judged against [`Self::target`].
    ///
    /// Order matters: sample size is checked first, because "four verdicts,
    /// all from one customer" is more usefully reported as *too few* than as
    /// *too concentrated* — with four verdicts the concentration is not the
    /// interesting fact.
    pub fn arm(&self, counts: &Counts, top_customer_share: Option<f64>) -> Arming {
        if counts.adjudicated < self.min_adjudications {
            return Arming::TooFewAdjudications {
                found: counts.adjudicated,
                needed: self.min_adjudications,
            };
        }
        match top_customer_share {
            Some(share) if share > self.max_customer_share => Arming::Concentrated {
                share,
                cap: self.max_customer_share,
            },
            _ => Arming::Armed,
        }
    }
}

/// One cohort's measurement.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CohortSli {
    pub cohort: FeedbackCohort,
    pub counts: Counts,
    pub arming: Arming,
}

/// One measurement: the evidence, the policies applied to it, and the window
/// it came from — everything [`Sli::publish`] needs and nothing it recomputes.
#[derive(Debug, Clone, PartialEq)]
pub struct Sli {
    pub window: Window,
    pub evidence: Evidence,
    pub policy: SloPolicy,
    /// One entry per cohort, always both, so a cohort with no verdicts still
    /// publishes an arming gauge instead of vanishing (§15b).
    pub cohorts: Vec<CohortSli>,
}

impl Sli {
    /// Measure: fold `evidence` under `policy`.
    pub fn new(window: Window, evidence: Evidence, policy: SloPolicy) -> Self {
        let share = evidence.top_customer_share();
        let mut by_cohort: BTreeMap<&'static str, Counts> = BTreeMap::new();
        for cohort in [FeedbackCohort::Volunteered, FeedbackCohort::Solicited] {
            by_cohort.insert(
                cohort.as_str(),
                Counts {
                    incidents: evidence.incidents,
                    ..Counts::default()
                },
            );
        }

        for cell in &evidence.cells {
            let counts = by_cohort
                .get_mut(cell.cohort.as_str())
                .expect("both cohorts are seeded above");
            match policy.disagreement.resolve(cell) {
                Resolved::FalsePositive => {
                    counts.adjudicated += cell.incidents;
                    counts.false_positives += cell.incidents;
                }
                Resolved::TruePositive => {
                    counts.adjudicated += cell.incidents;
                    counts.true_positives += cell.incidents;
                }
                Resolved::Undecided => {}
            }
        }

        let cohorts = [FeedbackCohort::Volunteered, FeedbackCohort::Solicited]
            .into_iter()
            .map(|cohort| {
                let counts = by_cohort[cohort.as_str()];
                CohortSli {
                    cohort,
                    counts,
                    arming: policy.arm(&counts, share),
                }
            })
            .collect();

        Self {
            window,
            evidence,
            policy,
            cohorts,
        }
    }

    /// This cohort's measurement.
    pub fn cohort(&self, cohort: FeedbackCohort) -> &CohortSli {
        self.cohorts
            .iter()
            .find(|c| c.cohort == cohort)
            .expect("every cohort is present")
    }

    /// Publish the §19 gauges.
    ///
    /// Rates and coverages are published **only when they exist**. A gauge
    /// that is absent while its neighbours are present is legible in PromQL
    /// (`and` composes, the alert simply does not fire) and it is the honest
    /// encoding: this platform has no false-positive rate until somebody tells
    /// it one. Everything else — arming, counts, the policy's own numbers —
    /// is always published, because an alert may never infer a fact from a
    /// missing series (§15b).
    pub fn publish(&self) {
        metrics::gauge!(FEEDBACK_WINDOW_INCIDENTS).set(self.evidence.incidents as f64);
        metrics::gauge!(FEEDBACK_WINDOW_SPAN_SECONDS)
            .set((self.window.to - self.window.from).num_seconds() as f64);
        metrics::gauge!(FEEDBACK_WINDOW_END_TIMESTAMP).set(self.window.to.timestamp() as f64);
        metrics::gauge!(FEEDBACK_CONCENTRATION_CAP).set(self.policy.max_customer_share);
        if let Some(share) = self.evidence.top_customer_share() {
            metrics::gauge!(FEEDBACK_TOP_CUSTOMER_SHARE).set(share);
        }
        if let Some(p50) = self.evidence.lag_p50_seconds {
            metrics::gauge!(FEEDBACK_LAG_P50_SECONDS).set(p50);
        }
        if let Some(p95) = self.evidence.lag_p95_seconds {
            metrics::gauge!(FEEDBACK_LAG_P95_SECONDS).set(p95);
        }

        for cohort in &self.cohorts {
            let sample = cohort.cohort.as_str();
            metrics::gauge!(FEEDBACK_WINDOW_ADJUDICATED, SAMPLE_LABEL => sample)
                .set(cohort.counts.adjudicated as f64);
            metrics::gauge!(FEEDBACK_FALSE_POSITIVE_TARGET, SAMPLE_LABEL => sample)
                .set(self.policy.target);
            metrics::gauge!(FEEDBACK_MIN_ADJUDICATIONS, SAMPLE_LABEL => sample)
                .set(self.policy.min_adjudications as f64);
            metrics::gauge!(FEEDBACK_SLO_ARMED, SAMPLE_LABEL => sample)
                .set(f64::from(u8::from(cohort.arming.is_armed())));
            if let Some(rate) = cohort.counts.false_positive_rate() {
                metrics::gauge!(FEEDBACK_FALSE_POSITIVE_RATE, SAMPLE_LABEL => sample).set(rate);
            }
            if let Some(coverage) = cohort.counts.coverage() {
                metrics::gauge!(FEEDBACK_COVERAGE, SAMPLE_LABEL => sample).set(coverage);
            }
        }
    }
}

/// How the exporter is configured. Resolved from env once at boot
/// ([`crate::config`]) and handed here whole.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ExporterConfig {
    pub span: Span,
    pub settle: Settle,
    pub policy: SloPolicy,
    /// How often to re-read the ledger. Minutes, not seconds: the numerator
    /// moves at human speed, and each refresh is a join over a month of
    /// incidents.
    pub refresh: Duration,
}

/// Re-measure the SLI on `cfg.refresh` until shutdown.
///
/// Runs in the `simulation-projection` binary, which is a **single writer**
/// (`Recreate`, one replica — see `deploy/k8s`): two replicas would publish two
/// versions of the same gauge and Prometheus would scrape whichever it reached,
/// so this is not a task to move into a horizontally-scaled service without
/// changing how it is aggregated.
///
/// A read failure leaves the previous gauges standing rather than zeroing them
/// — a broken ClickHouse must not read as "the platform got perfect" — and is
/// visible through [`FEEDBACK_SLI_AGE_SECONDS`], which keeps climbing until a
/// read succeeds.
pub async fn run_exporter(
    store: Arc<dyn FeedbackSliStore>,
    cfg: ExporterConfig,
    shutdown: CancellationToken,
) {
    // Published before the first read, not after: a gauge that only appears
    // once the first query succeeds is indistinguishable from an exporter that
    // was never started, which is the §15b mistake one layer up.
    metrics::gauge!(FEEDBACK_SLI_REFRESH_SECONDS).set(cfg.refresh.as_secs_f64());
    metrics::gauge!(FEEDBACK_WINDOW_SETTLE_SECONDS).set(cfg.settle.0.as_secs_f64());
    metrics::gauge!(FEEDBACK_WINDOW_SPAN_SECONDS).set(cfg.span.0.as_secs_f64());
    metrics::gauge!(FEEDBACK_CONCENTRATION_CAP).set(cfg.policy.max_customer_share);
    metrics::gauge!(FEEDBACK_SLI_AGE_SECONDS).set(0.0);
    for cohort in [FeedbackCohort::Volunteered, FeedbackCohort::Solicited] {
        let sample = cohort.as_str();
        metrics::gauge!(FEEDBACK_SLO_ARMED, SAMPLE_LABEL => sample).set(0.0);
        metrics::gauge!(FEEDBACK_FALSE_POSITIVE_TARGET, SAMPLE_LABEL => sample)
            .set(cfg.policy.target);
        metrics::gauge!(FEEDBACK_MIN_ADJUDICATIONS, SAMPLE_LABEL => sample)
            .set(cfg.policy.min_adjudications as f64);
    }

    let mut last_success = Utc::now();
    let mut ticker = tokio::time::interval(cfg.refresh);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                tracing::debug!("false-positive SLI exporter stopping");
                return;
            }
            _ = ticker.tick() => {}
        }

        let window = Window::settled(Utc::now(), cfg.span, cfg.settle);
        match store.feedback_evidence(window).await {
            Ok(evidence) => {
                let sli = Sli::new(window, evidence, cfg.policy);
                sli.publish();
                last_success = Utc::now();
                let volunteered = sli.cohort(FeedbackCohort::Volunteered);
                let solicited = sli.cohort(FeedbackCohort::Solicited);
                tracing::debug!(
                    incidents = sli.evidence.incidents,
                    volunteered_adjudicated = volunteered.counts.adjudicated,
                    solicited_adjudicated = solicited.counts.adjudicated,
                    policy = sli.policy.disagreement.as_str(),
                    armed_volunteered = volunteered.arming.is_armed(),
                    armed_solicited = solicited.arming.is_armed(),
                    "false-positive SLI refreshed"
                );
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "false-positive SLI read failed; leaving the previous values standing"
                );
            }
        }
        let age = (Utc::now() - last_success).num_milliseconds().max(0) as f64 / 1000.0;
        metrics::gauge!(FEEDBACK_SLI_AGE_SECONDS).set(age);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> SloPolicy {
        SloPolicy {
            target: 0.04,
            min_adjudications: 30,
            max_customer_share: 0.5,
            disagreement: DisagreementPolicy::AnyFalsePositive,
        }
    }

    fn window() -> Window {
        Window::settled(
            Utc::now(),
            Span(Duration::from_secs(28 * 86_400)),
            Settle(Duration::from_secs(2 * 86_400)),
        )
    }

    fn cell(cohort: FeedbackCohort, fp: bool, tp: bool, unclear: bool, n: u64) -> Cell {
        Cell {
            cohort,
            any_fp: fp,
            any_tp: tp,
            any_unclear: unclear,
            incidents: n,
        }
    }

    fn volunteered(fp: bool, tp: bool, unclear: bool, n: u64) -> Cell {
        cell(FeedbackCohort::Volunteered, fp, tp, unclear, n)
    }

    #[test]
    fn the_window_ends_before_now_by_the_settle_delay() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let w = Window::settled(
            now,
            Span(Duration::from_secs(7 * 86_400)),
            Settle(Duration::from_secs(86_400)),
        );
        assert_eq!(w.to, now - TimeDelta::days(1));
        assert_eq!(w.from, now - TimeDelta::days(8));
    }

    #[test]
    fn an_unadjudicated_window_has_no_rate_rather_than_a_perfect_one() {
        let sli = Sli::new(
            window(),
            Evidence {
                incidents: 400,
                ..Evidence::default()
            },
            policy(),
        );
        let v = sli.cohort(FeedbackCohort::Volunteered);
        assert_eq!(v.counts.false_positive_rate(), None);
        assert_eq!(v.counts.coverage(), Some(0.0));
    }

    #[test]
    fn the_rate_divides_by_adjudications_not_by_incidents() {
        // 1000 incidents, 40 looked at, 4 of those called noise. The rate is
        // 10% — the fraction of *reviewed* findings that were wrong — not the
        // 0.4% you would get by dividing into everything nobody read.
        let sli = Sli::new(
            window(),
            Evidence {
                incidents: 1000,
                cells: vec![
                    volunteered(true, false, false, 4),
                    volunteered(false, true, false, 36),
                ],
                verdicts: 40,
                top_customer_verdicts: 4,
                ..Evidence::default()
            },
            policy(),
        );
        let v = sli.cohort(FeedbackCohort::Volunteered);
        assert_eq!(v.counts.false_positive_rate(), Some(0.1));
        assert_eq!(v.counts.coverage(), Some(0.04));
    }

    #[test]
    fn an_unclear_only_incident_is_in_neither_half() {
        let sli = Sli::new(
            window(),
            Evidence {
                incidents: 100,
                cells: vec![volunteered(false, false, true, 9)],
                verdicts: 9,
                top_customer_verdicts: 1,
                ..Evidence::default()
            },
            policy(),
        );
        let v = sli.cohort(FeedbackCohort::Volunteered);
        assert_eq!(v.counts.adjudicated, 0);
        assert_eq!(v.counts.false_positive_rate(), None);
    }

    #[test]
    fn any_false_positive_wins_by_default_and_unanimity_can_be_required() {
        // One contested incident: somebody said noise, somebody said real.
        let evidence = Evidence {
            incidents: 10,
            cells: vec![volunteered(true, true, false, 1)],
            verdicts: 2,
            top_customer_verdicts: 1,
            ..Evidence::default()
        };

        let pessimistic = Sli::new(window(), evidence.clone(), policy());
        let counts = pessimistic.cohort(FeedbackCohort::Volunteered).counts;
        assert_eq!(
            (counts.adjudicated, counts.false_positives),
            (1, 1),
            "one dissenting voice makes the incident a false positive"
        );

        let unanimous = Sli::new(
            window(),
            evidence,
            SloPolicy {
                disagreement: DisagreementPolicy::RequireUnanimous,
                ..policy()
            },
        );
        let counts = unanimous.cohort(FeedbackCohort::Volunteered).counts;
        assert_eq!(
            (counts.adjudicated, counts.false_positives),
            (0, 0),
            "a contested incident is excluded from both halves, not split"
        );
    }

    #[test]
    fn cohorts_are_counted_separately_and_never_merged() {
        let sli = Sli::new(
            window(),
            Evidence {
                incidents: 100,
                cells: vec![
                    volunteered(true, false, false, 20),
                    cell(FeedbackCohort::Solicited, true, false, false, 1),
                    cell(FeedbackCohort::Solicited, false, true, false, 39),
                ],
                verdicts: 60,
                top_customer_verdicts: 10,
                ..Evidence::default()
            },
            policy(),
        );

        // Volunteered is 100% false positives (everyone who bothered was
        // complaining); solicited, over a sample nobody self-selected into, is
        // 2.5%. Merging them would report 52% and mean nothing.
        assert_eq!(
            sli.cohort(FeedbackCohort::Volunteered)
                .counts
                .false_positive_rate(),
            Some(1.0)
        );
        assert_eq!(
            sli.cohort(FeedbackCohort::Solicited)
                .counts
                .false_positive_rate(),
            Some(0.025)
        );
    }

    #[test]
    fn the_slo_is_disarmed_below_the_minimum_sample() {
        let sli = Sli::new(
            window(),
            Evidence {
                incidents: 100,
                cells: vec![
                    volunteered(true, false, false, 2),
                    volunteered(false, true, false, 2),
                ],
                verdicts: 4,
                top_customer_verdicts: 1,
                ..Evidence::default()
            },
            policy(),
        );
        let v = sli.cohort(FeedbackCohort::Volunteered);
        // A 50% rate, and it must not page anybody: it is two people's opinion.
        assert_eq!(v.counts.false_positive_rate(), Some(0.5));
        assert_eq!(
            v.arming,
            Arming::TooFewAdjudications {
                found: 4,
                needed: 30
            }
        );
    }

    #[test]
    fn one_customer_dominating_the_sample_disarms_the_slo() {
        let sli = Sli::new(
            window(),
            Evidence {
                incidents: 1000,
                cells: vec![volunteered(true, false, false, 60)],
                verdicts: 60,
                // 51 of the 60 verdicts are one tenant's — above the 50% cap.
                top_customer_verdicts: 51,
                ..Evidence::default()
            },
            policy(),
        );
        let v = sli.cohort(FeedbackCohort::Volunteered);
        assert!(matches!(v.arming, Arming::Concentrated { .. }));
        assert!(
            !v.arming.is_armed(),
            "a platform rate that is one customer's opinion must not page anyone"
        );
    }

    #[test]
    fn too_few_is_reported_before_too_concentrated() {
        // Four verdicts, all from one customer. Both conditions hold; the
        // useful thing to say is that there is almost no sample.
        let sli = Sli::new(
            window(),
            Evidence {
                incidents: 10,
                cells: vec![volunteered(true, false, false, 4)],
                verdicts: 4,
                top_customer_verdicts: 4,
                ..Evidence::default()
            },
            policy(),
        );
        assert!(matches!(
            sli.cohort(FeedbackCohort::Volunteered).arming,
            Arming::TooFewAdjudications { .. }
        ));
    }

    #[test]
    fn an_empty_sample_is_not_concentrated() {
        assert_eq!(Evidence::default().top_customer_share(), None);
    }

    #[test]
    fn publishing_omits_the_rate_when_there_is_none_and_still_declares_arming() {
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            Sli::new(
                window(),
                Evidence {
                    incidents: 12,
                    ..Evidence::default()
                },
                policy(),
            )
            .publish();
        });

        let published: Vec<String> = snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .map(|(key, _, _, _)| key.key().name().to_string())
            .collect();

        assert!(
            !published.iter().any(|n| n == FEEDBACK_FALSE_POSITIVE_RATE),
            "an unmeasured rate must be absent, not 0.0: {published:?}"
        );
        assert!(
            published.iter().any(|n| n == FEEDBACK_SLO_ARMED),
            "the arming gauge must be published even when the rate is not — an \
             alert may not infer 'switched off' from a missing series (§15b): {published:?}"
        );
        assert!(
            published.iter().any(|n| n == FEEDBACK_WINDOW_END_TIMESTAMP),
            "window provenance must be published: a rate whose window is \
             invisible can change meaning without anything looking different"
        );
    }

    #[test]
    fn both_cohorts_always_publish_an_arming_gauge() {
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            // Only volunteered verdicts exist …
            Sli::new(
                window(),
                Evidence {
                    incidents: 50,
                    cells: vec![volunteered(true, false, false, 40)],
                    verdicts: 40,
                    top_customer_verdicts: 2,
                    ..Evidence::default()
                },
                policy(),
            )
            .publish();
        });

        // … and the solicited cohort still says, explicitly, that it is not
        // armed. A missing series would have let `absent()` mean two things.
        let armed_samples: Vec<String> = snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .filter(|(key, _, _, _)| key.key().name() == FEEDBACK_SLO_ARMED)
            .map(|(key, _, _, _)| {
                key.key()
                    .labels()
                    .map(|l| l.value().to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .collect();
        assert!(
            armed_samples.iter().any(|s| s == "volunteered"),
            "{armed_samples:?}"
        );
        assert!(
            armed_samples.iter().any(|s| s == "solicited"),
            "{armed_samples:?}"
        );
    }
}
