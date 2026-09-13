//! The gates: every rule that can change the exit code, in one enumerable list.
//!
//! ## Why a registry and not seven free functions
//!
//! `slo.json` is a struct of budgets; the gates that read it were free
//! functions. Nothing connected the two, so adding a budget and forgetting its
//! gate was **silent** — the field would sit in a committed file, be discussed
//! in review, and do nothing at run time. That is the same failure the
//! copilot's `CheckRegistry` was built for ("adding a kind and forgetting its
//! answer-check fell through a `match` arm and reached a customer"), and it is
//! not hypothetical here: Epic D's next item is the §11 screening **p50 <
//! 100ms**, which arrives as a new `slo.json` field.
//!
//! So each rule declares the budgets it consumes ([`GateRule::budgets`]), and
//! [`every_committed_budget_is_read_by_a_gate`] walks the serialized `Slo` and
//! fails the build if a field is unclaimed — or if a rule claims a field that
//! does not exist, which catches the typo in the other direction.
//!
//! ## Not-applicable is `None`, not a passing gate
//!
//! [`GateRule::evaluate`] returns `Option<Gate>`. A profile with `api_qps: 0`
//! has no API gates *at all*, rather than three that quietly hold. The
//! distinction matters for the nightly job: its `ci-fastpath` profile drives no
//! API deliberately, and "this run does not cover that" must not look like
//! "that was measured and was fine" — nor like the inconclusive that means
//! something went wrong.

use crate::profile::Profile;
use crate::report::Gate;
use crate::run::Drain;
use crate::scrape::Histogram;
use crate::slo::{LatencyBudget, Measured, Slo, Verdict};
use crate::source::{self, Offered};

/// The share of samples a p99 budget requires. Named because it appears in
/// every latency gate and in their messages, and a `0.99` typed four times is a
/// `0.9` waiting to happen.
pub const P99: f64 = 0.99;

/// Everything a gate is allowed to look at.
pub struct RunData<'a> {
    pub profile: &'a Profile,
    pub slo: &'a Slo,
    /// One entry per configured [`crate::source::LoadSource`].
    pub offered: &'a [Offered],
    /// The fast-path series over the measurement window.
    pub window: &'a crate::run::FastPathWindow,
    /// The share of each source's delivered load that falls inside the
    /// measurement window ([`crate::source::Window::measured_share`]) — the
    /// factor that turns "delivered over the whole run" into the denominator an
    /// accounting check needs.
    pub window_share: f64,
    pub drain: &'a Drain,
    /// The API service's screening counters over the window, when scraped.
    pub screening: Option<&'a crate::run::ScreeningCounters>,
}

impl<'a> RunData<'a> {
    /// The named source's result, or `None` if this run had no such source.
    ///
    /// Borrows from the run's data (`'a`), not from `&self`, so a gate can hold
    /// the reference across its own logic without the `RunData` borrow tagging
    /// along.
    pub fn source(&self, name: &str) -> Option<&'a Offered> {
        self.offered.iter().find(|o| o.source == name)
    }
}

/// What a gate is for.
///
/// The distinction is not cosmetic: a `Claim` verdict is only meaningful if
/// every `Precondition` held. A run that offered 52% of its target load and
/// reported `fast_path_p99: HELD` beside `chain_load_achieved: UNKNOWN` has a
/// correct exit code (2) and a **misleading report** — someone skimming for the
/// green line finds one. [`crate::report::Report`] uses this to say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Establishes that the run measured what it claims to have measured: the
    /// load arrived, the work came back out, the pipeline caught up.
    Precondition,
    /// A published budget about the platform.
    Claim,
}

/// One rule that can change the exit code.
pub trait GateRule: Send + Sync {
    /// Stable id, so a CI job can grep for one result without parsing prose.
    fn id(&self) -> &'static str;

    /// Whether this rule validates the run or judges the platform.
    fn category(&self) -> Category;

    /// The `slo.json` field names this rule reads.
    ///
    /// Empty is legitimate and means "this gate has no committed budget" — a
    /// precondition like "did the pipeline drain", whose bar is a property of
    /// the procedure rather than a number someone tuned.
    fn budgets(&self) -> &'static [&'static str];

    /// Judge the run, or `None` if this gate does not apply to it.
    fn evaluate(&self, run: &RunData<'_>) -> Option<Gate>;
}

/// Every gate, in report order. Adding one here is the only way to add a rule
/// that can fail a run.
pub const RULES: &[&dyn GateRule] = &[
    &ChainLoadAchieved,
    &ApiLoadAchieved,
    &ApiSuccessRatio,
    &ApiLatency,
    &SCREEN_P50,
    &SCREEN_P99,
    &ScreenFailedClosed,
    &BlocksAccountedFor,
    &PipelineDrained,
    &FastPathLatency,
];

/// Run every applicable rule.
///
/// The registry stamps each gate's category rather than trusting the rule's own
/// constructor to, so a new rule cannot ship mis-filed — the same reason the
/// budget declarations are checked here rather than trusted.
pub fn evaluate(run: &RunData<'_>) -> Vec<Gate> {
    RULES
        .iter()
        .filter_map(|rule| {
            rule.evaluate(run)
                .map(|gate| gate.in_category(rule.category()))
        })
        .collect()
}

// ── Preconditions: was the subject actually loaded? ──────────────────

/// The generator delivered the block rate the profile asked for.
struct ChainLoadAchieved;

impl GateRule for ChainLoadAchieved {
    fn category(&self) -> Category {
        Category::Precondition
    }

    fn id(&self) -> &'static str {
        "chain_load_achieved"
    }

    fn budgets(&self) -> &'static [&'static str] {
        &["min_achieved_ratio"]
    }

    fn evaluate(&self, run: &RunData<'_>) -> Option<Gate> {
        let chain = run.source(source::CHAIN)?;
        Some(Gate::new(
            self.id(),
            format!(
                "generator delivered ≥ {:.0}% of {:.2} blocks/s ({:.0} tps)",
                run.slo.min_achieved_ratio * 100.0,
                run.profile.blocks_per_second,
                run.profile.chain_tps()
            ),
            achieved_verdict(chain, run.slo.min_achieved_ratio, None),
        ))
    }
}

/// The API driver delivered the qps the profile asked for.
struct ApiLoadAchieved;

impl GateRule for ApiLoadAchieved {
    fn category(&self) -> Category {
        Category::Precondition
    }

    fn id(&self) -> &'static str {
        "api_load_achieved"
    }

    fn budgets(&self) -> &'static [&'static str] {
        &["min_achieved_ratio"]
    }

    fn evaluate(&self, run: &RunData<'_>) -> Option<Gate> {
        let api = applicable_api(run)?;
        Some(Gate::new(
            self.id(),
            format!(
                "driver delivered ≥ {:.0}% of {:.0} qps",
                run.slo.min_achieved_ratio * 100.0,
                run.profile.api_qps
            ),
            achieved_verdict(
                api,
                run.slo.min_achieved_ratio,
                Some(
                    "no API load was offered: this profile asks for API traffic but \
                     LOADTEST_API_BASE_URL is unset, so the driver never started. Set it, \
                     or use a profile with `api_qps: 0` for a deliberate fast-path-only run",
                ),
            ),
        ))
    }
}

/// Enough of the offered load actually arrived to believe a latency measured
/// under it.
///
/// Deliberately **inconclusive**, never a breach: the harness failing to offer
/// load says nothing about the platform's latency, and reporting it as a
/// platform failure sends someone to profile the wrong process.
fn achieved_verdict(
    offered: &Offered,
    floor: f64,
    never_ran_reason: Option<&'static str>,
) -> Verdict {
    if let (true, Some(reason)) = (offered.never_ran(), never_ran_reason) {
        return Verdict::inconclusive(reason);
    }
    let ratio = offered.achieved_ratio();
    let measured = Measured::Rate {
        achieved: offered.achieved_rate(),
        target: offered.target_rate,
        unit: offered.unit,
    };
    if ratio >= floor {
        Verdict::Held { measured }
    } else {
        Verdict::inconclusive(format!(
            "{measured} — the latency numbers describe a system at that lower rate, \
             not at target"
        ))
    }
}

/// Roughly as many blocks came out of the fast path as actually went in.
///
/// The gap this closes: `min_alert_samples` only asks whether there were
/// *enough* samples to compute a percentile. A pipeline that silently dropped
/// half the offered blocks — a chain-id mismatch making every record a
/// commit-only pass, a decode failure parking records on the DLQ, a topic
/// nobody is subscribed to — can still clear that bar with the half that
/// survived, and those survivors are exactly the blocks that had a quiet
/// pipeline to run in. The p99 would be real, fast, and about a system doing
/// half the work.
///
/// **The denominator is what the generator delivered, not what the profile
/// asked for.** Getting that wrong is not a rounding error, it is a wrong
/// accusation: on a run where the broker died and only 52% of the target load
/// reached Kafka, dividing by the target produced *"blocks are being lost
/// before they are timed … check the DLQ"* — for blocks that were never sent.
/// Nothing was lost, and the report sent its reader to the wrong subsystem
/// while `chain_load_achieved` beside it already said exactly what had
/// happened. A gate that cannot distinguish "never offered" from "offered and
/// dropped" is worse than no gate, because the two have nothing in common
/// except the number.
struct BlocksAccountedFor;

/// Share of offered blocks that must reappear as fast-path samples.
///
/// Looser than the SLO's achieved-load ratio on purpose. The measurement window
/// is bounded by two scrapes, not by the block schedule, so blocks in flight
/// across either boundary land on one side or the other; at a few seconds of
/// pipeline depth that is a small single-digit percentage, and a tight bound
/// here would flag clock boundaries as data loss.
const MIN_ACCOUNTED: f64 = 0.9;

impl GateRule for BlocksAccountedFor {
    fn category(&self) -> Category {
        Category::Precondition
    }

    fn id(&self) -> &'static str {
        "blocks_accounted_for"
    }

    fn budgets(&self) -> &'static [&'static str] {
        // The floor is a property of the measurement's boundary effects, not a
        // service level anyone negotiated — so it is a const above, not a
        // committed budget someone might "tune".
        &[]
    }

    fn evaluate(&self, run: &RunData<'_>) -> Option<Gate> {
        // No chain source ⇒ nothing was offered ⇒ nothing to account for. Not a
        // gate that holds, and emphatically not one computed against a profile
        // number no driver ever acted on.
        let chain = run.source(source::CHAIN)?;
        if chain.never_ran() {
            return None;
        }

        // What the generator actually put on the wire, scaled to the part of
        // the run that was measured.
        let expected = chain.delivered as f64 * run.window_share;
        let observed = run.window.total_samples() as f64;
        if expected <= 0.0 {
            return Some(Gate::new(
                self.id(),
                "blocks delivered to the subject came back out of the fast path",
                Verdict::inconclusive(
                    "the generator delivered no blocks at all, so there is nothing to \
                     account for — see the chain load gate",
                ),
            ));
        }
        let ratio = observed / expected;

        Some(Gate::new(
            self.id(),
            format!(
                "≥ {:.0}% of the blocks *delivered* during the measurement window came \
                 out of the fast path",
                MIN_ACCOUNTED * 100.0
            ),
            if ratio >= MIN_ACCOUNTED {
                Verdict::Held {
                    measured: Measured::Share(ratio),
                }
            } else {
                Verdict::inconclusive(format!(
                    "{observed:.0} fast-path samples for ~{expected:.0} blocks delivered \
                     ({:.0}%) — these blocks reached the broker and did not come back \
                     out, so they are being lost inside the pipeline and the latency \
                     describes only the ones that made it. Check that the profile's \
                     chain ({}) matches the detection instance's CHAIN_ID (a foreign \
                     chain is a commit-only pass, §20), and check the DLQ",
                    ratio * 100.0,
                    run.profile.chain,
                ))
            },
        ))
    }
}

/// The pipeline caught up with the offered load before anything was measured.
///
/// Inconclusive rather than a breach when it did not, because the samples that
/// would have decided it were never taken — but never silent, since the p99
/// beside it was computed over the blocks that *did* keep up.
struct PipelineDrained;

impl GateRule for PipelineDrained {
    fn category(&self) -> Category {
        Category::Precondition
    }

    fn id(&self) -> &'static str {
        "pipeline_drained"
    }

    fn budgets(&self) -> &'static [&'static str] {
        &[]
    }

    fn evaluate(&self, run: &RunData<'_>) -> Option<Gate> {
        Some(Gate::new(
            self.id(),
            "the pipeline caught up with the offered load before measuring",
            match run.drain {
                Drain::Settled { .. } => Verdict::Held {
                    measured: Measured::Settled(true),
                },
                Drain::TimedOut { waited, .. } => Verdict::inconclusive(format!(
                    "fast-path samples were still arriving {}s after the load stopped — \
                     detection never caught up, so the p99 describes only the blocks that \
                     kept up",
                    waited.as_secs()
                )),
            },
        ))
    }
}

// ── The claims themselves ────────────────────────────────────────────

/// §6: a preliminary alert within one second, at p99, under load.
struct FastPathLatency;

impl GateRule for FastPathLatency {
    fn category(&self) -> Category {
        Category::Claim
    }

    fn id(&self) -> &'static str {
        "fast_path_p99"
    }

    fn budgets(&self) -> &'static [&'static str] {
        &["fast_path_p99_seconds", "min_alert_samples"]
    }

    fn evaluate(&self, run: &RunData<'_>) -> Option<Gate> {
        Some(Gate::new(
            self.id(),
            format!(
                "§6 fast path p99 < {}s (block → preliminary alert, under load)",
                run.slo.fast_path_p99_seconds
            ),
            fast_path_verdict(run.slo, &run.window.alerting),
        ))
    }
}

/// The §6 verdict, given the measured alerting window. Free rather than a
/// method so the load-test's own tests can exercise the rule on a hand-built
/// histogram without assembling a whole [`RunData`].
pub fn fast_path_verdict(slo: &Slo, alerting: &Histogram) -> Verdict {
    if alerting.count < slo.min_alert_samples {
        return Verdict::inconclusive(format!(
            "only {} alerting fast-path samples (need {}) — a p99 over this few samples \
             moves a full bucket per sample; is the detector roster firing? a build \
             without detection's `demo` feature produces none on header-only blocks",
            alerting.count, slo.min_alert_samples
        ));
    }
    Verdict::share_at_least(
        alerting.share_at_most(slo.fast_path_p99_seconds.seconds()),
        P99,
        format!(
            "the exported histogram has no bucket boundary at {}s, so this threshold \
             cannot be decided from it",
            slo.fast_path_p99_seconds
        ),
    )
}

/// Client-observed API p99 (§19's API panel).
struct ApiLatency;

impl GateRule for ApiLatency {
    fn category(&self) -> Category {
        Category::Claim
    }

    fn id(&self) -> &'static str {
        "api_p99"
    }

    fn budgets(&self) -> &'static [&'static str] {
        &["api_p99_seconds"]
    }

    fn evaluate(&self, run: &RunData<'_>) -> Option<Gate> {
        let api = applicable_api(run)?;
        let share = api
            .latency
            .as_ref()
            .and_then(|h| h.share_at_most(run.slo.api_p99_seconds.seconds()));
        Some(Gate::new(
            self.id(),
            format!("client-observed API p99 < {}s", run.slo.api_p99_seconds),
            Verdict::share_at_least(share, P99, "no API latency samples"),
        ))
    }
}

/// The route whose latency is contractual (§11): `/screen` sits inline on
/// customer withdrawals. Matched against a profile's path *template*.
pub const SCREEN_ROUTE: &str = "/v1/address/{address}/screen";

/// §11/§19: the screening decision's p50 (< 100ms, contractual) and its bounded
/// p99 (readiness Epic D), over that route's successful responses alone.
///
/// **Per route**, because the aggregate API histogram is a weighted mix and the
/// cheapest route drags every quantile toward itself — a cached `/labels` read
/// can hold the aggregate p50 under 100ms while every screening call misses it.
/// **Successes only**, because a 429 or a fail-closed 502 answers in
/// microseconds and is not a decision; counting them would let a throttled or
/// broken endpoint report its best latency ever. `api_success_ratio` already
/// says how many there were. A stale-but-flagged answer (`server::degrade`) is
/// a 2xx decision and counts, as it should: it is what the customer waited for.
struct ScreenLatency {
    id: &'static str,
    budget_fields: &'static [&'static str],
    label: &'static str,
    quantile: f64,
    budget: fn(&Slo) -> LatencyBudget,
}

const SCREEN_P50: ScreenLatency = ScreenLatency {
    id: "screen_p50",
    budget_fields: &["screen_p50_seconds"],
    label: "p50",
    quantile: 0.5,
    budget: screen_p50_budget,
};

const SCREEN_P99: ScreenLatency = ScreenLatency {
    id: "screen_p99",
    budget_fields: &["screen_p99_seconds"],
    label: "p99",
    quantile: P99,
    budget: screen_p99_budget,
};

fn screen_p50_budget(slo: &Slo) -> LatencyBudget {
    slo.screen_p50_seconds
}

fn screen_p99_budget(slo: &Slo) -> LatencyBudget {
    slo.screen_p99_seconds
}

impl GateRule for ScreenLatency {
    fn category(&self) -> Category {
        Category::Claim
    }

    fn id(&self) -> &'static str {
        self.id
    }

    fn budgets(&self) -> &'static [&'static str] {
        self.budget_fields
    }

    fn evaluate(&self, run: &RunData<'_>) -> Option<Gate> {
        let api = applicable_api(run)?;
        // A profile that never screens has no screening gate — not one that
        // quietly holds.
        let screens = run
            .profile
            .api_routes
            .iter()
            .any(|route| route.path == SCREEN_ROUTE && route.weight > 0);
        if !screens {
            return None;
        }
        let budget = (self.budget)(run.slo);
        let share = api
            .route_latency
            .get(SCREEN_ROUTE)
            .and_then(|h| h.share_at_most(budget.seconds()));
        Some(Gate::new(
            self.id,
            format!(
                "§11 screening {} < {budget}s (successful /screen responses, under load)",
                self.label
            ),
            Verdict::share_at_least(
                share,
                self.quantile,
                "no successful /screen responses to time — check api_success_ratio, and \
                 SCREENING_RATE_LIMIT_PER_MINUTE on the subject (the default throttles any \
                 single-identity load above ~2 qps)",
            ),
        ))
    }
}

/// Readiness Epic D, under an injected intelligence fault: withdrawals got a
/// decision — fresh, or stale and flagged — rather than a fail-closed 502.
///
/// Only applies to a profile that injects a fault. And it refuses to hold
/// vacuously: if nothing left the fresh path, the fault never reached the
/// screening read (the subject was not pointed at the proxy, or the injected
/// latency sat under its fresh budget), and "no call failed closed" describes a
/// healthy system, not a degraded one.
struct ScreenFailedClosed;

impl GateRule for ScreenFailedClosed {
    fn category(&self) -> Category {
        Category::Claim
    }

    fn id(&self) -> &'static str {
        "screen_failed_closed"
    }

    fn budgets(&self) -> &'static [&'static str] {
        &["max_screen_failed_closed_share"]
    }

    fn evaluate(&self, run: &RunData<'_>) -> Option<Gate> {
        run.profile.fault?;
        let description = format!(
            "under the injected fault, ≥ {:.1}% of screening calls got a decision (fresh or \
             stale-but-flagged) instead of failing closed",
            (1.0 - run.slo.max_screen_failed_closed_share) * 100.0
        );
        let verdict = match run.screening {
            None => Verdict::inconclusive(
                "the profile injects a fault but the API service's screening counters were \
                 not scraped — set LOADTEST_API_METRICS_URL",
            ),
            Some(counters) if counters.degraded() == 0.0 => Verdict::inconclusive(
                "no screening call left the fresh path, so the fault never reached it — is the \
                 subject's INTELLIGENCE_GRPC_ADDR the proxy, and is the injected latency above \
                 its fresh budget?",
            ),
            Some(counters) => Verdict::share_at_least(
                counters.decided_share(),
                1.0 - run.slo.max_screen_failed_closed_share,
                "the API service handled no screening calls",
            ),
        };
        Some(Gate::new(self.id(), description, verdict))
    }
}

/// Enough API responses succeeded that the latency above describes the API
/// rather than its error path.
struct ApiSuccessRatio;

impl GateRule for ApiSuccessRatio {
    fn category(&self) -> Category {
        Category::Precondition
    }

    fn id(&self) -> &'static str {
        "api_success_ratio"
    }

    fn budgets(&self) -> &'static [&'static str] {
        &["min_api_success_ratio"]
    }

    fn evaluate(&self, run: &RunData<'_>) -> Option<Gate> {
        let api = applicable_api(run)?;
        Some(Gate::new(
            self.id(),
            format!(
                "≥ {:.0}% of API responses were 2xx",
                run.slo.min_api_success_ratio * 100.0
            ),
            Verdict::share_at_least(
                api.success_ratio(),
                run.slo.min_api_success_ratio,
                "no API request was answered — errors are cheap and fast, so a latency \
                 measured over them would be meaningless",
            ),
        ))
    }
}

/// The API source, when this profile asked for API load at all.
///
/// `None` — no gate — when `api_qps` is 0: a fast-path-only profile does not
/// cover the API, and saying nothing is the honest report. A driver that was
/// *configured* to run and did not still yields a gate, because that is a
/// misconfiguration worth reporting.
fn applicable_api<'a>(run: &RunData<'a>) -> Option<&'a Offered> {
    (run.profile.api_qps > 0.0)
        .then(|| run.source(source::API))
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    /// The point of the registry.
    ///
    /// Fails in both directions: a budget added to `slo.json` that no rule
    /// reads (it would look enforced in review and do nothing), and a rule
    /// claiming a field that does not exist (a typo, which would silently
    /// stop protecting anything the day the field is renamed).
    #[test]
    fn every_committed_budget_is_read_by_a_gate() {
        let slo = Slo::load(&Slo::committed_path()).expect("slo.json must be valid");
        let value = serde_json::to_value(&slo).expect("Slo serializes");
        let committed: BTreeSet<String> = value
            .as_object()
            .expect("Slo is a JSON object")
            .keys()
            .cloned()
            .collect();

        let claimed: BTreeSet<String> = RULES
            .iter()
            .flat_map(|rule| rule.budgets())
            .map(|field| (*field).to_owned())
            .collect();

        assert_eq!(
            committed, claimed,
            "every slo.json field must be read by some GateRule, and every budget a \
             rule claims must exist. Left-only = a budget nobody enforces; right-only \
             = a rule reading a field that is gone"
        );
    }

    mod screening {
        use std::time::Duration;

        use super::super::*;
        use crate::profile::{ApiRoute, Method};
        use crate::run::FastPathWindow;
        use crate::scrape::OrderedBound;

        fn api_profile(paths: &[&str]) -> Profile {
            Profile {
                name: "t".into(),
                rationale: "t".into(),
                chain: 1,
                blocks_per_second: 1.0,
                txs_per_block: 1,
                alerting_block_fraction: 1.0,
                api_qps: 10.0,
                api_routes: paths
                    .iter()
                    .map(|path| ApiRoute {
                        path: (*path).into(),
                        weight: 1,
                        method: Method::Post,
                        body: None,
                    })
                    .collect(),
                warmup: Duration::from_secs(1),
                duration: Duration::from_secs(1),
                drain_timeout: Duration::from_secs(1),
                address_pool: None,
                fault: None,
            }
        }

        /// A `/screen` histogram: `under_100ms` samples at or below 0.1s,
        /// `under_250ms` (cumulative) at or below 0.25s, out of `total`.
        fn screen_histogram(under_100ms: u64, under_250ms: u64, total: u64) -> Histogram {
            Histogram {
                buckets: [
                    (OrderedBound(0.1), under_100ms),
                    (OrderedBound(0.25), under_250ms),
                ]
                .into_iter()
                .collect(),
                count: total,
                sum: 0.0,
            }
        }

        fn api_offered(screen: Option<Histogram>) -> Offered {
            Offered {
                source: source::API,
                unit: "qps",
                scheduled: 1000,
                delivered: 1000,
                failed: 0,
                target_rate: 10.0,
                elapsed: Duration::from_secs(100),
                max_lateness: Some(Duration::ZERO),
                latency: None,
                route_latency: screen
                    .into_iter()
                    .map(|h| (SCREEN_ROUTE.to_owned(), h))
                    .collect(),
                outcomes: None,
            }
        }

        /// Judge against the committed budgets, so a retuned `slo.json` is what
        /// these expectations are read against.
        fn judge(rule: &dyn GateRule, profile: &Profile, offered: Offered) -> Option<Gate> {
            judge_with(rule, profile, offered, None)
        }

        fn judge_with(
            rule: &dyn GateRule,
            profile: &Profile,
            offered: Offered,
            screening: Option<crate::run::ScreeningCounters>,
        ) -> Option<Gate> {
            let slo = Slo::load(&Slo::committed_path()).expect("slo.json must be valid");
            let offered = [offered];
            let window = FastPathWindow::default();
            let drain = Drain::Settled {
                waited: Duration::from_secs(1),
            };
            rule.evaluate(&RunData {
                profile,
                slo: &slo,
                offered: &offered,
                window: &window,
                window_share: 1.0,
                drain: &drain,
                screening: screening.as_ref(),
            })
        }

        fn faulted(mut profile: Profile) -> Profile {
            profile.address_pool = Some(100);
            profile.fault = Some(crate::profile::Fault {
                intelligence_latency_ms: 300,
            });
            profile
        }

        fn counters(fresh: f64, stale: f64, failed_closed: f64) -> crate::run::ScreeningCounters {
            crate::run::ScreeningCounters {
                fresh,
                stale,
                failed_closed,
            }
        }

        #[test]
        fn the_failed_closed_gate_applies_only_to_a_faulted_profile() {
            let healthy = api_profile(&[SCREEN_ROUTE]);
            assert!(judge_with(
                &ScreenFailedClosed,
                &healthy,
                api_offered(None),
                Some(counters(10.0, 0.0, 0.0))
            )
            .is_none());
        }

        #[test]
        fn the_failed_closed_gate_holds_breaches_and_refuses_a_fault_that_never_landed() {
            let profile = faulted(api_profile(&[SCREEN_ROUTE]));
            let judge_counters =
                |c| judge_with(&ScreenFailedClosed, &profile, api_offered(None), c).unwrap();

            let served = judge_counters(Some(counters(100.0, 895.0, 5.0)));
            assert!(
                matches!(served.verdict, Verdict::Held { .. }),
                "{:?}",
                served.verdict
            );

            assert!(judge_counters(Some(counters(100.0, 700.0, 200.0)))
                .verdict
                .is_breach());

            assert!(
                judge_counters(Some(counters(1000.0, 0.0, 0.0)))
                    .verdict
                    .is_inconclusive(),
                "a healthy run is not a degraded pass"
            );
            assert!(judge_counters(None).verdict.is_inconclusive());
        }

        #[test]
        fn a_profile_that_never_screens_has_no_screening_gate() {
            let profile = api_profile(&["/v1/incidents"]);
            assert!(judge(&SCREEN_P50, &profile, api_offered(None)).is_none());
            assert!(judge(&SCREEN_P99, &profile, api_offered(None)).is_none());
        }

        #[test]
        fn p50_and_p99_are_judged_on_their_own_budgets() {
            let profile = api_profile(&[SCREEN_ROUTE]);

            let healthy = screen_histogram(600, 995, 1000);
            let p50 = judge(&SCREEN_P50, &profile, api_offered(Some(healthy.clone()))).unwrap();
            let p99 = judge(&SCREEN_P99, &profile, api_offered(Some(healthy))).unwrap();
            assert!(
                matches!(p50.verdict, Verdict::Held { .. }),
                "{:?}",
                p50.verdict
            );
            assert!(
                matches!(p99.verdict, Verdict::Held { .. }),
                "{:?}",
                p99.verdict
            );

            // The contractual failure the aggregate cannot see: most screening
            // calls over 100ms while the tail is still bounded.
            let slow_median = screen_histogram(400, 995, 1000);
            let p50 = judge(
                &SCREEN_P50,
                &profile,
                api_offered(Some(slow_median.clone())),
            )
            .unwrap();
            let p99 = judge(&SCREEN_P99, &profile, api_offered(Some(slow_median))).unwrap();
            assert!(p50.verdict.is_breach());
            assert!(matches!(p99.verdict, Verdict::Held { .. }));

            // And the unbounded tail with a healthy median.
            let long_tail = screen_histogram(900, 950, 1000);
            let p99 = judge(&SCREEN_P99, &profile, api_offered(Some(long_tail))).unwrap();
            assert!(p99.verdict.is_breach());
        }

        #[test]
        fn a_screening_profile_with_nothing_to_time_is_inconclusive_not_green() {
            let profile = api_profile(&[SCREEN_ROUTE]);
            let gate = judge(&SCREEN_P50, &profile, api_offered(None))
                .expect("the profile screens, so the gate applies");
            assert!(gate.verdict.is_inconclusive());

            let gate = judge(
                &SCREEN_P99,
                &profile,
                api_offered(Some(screen_histogram(0, 0, 0))),
            )
            .unwrap();
            assert!(gate.verdict.is_inconclusive());
        }
    }

    #[test]
    fn gate_ids_are_unique_so_a_ci_job_can_grep_for_one() {
        let ids: BTreeSet<&str> = RULES.iter().map(|r| r.id()).collect();
        assert_eq!(ids.len(), RULES.len());
    }
}
