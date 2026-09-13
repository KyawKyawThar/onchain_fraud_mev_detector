//! The load seam: what "offering load" means, independent of how.
//!
//! Two things depend on this being a trait rather than two bespoke functions.
//!
//! **The orchestrator becomes testable.** [`crate::run`] owns the ordering that
//! makes a result valid — pre-flight, warm up, baseline scrape, load, *drain*,
//! closing scrape, difference. That ordering is the part which, if silently
//! broken, produces a confidently green run: measure before the drain and the
//! p99 is the p99 of the blocks that kept up. With a seam, that procedure can
//! be driven against in-memory doubles and asserted; without one it needs Kafka,
//! a broker, a service and six minutes, so in practice it is never asserted at
//! all.
//!
//! **A third dimension becomes an `impl`.** `sim.jobs` queue depth (§7's
//! designed backpressure signal) and WebSocket subscriber fan-out are the next
//! two things worth loading, and neither should mean another bespoke function
//! with its own shape of report.
//!
//! ## Why `Offered` has optional fields rather than being an enum
//!
//! Every source can say how much load it delivered against how much it offered
//! — that is the precondition every latency verdict rests on, and the generic
//! achieved-rate gate reads exactly that. Only some sources can say more: the
//! API driver observes its own latency and response statuses; the block
//! generator observes neither, because a block's latency is the *subject's* to
//! report (that is the whole point of the fast-path metric) and a published
//! event has no status code. Modelling that as `Option` says "this source
//! cannot know" — an enum would force every gate to match on a source kind it
//! does not care about.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::scrape::Histogram;

/// Canonical source names. Gates look loads up by name, so the strings are
/// constants rather than literals scattered across two modules.
pub const CHAIN: &str = "chain";
pub const API: &str = "api";

/// The run's clock, owned by the orchestrator and handed to every source.
///
/// It is a parameter rather than something each source reads off the profile
/// because "how long does this run last" was previously answered in three
/// places — the orchestrator's warmup sleep, the block generator's schedule
/// length, and the API driver's request count — which agreed only because all
/// three happened to read the same `Profile`. Three readings of one clock is
/// two too many: a `--duration` override, an adaptive early stop, or a source
/// added later each have to find and match all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// Load offered before measurement starts. Its samples are excluded by the
    /// baseline scrape, not merely ignored.
    pub warmup: Duration,
    /// The measurement window proper.
    pub duration: Duration,
}

impl Window {
    /// Total wall time a source offers load for.
    pub fn total(&self) -> Duration {
        self.warmup + self.duration
    }

    /// The share of the offered load that falls inside the measurement window.
    ///
    /// The bridge between "what a source delivered over the whole run" and
    /// "what should have reached the subject during the part that was measured"
    /// — which is the denominator any accounting check needs, and the number
    /// that must never be taken from the *target* rate instead (see
    /// [`crate::gates`]).
    pub fn measured_share(&self) -> f64 {
        let total = self.total().as_secs_f64();
        if total <= 0.0 {
            return 0.0;
        }
        self.duration.as_secs_f64() / total
    }
}

/// One driver of load against the subject.
#[async_trait]
pub trait LoadSource: Send + Sync {
    /// Stable name ([`CHAIN`], [`API`]) — how a gate finds this source's result.
    fn name(&self) -> &'static str;

    /// Offer load for `window`, or until `shutdown` fires.
    ///
    /// Returning early on cancellation is expected, not an error: an
    /// interrupted run is a short run, and the achieved-rate gate decides
    /// whether it was long enough to conclude anything.
    async fn offer(&self, window: Window, shutdown: CancellationToken) -> Result<Offered>;
}

/// What a source actually managed — the load the verdicts describe.
#[derive(Debug, Clone, Serialize)]
pub struct Offered {
    pub source: &'static str,
    /// Unit of [`Self::target_rate`], for rendering (`blocks/s`, `qps`).
    pub unit: &'static str,
    /// Work items the schedule called for.
    pub scheduled: u64,
    /// Work items that reached the subject (published / answered).
    pub delivered: u64,
    /// Work items that did not (publish error, no HTTP response).
    pub failed: u64,
    /// The rate the profile asked for, in [`Self::unit`].
    pub target_rate: f64,
    /// Wall time the source ran for.
    #[serde(with = "crate::profile::secs_f64")]
    pub elapsed: Duration,
    /// Worst gap between a work item's due time and its actual issue.
    ///
    /// The harness's own lateness, reported because a driver that fell behind
    /// offered less load than the profile says — and because lateness is
    /// exactly the quantity whose fabrication the due-time stamping in
    /// [`crate::chain`] exists to prevent. Every source that paces on a
    /// schedule measures it; `None` would mean a source that genuinely cannot,
    /// and printing a zero there would be a fabricated measurement of the one
    /// thing this harness is most careful about.
    #[serde(with = "crate::profile::opt_secs_f64")]
    pub max_lateness: Option<Duration>,
    /// Client-observed latency, where the source can measure it.
    #[serde(skip)]
    pub latency: Option<Histogram>,
    /// Client-observed latency of *successful* responses, per route template.
    ///
    /// A route that carries its own budget (`/screen`'s p50/p99) cannot be
    /// judged from [`Self::latency`]: that histogram is a weighted mix, and the
    /// cheapest route in the mix drags every quantile toward itself. Empty for a
    /// source without routes.
    #[serde(skip)]
    pub route_latency: BTreeMap<String, Histogram>,
    /// Response outcomes, where the source has them.
    pub outcomes: Option<Outcomes>,
}

/// Response statuses, for a source that gets responses.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Outcomes {
    pub succeeded: u64,
    pub client_errors: u64,
    pub server_errors: u64,
}

impl Offered {
    /// An empty result for a source that was configured away. Distinguishable
    /// from a source that ran and delivered nothing by `scheduled == 0`, which
    /// is what lets the API gate tell "pointed at no API" from "the API could
    /// not keep up" — two failures that want two different messages.
    pub fn none(source: &'static str, unit: &'static str, target_rate: f64) -> Self {
        Self {
            source,
            unit,
            scheduled: 0,
            delivered: 0,
            failed: 0,
            target_rate,
            elapsed: Duration::ZERO,
            max_lateness: None,
            latency: None,
            route_latency: BTreeMap::new(),
            outcomes: None,
        }
    }

    /// Work items per second actually delivered.
    pub fn achieved_rate(&self) -> f64 {
        if self.elapsed.is_zero() {
            return 0.0;
        }
        self.delivered as f64 / self.elapsed.as_secs_f64()
    }

    /// Delivered rate as a share of the offered rate.
    pub fn achieved_ratio(&self) -> f64 {
        if self.target_rate <= 0.0 {
            return 0.0;
        }
        self.achieved_rate() / self.target_rate
    }

    /// True when the source never issued anything — a harness misconfiguration
    /// rather than a finding about the subject.
    pub fn never_ran(&self) -> bool {
        self.scheduled == 0
    }

    /// Share of answered requests that succeeded. `None` when the source has no
    /// notion of success, or answered nothing: reporting `0.0` there would look
    /// like a total outage rather than a run that never started.
    pub fn success_ratio(&self) -> Option<f64> {
        let outcomes = self.outcomes?;
        let answered = outcomes.succeeded + outcomes.client_errors + outcomes.server_errors;
        (answered > 0).then(|| outcomes.succeeded as f64 / answered as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offered(delivered: u64, elapsed_secs: u64, target: f64) -> Offered {
        Offered {
            scheduled: delivered,
            delivered,
            elapsed: Duration::from_secs(elapsed_secs),
            target_rate: target,
            ..Offered::none(CHAIN, "blocks/s", target)
        }
    }

    #[test]
    fn the_measured_share_is_the_part_of_a_run_that_counts() {
        let w = Window {
            warmup: Duration::from_secs(30),
            duration: Duration::from_secs(270),
        };
        assert_eq!(w.total(), Duration::from_secs(300));
        assert_eq!(w.measured_share(), 0.9);
    }

    #[test]
    fn a_zero_length_window_shares_nothing_rather_than_dividing_by_zero() {
        let w = Window {
            warmup: Duration::ZERO,
            duration: Duration::ZERO,
        };
        assert_eq!(w.measured_share(), 0.0);
    }

    #[test]
    fn achieved_ratio_is_the_precondition_for_believing_a_latency() {
        let o = offered(30, 10, 6.0);
        assert_eq!(o.achieved_rate(), 3.0);
        assert_eq!(o.achieved_ratio(), 0.5);
    }

    #[test]
    fn a_source_that_never_ran_reports_zero_not_a_division_by_zero() {
        let none = Offered::none(API, "qps", 100.0);
        assert_eq!(none.achieved_rate(), 0.0);
        assert_eq!(none.achieved_ratio(), 0.0);
        assert!(none.never_ran());
    }

    #[test]
    fn a_source_that_ran_and_delivered_nothing_is_not_a_source_that_never_ran() {
        let ran_badly = Offered {
            scheduled: 100,
            delivered: 0,
            elapsed: Duration::from_secs(10),
            ..Offered::none(API, "qps", 10.0)
        };
        assert!(!ran_badly.never_ran(), "these want different messages");
    }

    #[test]
    fn a_source_with_no_notion_of_success_has_no_success_ratio() {
        assert_eq!(offered(10, 1, 10.0).success_ratio(), None);
    }

    #[test]
    fn success_ratio_counts_every_answered_request_not_just_the_good_ones() {
        let o = Offered {
            outcomes: Some(Outcomes {
                succeeded: 90,
                client_errors: 5,
                server_errors: 5,
            }),
            ..offered(100, 1, 100.0)
        };
        assert_eq!(o.success_ratio(), Some(0.9));
    }
}
