//! Per-customer token budget **alarms** (§13, Sprint 20 t5).
//!
//! # An alarm, not a quota — and the distinction is the design
//!
//! This product meters usage and never gates on it (all features to all users,
//! no tiers). A per-customer ceiling enforced at request time would be quota
//! enforcement by another name, which is why `llm::admission`'s spend ceiling
//! is deliberately **platform-wide**: it is a runaway-loop safety valve, not a
//! per-tenant limit. `llm::admission`'s own module docs close with the sentence
//! this module implements — *"per-customer spend stays a metering question
//! answered from the `UsageRecorded` stream, with alarms"*.
//!
//! So nothing here refuses a call, cancels work, or reaches back into the LLM
//! seam. It reads what was already metered and tells a human when one
//! customer's token spend has gone somewhere nobody expected. Whether that is
//! a stuck retry loop, a backfill pointed at the wrong window, or a customer
//! who is simply using the product hard, is a judgement a person makes.
//!
//! # Why it lives here
//!
//! `UsageRecorded` has one producer path and one sink (§13). Answering "how
//! many tokens has this customer spent" anywhere else would mean a second view
//! of a number the platform already has one view of — and the two would
//! eventually disagree, at which point neither is evidence of anything.
//!
//! # The customer id is a log field, never a metric label
//!
//! Customer ids are an unbounded set; a `customer` label on a Prometheus series
//! is a cardinality incident waiting for the first busy month. The metrics here
//! therefore carry `{level, scope}` only, and answer *"is anyone over budget,
//! and how far"*. **Which** customer is a question for the log line each alarm
//! writes, and for `usage budget`, the subcommand that prints the table. That
//! is the same split §19 already makes for the LLM seam's refusal categories.
//!
//! # Accuracy, stated rather than assumed
//!
//! Spend is read from `usage_rollup_daily`, whose header is honest about being
//! approximate: its materialized view fires on raw inserts, so a batch
//! redelivered after a crash between flush and commit double-counts there. That
//! is bounded to one batch and irrelevant at the scale a token budget is set
//! at — an alarm is a "look at this" signal, not an invoice. Anything that must
//! be exact reads `usage_events` with `count(DISTINCT event_id)`, and this
//! module deliberately does not, because an exact read of the raw table is a
//! full scan of the largest table in the system on a timer.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::system::UsageEventType;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::store::{StoreError, UsageStore, NIL_CUSTOMER};

/// Default window a budget is expressed over.
pub const DEFAULT_WINDOW_DAYS: u32 = 30;

/// Default gap between evaluations. Minutes, not seconds: this reads an
/// aggregate over a month of data to answer a question whose answer changes on
/// the scale of hours.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// Default share of the budget at which a warning is raised.
pub const DEFAULT_WARN_RATIO: f64 = 0.8;

/// Default cap on customers named in one report.
pub const DEFAULT_MAX_REPORTED: usize = 20;

/// Every token SKU that counts against a budget — the four live ones and the
/// four half-price batch ones (§20.4).
///
/// Enumerated rather than matched on a `llm_` prefix: a prefix is a convention
/// that a new SKU silently opts into or out of, and either mistake is a budget
/// that quietly stops counting something. A new variant on
/// [`UsageEventType`] that belongs here has to be added here, and the test
/// below is what says so.
pub const TOKEN_SKUS: &[UsageEventType] = &[
    UsageEventType::LlmInputTokens,
    UsageEventType::LlmOutputTokens,
    UsageEventType::LlmCacheWriteTokens,
    UsageEventType::LlmCacheReadTokens,
    UsageEventType::LlmBatchInputTokens,
    UsageEventType::LlmBatchOutputTokens,
    UsageEventType::LlmBatchCacheWriteTokens,
    UsageEventType::LlmBatchCacheReadTokens,
];

/// How much a customer may spend before somebody is told.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BudgetPolicy {
    /// Tokens per window before an alarm. `0` disables the whole monitor.
    pub tokens: u64,
    /// Share of `tokens` at which a warning is raised first — the point of a
    /// budget alarm being to arrive *before* the number is interesting.
    pub warn_ratio: f64,
    /// How far back spend is summed.
    pub window: Duration,
    /// How often the window is re-evaluated.
    pub interval: Duration,
    /// Cap on customers named in one report.
    pub max_reported: usize,
}

impl Default for BudgetPolicy {
    fn default() -> Self {
        Self {
            tokens: 0,
            warn_ratio: DEFAULT_WARN_RATIO,
            window: Duration::from_secs(u64::from(DEFAULT_WINDOW_DAYS) * 24 * 60 * 60),
            interval: DEFAULT_INTERVAL,
            max_reported: DEFAULT_MAX_REPORTED,
        }
    }
}

impl BudgetPolicy {
    /// Whether this deployment watches budgets at all.
    pub fn is_enabled(&self) -> bool {
        self.tokens > 0
    }

    /// Tokens at which a warning is raised.
    pub fn warn_tokens(&self) -> u64 {
        (self.tokens as f64 * self.warn_ratio) as u64
    }

    /// Whole days in the window — the rollup's own granularity.
    pub fn window_days(&self) -> i64 {
        (self.window.as_secs() / (24 * 60 * 60)).max(1) as i64
    }

    /// Refuse a policy that cannot mean what it says, at boot rather than at
    /// the first evaluation (§9).
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            (0.0..=1.0).contains(&self.warn_ratio),
            "USAGE_TOKEN_BUDGET_WARN_RATIO ({}) must be a share between 0 and 1 — it is the \
             fraction of the budget at which a warning precedes the alarm",
            self.warn_ratio
        );
        anyhow::ensure!(
            self.window.as_secs() >= 24 * 60 * 60,
            "USAGE_BUDGET_WINDOW_DAYS must be at least 1 — spend is read from the daily \
             rollup, so a sub-day window would silently round to one day anyway"
        );
        anyhow::ensure!(
            self.interval.as_secs() >= 60,
            "USAGE_BUDGET_INTERVAL_SECS ({}s) is under a minute — this reads a month-wide \
             aggregate to answer a question whose answer moves on the scale of hours",
            self.interval.as_secs()
        );
        Ok(())
    }
}

/// One customer's token spend over the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustomerSpend {
    /// `None` is platform-internal spend — the [`NIL_CUSTOMER`] sentinel rows,
    /// which is what every incident-narrative draft is billed to (nobody asked
    /// for it, so there is no customer in scope).
    ///
    /// Deliberately *not* filtered out: the runaway loop this alarm is most
    /// likely to catch first is a backfill or a redelivery storm on exactly
    /// that path, and dropping the biggest spender in the system from a spend
    /// alarm would be an odd way to watch spend.
    pub customer: Option<Uuid>,
    pub tokens: u64,
}

impl CustomerSpend {
    /// The metrics label for this row's scope — a two-value closed set, unlike
    /// the customer id itself.
    pub fn scope(&self) -> &'static str {
        match self.customer {
            Some(_) => "customer",
            None => "platform",
        }
    }

    /// How this spender is named in a log line and in the printed table.
    pub fn name(&self) -> String {
        match self.customer {
            Some(id) => id.to_string(),
            None => "platform (no customer in scope)".to_owned(),
        }
    }
}

/// One window's spend, and whether the read saw all of it.
///
/// The flag travels *with* the rows rather than beside them, exactly as
/// [`copilot::audit::AuditStream::truncated`](../../copilot/src/audit.rs) does
/// for the incident streams this platform's other bounded read produces. The
/// alternative — returning a bare `Vec` and remembering elsewhere that it was
/// capped — is how "the top 10,000 spenders" gets printed as "10,000 spenders,
/// N tokens total". That sentence is wrong, and nothing about the `Vec` says
/// so.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpendWindow {
    /// Spenders, largest first.
    pub spenders: Vec<CustomerSpend>,
    /// Whether the read hit its ceiling, so `spenders` is a *prefix* of the
    /// population ordered by spend.
    ///
    /// Harmless for the alarm — the spenders who breach a budget are by
    /// definition in that prefix — and load-bearing for every total derived
    /// from it.
    pub truncated: bool,
}

impl SpendWindow {
    /// The rows a read returned, marked truncated when it filled its limit.
    pub fn new(spenders: Vec<CustomerSpend>, limit: usize) -> Self {
        Self {
            truncated: spenders.len() >= limit,
            spenders,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.spenders.is_empty()
    }

    pub fn len(&self) -> usize {
        self.spenders.len()
    }
}

/// How loud one spender is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Past `warn_ratio` of the budget, not yet past it.
    Warn,
    /// Past the budget.
    Alarm,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Warn => "warn",
            Level::Alarm => "alarm",
        }
    }
}

/// One spender worth telling somebody about.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BudgetAlarm {
    pub spend: CustomerSpend,
    pub level: Level,
    /// Spend as a share of the budget. Above 1.0 for an alarm — and the number
    /// an operator actually wants, because "3.4x the budget" and "1.01x" are
    /// the same alarm and very different mornings.
    pub ratio: f64,
}

/// What one evaluation found.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BudgetReport {
    /// Spenders the read returned — the whole population unless
    /// [`truncated`](Self::truncated).
    pub spenders: usize,
    /// Tokens across *those* spenders.
    ///
    /// Named `seen` and not `total` on purpose: when the read is truncated
    /// this is the sum over the heaviest `spenders` only, and a field called
    /// `total_tokens` would be quietly reported as platform-wide spend. The
    /// module's whole accuracy posture is that approximations say so.
    pub tokens_seen: u64,
    /// Whether the underlying read hit its ceiling.
    pub truncated: bool,
    /// Those past a threshold, worst first, capped at `max_reported`.
    pub alarms: Vec<BudgetAlarm>,
    pub warning: usize,
    pub alarming: usize,
    /// The highest single ratio seen — including spenders under every
    /// threshold, so the gauge it feeds is a trend and not just an alarm.
    pub max_ratio: f64,
}

impl BudgetReport {
    pub fn is_quiet(&self) -> bool {
        self.warning == 0 && self.alarming == 0
    }

    /// The printed table — what `usage budget` writes, and the only place a
    /// customer id appears outside a log line.
    pub fn render(&self, policy: &BudgetPolicy) -> String {
        let mut out = format!(
            "token budget: {} tokens per {} day(s); {}{} spender(s), {} tokens{}, \
             {} warning, {} alarming (peak {:.2}x)",
            policy.tokens,
            policy.window_days(),
            if self.truncated { "top " } else { "" },
            self.spenders,
            self.tokens_seen,
            if self.truncated {
                " across those (the read hit its ceiling — not platform-wide spend)"
            } else {
                " total"
            },
            self.warning,
            self.alarming,
            self.max_ratio,
        );
        for alarm in &self.alarms {
            out.push_str(&format!(
                "\n  {:<5} {:<45} {:>14} tokens  {:.2}x",
                alarm.level.as_str(),
                alarm.spend.name(),
                alarm.spend.tokens,
                alarm.ratio,
            ));
        }
        out
    }
}

/// Apply a policy to a window's spend.
///
/// Pure — no store, no clock, no metrics. That is what lets an operator ask
/// *"what would a budget of X have alarmed on last month"* without a threshold
/// sweep also emitting a month of alarms, the same reason the grounding check
/// on the other half of this task returns its rejection instead of counting it.
pub fn evaluate(window: &SpendWindow, policy: &BudgetPolicy) -> BudgetReport {
    let mut report = BudgetReport {
        spenders: window.len(),
        tokens_seen: window.spenders.iter().map(|s| s.tokens).sum(),
        truncated: window.truncated,
        ..BudgetReport::default()
    };
    if !policy.is_enabled() {
        return report;
    }
    let warn_at = policy.warn_tokens();

    let mut alarms: Vec<BudgetAlarm> = Vec::new();
    for spend in &window.spenders {
        let ratio = spend.tokens as f64 / policy.tokens as f64;
        report.max_ratio = report.max_ratio.max(ratio);
        let level = if spend.tokens >= policy.tokens {
            Level::Alarm
        } else if spend.tokens >= warn_at {
            Level::Warn
        } else {
            continue;
        };
        match level {
            Level::Alarm => report.alarming += 1,
            Level::Warn => report.warning += 1,
        }
        alarms.push(BudgetAlarm {
            spend: *spend,
            level,
            ratio,
        });
    }

    // Worst first: a capped list has to keep the spenders that matter.
    alarms.sort_by_key(|alarm| std::cmp::Reverse(alarm.spend.tokens));
    alarms.truncate(policy.max_reported);
    report.alarms = alarms;
    report
}

/// Reads per-customer token spend over a window.
///
/// A seam for the usual reason: the monitor's alarm/fail-open behaviour has to
/// be exercisable without ClickHouse, and "what has been spent" is the only
/// thing it reads.
#[async_trait]
pub trait SpendSource: Send + Sync + std::fmt::Debug {
    /// Token spend per customer since `since`, largest first, at most `limit`
    /// rows — and [`SpendWindow::truncated`] when that limit bound the answer.
    async fn token_spend(
        &self,
        since: DateTime<Utc>,
        limit: usize,
    ) -> Result<SpendWindow, StoreError>;
}

#[async_trait]
impl SpendSource for UsageStore {
    async fn token_spend(
        &self,
        since: DateTime<Utc>,
        limit: usize,
    ) -> Result<SpendWindow, StoreError> {
        // The SKU list is inlined rather than bound. Two reasons, and the
        // second is the load-bearing one: these strings come from a `&'static`
        // slice of our own enum (never user input), which is the same
        // injection argument `intelligence::adjacency` makes for its canonical
        // address lists — and the `clickhouse` crate treats **every literal
        // `?`** in a query as a bind placeholder, so a query with no
        // placeholders at all is a query that cannot be mis-bound.
        let skus = TOKEN_SKUS
            .iter()
            .map(|sku| format!("'{}'", sku.as_wire_str()))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT customer_id, sum(total_quantity) AS tokens \
               FROM usage_rollup_daily \
              WHERE day >= toDate('{since}') AND event_type IN ({skus}) \
              GROUP BY customer_id \
              ORDER BY tokens DESC \
              LIMIT {limit}",
            since = since.format("%Y-%m-%d"),
            limit = limit.max(1),
        );
        let rows: Vec<SpendRow> = self.client().query(&sql).fetch_all().await?;
        Ok(SpendWindow::new(
            rows.into_iter().map(CustomerSpend::from).collect(),
            limit,
        ))
    }
}

/// One grouped row of the spend query.
#[derive(Debug, Clone, clickhouse::Row, serde::Deserialize)]
struct SpendRow {
    #[serde(with = "clickhouse::serde::uuid")]
    customer_id: Uuid,
    tokens: u64,
}

impl From<SpendRow> for CustomerSpend {
    fn from(row: SpendRow) -> Self {
        Self {
            // The sentinel comes back as itself; the domain meaning is
            // "no customer in scope", and it is restored here rather than left
            // for every reader to remember.
            customer: (row.customer_id != NIL_CUSTOMER).then_some(row.customer_id),
            tokens: row.tokens,
        }
    }
}

/// The periodic evaluation.
///
/// **Fails open, and says that it did** (§15). A ClickHouse blip must not stop
/// the sink it shares a process with, so a failed evaluation is counted and
/// logged and the loop keeps its cadence. `usage_budget_last_success_timestamp`
/// exists for the other half of that rule: a monitor that has quietly stopped
/// evaluating looks exactly like a monitor with nothing to report.
#[derive(Debug)]
pub struct BudgetMonitor {
    spend: Arc<dyn SpendSource>,
    policy: BudgetPolicy,
}

impl BudgetMonitor {
    pub fn new(spend: Arc<dyn SpendSource>, policy: BudgetPolicy) -> Self {
        Self { spend, policy }
    }

    /// One evaluation. Public so the `usage budget` subcommand runs exactly
    /// what the loop runs — an operator checking the alarm must not be
    /// checking a second implementation of it.
    pub async fn evaluate_now(&self, now: DateTime<Utc>) -> Result<BudgetReport, StoreError> {
        let since = now - chrono::Duration::days(self.policy.window_days());
        // One row per spender, and the cap is generous: the report is capped
        // separately, but a *count* of spenders over budget has to see all of
        // them to be a count.
        let window = self.spend.token_spend(since, MAX_SPENDERS_READ).await?;
        Ok(evaluate(&window, &self.policy))
    }

    /// Evaluate on the policy's interval until cancelled.
    pub async fn run(&self, shutdown: CancellationToken) {
        if !self.policy.is_enabled() {
            tracing::info!(
                "per-customer token budget alarms are off (USAGE_TOKEN_BUDGET unset or 0)"
            );
            return;
        }
        tracing::info!(
            budget_tokens = self.policy.tokens,
            window_days = self.policy.window_days(),
            interval_secs = self.policy.interval.as_secs(),
            "per-customer token budget alarms armed"
        );

        let mut ticker = tokio::time::interval(self.policy.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = ticker.tick() => match self.evaluate_now(Utc::now()).await {
                    Ok(report) => {
                        announce(&report, &self.policy);
                        metrics::counter!(BUDGET_EVALUATIONS_TOTAL, "outcome" => "ok")
                            .increment(1);
                        metrics::gauge!(BUDGET_LAST_SUCCESS_TIMESTAMP)
                            .set(Utc::now().timestamp() as f64);
                    }
                    Err(err) => {
                        // Fail open: the metering sink in this process keeps
                        // running, and the fact that the monitor did not is
                        // itself a signal rather than a silence.
                        metrics::counter!(BUDGET_EVALUATIONS_TOTAL, "outcome" => "failed")
                            .increment(1);
                        tracing::error!(
                            error = %err,
                            "token budget evaluation failed; alarms are stale until it recovers"
                        );
                    }
                },
            }
        }
        tracing::info!("token budget monitor stopped");
    }
}

/// Ceiling on spenders read from one query. High enough that the counts are
/// counts, bounded so a pathological month cannot pull an unbounded result set
/// into memory on a timer.
const MAX_SPENDERS_READ: usize = 10_000;

/// Publish one report: gauges for the current state, counters for the rate,
/// and a log line per alarming spender — the only place the id appears.
fn announce(report: &BudgetReport, policy: &BudgetPolicy) {
    metrics::gauge!(BUDGET_CUSTOMERS, "level" => "warn").set(report.warning as f64);
    metrics::gauge!(BUDGET_CUSTOMERS, "level" => "alarm").set(report.alarming as f64);
    metrics::gauge!(BUDGET_MAX_RATIO).set(report.max_ratio);

    for alarm in &report.alarms {
        metrics::counter!(
            BUDGET_ALARMS_TOTAL,
            "level" => alarm.level.as_str(),
            "scope" => alarm.spend.scope(),
        )
        .increment(1);

        // `warn!` for both levels rather than `error!` for the alarm: nothing
        // is broken and nothing is being refused. Somebody is spending more
        // than the deployment expected, which is a thing to look at, not a
        // page for the on-call to fix at 3am.
        tracing::warn!(
            customer = %alarm.spend.name(),
            scope = alarm.spend.scope(),
            level = alarm.level.as_str(),
            tokens = alarm.spend.tokens,
            budget = policy.tokens,
            window_days = policy.window_days(),
            ratio = alarm.ratio,
            "token budget {}: {} spent {} tokens over {} day(s) ({:.2}x the {} budget)",
            alarm.level.as_str(),
            alarm.spend.name(),
            alarm.spend.tokens,
            policy.window_days(),
            alarm.ratio,
            policy.tokens,
        );
    }
}

/// Gauge (labeled by `level`): spenders currently at or over a threshold.
///
/// A gauge and not just a counter, because "is anyone over budget **now**" is
/// the alertable question; the counter beside it says how often that has been
/// true. Deliberately carries no `customer` label — an unbounded id set has no
/// business in a series (§19); the id is in the log line the alarm writes.
pub const BUDGET_CUSTOMERS: &str = "usage_token_budget_customers";

/// Gauge: the highest single spender's share of the budget.
///
/// Recorded for every evaluation including quiet ones, so the threshold can be
/// tuned against the distribution rather than against the alarms it already
/// produced — the same argument `copilot_grounding_cited_ratio` makes.
pub const BUDGET_MAX_RATIO: &str = "usage_token_budget_max_ratio";

/// Counter (labeled by `level`, `scope`): budget alarms observed, one per
/// spender per evaluation. `scope` splits customer spend from platform-internal
/// spend (the copilot's own incident narratives, which bill to no customer).
pub const BUDGET_ALARMS_TOTAL: &str = "usage_token_budget_alarms_total";

/// Counter (labeled by `outcome`: `ok`/`failed`): evaluations attempted.
///
/// §15's second half: a monitor that fails open has to say that it did, or a
/// flat alarm gauge is indistinguishable from a healthy one.
pub const BUDGET_EVALUATIONS_TOTAL: &str = "usage_budget_evaluations_total";

/// Gauge: unix seconds of the last successful evaluation — the staleness
/// signal for an alarm that can go quiet by failing rather than by passing.
pub const BUDGET_LAST_SUCCESS_TIMESTAMP: &str = "usage_budget_last_success_timestamp_seconds";

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(tokens: u64) -> BudgetPolicy {
        BudgetPolicy {
            tokens,
            ..BudgetPolicy::default()
        }
    }

    fn customer(tokens: u64) -> CustomerSpend {
        CustomerSpend {
            customer: Some(Uuid::new_v4()),
            tokens,
        }
    }

    /// A complete read — nothing was cut off.
    fn window(spenders: Vec<CustomerSpend>) -> SpendWindow {
        SpendWindow {
            spenders,
            truncated: false,
        }
    }

    #[test]
    fn spend_is_split_into_warn_and_alarm_around_the_budget() {
        let policy = policy(1_000);
        assert_eq!(policy.warn_tokens(), 800);

        let report = evaluate(
            &window(vec![
                customer(100),
                customer(850),
                customer(1_000),
                customer(3_400),
            ]),
            &policy,
        );
        assert_eq!((report.spenders, report.tokens_seen), (4, 5_350));
        assert!(!report.truncated);
        assert_eq!((report.warning, report.alarming), (1, 2));
        assert_eq!(
            report
                .alarms
                .iter()
                .map(|a| a.spend.tokens)
                .collect::<Vec<_>>(),
            vec![3_400, 1_000, 850],
            "worst first, or a capped list drops the spender that mattered"
        );
        assert_eq!(report.alarms[0].level, Level::Alarm);
        assert_eq!(report.alarms[2].level, Level::Warn);
        assert!((report.max_ratio - 3.4).abs() < 1e-9);
    }

    /// The max ratio is recorded even when nothing alarms — otherwise the only
    /// data the threshold could be tuned against is the alarms it already
    /// produced.
    #[test]
    fn a_quiet_window_still_reports_where_the_peak_was() {
        let report = evaluate(&window(vec![customer(100), customer(250)]), &policy(1_000));
        assert!(report.is_quiet());
        assert!(report.alarms.is_empty());
        assert!((report.max_ratio - 0.25).abs() < 1e-9);
    }

    /// Platform-internal spend is the copilot's own narratives — the most
    /// likely runaway loop in the system, and the one a "per-customer" alarm
    /// would be most tempted to filter out.
    #[test]
    fn platform_spend_is_watched_too_and_is_labelled_apart() {
        let platform = CustomerSpend {
            customer: None,
            tokens: 5_000,
        };
        assert_eq!(platform.scope(), "platform");
        assert_eq!(customer(1).scope(), "customer");

        let report = evaluate(&window(vec![platform]), &policy(1_000));
        assert_eq!(report.alarming, 1);
        assert_eq!(report.alarms[0].spend.customer, None);
        assert!(report.alarms[0].spend.name().contains("platform"));
    }

    /// Disabled is disabled: no thresholds, no division, no alarms.
    #[test]
    fn a_zero_budget_disables_the_monitor_entirely() {
        let policy = policy(0);
        assert!(!policy.is_enabled());
        let report = evaluate(&window(vec![customer(u64::MAX)]), &policy);
        assert!(report.is_quiet());
        assert_eq!(report.max_ratio, 0.0, "no budget means no ratio to report");
        assert_eq!(
            report.spenders, 1,
            "spend is still counted, just not judged"
        );
    }

    #[test]
    fn the_cap_keeps_the_worst_spenders() {
        let policy = BudgetPolicy {
            max_reported: 2,
            ..policy(10)
        };
        let report = evaluate(
            &window(vec![
                customer(100),
                customer(20),
                customer(3_000),
                customer(50),
            ]),
            &policy,
        );
        assert_eq!(report.alarming, 4, "the count is not capped");
        assert_eq!(report.alarms.len(), 2, "the detail is");
        assert_eq!(report.alarms[0].spend.tokens, 3_000);
    }

    #[test]
    fn a_policy_that_cannot_mean_what_it_says_is_refused_at_boot() {
        let mut policy = policy(1_000);
        policy.validate().expect("the shipped defaults are valid");

        policy.warn_ratio = 1.5;
        assert!(policy.validate().is_err());

        policy.warn_ratio = DEFAULT_WARN_RATIO;
        policy.interval = Duration::from_secs(5);
        assert!(policy.validate().is_err());
    }

    /// Every LLM token SKU counts. A new one that this list forgets is a
    /// budget that quietly stops counting part of the bill.
    #[test]
    fn every_llm_token_sku_counts_against_the_budget() {
        use strum::IntoEnumIterator;

        let watched: Vec<&str> = TOKEN_SKUS.iter().map(|s| s.as_wire_str()).collect();
        for sku in UsageEventType::iter() {
            let wire = sku.as_wire_str();
            if wire.contains("tokens") {
                assert!(
                    watched.contains(&wire),
                    "{wire} is a token SKU that no budget counts — add it to TOKEN_SKUS"
                );
            }
        }
        assert_eq!(
            watched.len(),
            8,
            "four live SKUs and four half-price batch ones"
        );
    }

    /// The honesty rule this window type exists for: a capped read must not be
    /// rendered as a platform-wide total.
    #[test]
    fn a_truncated_read_is_never_printed_as_a_total() {
        let policy = policy(1_000);
        // Exactly as many rows as were asked for — which is how a capped read
        // is indistinguishable from a complete one unless the reader says so.
        let capped = SpendWindow::new(vec![customer(5_000), customer(4_000)], 2);
        assert!(capped.truncated, "a full page means there may be more");

        let report = evaluate(&capped, &policy);
        assert!(report.truncated);
        assert_eq!(report.tokens_seen, 9_000);
        let rendered = report.render(&policy);
        assert!(rendered.contains("top 2 spender(s)"), "{rendered}");
        assert!(rendered.contains("the read hit its ceiling"), "{rendered}");
        assert!(
            !rendered.contains("tokens total"),
            "a prefix must never be printed as a total: {rendered}"
        );

        // A short page is the whole population, and says so.
        let complete = SpendWindow::new(vec![customer(5_000)], 2);
        assert!(!complete.truncated);
        assert!(evaluate(&complete, &policy)
            .render(&policy)
            .contains("tokens total"));
    }

    #[test]
    fn the_rendered_table_names_the_spender_the_metrics_cannot() {
        let policy = policy(1_000);
        let report = evaluate(&window(vec![customer(2_000)]), &policy);
        let rendered = report.render(&policy);
        assert!(rendered.contains("alarm"), "{rendered}");
        assert!(rendered.contains("2000 tokens"), "{rendered}");
        assert!(rendered.contains("2.00x"), "{rendered}");
    }
}
