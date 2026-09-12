//! The alert rules' invariants, executable (§19 of
//! [engineering-conventions](../../../docs/engineering-conventions.md)).
//!
//! `deploy/prometheus-rules.yml` opens with a contract: what a threshold is
//! allowed to be derived from, that a latency threshold must land on a bucket
//! boundary, that `severity: informational` is not a parking space. That
//! contract was prose, and prose does not fail a build — so the file
//! accumulated **four rules that could not fire at any threshold**, and they
//! were found by a human reading PromQL, which is not a control.
//!
//! Every rule below is one of those defects turned into a question a test can
//! ask. They are checked against the real deployed file by `tests/rules.rs`, so
//! a rule that cannot fire fails the same gate as a compile error.
//!
//! ## The defect class these exist for
//!
//! A Prometheus alert has no failing state. A rule whose threshold is
//! unreachable, whose series is never scraped, or whose window is narrower than
//! the job that writes it, is *indistinguishable from a healthy system* — it is
//! green, and green is what you wanted to see. There is no stack trace and no
//! log line. That asymmetry is why these checks are worth their weight: for
//! almost everything else in the workspace, being wrong eventually announces
//! itself.
//!
//! When one of these fails you either fix the rule, or are consciously changing
//! an alerting decision — do it in this file, in the same PR, with the
//! reasoning in the commit.

use std::collections::BTreeMap;

use regex::Regex;

/// One alert, reduced to the fields these rules read.
///
/// Deliberately not a full Prometheus schema: the I/O shell in `tests/` owns
/// the YAML, and this stays a pure function of plain data so the rules can be
/// unit-tested against hand-written fixtures rather than the deploy file.
#[derive(Debug, Clone)]
pub struct Alert {
    /// The `groups[].name` this alert was declared under.
    pub group: String,
    /// `alert:` — the name that shows up in Alertmanager.
    pub name: String,
    /// `expr:` — the PromQL, whitespace preserved.
    pub expr: String,
    /// `labels.severity`, already parsed — see [`Severity`].
    pub severity: Severity,
    /// `annotations.summary`.
    pub summary: String,
    /// `annotations.description`.
    pub description: String,
}

/// Every alert in the file, in declaration order.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    pub alerts: Vec<Alert>,
    /// Rules the I/O shell could not turn into an [`Alert`] — an unroutable
    /// severity, a missing `labels` block.
    ///
    /// Carried rather than returned as a parse error so that ONE malformed rule
    /// does not hide the violations in all the others: a run that reports a
    /// single "could not parse" and stops is how a batch of findings becomes a
    /// one-line fix and another silent pass. [`violations`] reports these first.
    pub malformed: Vec<String>,
    /// [`BatchSeries::prefix`] → the cadence the I/O shell read out of that
    /// series' manifest. A missing entry is a violation, not a skip.
    pub batch_cadences: BTreeMap<&'static str, u64>,
}

/// How an alert is routed by `deploy/alertmanager.yml`.
///
/// An enum rather than a `String`, and parsed at the I/O boundary, so the
/// "severity nobody routes" case is **unrepresentable** past the shell instead
/// of being a check some future rule has to remember to run. Same move as
/// `loadtest`'s `LatencyBudget` and `copilot`'s `CompiledDraft`: make the
/// invalid state impossible to build rather than possible-but-checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Wake someone now.
    Page,
    /// Look at this today.
    Warning,
    /// See [`INFORMATIONAL_ALLOWLIST`] — not a parking space for untuned
    /// numbers.
    Informational,
}

impl Severity {
    /// The label values Alertmanager actually routes. A typo routes nowhere,
    /// silently, which is why this is a closed set.
    pub const ROUTED: &'static [&'static str] = &["page", "warning", "informational"];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Page => "page",
            Self::Warning => "warning",
            Self::Informational => "informational",
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(raw: &str) -> std::result::Result<Self, Self::Err> {
        match raw {
            "page" => Ok(Self::Page),
            "warning" => Ok(Self::Warning),
            "informational" => Ok(Self::Informational),
            other => Err(format!(
                "severity `{other}` is not one of {:?} — deploy/alertmanager.yml \
                 routes on this label, so an unknown value routes nowhere and fails \
                 silently",
                Self::ROUTED
            )),
        }
    }
}

/// The alerts allowed to carry `severity: informational`.
///
/// An allowlist rather than a free choice, because `informational` was the
/// parking space for "we have not tuned this yet" and fifteen rules
/// accumulated in it. Six were deleted (an invented number attached to an
/// observation, not a fault), five were promoted (structural all along, merely
/// mislabeled), and this is what is left. Adding a name here should require
/// saying why over-alerting is the *milder* failure for that specific rule —
/// which is the argument the one entry makes.
pub const INFORMATIONAL_ALLOWLIST: &[&str] = &[
    // Over-retention is genuinely milder than under-retention (the paired
    // `CopilotGroundingAuditUnverifiable` pages), so a backlog of released-but-
    // unpurged artifacts is a policy nobody is keeping, not an incident.
    "CopilotRetentionPurgeStalled",
];

/// A metric written by a scheduled job rather than a long-running service.
///
/// These need range selectors at least as wide as the job's cadence, and they
/// need `max_over_time` rather than `increase`/`rate` — see [`Rule::BatchWindow`]
/// for why both, and why either alone is enough to keep a rule green forever.
#[derive(Debug, Clone, Copy)]
pub struct BatchSeries {
    /// Metric-name prefix that identifies the family.
    pub prefix: &'static str,
    /// What writes it, for the violation message.
    pub job: &'static str,
    /// The manifest that declares the schedule, relative to the repo root.
    ///
    /// The cadence is **derived from this file**, never restated here. A
    /// `cadence_secs: 604_800` literal next to a `schedule: "0 3 * * 0"` in
    /// YAML is two definitions of one policy: change the CronJob to daily and
    /// the rule below silently over-demands an 8-day window forever. The same
    /// argument this crate makes about bucket ladders, applied to itself.
    pub manifest: &'static str,
}

/// The batch-written metric families alert rules read.
pub const BATCH_SERIES: &[BatchSeries] = &[BatchSeries {
    prefix: "copilot_grounding_audit_",
    job: "the copilot-audit CronJob",
    manifest: "deploy/k8s/base/services/copilot-audit.yaml",
}];

/// How often a 5-field cron expression fires, in seconds.
///
/// Not a general cron evaluator — it classifies the *shapes this repo uses* and
/// returns `None` for anything else, so an unrecognised schedule becomes a
/// reported violation rather than a plausible default. A wrong period here
/// silently mis-sizes an alert window, which is the failure being designed out.
///
/// Returns the **longest** interval between firings, since that is what an
/// alert window has to span: a weekly job's metric is absent for seven days.
pub fn cron_period_secs(schedule: &str) -> Option<u64> {
    let fields: Vec<&str> = schedule.split_whitespace().collect();
    let [minute, hour, dom, month, dow] = fields.as_slice() else {
        return None;
    };
    // Anything with a list, range or step is outside what this understands.
    let simple = |f: &str| f == "*" || f.parse::<u32>().is_ok();
    if ![minute, hour, dom, month, dow].iter().all(|f| simple(f)) {
        return None;
    }
    const MINUTE: u64 = 60;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;
    Some(
        match (*minute == "*", *hour == "*", *dom == "*", *dow == "*") {
            // A pinned day-of-week fires once a week.
            (false, false, true, false) => 7 * DAY,
            // A pinned day-of-month: use 31 days, the longest gap.
            (false, false, false, true) => 31 * DAY,
            (false, false, true, true) => DAY,
            (false, true, true, true) => HOUR,
            (true, true, true, true) => MINUTE,
            _ => return None,
        },
    )
}

/// Run every rule. Each violation is one human-readable sentence naming the
/// alert, what is wrong, and what to do. Empty means conforming.
pub fn violations(rules: &RuleSet) -> Vec<String> {
    // Malformed rules first: they are the ones the checks below could not even
    // be applied to, so reporting them last would bury them.
    let mut out = rules.malformed.clone();
    whole_file_rules(rules, &mut out);
    for alert in &rules.alerts {
        per_alert_rules(alert, &rules.batch_cadences, &mut out);
    }
    out
}

/// Checks that read one alert in isolation.
///
/// Split from [`whole_file_rules`] because the two answer different questions,
/// and conflating them made the rules untestable against a single-alert
/// fixture: a whole-file check has no opinion to offer about one alert, but it
/// still fired, so every fixture carried findings about the rest of a file that
/// was not there.
fn per_alert_rules(alert: &Alert, cadences: &BTreeMap<&str, u64>, out: &mut Vec<String>) {
    check_severity(alert, out);
    check_annotations(alert, out);
    check_quantile_threshold(alert, out);
    check_batch_windows(alert, cadences, out);
}

/// Checks that are only meaningful over the complete rule set.
fn whole_file_rules(rules: &RuleSet, out: &mut Vec<String>) {
    check_unique_names(rules, out);
    check_allowlist_is_current(rules, out);
}

/// Two alerts with one name: Alertmanager silences and runbooks address a name,
/// so a duplicate makes both ambiguous.
fn check_unique_names(rules: &RuleSet, out: &mut Vec<String>) {
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for alert in &rules.alerts {
        *seen.entry(alert.name.as_str()).or_default() += 1;
    }
    for (name, count) in seen {
        if count > 1 {
            out.push(format!(
                "{name}: declared {count} times — an alert name is what a silence \
                 and a runbook address, so it must be unique"
            ));
        }
    }
}

/// Note there is no "unknown severity" arm: [`Severity`] cannot hold one, so
/// that check lives at the parse boundary and cannot be skipped here.
fn check_severity(alert: &Alert, out: &mut Vec<String>) {
    let Alert { name, severity, .. } = alert;
    if *severity == Severity::Informational && !INFORMATIONAL_ALLOWLIST.contains(&name.as_str()) {
        out.push(format!(
            "{name}: new `severity: informational` rules are not accepted. That \
             tier was the parking space for untuned numbers and had to be emptied \
             once. If the threshold is invented AND the condition is an \
             observation rather than a fault, the rule does not belong in the \
             file; if it is a fault, it is a `warning`. To make a genuine \
             exception, add it to INFORMATIONAL_ALLOWLIST with the argument for \
             why over-alerting is the milder failure here"
        ));
    }
}

/// An alert with no description is a page with no runbook.
fn check_annotations(alert: &Alert, out: &mut Vec<String>) {
    for (field, value) in [
        ("summary", &alert.summary),
        ("description", &alert.description),
    ] {
        if value.trim().is_empty() {
            out.push(format!(
                "{}: empty `annotations.{field}` — whoever this wakes at 3am sees \
                 only the alert name",
                alert.name
            ));
        }
    }
}

/// **The rule this crate exists for.**
///
/// `histogram_quantile` reports the highest *finite* bucket bound for a quantile
/// that lands in `+Inf`, and interpolates linearly *inside* a bucket. So a
/// threshold above the metric's ceiling can never be exceeded — the rule is
/// green forever — and a threshold between two rungs is compared against a
/// value the histogram never observed.
fn check_quantile_threshold(alert: &Alert, out: &mut Vec<String>) {
    if !alert.expr.contains("histogram_quantile") {
        return;
    }
    let name = &alert.name;
    let metrics = quantile_metrics(&alert.expr);
    let metric = match metrics.as_slice() {
        [one] => one,
        [] => {
            out.push(format!(
                "{name}: uses histogram_quantile but reads no `<metric>_bucket` \
                 series — histogram_quantile requires one"
            ));
            return;
        }
        many => {
            out.push(format!(
                "{name}: reads {} different `_bucket` series ({many:?}); this check \
                 cannot tell which ladder the threshold is denominated in. Split \
                 the rule, or teach quantile_metrics the shape",
                many.len()
            ));
            return;
        }
    };

    let Some(ladder) = telemetry::metrics::buckets_for(metric) else {
        out.push(format!(
            "{name}: `{metric}` is not exported as a bucketed histogram \
             (telemetry::metrics::bucket_class returned None), so \
             histogram_quantile over it is meaningless"
        ));
        return;
    };
    let (op, threshold) = match comparison(&alert.expr) {
        Comparison::Literal { op, value } => (op, value),
        // Comparing one quantile against another series is legitimate (§2 of
        // the rules file's contract) and has no literal to validate.
        Comparison::Series => return,
        // FAIL CLOSED. The first version of this check returned early here,
        // treating "I could not parse this" as "there is nothing to check" —
        // which silently skipped an unfireable `> 30` the moment it carried a
        // trailing PromQL comment. A checker that exists to find rules which
        // cannot fire must not itself have a branch that quietly declines to
        // look; that is the same defect one level up. Compare `loadtest`'s
        // exit 2: "could not measure" is its own outcome, never a pass.
        Comparison::Unrecognised => {
            out.push(format!(
                "{name}: this check cannot tell what the quantile over `{metric}` is \
                 compared against, so its threshold is UNVERIFIED — which is not the \
                 same as correct. Put the comparison at the end of the expression \
                 (`... ) > 0.25`), move any PromQL comment out of the `expr`, or teach \
                 `comparison()` the shape"
            ));
            return;
        }
    };

    let ceiling = ladder.last().copied().unwrap_or(f64::INFINITY);
    if threshold >= ceiling {
        out.push(format!(
            "{name}: UNFIREABLE. Threshold `{op} {threshold}` on `{metric}`, whose \
             ladder tops out at {ceiling}s — a quantile landing in `+Inf` reports \
             the highest finite bound, so this expression can never exceed \
             {ceiling} and the rule has never been able to fire. Either pick a \
             boundary below the ceiling, or, if the quantity really runs that \
             long, add `{metric}` to telemetry::metrics::JOB_DURATION_METRICS"
        ));
        return;
    }
    if !ladder.iter().any(|b| (b - threshold).abs() < f64::EPSILON) {
        out.push(format!(
            "{name}: threshold `{op} {threshold}` on `{metric}` is not a bucket \
             boundary. histogram_quantile interpolates inside a bucket, so this \
             compares against a value the histogram never observed. Nearest \
             usable boundaries: {:?}",
            neighbours(ladder, threshold)
        ));
    }
}

/// A weekly job watched through a one-day window is blind six days in seven,
/// and `increase()` needs two samples in the window where a short-lived Job may
/// be scraped once. Either alone keeps the rule green forever.
fn check_batch_windows(alert: &Alert, cadences: &BTreeMap<&str, u64>, out: &mut Vec<String>) {
    for batch in BATCH_SERIES {
        if !alert.expr.contains(batch.prefix) {
            continue;
        }
        let name = &alert.name;
        let Some(&cadence_secs) = cadences.get(batch.prefix) else {
            out.push(format!(
                "{name}: reads `{}*` but the cadence of {} could not be read from {} \
                 — without it this window cannot be checked, and an unchecked window \
                 is how a weekly job came to be watched through a one-day rule",
                batch.prefix, batch.job, batch.manifest
            ));
            continue;
        };
        for (literal, secs) in range_windows(&alert.expr) {
            if secs < cadence_secs {
                out.push(format!(
                    "{name}: range selector `[{literal}]` ({secs}s) is narrower than \
                     the cadence of {} ({cadence_secs}s, from {}). Between runs the \
                     series carries nothing, so this rule reads zero for most of every \
                     cycle regardless of what the job found — widen it past one full \
                     cadence",
                    batch.job, batch.manifest
                ));
            }
        }
        for forbidden in ["increase(", "rate("] {
            if alert.expr.contains(forbidden) {
                out.push(format!(
                    "{name}: uses `{forbidden}` over `{}*`, which is written by {}. \
                     Both need two samples inside the window to return anything, and \
                     a short-lived Job may be scraped once or not at all. Use \
                     `max_over_time` — on a counter from a fresh process that starts \
                     at zero it is the right reading of what that run reported",
                    batch.prefix, batch.job
                ));
            }
        }
    }
}

/// A stale allowlist is the same failure as a stale baseline: it looks like a
/// reviewed decision and is actually a leftover.
fn check_allowlist_is_current(rules: &RuleSet, out: &mut Vec<String>) {
    for allowed in INFORMATIONAL_ALLOWLIST {
        match rules.alerts.iter().find(|a| a.name == *allowed) {
            None => out.push(format!(
                "{allowed}: in INFORMATIONAL_ALLOWLIST but no such alert exists — \
                 drop the entry"
            )),
            Some(alert) if alert.severity != Severity::Informational => out.push(format!(
                "{allowed}: in INFORMATIONAL_ALLOWLIST but its severity is now \
                 `{}` — drop the entry so the list keeps meaning something",
                alert.severity.as_str()
            )),
            Some(_) => {}
        }
    }
}

// ── PromQL extraction ────────────────────────────────────────────────────

/// The base metric names behind every `<metric>_bucket` series in `expr`.
fn quantile_metrics(expr: &str) -> Vec<String> {
    let re = Regex::new(r"([a-zA-Z_][a-zA-Z0-9_]*)_bucket").expect("static pattern");
    let mut found: Vec<String> = re
        .captures_iter(expr)
        .map(|c| c[1].to_owned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    found.sort();
    found
}

/// What the right-hand side of an expression's final comparison is.
///
/// Three cases and no fourth, because the fourth — "something I did not
/// recognise" — is exactly where a silent skip would live. It is a variant
/// here so the caller has to decide what to do about it.
#[derive(Debug, PartialEq)]
enum Comparison {
    /// `... ) > 0.25` — a literal threshold, which is checkable.
    Literal { op: String, value: f64 },
    /// `... > on(model) some_other_series` — legitimate, nothing to check.
    Series,
    /// No comparison at all, or a shape this checker does not understand.
    Unrecognised,
}

/// Classify the comparison an expression ends in.
///
/// The operator is found last-first rather than anchored to end-of-string:
/// anchoring is what kept the digits inside a range selector (`[5m]`) or a
/// quantile argument (`0.99`) from being read as the threshold, but it also
/// meant any trailing text at all — a comment, an `or vector(0)` — made the
/// whole rule invisible to this check rather than merely unparsed.
fn comparison(expr: &str) -> Comparison {
    // `!=`, `==` and `=~` cannot match: the pattern requires `<` or `>` first.
    // This asks about *ordering* comparisons, which is what a threshold is.
    // (No lookahead — Rust's `regex` has none, by design.)
    let re = Regex::new(r"[<>]=?").expect("static pattern");
    let Some(last) = re.find_iter(expr).last() else {
        return Comparison::Unrecognised;
    };
    let op = expr[last.start()..last.end()].to_owned();
    let tail = expr[last.end()..].trim();

    if let Ok(value) = tail.parse::<f64>() {
        return Comparison::Literal { op, value };
    }
    // A series comparison starts with an identifier, a modifier like `on(`, or
    // a parenthesised sub-expression.
    if tail.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_' || c == '(') {
        return Comparison::Series;
    }
    Comparison::Unrecognised
}

/// Every range selector in `expr`, as `("1d", 86400)`.
fn range_windows(expr: &str) -> Vec<(String, u64)> {
    let re = Regex::new(r"\[([0-9]+)([smhdw])\]").expect("static pattern");
    re.captures_iter(expr)
        .filter_map(|c| {
            let n: u64 = c[1].parse().ok()?;
            let unit = match &c[2] {
                "s" => 1,
                "m" => 60,
                "h" => 3_600,
                "d" => 86_400,
                "w" => 604_800,
                _ => return None,
            };
            Some((format!("{}{}", &c[1], &c[2]), n * unit))
        })
        .collect()
}

/// The boundaries either side of `value`, to make a violation actionable.
fn neighbours(ladder: &[f64], value: f64) -> Vec<f64> {
    let below = ladder.iter().rev().find(|b| **b < value).copied();
    let above = ladder.iter().find(|b| **b > value).copied();
    below.into_iter().chain(above).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(name: &str, expr: &str) -> Alert {
        Alert {
            group: "g".into(),
            name: name.into(),
            expr: expr.into(),
            severity: Severity::Page,
            summary: "s".into(),
            description: "d".into(),
        }
    }

    /// The cadences the I/O shell would have read, for fixtures that exercise
    /// the batch rules without touching the filesystem.
    fn cadences() -> BTreeMap<&'static str, u64> {
        BATCH_SERIES
            .iter()
            .map(|b| (b.prefix, 7 * 24 * 60 * 60))
            .collect()
    }

    fn rule_set(alerts: Vec<Alert>) -> RuleSet {
        RuleSet {
            alerts,
            malformed: Vec::new(),
            batch_cadences: cadences(),
        }
    }

    /// Per-alert rules only — a one-alert fixture is not a file, and the
    /// whole-file rules would (correctly) complain about everything missing
    /// from it.
    fn findings(alert: Alert) -> Vec<String> {
        let mut out = Vec::new();
        per_alert_rules(&alert, &cadences(), &mut out);
        out
    }

    /// The two real bugs, as regression fixtures. Both shipped and both were
    /// green.
    #[test]
    fn the_unfireable_thresholds_that_shipped_are_caught() {
        let end_to_end = findings(alert(
            "AlertEndToEndLatencyHigh",
            "histogram_quantile(0.95, sum(rate(notification_alert_end_to_end_seconds_bucket[10m])) by (le)) > 30",
        ));
        assert!(
            end_to_end.iter().any(|v| v.contains("UNFIREABLE")),
            "30s on the 10s latency ladder must be caught: {end_to_end:?}"
        );

        let sweep = findings(alert(
            "EmbeddingSweepLapTooSlow",
            "histogram_quantile(0.9, sum(rate(intelligence_embedding_sweep_lap_seconds_bucket[6h])) by (le)) > 21600",
        ));
        assert!(
            sweep.is_empty(),
            "21600 IS on the job-duration ladder now that the sweep lap is \
             classified there — this is the fix working, not a miss: {sweep:?}"
        );
    }

    /// The hole this checker had: an unfireable `> 30` became invisible the
    /// moment the expression carried anything after the literal.
    #[test]
    fn a_trailing_comment_cannot_hide_an_unverified_rule() {
        let v = findings(alert(
            "Hypothetical",
            "histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m])) > 30  # TODO tune",
        ));
        assert!(
            !v.is_empty(),
            "an unfireable `> 30` with a trailing PromQL comment must not be \
             silently skipped"
        );
    }

    /// The same expression against a metric still on the latency ladder is a
    /// violation — which is what makes the previous assertion meaningful.
    #[test]
    fn an_hours_threshold_on_a_latency_metric_is_unfireable() {
        let v = findings(alert(
            "Hypothetical",
            "histogram_quantile(0.9, sum(rate(http_request_duration_seconds_bucket[6h])) by (le)) > 21600",
        ));
        assert!(v.iter().any(|v| v.contains("UNFIREABLE")), "{v:?}");
        assert!(
            v.iter().any(|v| v.contains("JOB_DURATION_METRICS")),
            "the violation must name the fix"
        );
    }

    #[test]
    fn an_off_ladder_threshold_is_reported_with_its_neighbours() {
        let v = findings(alert(
            "Hypothetical",
            "histogram_quantile(0.99, sum(rate(http_request_duration_seconds_bucket[5m])) by (le)) > 0.75",
        ));
        assert!(
            v.iter().any(|v| v.contains("not a bucket boundary")),
            "{v:?}"
        );
        assert!(
            v.iter().any(|v| v.contains("0.5") && v.contains("1.0")),
            "must name the usable boundaries either side: {v:?}"
        );
    }

    #[test]
    fn a_boundary_threshold_is_accepted() {
        assert!(findings(alert(
            "FastPathLatencyHigh",
            "histogram_quantile(0.99, sum(rate(detection_fast_path_duration_seconds_bucket[5m])) by (le)) > 1",
        ))
        .is_empty());
    }

    /// The quantile argument and the range selector must not be mistaken for
    /// the threshold — and an unparseable tail must be its own answer, not
    /// silently folded into "nothing to check".
    #[test]
    fn a_comparison_is_classified_into_exactly_three_cases() {
        assert_eq!(
            comparison("histogram_quantile(0.99, rate(x_bucket[5m])) > 0.25"),
            Comparison::Literal {
                op: ">".to_owned(),
                value: 0.25
            }
        );
        assert_eq!(comparison("a > on(model) b"), Comparison::Series);
        assert_eq!(
            comparison("a >= (max by (m) (b) * 2.5)"),
            Comparison::Series
        );
        assert_eq!(comparison("up == 0"), Comparison::Unrecognised);
        assert_eq!(
            comparison("histogram_quantile(0.99, rate(x_bucket[5m])) > 30  # tune"),
            Comparison::Unrecognised,
            "a trailing comment must be reported, never silently skipped"
        );
    }

    #[test]
    fn a_quantile_compared_against_another_series_has_no_literal_to_check() {
        assert!(findings(alert(
            "Hypothetical",
            "histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m])) > on(x) some_budget_seconds",
        ))
        .is_empty());
    }

    /// Both halves of the weekly-audit bug.
    #[test]
    fn a_batch_series_must_not_be_read_through_a_narrow_increase_window() {
        let v = findings(alert(
            "CopilotGroundingAuditFindings",
            r#"sum(increase(copilot_grounding_audit_drafts_total{verdict="drifted"}[1d])) > 0"#,
        ));
        assert!(
            v.iter().any(|f| f.contains("narrower than the cadence")),
            "{v:?}"
        );
        assert!(v.iter().any(|f| f.contains("max_over_time")), "{v:?}");

        assert!(findings(alert(
            "CopilotGroundingAuditFindings",
            r#"sum(max_over_time(copilot_grounding_audit_drafts_total{verdict="drifted"}[8d])) > 0"#,
        ))
        .is_empty());
    }

    /// An allowlisted alert, so whole-file fixtures start conforming.
    fn allowlisted() -> Alert {
        let mut a = alert(INFORMATIONAL_ALLOWLIST[0], "up == 0");
        a.severity = Severity::Informational;
        a
    }

    #[test]
    fn a_new_informational_rule_is_refused() {
        let mut untuned = alert("SomethingUntuned", "up == 0");
        untuned.severity = Severity::Informational;
        let v = violations(&rule_set(vec![allowlisted(), untuned]));
        assert_eq!(
            v.len(),
            1,
            "only the un-allowlisted one is a violation: {v:?}"
        );
        assert!(v[0].contains("SomethingUntuned") && v[0].contains("not accepted"));
    }

    /// The allowlist must not outlive the rule it excuses.
    #[test]
    fn a_stale_allowlist_entry_is_reported() {
        let mut promoted = allowlisted();
        promoted.severity = Severity::Warning;
        let v = violations(&rule_set(vec![promoted]));
        assert!(
            v.iter().any(|f| f.contains("drop the entry")),
            "an allowlisted alert that is no longer informational must be \
             reported, or the list quietly becomes a leftover: {v:?}"
        );

        let absent = violations(&RuleSet::default());
        assert!(
            absent.iter().any(|f| f.contains("no such alert exists")),
            "{absent:?}"
        );
    }

    #[test]
    fn missing_annotations_are_caught() {
        let mut a = alert("Typo", "up == 0");
        a.description = "  ".into();
        let v = findings(a);
        assert!(
            v.iter().any(|f| f.contains("annotations.description")),
            "{v:?}"
        );
    }

    /// The check that used to live in `check_severity` and now cannot: an
    /// unroutable value is refused where the string enters the program, so no
    /// downstream rule has to remember to look for it.
    #[test]
    fn an_unroutable_severity_is_refused_at_the_parse_boundary() {
        let err = "critical".parse::<Severity>().unwrap_err();
        assert!(err.contains("routes nowhere"), "{err}");
        for routed in Severity::ROUTED {
            assert_eq!(
                routed.parse::<Severity>().expect("routed").as_str(),
                *routed
            );
        }
    }

    /// The cadence must come from the manifest, and an unclassifiable schedule
    /// must be `None` rather than a plausible default.
    #[test]
    fn cron_schedules_are_classified_or_refused() {
        assert_eq!(cron_period_secs("0 3 * * 0"), Some(7 * 24 * 60 * 60));
        assert_eq!(cron_period_secs("0 2 * * 6"), Some(7 * 24 * 60 * 60));
        assert_eq!(cron_period_secs("0 3 * * *"), Some(24 * 60 * 60));
        assert_eq!(cron_period_secs("0 * * * *"), Some(60 * 60));
        assert_eq!(cron_period_secs("0 3 1 * *"), Some(31 * 24 * 60 * 60));
        for unsupported in ["*/15 * * * *", "0 3 * * 1-5", "0 0,12 * * *", "nonsense"] {
            assert_eq!(
                cron_period_secs(unsupported),
                None,
                "`{unsupported}` must be refused, not guessed"
            );
        }
    }

    /// A batch rule whose cadence could not be read is UNCHECKED, and unchecked
    /// must be reported — the same fail-closed stance as `Comparison`.
    #[test]
    fn a_batch_rule_with_no_known_cadence_is_reported_not_skipped() {
        let a = alert(
            "CopilotGroundingAuditFindings",
            "sum(max_over_time(copilot_grounding_audit_drafts_total[8d])) > 0",
        );
        let mut out = Vec::new();
        per_alert_rules(&a, &BTreeMap::new(), &mut out);
        assert!(
            out.iter().any(|f| f.contains("could not be read from")),
            "{out:?}"
        );
    }

    #[test]
    fn duplicate_alert_names_are_caught() {
        let v = violations(&rule_set(vec![
            allowlisted(),
            alert("Same", "up == 0"),
            alert("Same", "up == 1"),
        ]));
        assert!(v.iter().any(|f| f.contains("declared 2 times")), "{v:?}");
    }
}
