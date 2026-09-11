//! Reading a verdict out of a Prometheus histogram.
//!
//! The load test's subject reports its own latency as a bucketed histogram
//! (`telemetry::metrics` buckets every `_seconds` series), so the question
//! "did the p99 stay under a second?" is answered from bucket counts, not from
//! a stream of samples. Two consequences shape this module:
//!
//! **A bucketed quantile is a bound, never a point.** With a bucket boundary at
//! exactly `1.0` — which the shared ladder has — "p99 < 1s" is *exactly*
//! decidable without interpolating: it holds iff at least 99% of samples landed
//! in buckets with `le <= 1.0`. [`Histogram::share_at_most`] answers that and
//! nothing else. Where no boundary sits on the threshold the honest answer is
//! that this histogram cannot decide it, so `share_at_most` returns `None`
//! rather than interpolating a plausible-looking number — a load test that
//! invents its own headline figure is worse than one that admits it cannot
//! measure.
//!
//! **Counters are cumulative, so a measurement is a difference.** A scrape
//! reports every sample since the process started, including the warmup and any
//! traffic that happened to precede the run. [`Histogram::since`] subtracts a
//! baseline scrape so the reported window is the load window. Without it a long
//! -lived service's healthy idle history dilutes the run's own samples and a
//! breach disappears into the denominator.

use std::collections::BTreeMap;

use anyhow::{Context, Result};

/// One histogram series' state at a moment: cumulative bucket counts (keyed by
/// their `le` upper bound), plus the `_count`/`_sum` pair.
///
/// `+Inf` is held in `count` rather than as a bucket, so `buckets` contains only
/// finite bounds and iteration order is the ladder's order.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Histogram {
    /// `le` upper bound → cumulative sample count at or below it.
    pub buckets: BTreeMap<OrderedBound, u64>,
    /// Total observations (the `_count` series, equal to the `+Inf` bucket).
    pub count: u64,
    /// Sum of all observed values (the `_sum` series), in the metric's unit.
    pub sum: f64,
}

/// A bucket's `le` bound, ordered — `f64` is not `Ord`, and these come from a
/// fixed ladder of positive finite values, so a total order over the bits is
/// both sound and exactly what a `BTreeMap` key needs.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OrderedBound(pub f64);

impl Eq for OrderedBound {}

impl Ord for OrderedBound {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Bounds are finite and positive (a bucket ladder), so `total_cmp`
        // agrees with the usual float ordering on every value that can appear
        // here — and gives a total order on the ones that can't.
        self.0.total_cmp(&other.0)
    }
}

impl PartialOrd for OrderedBound {
    /// Delegates to [`Ord`] rather than deriving. A derived `PartialOrd`
    /// alongside a hand-written `Ord` is two orderings that agree today and are
    /// free to disagree after any edit — the `BTreeMap` this keys would then
    /// look up by one and iterate by the other.
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Histogram {
    /// This histogram minus `baseline` — the samples observed *between* the two
    /// scrapes.
    ///
    /// A restart between the scrapes resets the cumulative counters, which shows
    /// up as a bucket going backwards. That is not a small measurement error, it
    /// is a different process: the run is reported as inconclusive rather than
    /// clamped to zero and passed.
    pub fn since(&self, baseline: &Self) -> Result<Self> {
        let count = self.count.checked_sub(baseline.count).context(
            "histogram count went backwards between scrapes — the service restarted \
             mid-run, so no window of samples was observed",
        )?;
        let mut buckets = BTreeMap::new();
        for (bound, cumulative) in &self.buckets {
            let before = baseline.buckets.get(bound).copied().unwrap_or(0);
            let delta = cumulative.checked_sub(before).with_context(|| {
                format!(
                    "histogram bucket le={} went backwards between scrapes — the service \
                     restarted mid-run",
                    bound.0
                )
            })?;
            buckets.insert(*bound, delta);
        }
        Ok(Self {
            buckets,
            count,
            sum: self.sum - baseline.sum,
        })
    }

    /// The fraction of samples that landed at or below `bound`, or `None` if no
    /// bucket boundary sits exactly there.
    ///
    /// `None` is the answer, not an error: this histogram's ladder simply cannot
    /// decide a threshold it has no boundary for, and the caller reports that as
    /// inconclusive. Interpolating between the neighbouring bounds would produce
    /// a number whose error is the width of a bucket — at the top of the ladder,
    /// several seconds wide — presented as if it were measured.
    pub fn share_at_most(&self, bound: f64) -> Option<f64> {
        if self.count == 0 {
            return None;
        }
        let at_or_below = self.buckets.get(&OrderedBound(bound))?;
        Some(*at_or_below as f64 / self.count as f64)
    }

    /// The tightest upper bound this histogram can put on the `q`-quantile: the
    /// smallest bucket bound whose cumulative share reaches `q`.
    ///
    /// `None` when every finite bucket is below `q` — i.e. more than `1 - q` of
    /// the samples overflowed the ladder's top. That is a real outcome (the
    /// quantile is above the highest bound), reported rather than clamped.
    pub fn quantile_upper_bound(&self, q: f64) -> Option<f64> {
        if self.count == 0 {
            return None;
        }
        let needed = q * self.count as f64;
        self.buckets
            .iter()
            .find(|(_, cumulative)| **cumulative as f64 >= needed)
            .map(|(bound, _)| bound.0)
    }

    /// This histogram plus another instance's.
    ///
    /// Bucket counts add, which is what makes `sum by (le)` the right way to
    /// state an SLO over a replicated service: the quantile of the union is the
    /// quantile the deployment delivers. Buckets missing from one side count as
    /// zero rather than dropping the bound — a replica that has recorded
    /// nothing yet exports no buckets at all, and losing the boundary at 1.0
    /// because one pod was idle would make the budget undecidable.
    pub fn plus(&self, other: &Self) -> Self {
        let mut buckets = self.buckets.clone();
        for (bound, count) in &other.buckets {
            *buckets.entry(*bound).or_insert(0) += count;
        }
        Self {
            buckets,
            count: self.count + other.count,
            sum: self.sum + other.sum,
        }
    }

    /// Mean observed value — context for a quantile, never a substitute: a mean
    /// under budget with a p99 over it is the exact shape this test exists to
    /// catch.
    pub fn mean(&self) -> Option<f64> {
        (self.count > 0).then(|| self.sum / self.count as f64)
    }
}

/// A parsed Prometheus text-format exposition, indexed enough to pull one
/// series out of it.
#[derive(Debug, Clone, Default)]
pub struct Exposition {
    /// `(metric name, sorted label pairs)` → value, for every non-comment line.
    samples: Vec<Sample>,
}

#[derive(Debug, Clone)]
struct Sample {
    name: String,
    labels: Vec<(String, String)>,
    value: f64,
}

impl Exposition {
    /// Parse the body of a `/metrics` response.
    ///
    /// Deliberately tolerant: unknown metric types, `# HELP`/`# TYPE` lines and
    /// exemplars are skipped, and a line that does not parse is skipped rather
    /// than failing the run — the harness reads a handful of named series out of
    /// an exposition that carries hundreds, and one malformed unrelated line
    /// must not decide a latency verdict.
    pub fn parse(body: &str) -> Self {
        let samples = body
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(parse_line)
            .collect();
        Self { samples }
    }

    /// Assemble the histogram named `name` whose labels include every pair in
    /// `selector`, summed across every other label dimension.
    ///
    /// Summing across the rest is what makes a multi-instance scrape work the
    /// way `sum by (le)` does in PromQL: bucket counts add, and the quantile of
    /// the union is what an SLO is stated over.
    pub fn histogram(&self, name: &str, selector: &[(&str, &str)]) -> Histogram {
        let mut histogram = Histogram::default();
        for sample in &self.samples {
            if !sample.matches(selector) {
                continue;
            }
            if let Some(stripped) = sample.name.strip_suffix("_bucket") {
                if stripped != name {
                    continue;
                }
                let Some(le) = sample.label("le") else {
                    continue;
                };
                if le == "+Inf" {
                    continue; // `_count` carries this; a bucket key must be finite.
                }
                let Ok(bound) = le.parse::<f64>() else {
                    continue;
                };
                *histogram.buckets.entry(OrderedBound(bound)).or_insert(0) += sample.value as u64;
            } else if sample.name == format!("{name}_count") {
                histogram.count += sample.value as u64;
            } else if sample.name == format!("{name}_sum") {
                histogram.sum += sample.value;
            }
        }
        histogram
    }

    /// Sum a counter across every series matching `selector`.
    pub fn counter(&self, name: &str, selector: &[(&str, &str)]) -> f64 {
        self.samples
            .iter()
            .filter(|s| s.name == name && s.matches(selector))
            .map(|s| s.value)
            .sum()
    }
}

impl Sample {
    fn label(&self, key: &str) -> Option<&str> {
        self.labels
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    fn matches(&self, selector: &[(&str, &str)]) -> bool {
        selector
            .iter()
            .all(|(k, v)| self.label(k).is_some_and(|actual| actual == *v))
    }
}

/// `metric_name{a="1",b="2"} 3.5` → a sample. `None` for anything that does not
/// have that shape.
fn parse_line(line: &str) -> Option<Sample> {
    let (head, value) = line.rsplit_once(' ')?;
    let value: f64 = value.trim().parse().ok()?;
    let (name, labels) = match head.split_once('{') {
        Some((name, rest)) => (name, parse_labels(rest.strip_suffix('}')?)),
        None => (head, Vec::new()),
    };
    Some(Sample {
        name: name.trim().to_owned(),
        labels,
        value,
    })
}

/// `a="1",b="2"` → the pairs. Values are taken literally; the exporter quotes
/// them and the harness only ever compares them for equality, so unescaping
/// would be a distinction without a difference here.
fn parse_labels(raw: &str) -> Vec<(String, String)> {
    raw.split(',')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some((
                key.trim().to_owned(),
                value.trim().trim_matches('"').to_owned(),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = r#"
# HELP detection_fast_path_duration_seconds the fast path
# TYPE detection_fast_path_duration_seconds histogram
detection_fast_path_duration_seconds_bucket{outcome="alert",le="0.5"} 90
detection_fast_path_duration_seconds_bucket{outcome="alert",le="1"} 99
detection_fast_path_duration_seconds_bucket{outcome="alert",le="2.5"} 100
detection_fast_path_duration_seconds_bucket{outcome="alert",le="+Inf"} 100
detection_fast_path_duration_seconds_sum{outcome="alert"} 40
detection_fast_path_duration_seconds_count{outcome="alert"} 100
detection_fast_path_duration_seconds_bucket{outcome="no_alert",le="0.5"} 7
detection_fast_path_duration_seconds_bucket{outcome="no_alert",le="+Inf"} 7
detection_fast_path_duration_seconds_count{outcome="no_alert"} 7
"#;

    fn alert_histogram() -> Histogram {
        Exposition::parse(BODY).histogram(
            "detection_fast_path_duration_seconds",
            &[("outcome", "alert")],
        )
    }

    #[test]
    fn a_selector_reads_one_outcome_and_leaves_the_other_alone() {
        let h = alert_histogram();
        assert_eq!(h.count, 100, "the no_alert series must not be folded in");
        assert_eq!(h.buckets[&OrderedBound(1.0)], 99);
    }

    #[test]
    fn the_one_second_threshold_is_decided_on_a_real_bucket_boundary() {
        // Exactly 99/100 at or below 1s: the boundary case the SLO turns on.
        assert_eq!(alert_histogram().share_at_most(1.0), Some(0.99));
    }

    #[test]
    fn a_threshold_with_no_bucket_boundary_is_undecidable_not_interpolated() {
        assert_eq!(
            alert_histogram().share_at_most(0.75),
            None,
            "0.75 is between bucket bounds; guessing there would invent the headline number"
        );
    }

    #[test]
    fn an_empty_histogram_decides_nothing() {
        let empty = Histogram::default();
        assert_eq!(empty.share_at_most(1.0), None);
        assert_eq!(empty.quantile_upper_bound(0.99), None);
        assert_eq!(empty.mean(), None);
    }

    #[test]
    fn the_quantile_is_reported_as_the_bucket_that_contains_it() {
        let h = alert_histogram();
        assert_eq!(h.quantile_upper_bound(0.5), Some(0.5));
        assert_eq!(h.quantile_upper_bound(0.99), Some(1.0));
        assert_eq!(h.quantile_upper_bound(1.0), Some(2.5));
    }

    #[test]
    fn a_measurement_is_the_difference_between_two_scrapes() {
        let baseline = Exposition::parse(
            r#"
detection_fast_path_duration_seconds_bucket{outcome="alert",le="0.5"} 40
detection_fast_path_duration_seconds_bucket{outcome="alert",le="1"} 40
detection_fast_path_duration_seconds_bucket{outcome="alert",le="2.5"} 40
detection_fast_path_duration_seconds_sum{outcome="alert"} 4
detection_fast_path_duration_seconds_count{outcome="alert"} 40
"#,
        )
        .histogram(
            "detection_fast_path_duration_seconds",
            &[("outcome", "alert")],
        );

        let window = alert_histogram().since(&baseline).unwrap();
        assert_eq!(window.count, 60);
        // 59/60 under a second in the window, against 99/100 cumulatively — the
        // warmup's clean history would otherwise flatter the run.
        assert_eq!(window.buckets[&OrderedBound(1.0)], 59);
        assert!(window.share_at_most(1.0).unwrap() < 0.99);
    }

    /// Two replicas summed is what the SLO is stated over. Each alone would
    /// have passed here; together they do not — which is the answer the
    /// deployment actually delivers.
    #[test]
    fn replicas_sum_into_the_series_the_slo_is_stated_over() {
        let mut fast = BTreeMap::new();
        fast.insert(OrderedBound(1.0), 100);
        let fast = Histogram {
            buckets: fast,
            count: 100,
            sum: 10.0,
        };

        let mut slow = BTreeMap::new();
        slow.insert(OrderedBound(1.0), 90);
        let slow = Histogram {
            buckets: slow,
            count: 100,
            sum: 150.0,
        };

        let both = fast.plus(&slow);
        assert_eq!(both.count, 200);
        assert_eq!(both.share_at_most(1.0), Some(0.95));
        assert!(
            both.share_at_most(1.0).unwrap() < 0.99,
            "one healthy replica must not carry a struggling one to a pass"
        );
    }

    #[test]
    fn a_replica_that_has_recorded_nothing_keeps_the_others_bucket_bounds() {
        let mut only = BTreeMap::new();
        only.insert(OrderedBound(1.0), 50);
        let recorded = Histogram {
            buckets: only,
            count: 50,
            sum: 5.0,
        };

        let summed = Histogram::default().plus(&recorded);
        assert_eq!(
            summed.share_at_most(1.0),
            Some(1.0),
            "an idle replica must not cost the budget its bucket boundary"
        );
    }

    #[test]
    fn a_restart_mid_run_is_an_error_not_a_zero() {
        let later = Histogram::default();
        let err = later.since(&alert_histogram()).unwrap_err().to_string();
        assert!(err.contains("restarted"), "got: {err}");
    }

    #[test]
    fn unparseable_and_comment_lines_are_skipped_rather_than_fatal() {
        let e = Exposition::parse("# TYPE x counter\ngarbage line here\nx_total{a=\"1\"} 5\n");
        assert_eq!(e.counter("x_total", &[("a", "1")]), 5.0);
    }
}
