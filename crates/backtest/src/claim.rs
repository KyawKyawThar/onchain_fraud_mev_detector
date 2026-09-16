//! The false-positive-rate claim (§18; Hardening Epic E) — when, and only
//! when, the corpus supports saying "< 4% false positives" as a **result**
//! rather than a **target**.
//!
//! # What is being claimed
//!
//! *Of the alerts the roster raises on real traffic, fewer than
//! [`ClaimPolicy::target`] are ones simulation refutes.* Three choices in that
//! sentence are deliberate:
//!
//! - **Per alert, not per block.** The rate is `fp / (tp + fp)` over
//!   adjudicated alerts, i.e. one minus precision. A per-block rate could be
//!   driven to zero by padding the corpus with quiet blocks, and quiet blocks
//!   are exactly what hand-built fixtures are cheap to make.
//! - **Simulation's verdict, not ours.** Only [`Provenance::MainnetReplay`]
//!   fixtures count. Hand-built and adversarial fixtures are author-written:
//!   they test each detector's *contract* (does it fire on its signature, does
//!   it stay quiet on a near miss), and an author can write as many as it takes
//!   to make any rate look good. They are reported, never pooled in.
//! - **An upper bound, not a point estimate.** Zero false positives over ten
//!   alerts is a point estimate of 0% and evidence of almost nothing. The claim
//!   holds when the one-sided Wilson score *upper* bound is
//!   under the target — with no refutations at all, that takes 65 adjudicated
//!   alerts. Wilson rather than the normal approximation because the
//!   interesting regime is `k` near zero, where the normal interval collapses
//!   to `[0, 0]` and would "prove" the claim from one clean alert.
//!
//! # Why a second, clustered bound
//!
//! Wilson treats alerts as independent, and mainnet alerts come in bursts. The
//! committed policy therefore also requires the upper bound of a moving-block
//! bootstrap ([`crate::bootstrap`]) to clear the target, which resamples runs
//! of consecutive blocks so a burst counts as the one event it is. The "more
//! clean alerts" figure a report prints is still Wilson's: a bootstrap cannot
//! forecast evidence that does not exist yet.
//!
//! # Why a minimum number of windows
//!
//! Alerts inside one window are not independent draws — one hour of one
//! market regime, one bot's strategy repeated a hundred times. A bound over a
//! single window is a bound about that hour. Requiring several windows does not
//! make the sample independent, but it stops the cheapest way of pretending it
//! is.
//!
//! # Why unadjudicated alerts are excluded, and reported
//!
//! An alert simulation never saw has no verdict (see [`crate::fixture`]). It
//! cannot count against the rate, and it cannot count for it. But a large
//! unadjudicated share means the verdicts cover a *selected* subset of what the
//! roster now raises, so it is printed next to the bound rather than hidden.
//!
//! # What this is not
//!
//! Recall. The flywheel's labels only exist where a detector already fired,
//! so nothing here can say what fraction of real incidents is caught. The
//! hand-built fixtures measure that the signatures still fire; a field recall
//! number needs an independent incident source this repository does not have.
//!
//! # Policy is a value
//!
//! The target, the confidence and the window floor are one [`ClaimPolicy`],
//! and [`ClaimPolicy::COMMITTED`] is the one this repository states. The
//! confidence is a [`OneSided`] level that owns its z-quantile, so the level a
//! report prints and the quantile the bound uses cannot disagree. Moving the
//! committed policy is a reviewed diff, like the promotion gate's file. The
//! README must quote its target and, until [`ClaimVerdict::Supported`], must
//! call it a target. `tests/readme_claim.rs` enforces both.

use std::collections::BTreeMap;

use crate::bootstrap::{BlockBootstrap, BlockTally};
use crate::fixture::Provenance;
use crate::scoring::{aggregate, DetectorStats};
use crate::Report;

/// A one-sided confidence level, carrying its own standard-normal quantile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OneSided {
    P95,
    P99,
}

impl OneSided {
    /// The z-quantile the Wilson bound is taken at.
    pub fn z(self) -> f64 {
        match self {
            OneSided::P95 => 1.644_853_626_951_472_2,
            OneSided::P99 => 2.326_347_874_040_840_8,
        }
    }

    pub fn percent(self) -> u32 {
        match self {
            OneSided::P95 => 95,
            OneSided::P99 => 99,
        }
    }
}

/// What it takes for the corpus to support the claim.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClaimPolicy {
    /// The false-positive rate the claim names.
    pub target: f64,
    pub confidence: OneSided,
    /// Minimum distinct mainnet windows (see the module docs).
    pub min_windows: usize,
    /// The clustered bound that must clear too, or `None` to rely on Wilson
    /// alone (tests only; the committed policy always sets it).
    pub bootstrap: Option<BlockBootstrap>,
}

impl ClaimPolicy {
    /// The policy this repository states in its README.
    pub const COMMITTED: ClaimPolicy = ClaimPolicy {
        target: 0.04,
        confidence: OneSided::P95,
        min_windows: 3,
        bootstrap: Some(BlockBootstrap {
            block_len: 25,
            replicates: 2_000,
            seed: 0x0000_E91C_2026_0917,
        }),
    };

    /// The quantile the upper bounds are read at.
    pub fn quantile(&self) -> f64 {
        f64::from(self.confidence.percent()) / 100.0
    }

    /// The Wilson score interval for `k` refutations in `n` adjudicated
    /// alerts, as `(lower, upper)`. `None` for `n == 0`: no trials, no
    /// interval.
    pub fn wilson_interval(&self, k: u64, n: u64) -> Option<(f64, f64)> {
        if n == 0 {
            return None;
        }
        let z = self.confidence.z();
        let n_f = n as f64;
        let p = k.min(n) as f64 / n_f;
        let z2 = z * z;
        let denom = 1.0 + z2 / n_f;
        let centre = p + z2 / (2.0 * n_f);
        let margin = z * (p * (1.0 - p) / n_f + z2 / (4.0 * n_f * n_f)).sqrt();
        let lower = ((centre - margin) / denom).max(0.0);
        let upper = ((centre + margin) / denom).min(1.0);
        Some((lower, upper))
    }

    /// The interval for one detector's (or the pooled) adjudicated alerts.
    pub fn interval(&self, stats: &DetectorStats) -> Option<(f64, f64)> {
        self.wilson_interval(stats.false_positives, adjudicated(stats))
    }

    /// How many **more** adjudicated alerts, all confirmed, it would take for
    /// the upper bound over `k` refutations in `n` alerts to fall under the
    /// target.
    pub fn clean_alerts_needed(&self, k: u64, n: u64) -> u64 {
        let clears = |extra: u64| {
            self.wilson_interval(k, n + extra)
                .is_some_and(|(_, upper)| upper < self.target)
        };
        if clears(0) {
            return 0;
        }
        // The bound falls monotonically as clean alerts are added at fixed
        // `k`, so bracket, then bisect.
        let mut high = 1u64;
        while !clears(high) {
            high = high.saturating_mul(2);
        }
        let mut low = high / 2;
        while high - low > 1 {
            let mid = low + (high - low) / 2;
            if clears(mid) {
                high = mid;
            } else {
                low = mid;
            }
        }
        high
    }

    /// Whether the evidence shows the rate is above the target.
    fn contradicted_by(&self, stats: &DetectorStats) -> bool {
        self.interval(stats)
            .is_some_and(|(lower, _)| lower > self.target)
    }
}

/// Alerts that carry a verdict: the rate's denominator. On mainnet-replay
/// results, true positives are confirmed alerts and false positives refuted
/// ones; unadjudicated alerts are in neither.
pub fn adjudicated(stats: &DetectorStats) -> u64 {
    stats.true_positives + stats.false_positives
}

/// Whether the corpus supports stating the target as a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimVerdict {
    /// The bound is under the target, over enough windows.
    Supported,
    /// Not enough evidence either way. The README states a target.
    Insufficient {
        more_clean_alerts: u64,
        more_windows: usize,
        /// Whether the clustered bound clears (always `true` without one).
        clustered_bound_clears: bool,
    },
    /// The evidence shows the rate is *above* the target (the lower bound
    /// clears it), pooled or for the named detectors.
    Contradicted { detectors: Vec<String> },
}

impl ClaimVerdict {
    pub fn is_supported(&self) -> bool {
        matches!(self, ClaimVerdict::Supported)
    }
}

/// The evaluated claim, printable.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimReport {
    pub policy: ClaimPolicy,
    pub windows: usize,
    pub window_blocks: u64,
    pub pooled: DetectorStats,
    pub per_detector: BTreeMap<String, DetectorStats>,
    /// The block-bootstrap upper bound, when the policy has one and the
    /// evidence supports it.
    pub clustered_upper: Option<f64>,
    /// Verdicts dropped because this build does not link their detector.
    pub orphaned_verdicts: u64,
    /// Author-written fixtures replayed but kept out of the claim, by
    /// provenance.
    pub excluded_fixtures: BTreeMap<&'static str, usize>,
    pub verdict: ClaimVerdict,
}

/// Evaluate the claim over the mainnet-replay part of `report`.
pub fn evaluate(report: &Report, policy: &ClaimPolicy) -> ClaimReport {
    let mut excluded_fixtures: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut replays = Vec::new();
    for fixture in &report.fixtures {
        if fixture.provenance == Provenance::MainnetReplay {
            replays.push(fixture);
        } else {
            *excluded_fixtures
                .entry(fixture.provenance.as_str())
                .or_default() += 1;
        }
    }

    let windows = replays.len();
    let window_blocks = replays.iter().map(|r| r.blocks_replayed).sum();
    let orphaned_verdicts = replays.iter().map(|r| r.orphaned_verdicts).sum();
    let per_detector = aggregate(replays.iter().copied());
    let pooled = per_detector
        .values()
        .fold(DetectorStats::default(), |mut acc, s| {
            acc.true_positives += s.true_positives;
            acc.false_positives += s.false_positives;
            acc.false_negatives += s.false_negatives;
            acc.unadjudicated += s.unadjudicated;
            acc.blocks_hit += s.blocks_hit;
            acc
        });

    let by_block: Vec<&[BlockTally]> = replays
        .iter()
        .map(|r| r.adjudicated_by_block.as_slice())
        .collect();
    let clustered_upper = policy
        .bootstrap
        .and_then(|b| b.upper_bound(&by_block, policy.quantile()));
    let clustered_bound_clears = match policy.bootstrap {
        None => true,
        Some(_) => clustered_upper.is_some_and(|upper| upper < policy.target),
    };

    let mut contradicting: Vec<String> = per_detector
        .iter()
        .filter(|(_, s)| policy.contradicted_by(s))
        .map(|(id, _)| id.clone())
        .collect();
    if contradicting.is_empty() && policy.contradicted_by(&pooled) {
        contradicting.push("(pooled)".to_owned());
    }

    let verdict = if !contradicting.is_empty() {
        ClaimVerdict::Contradicted {
            detectors: contradicting,
        }
    } else {
        let more_clean_alerts =
            policy.clean_alerts_needed(pooled.false_positives, adjudicated(&pooled));
        let more_windows = policy.min_windows.saturating_sub(windows);
        if more_clean_alerts == 0 && more_windows == 0 && clustered_bound_clears {
            ClaimVerdict::Supported
        } else {
            ClaimVerdict::Insufficient {
                more_clean_alerts,
                more_windows,
                clustered_bound_clears,
            }
        }
    };

    ClaimReport {
        policy: *policy,
        windows,
        window_blocks,
        pooled,
        per_detector,
        clustered_upper,
        orphaned_verdicts,
        excluded_fixtures,
        verdict,
    }
}

fn pct(rate: f64) -> String {
    format!("{:.1}%", rate * 100.0)
}

impl ClaimReport {
    fn fmt_stats(&self, s: &DetectorStats) -> String {
        let n = adjudicated(s);
        let rate = if n > 0 {
            pct(s.false_positives as f64 / n as f64)
        } else {
            "n/a".to_owned()
        };
        let bound = self.policy.interval(s).map_or_else(
            || "n/a".to_owned(),
            |(lo, hi)| format!("[{}, {}]", pct(lo), pct(hi)),
        );
        format!(
            "fp rate {rate} {bound} over {n} adjudicated (refuted={}, unadjudicated={})",
            s.false_positives, s.unadjudicated
        )
    }
}

impl std::fmt::Display for ClaimReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "false-positive rate claim (§18): target < {} of simulation-adjudicated alerts, \
             {}% one-sided Wilson{} bound, ≥ {} mainnet windows",
            pct(self.policy.target),
            self.policy.confidence.percent(),
            if self.policy.bootstrap.is_some() {
                " and block-bootstrap"
            } else {
                ""
            },
            self.policy.min_windows,
        )?;
        writeln!(
            f,
            "  evidence: {} mainnet window(s) / {} blocks — {}",
            self.windows,
            self.window_blocks,
            self.fmt_stats(&self.pooled)
        )?;
        for (id, stats) in &self.per_detector {
            writeln!(f, "    {id:<20} {}", self.fmt_stats(stats))?;
        }
        if let Some(b) = self.policy.bootstrap {
            let bound = self
                .clustered_upper
                .map_or_else(|| "n/a (too little evidence)".to_owned(), pct);
            writeln!(
                f,
                "  clustered bound: {bound} ({}-block runs, {} replicates)",
                b.block_len, b.replicates
            )?;
        }
        if self.orphaned_verdicts > 0 {
            writeln!(
                f,
                "  orphaned: {} verdict(s) for detectors this build does not link — not scored",
                self.orphaned_verdicts
            )?;
        }
        if !self.excluded_fixtures.is_empty() {
            let excluded: Vec<String> = self
                .excluded_fixtures
                .iter()
                .map(|(kind, n)| format!("{n} {kind}"))
                .collect();
            writeln!(
                f,
                "  not evidence: {} fixture(s) — author-written, they test detector contracts, \
                 not field precision",
                excluded.join(" + ")
            )?;
        }
        let target = pct(self.policy.target);
        match &self.verdict {
            ClaimVerdict::Supported => writeln!(
                f,
                "  SUPPORTED — the bound is under the target; the README may state it as a result"
            ),
            ClaimVerdict::Insufficient {
                more_clean_alerts,
                more_windows,
                clustered_bound_clears,
            } => writeln!(
                f,
                "  INSUFFICIENT — needs {more_clean_alerts} more clean adjudicated alert(s) and \
                 {more_windows} more window(s){}; the README states < {target} as a target",
                if *clustered_bound_clears {
                    ""
                } else {
                    ", and the clustered bound must clear"
                }
            ),
            ClaimVerdict::Contradicted { detectors } => writeln!(
                f,
                "  CONTRADICTED — the rate is above the target for: {}; the README must not \
                 state it as a result",
                detectors.join(", ")
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::ExpectedIncident;
    use crate::scoring::{Finding, FixtureResult};
    use detection::DetectorId;
    use events::primitives::AlertKind;
    use std::borrow::Cow;

    const POLICY: ClaimPolicy = ClaimPolicy::COMMITTED;

    #[test]
    fn wilson_with_no_failures_needs_sixty_five_trials_to_clear_four_percent() {
        // The figure the module docs quote.
        assert!(POLICY.wilson_interval(0, 64).unwrap().1 >= POLICY.target);
        assert!(POLICY.wilson_interval(0, 65).unwrap().1 < POLICY.target);
        assert_eq!(POLICY.clean_alerts_needed(0, 0), 65);
        assert_eq!(POLICY.clean_alerts_needed(0, 60), 5);
        assert_eq!(POLICY.clean_alerts_needed(0, 65), 0);
    }

    #[test]
    fn wilson_does_not_collapse_at_zero_like_the_normal_interval() {
        let (lower, upper) = POLICY.wilson_interval(0, 1).unwrap();
        assert_eq!(lower, 0.0);
        assert!(
            upper > 0.5,
            "one clean trial is almost no evidence: {upper}"
        );
        assert_eq!(POLICY.wilson_interval(0, 0), None);
    }

    #[test]
    fn each_refutation_raises_the_bar() {
        assert!(POLICY.clean_alerts_needed(1, 0) > POLICY.clean_alerts_needed(0, 0));
        assert!(POLICY.clean_alerts_needed(2, 0) > POLICY.clean_alerts_needed(1, 0));
    }

    #[test]
    fn a_stricter_confidence_needs_more_evidence() {
        let strict = ClaimPolicy {
            confidence: OneSided::P99,
            ..POLICY
        };
        assert!(strict.clean_alerts_needed(0, 0) > POLICY.clean_alerts_needed(0, 0));
    }

    fn finding(detector: &str) -> Finding {
        Finding {
            block: 1,
            detector: detector.to_owned(),
            kind: AlertKind::Sandwich,
            txs: Vec::new(),
        }
    }

    fn incident(detector: &'static str) -> ExpectedIncident {
        ExpectedIncident::new(1, DetectorId::new(detector), AlertKind::Sandwich, "x")
    }

    fn result(
        provenance: Provenance,
        confirmed: usize,
        refuted: usize,
        unadj: usize,
    ) -> FixtureResult {
        FixtureResult {
            name: Cow::Borrowed("f"),
            provenance,
            caught: vec![incident("sandwich"); confirmed],
            missed: Vec::new(),
            unexpected: vec![finding("sandwich"); refuted],
            unadjudicated: vec![finding("sandwich"); unadj],
            refutations_cleared: 0,
            orphaned_verdicts: 0,
            blocks_replayed: 10,
            // Spread evenly, so the clustered bound agrees with Wilson.
            adjudicated_by_block: spread(10, confirmed, refuted),
            detector_hits: BTreeMap::new(),
        }
    }

    fn spread(blocks: usize, confirmed: usize, refuted: usize) -> Vec<BlockTally> {
        (0..blocks)
            .map(|i| BlockTally {
                confirmed: (confirmed / blocks + usize::from(i < confirmed % blocks)) as u32,
                refuted: (refuted / blocks + usize::from(i < refuted % blocks)) as u32,
            })
            .collect()
    }

    const MAINNET: Provenance = Provenance::MainnetReplay;

    fn report(fixtures: Vec<FixtureResult>) -> Report {
        Report {
            fixtures,
            detectors: BTreeMap::new(),
            total_blocks: 0,
        }
    }

    #[test]
    fn hand_built_evidence_never_supports_the_claim() {
        // A thousand perfect hand-built alerts are still zero field evidence.
        let claim = evaluate(
            &report(vec![
                result(Provenance::HandBuilt, 1_000, 0, 0),
                result(Provenance::Adversarial, 0, 0, 0),
            ]),
            &POLICY,
        );
        assert_eq!(claim.pooled, DetectorStats::default());
        assert_eq!(
            claim.verdict,
            ClaimVerdict::Insufficient {
                more_clean_alerts: 65,
                more_windows: POLICY.min_windows,
                clustered_bound_clears: false,
            }
        );
        assert_eq!(claim.excluded_fixtures.get("hand-built"), Some(&1));
        assert_eq!(claim.excluded_fixtures.get("adversarial"), Some(&1));
    }

    #[test]
    fn enough_clean_alerts_over_enough_windows_is_supported() {
        let claim = evaluate(
            &report(vec![
                result(MAINNET, 30, 0, 5),
                result(MAINNET, 30, 0, 0),
                result(MAINNET, 30, 0, 0),
            ]),
            &POLICY,
        );
        assert_eq!(adjudicated(&claim.pooled), 90);
        assert_eq!(claim.pooled.unadjudicated, 5);
        assert!(claim.verdict.is_supported(), "{claim}");
    }

    #[test]
    fn one_big_window_is_not_enough() {
        let claim = evaluate(&report(vec![result(MAINNET, 500, 0, 0)]), &POLICY);
        assert_eq!(
            claim.verdict,
            ClaimVerdict::Insufficient {
                more_clean_alerts: 0,
                more_windows: POLICY.min_windows - 1,
                clustered_bound_clears: true,
            }
        );
    }

    #[test]
    fn unadjudicated_alerts_count_neither_way() {
        let claim = evaluate(
            &report(vec![
                result(MAINNET, 0, 0, 10_000),
                result(MAINNET, 0, 0, 0),
                result(MAINNET, 0, 0, 0),
            ]),
            &POLICY,
        );
        assert_eq!(adjudicated(&claim.pooled), 0);
        assert!(!claim.verdict.is_supported());
    }

    #[test]
    fn a_rate_clearly_above_target_contradicts_the_claim() {
        let claim = evaluate(
            &report(vec![
                result(MAINNET, 50, 20, 0),
                result(MAINNET, 50, 20, 0),
                result(MAINNET, 50, 20, 0),
            ]),
            &POLICY,
        );
        assert_eq!(
            claim.verdict,
            ClaimVerdict::Contradicted {
                detectors: vec!["sandwich".to_owned()]
            }
        );
        assert!(claim.to_string().contains("CONTRADICTED"));
    }

    #[test]
    fn a_burst_that_wilson_would_pass_is_held_by_the_clustered_bound() {
        // 600 confirmed alerts; 12 refutations all in one block of one window.
        let window = |burst: bool| {
            let mut r = result(MAINNET, 0, 0, 0);
            r.adjudicated_by_block = vec![
                BlockTally {
                    confirmed: 2,
                    refuted: 0
                };
                100
            ];
            r.caught = vec![incident("sandwich"); 200];
            if burst {
                r.adjudicated_by_block[50].refuted = 12;
                r.unexpected = vec![finding("sandwich"); 12];
            }
            r
        };
        let wilson_only = ClaimPolicy {
            bootstrap: None,
            ..POLICY
        };
        let fixtures = || vec![window(true), window(false), window(false)];

        assert!(evaluate(&report(fixtures()), &wilson_only)
            .verdict
            .is_supported());
        let claim = evaluate(&report(fixtures()), &POLICY);
        assert!(
            matches!(
                claim.verdict,
                ClaimVerdict::Insufficient {
                    more_clean_alerts: 0,
                    more_windows: 0,
                    clustered_bound_clears: false,
                }
            ),
            "{claim}"
        );
        assert!(claim.clustered_upper.unwrap() > POLICY.target);
        assert!(claim.to_string().contains("clustered bound must clear"));
    }

    #[test]
    fn orphaned_verdicts_are_reported_not_scored() {
        let mut orphaned = result(MAINNET, 0, 0, 0);
        orphaned.orphaned_verdicts = 4;
        let claim = evaluate(&report(vec![orphaned]), &POLICY);
        assert_eq!(claim.orphaned_verdicts, 4);
        assert_eq!(adjudicated(&claim.pooled), 0);
        assert!(claim.to_string().contains("orphaned: 4"));
    }
}
