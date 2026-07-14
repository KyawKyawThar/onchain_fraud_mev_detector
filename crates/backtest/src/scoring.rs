//! Replay a [`Fixture`] through the pure detection core and score the result
//! against its ground truth (§18, Sprint 10 t2) — the harness's payoff.
//!
//! Replay itself is deliberately the same two calls the live scheduler's
//! `Assembled` branch makes ([`crate::scheduler::Scheduler::process`] in
//! `detection`), just without the rayon/async wrapper around them:
//! [`DetectionPlan::detection_events`] for the `Block` roster, then
//! `CrossBlockStates::observe_and_detect` for the cross-block one. No Kafka, no
//! envelopes — a `Fixture`'s blocks go straight in and its alerts come straight
//! back out, which is what makes this replayable at all.

use std::collections::BTreeMap;

use detection::register_cross_block_builtins;
use events::primitives::AlertKind;
use events::DomainEvent;

use crate::fixture::{ExpectedIncident, Fixture};
use crate::Roster;

/// One alert the roster raised while replaying a fixture — just enough to match
/// against an [`ExpectedIncident`] or, left unmatched, count as a false positive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub block: u64,
    pub detector: String,
    pub kind: AlertKind,
}

/// One fixture's replay outcome.
#[derive(Debug)]
pub struct FixtureResult {
    pub name: &'static str,
    /// Ground-truth incidents a raised alert matched.
    pub caught: Vec<ExpectedIncident>,
    /// Ground-truth incidents no raised alert matched — false negatives.
    pub missed: Vec<ExpectedIncident>,
    /// Raised alerts that matched no ground-truth incident — false positives.
    pub unexpected: Vec<Finding>,
}

/// Replay `fixture`'s blocks, in order, through `roster.plan` (the linked
/// `Block` roster) and a **fresh** cross-block roster built fresh from
/// `roster.flags` — so wash-trading's trailing window can't leak state between
/// independent fixtures — then match the raised alerts against ground truth.
///
/// Matching is by `(block, detector, kind)`, greedy and one-to-one: each
/// expected incident consumes at most one raised alert, and whatever alerts are
/// left over afterwards are unexplained. `expected.detector` (a `DetectorId`)
/// is compared against `Finding.detector` (a wire `String` — the alert didn't
/// come off a `'static` constant, so it can't be typed as one) via `as_str`.
pub fn run_fixture(fixture: &Fixture, roster: &Roster) -> FixtureResult {
    let mut cross_block = register_cross_block_builtins(&roster.flags);
    let mut findings = Vec::new();
    for ctx in &fixture.blocks {
        let block = ctx.block().number;
        let mut events = roster.plan.detection_events(ctx);
        events.extend(cross_block.observe_and_detect(ctx));
        findings.extend(events.into_iter().filter_map(|event| match event {
            DomainEvent::PreliminaryAlertCreated(alert) => Some(Finding {
                block,
                detector: alert.detector.id,
                kind: alert.kind,
            }),
            _ => None,
        }));
    }

    let mut caught = Vec::new();
    let mut missed = Vec::new();
    for expected in &fixture.expected {
        let matched = findings.iter().position(|f| {
            f.block == expected.block
                && f.detector == expected.detector.as_str()
                && f.kind == expected.kind
        });
        match matched {
            Some(idx) => {
                findings.remove(idx);
                caught.push(expected.clone());
            }
            None => missed.push(expected.clone()),
        }
    }

    FixtureResult {
        name: fixture.name,
        caught,
        missed,
        unexpected: findings,
    }
}

/// One detector's track record across a fixture set (§18): counted
/// true/false positives/negatives, from which precision/recall derive.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DetectorStats {
    pub true_positives: u64,
    pub false_positives: u64,
    pub false_negatives: u64,
}

impl DetectorStats {
    /// Of the alerts this detector raised, the fraction that were true
    /// positives. `None` when it raised nothing — "0 of 0" is undefined, not 0.
    pub fn precision(&self) -> Option<f64> {
        let total = self.true_positives + self.false_positives;
        (total > 0).then(|| self.true_positives as f64 / total as f64)
    }

    /// Of the incidents ground-truthed for this detector, the fraction it
    /// caught. `None` when none were ground-truthed.
    pub fn recall(&self) -> Option<f64> {
        let total = self.true_positives + self.false_negatives;
        (total > 0).then(|| self.true_positives as f64 / total as f64)
    }
}

/// The whole fixture set's replay: per-fixture detail plus the per-detector
/// precision/recall roll-up (§18) — the reference stats a future CI gate
/// (Sprint 10 t3) and `ModelCard::Performance` (t4) build on.
#[derive(Debug)]
pub struct Report {
    pub fixtures: Vec<FixtureResult>,
    /// Keyed by `DetectorId` string, deterministic order for a stable report.
    pub detectors: BTreeMap<String, DetectorStats>,
}

/// Replay every fixture and roll the per-fixture outcomes up into per-detector
/// precision/recall. `roster` is built once by the caller (the same boot-time
/// link-or-fail discipline as the live service, see [`crate::boot`]) and shared
/// across every fixture; each fixture still gets its own fresh cross-block state.
pub fn run_backtest(fixtures: &[Fixture], roster: &Roster) -> Report {
    let mut detectors: BTreeMap<String, DetectorStats> = BTreeMap::new();
    let mut results = Vec::with_capacity(fixtures.len());

    for fixture in fixtures {
        let result = run_fixture(fixture, roster);
        for hit in &result.caught {
            detectors
                .entry(hit.detector.to_string())
                .or_default()
                .true_positives += 1;
        }
        for miss in &result.missed {
            detectors
                .entry(miss.detector.to_string())
                .or_default()
                .false_negatives += 1;
        }
        for fp in &result.unexpected {
            detectors
                .entry(fp.detector.clone())
                .or_default()
                .false_positives += 1;
        }
        results.push(result);
    }

    Report {
        fixtures: results,
        detectors,
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "backtest: {} fixtures replayed\n", self.fixtures.len())?;
        for fx in &self.fixtures {
            writeln!(f, "{}", fx.name)?;
            for hit in &fx.caught {
                writeln!(
                    f,
                    "  caught      block {} {} {:?}",
                    hit.block, hit.detector, hit.kind
                )?;
            }
            for miss in &fx.missed {
                writeln!(
                    f,
                    "  MISSED      block {} {} {:?} — {}",
                    miss.block, miss.detector, miss.kind, miss.description
                )?;
            }
            for fp in &fx.unexpected {
                writeln!(
                    f,
                    "  UNEXPECTED  block {} {} {:?}",
                    fp.block, fp.detector, fp.kind
                )?;
            }
        }

        writeln!(f, "\nper-detector precision / recall:")?;
        for (id, stats) in &self.detectors {
            writeln!(
                f,
                "  {id:<20} precision {}  recall {}  (tp={} fp={} fn={})",
                fmt_rate(stats.precision()),
                fmt_rate(stats.recall()),
                stats.true_positives,
                stats.false_positives,
                stats.false_negatives,
            )?;
        }
        Ok(())
    }
}

fn fmt_rate(rate: Option<f64>) -> String {
    match rate {
        Some(r) => format!("{r:.3}"),
        None => "  n/a".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precision_and_recall_are_none_over_zero_samples() {
        let stats = DetectorStats::default();
        assert_eq!(stats.precision(), None);
        assert_eq!(stats.recall(), None);
    }

    #[test]
    fn precision_and_recall_compute_over_nonzero_samples() {
        let stats = DetectorStats {
            true_positives: 3,
            false_positives: 1,
            false_negatives: 1,
        };
        assert_eq!(stats.precision(), Some(0.75));
        assert_eq!(stats.recall(), Some(0.75));
    }
}
