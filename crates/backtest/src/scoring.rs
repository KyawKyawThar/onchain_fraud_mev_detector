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

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use alloy_primitives::B256;
use detection::{register_cross_block_builtins, PerformanceStore, RolloutPolicy};
use events::primitives::AlertKind;
use events::DomainEvent;

use crate::bootstrap::BlockTally;
use crate::fixture::{ExpectedIncident, Fixture, GroundTruth, Provenance};
use crate::Roster;

/// One alert the roster raised while replaying a fixture — just enough to match
/// against an [`ExpectedIncident`] or, left unmatched, count as a false positive
/// (closed world) or an unadjudicated alert (open world).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub block: u64,
    pub detector: String,
    pub kind: AlertKind,
    /// The transactions the finding implicated, read off the
    /// `DetectorTriggered` emitted immediately before its alert.
    pub txs: Vec<B256>,
}

impl Finding {
    /// Whether this alert is the one `incident` describes: same block,
    /// detector and kind, and — when the incident pins them — the same set of
    /// implicated transactions. Order is ignored: it is a detector's reporting
    /// choice, not part of what was found.
    fn matches(&self, incident: &ExpectedIncident) -> bool {
        self.block == incident.block
            && self.detector == incident.detector.as_str()
            && self.kind == incident.kind
            && incident
                .txs
                .as_ref()
                .is_none_or(|txs| same_set(txs, &self.txs))
    }
}

fn same_set(a: &[B256], b: &[B256]) -> bool {
    let a: BTreeSet<&B256> = a.iter().collect();
    let b: BTreeSet<&B256> = b.iter().collect();
    a == b
}

/// One fixture's replay outcome.
#[derive(Debug)]
pub struct FixtureResult {
    pub name: Cow<'static, str>,
    pub provenance: Provenance,
    /// Ground-truth incidents a raised alert matched.
    pub caught: Vec<ExpectedIncident>,
    /// Ground-truth incidents no raised alert matched — false negatives.
    pub missed: Vec<ExpectedIncident>,
    /// Raised alerts known to be wrong — false positives. On a closed-world
    /// fixture, every alert that matched no incident; on an open-world one,
    /// only alerts matching a refuted verdict.
    pub unexpected: Vec<Finding>,
    /// Raised alerts an open-world fixture has no verdict for. Neither true
    /// nor false; counted so the share of the replay that went unjudged is
    /// visible. Always empty on a closed-world fixture.
    pub unadjudicated: Vec<Finding>,
    /// Refuted verdicts the replay no longer raises an alert for — a false
    /// positive the current roster has stopped making.
    pub refutations_cleared: u64,
    /// Verdicts dropped at load because this build does not link their
    /// detector (see [`crate::fixture::GroundTruth::Replay`]).
    pub orphaned_verdicts: u64,
    /// How many blocks this fixture replayed — the hit-rate denominator (§18).
    pub blocks_replayed: u64,
    /// Confirmed (caught) and refuted (unexpected) alerts per replayed block,
    /// in block order: what the claim's block bootstrap resamples
    /// ([`crate::bootstrap`]).
    pub adjudicated_by_block: Vec<BlockTally>,
    /// Distinct blocks *within this fixture* each detector raised at least one
    /// alert on — the hit-rate numerator, keyed by `DetectorId` string. Computed
    /// from every raised alert (true positive or false positive alike): firing
    /// is firing, regardless of whether ground truth later confirms it.
    pub detector_hits: BTreeMap<String, u64>,
}

/// Replay `fixture`'s blocks, in order, through `roster.plan` (the linked
/// `Block` roster) and a **fresh** cross-block roster built fresh from
/// `roster.flags` — so wash-trading's trailing window can't leak state between
/// independent fixtures — then match the raised alerts against ground truth.
///
/// Every detector here runs as [`RolloutPolicy::default`] (`Active`), regardless
/// of the live service's current staging: the backtest harness measures a
/// detector's true detection capability so it can *inform* a Shadow→Active
/// promotion, so it can't itself be gated by that decision (§18, Sprint 10 t4).
///
/// Matching is by `(block, detector, kind)`, greedy and one-to-one: each
/// expected incident consumes at most one raised alert, and whatever alerts are
/// left over afterwards are unexplained. `expected.detector` (a `DetectorId`)
/// is compared against `Finding.detector` (a wire `String` — the alert didn't
/// come off a `'static` constant, so it can't be typed as one) via `as_str`.
pub fn run_fixture(fixture: &Fixture, roster: &Roster) -> FixtureResult {
    let mut cross_block = register_cross_block_builtins(
        &roster.flags,
        &RolloutPolicy::default(),
        &PerformanceStore::new(),
    );
    let mut findings = Vec::new();
    for ctx in &fixture.blocks {
        let block = ctx.block().number;
        let mut events = roster.plan.detection_events(ctx);
        events.extend(cross_block.observe_and_detect(ctx));
        // The emitter publishes each finding's trigger immediately before its
        // alert (`evidence_events`), so the last trigger seen is this alert's.
        // A `Shadow` detector emits a trigger with no alert; the next trigger
        // simply replaces it.
        let mut last_txs = Vec::new();
        for event in events {
            match event {
                DomainEvent::DetectorTriggered(trigger) => last_txs = trigger.txs,
                DomainEvent::PreliminaryAlertCreated(alert) => findings.push(Finding {
                    block,
                    detector: alert.detector.id,
                    kind: alert.kind,
                    txs: std::mem::take(&mut last_txs),
                }),
                _ => {}
            }
        }
    }

    // Distinct (detector, block) pairs, captured before matching below consumes
    // any finding — a false positive still counts as the detector having fired.
    let mut hit_blocks: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
    for f in &findings {
        hit_blocks
            .entry(f.detector.clone())
            .or_default()
            .insert(f.block);
    }
    let detector_hits = hit_blocks
        .into_iter()
        .map(|(id, blocks)| (id, blocks.len() as u64))
        .collect();

    let mut caught = Vec::new();
    let mut missed = Vec::new();
    for expected in fixture.expected() {
        match take_match(&mut findings, expected) {
            Some(_) => caught.push(expected.clone()),
            None => missed.push(expected.clone()),
        }
    }

    let mut unexpected = Vec::new();
    let mut refutations_cleared = 0;
    for refuted in fixture.truth().refuted() {
        match take_match(&mut findings, refuted) {
            Some(finding) => unexpected.push(finding),
            None => refutations_cleared += 1,
        }
    }

    // Whatever is left matched nothing listed: a false positive only where the
    // listing is complete.
    let provenance = fixture.provenance();
    let unadjudicated = if provenance.is_closed_world() {
        unexpected.extend(findings);
        Vec::new()
    } else {
        findings
    };

    let position: BTreeMap<u64, usize> = fixture
        .blocks
        .iter()
        .enumerate()
        .map(|(i, ctx)| (ctx.block().number, i))
        .collect();
    let mut adjudicated_by_block = vec![BlockTally::default(); fixture.blocks.len()];
    for hit in &caught {
        if let Some(&i) = position.get(&hit.block) {
            adjudicated_by_block[i].confirmed += 1;
        }
    }
    for fp in &unexpected {
        if let Some(&i) = position.get(&fp.block) {
            adjudicated_by_block[i].refuted += 1;
        }
    }

    FixtureResult {
        name: fixture.name.clone(),
        provenance,
        caught,
        missed,
        unexpected,
        unadjudicated,
        refutations_cleared,
        orphaned_verdicts: match fixture.truth() {
            GroundTruth::Replay { orphaned, .. } => *orphaned,
            GroundTruth::Authored { .. } => 0,
        },
        blocks_replayed: fixture.blocks.len() as u64,
        adjudicated_by_block,
        detector_hits,
    }
}

/// Remove and return the first finding matching `incident` — greedy and
/// one-to-one, so each label consumes at most one alert.
fn take_match(findings: &mut Vec<Finding>, incident: &ExpectedIncident) -> Option<Finding> {
    let index = findings.iter().position(|f| f.matches(incident))?;
    Some(findings.remove(index))
}

/// One detector's track record across a fixture set (§18): counted
/// true/false positives/negatives, from which precision/recall derive, plus how
/// many blocks it fired on (the hit-rate numerator — see [`Report::hit_rate`]).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DetectorStats {
    pub true_positives: u64,
    pub false_positives: u64,
    pub false_negatives: u64,
    pub blocks_hit: u64,
    /// Alerts on open-world fixtures with no verdict — excluded from precision
    /// on both sides of the ratio.
    pub unadjudicated: u64,
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
    /// Total blocks replayed across every fixture — the same denominator for
    /// every detector's hit rate, since every detector runs over every block.
    pub total_blocks: u64,
}

impl Report {
    /// Fraction of replayed blocks `id` fired on at least once — the
    /// volume/noise signal `Performance::Measured::hit_rate` carries. `None`
    /// when no blocks were replayed (an empty fixture set).
    pub fn hit_rate(&self, id: &str) -> Option<f64> {
        (self.total_blocks > 0).then(|| {
            let hits = self.detectors.get(id).map_or(0, |s| s.blocks_hit);
            hits as f64 / self.total_blocks as f64
        })
    }
}

/// Replay every fixture and roll the per-fixture outcomes up into per-detector
/// precision/recall. `roster` is built once by the caller (the same boot-time
/// link-or-fail discipline as the live service, see [`crate::boot`]) and shared
/// across every fixture; each fixture still gets its own fresh cross-block state.
pub fn run_backtest(fixtures: &[Fixture], roster: &Roster) -> Report {
    let results: Vec<FixtureResult> = fixtures.iter().map(|f| run_fixture(f, roster)).collect();
    Report {
        detectors: aggregate(&results),
        total_blocks: results.iter().map(|r| r.blocks_replayed).sum(),
        fixtures: results,
    }
}

/// Roll per-fixture outcomes up into per-detector stats.
///
/// The one fold over [`FixtureResult`]s: [`run_backtest`] applies it to every
/// fixture, and [`crate::claim`] to the mainnet-replay subset. Two
/// hand-written folds over the same results would be two definitions of a
/// true positive, free to drift apart.
pub fn aggregate<'a>(
    results: impl IntoIterator<Item = &'a FixtureResult>,
) -> BTreeMap<String, DetectorStats> {
    let mut detectors: BTreeMap<String, DetectorStats> = BTreeMap::new();
    for result in results {
        for hit in &result.caught {
            entry(&mut detectors, hit.detector.as_str()).true_positives += 1;
        }
        for miss in &result.missed {
            entry(&mut detectors, miss.detector.as_str()).false_negatives += 1;
        }
        for fp in &result.unexpected {
            entry(&mut detectors, &fp.detector).false_positives += 1;
        }
        for alert in &result.unadjudicated {
            entry(&mut detectors, &alert.detector).unadjudicated += 1;
        }
        for (id, hits) in &result.detector_hits {
            entry(&mut detectors, id).blocks_hit += hits;
        }
    }
    detectors
}

/// The stats for `id`, allocating its key only on first sight.
fn entry<'m>(
    detectors: &'m mut BTreeMap<String, DetectorStats>,
    id: &str,
) -> &'m mut DetectorStats {
    if !detectors.contains_key(id) {
        detectors.insert(id.to_owned(), DetectorStats::default());
    }
    detectors.get_mut(id).expect("inserted above")
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "backtest: {} fixtures replayed\n", self.fixtures.len())?;
        for fx in &self.fixtures {
            writeln!(f, "[{}] {}", fx.provenance.as_str(), fx.name)?;
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
            if !fx.unadjudicated.is_empty() {
                writeln!(
                    f,
                    "  unadjudicated alerts: {} (no simulation verdict — excluded from precision)",
                    fx.unadjudicated.len()
                )?;
            }
            if fx.refutations_cleared > 0 {
                writeln!(
                    f,
                    "  refutations cleared: {} (refuted live, no longer raised)",
                    fx.refutations_cleared
                )?;
            }
        }

        writeln!(f, "\nper-detector precision / recall / hit_rate:")?;
        for (id, stats) in &self.detectors {
            writeln!(
                f,
                "  {id:<20} precision {}  recall {}  hit_rate {}  (tp={} fp={} fn={} blocks_hit={}/{})",
                fmt_rate(stats.precision()),
                fmt_rate(stats.recall()),
                fmt_rate(self.hit_rate(id)),
                stats.true_positives,
                stats.false_positives,
                stats.false_negatives,
                stats.blocks_hit,
                self.total_blocks,
            )?;
            if stats.unadjudicated > 0 {
                writeln!(f, "  {:<20} unadjudicated={}", "", stats.unadjudicated)?;
            }
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
            ..Default::default()
        };
        assert_eq!(stats.precision(), Some(0.75));
        assert_eq!(stats.recall(), Some(0.75));
    }

    fn report_of(total_blocks: u64, entries: &[(&str, DetectorStats)]) -> Report {
        Report {
            fixtures: Vec::new(),
            detectors: entries
                .iter()
                .map(|(id, stats)| (id.to_string(), *stats))
                .collect(),
            total_blocks,
        }
    }

    #[test]
    fn hit_rate_divides_blocks_hit_by_total_blocks() {
        let report = report_of(
            10,
            &[(
                "sandwich",
                DetectorStats {
                    blocks_hit: 3,
                    ..Default::default()
                },
            )],
        );
        assert_eq!(report.hit_rate("sandwich"), Some(0.3));
    }

    #[test]
    fn hit_rate_is_zero_not_none_for_a_detector_with_no_hits() {
        let report = report_of(10, &[]);
        assert_eq!(report.hit_rate("sandwich"), Some(0.0));
    }

    #[test]
    fn hit_rate_is_none_over_an_empty_fixture_set() {
        let report = report_of(0, &[]);
        assert_eq!(report.hit_rate("sandwich"), None);
    }

    #[test]
    fn run_fixture_counts_a_real_hit_on_the_textbook_sandwich_fixture() {
        // End-to-end: the sandwich fixture's one block should register as a
        // block-hit for "sandwich" (it raises the textbook alert) and count
        // toward `blocks_replayed`.
        let roster = crate::boot().expect("linking the built-in roster");
        let result = run_fixture(&crate::fixtures::sandwich(), &roster);

        assert_eq!(result.blocks_replayed, 1);
        assert_eq!(result.detector_hits.get("sandwich"), Some(&1));
    }
}
