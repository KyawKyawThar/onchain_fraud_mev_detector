//! The `DetectorTriggered` → `SimulationCompleted` join (§20.1) — a pure fold
//! over one replayed window.
//!
//! # The linkage problem, stated honestly
//!
//! The flywheel's ground truth is spread across four events, and the chain
//! between them has one weak link:
//!
//! ```text
//!   DetectorTriggered   { detector, block, txs, raw_confidence }   ← features
//!            ?                                     the weak link
//!   PreliminaryAlertCreated { alert_id, detector, kind, confidence }
//!            │ alert_id
//!   SimulationCompleted { alert_id, confirmed, profit }            ← label
//!            │ alert_id
//!   IncidentCreated    { incident_id, alert_id, txs }
//! ```
//!
//! `DetectorTriggered` carries no id, and `PreliminaryAlertCreated` carries
//! neither the block nor the txs — the same gap that leaves `simulation`'s
//! `JobResolver` stubbed. So the trigger→alert edge has to be *reconstructed*,
//! and this module does it in three layers, strongest first:
//!
//! 1. **Adjacency + confidence.** `detection::emit::evidence_events` emits each
//!    finding's trigger immediately followed by its alert, and carries the
//!    detector's `raw_confidence` onto the alert **unadjusted by design** (the
//!    fast path is attribution-blind, so nothing reweights it). Within one
//!    detector's stream, binding an alert to the oldest unbound trigger of the
//!    same detector *with the same confidence* recovers the pairing.
//! 2. **Incident correction.** `IncidentCreated` carries `alert_id` **and**
//!    `txs` — the one authoritative alert→bundle link in the schema. Whenever
//!    it contradicts a guessed binding, the guess is repaired (or, if it
//!    contradicts an unambiguous binding, recorded as a conflict rather than
//!    silently overwritten).
//! 3. **Marking what is left.** Anything still ambiguous is *labeled as such*
//!    ([`Binding`]) and excluded by default. A mislabeled training row is worse
//!    than a missing one.
//!
//! When can layer 1 be wrong? The store's total order is `(occurred_at,
//! event_id)`, `occurred_at` is millisecond-resolution, and the tie-break is a
//! random `event_id` — so among events stamped the *same millisecond* the
//! stored order is arbitrary. Two findings from one detector at one instant,
//! sharing a confidence, can therefore store with their pairs interleaved, and
//! an alert can even land ahead of its own trigger.
//!
//! The dangerous case is subtler than "two candidates in the queue". If the
//! rival's trigger is stored *after* the alert, the fold sees exactly one
//! candidate and would bind it confidently — to the wrong finding. A streaming
//! fold cannot see that, because the evidence arrives later; so
//! [`TriggerIndex`] counts the rivals in a pass **before** the fold, and any
//! binding with a same-instant rival is [`Binding::Ambiguous`] however few
//! candidates were queued. Ambiguity is counted in [`JoinStats`] and excluded
//! by default. Nothing is silently guessed — that invariant is the subject of
//! the property test in `tests/join_invariants.rs`.
//!
//! # Determinism
//!
//! The fold is a total function of the replayed sequence, and the sequence is
//! the store's immutable total order — so two runs over the same window
//! produce byte-identical findings, ambiguity classification included. Nothing
//! here reads a clock, a hash map's iteration order, or a random id.

use std::collections::{BTreeMap, HashMap, HashSet};

use alloy_primitives::B256;
use chrono::{DateTime, Utc};
use events::primitives::{AlertId, BlockRef, Chain, Confidence, DetectorRef, IncidentId};
use events::{DomainEvent, EventEnvelope};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::label::Outcome;

/// The event types the join reads. Everything else in the window is ignored,
/// so the replay narrows to exactly these (see [`crate::source`]) instead of
/// dragging the whole log across the wire.
///
/// Validated against the schema by `events::topics_for` at subscribe time in
/// the consumers; here the same discipline is a unit test asserting every name
/// is a live `DomainEvent` variant.
pub const JOINED_EVENT_TYPES: &[&str] = &[
    "DetectorTriggered",
    "PreliminaryAlertCreated",
    "SimulationCompleted",
    "IncidentCreated",
    "IncidentRetracted",
    "BlockReverted",
    // Not joined, but read: it is the only event carrying a block's true
    // `tx_count`, which is how `crate::ctx` tells a complete reconstructed
    // bundle from a partial one.
    "BlockAssembled",
];

/// How confidently a finding was tied to its alert. Recorded on every row, so
/// a downstream analysis can re-filter without re-running the export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Binding {
    /// No alert was bound — a `Shadow`/`Deprecated` detector's trigger, or the
    /// alert fell outside the window.
    Unbound,
    /// Exactly one candidate trigger matched the alert. Trustworthy.
    Exact,
    /// A guessed binding that `IncidentCreated`'s authoritative `alert_id` +
    /// `txs` then confirmed by repairing it. Trustworthy — this is the
    /// strongest link the schema offers.
    Corrected,
    /// More than one trigger could have raised this alert. The oldest was
    /// bound so the outcome is still *visible*, but the row is excluded unless
    /// `--include-ambiguous` is set.
    Ambiguous,
    /// An unambiguous binding that `IncidentCreated` later contradicted — the
    /// events disagree with each other. Never repaired silently; surfaced in
    /// [`JoinStats::binding_conflicts`] and excluded like an ambiguous one.
    Conflicted,
}

impl Binding {
    pub fn as_str(self) -> &'static str {
        match self {
            Binding::Unbound => "unbound",
            Binding::Exact => "exact",
            Binding::Corrected => "corrected",
            Binding::Ambiguous => "ambiguous",
            Binding::Conflicted => "conflicted",
        }
    }

    /// Whether this binding is strong enough to carry a label by default.
    pub fn is_trusted(self) -> bool {
        matches!(self, Binding::Exact | Binding::Corrected)
    }
}

/// One `DetectorTriggered` with everything the replay learned about it.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// The trigger's own envelope id — this finding's stable identity, and the
    /// dedup key if a dataset is exported twice into the same table.
    pub trigger_event_id: Uuid,
    /// When the trigger was recorded. Provenance and the natural split column
    /// for a time-ordered train/test split.
    pub occurred_at: DateTime<Utc>,
    pub chain: Chain,
    pub block: BlockRef,
    pub detector: DetectorRef,
    /// The transactions the detector implicated, in the order it reported them.
    pub txs: Vec<B256>,
    pub raw_confidence: Confidence,
    pub alert_id: Option<AlertId>,
    pub binding: Binding,
    pub outcome: Outcome,
}

impl Finding {
    /// The outcome to label from, after applying the ambiguity policy: a
    /// finding whose binding is not trusted has no dependable outcome, so it
    /// reads as [`Outcome::Unlinkable`] unless the caller opted into
    /// ambiguous rows.
    ///
    /// [`Binding::Unbound`] is exempt: nothing was guessed, so the honest
    /// [`Outcome::Unalerted`] stands on its own.
    pub fn effective_outcome(&self, include_ambiguous: bool) -> Outcome {
        if include_ambiguous || self.binding.is_trusted() || self.binding == Binding::Unbound {
            self.outcome
        } else {
            Outcome::Unlinkable
        }
    }
}

/// Counts describing what the join saw. Every one of these lands in the
/// manifest: a dataset that came out smaller than expected is then explainable
/// from its own artefact, without re-running anything.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinStats {
    /// Envelopes fed to the fold, before any filtering.
    pub events_seen: u64,
    /// Envelopes skipped because they belong to another chain (defensive — the
    /// replay already filters server-side).
    pub foreign_chain_skipped: u64,
    pub triggers: u64,
    pub alerts: u64,
    /// Alerts whose trigger was not in the window (the window started
    /// mid-block). Expected to be small and near-constant per window.
    pub alerts_without_trigger: u64,
    /// Simulation results for an alert no finding in the window claimed.
    pub outcomes_without_finding: u64,
    pub ambiguous_bindings: u64,
    /// Ambiguous bindings that `IncidentCreated` subsequently repaired.
    pub corrected_bindings: u64,
    /// `IncidentCreated` contradicting an *unambiguous* binding — an
    /// inconsistency worth investigating, never a silent repair.
    pub binding_conflicts: u64,
    /// Distinct blocks reverted during the window (§15).
    pub reverted_blocks: u64,
}

impl JoinStats {
    /// Accumulate another shard's stats into this one.
    ///
    /// Every field is a plain count of independently-observed occurrences, so
    /// summing is exact — with one honest caveat: `reverted_blocks` counts
    /// *distinct* blocks per shard, so a block reverted in two shards' windows
    /// (possible, since each shard reads a lookahead tail past its own end)
    /// counts twice here. It is a health signal, not a ledger, and the
    /// alternative — carrying every reverted hash across the whole export —
    /// would trade an unbounded set for a rounding error.
    pub fn merge(&mut self, other: JoinStats) {
        self.events_seen += other.events_seen;
        self.foreign_chain_skipped += other.foreign_chain_skipped;
        self.triggers += other.triggers;
        self.alerts += other.alerts;
        self.alerts_without_trigger += other.alerts_without_trigger;
        self.outcomes_without_finding += other.outcomes_without_finding;
        self.ambiguous_bindings += other.ambiguous_bindings;
        self.corrected_bindings += other.corrected_bindings;
        self.binding_conflicts += other.binding_conflicts;
        self.reverted_blocks += other.reverted_blocks;
    }
}

/// The join's result: findings in trigger order, plus what the fold saw.
#[derive(Debug, Clone, PartialEq)]
pub struct JoinResult {
    /// In `DetectorTriggered` stream order — i.e. the store's total order,
    /// which is why row order is reproducible.
    pub findings: Vec<Finding>,
    pub stats: JoinStats,
}

/// Identity of a detector build, as a map key. The full `(id, version,
/// config_hash)` triple: two builds of the same detector are different
/// detectors for pairing purposes, because a config change moves the
/// confidence a finding reports.
type DetectorKey = (String, String, String);

fn detector_key(detector: &DetectorRef) -> DetectorKey {
    (
        detector.id.clone(),
        detector.version.clone(),
        detector.config_hash.clone(),
    )
}

/// How far apart a trigger and its own alert may be stamped and still count as
/// "the same instant". They are published back-to-back by one producer, so one
/// millisecond of slack covers a pair that straddles a tick boundary.
const PAIR_TOLERANCE_MS: i64 = 1;

/// Where every trigger sits in time, grouped by the identity an alert can
/// match on.
///
/// # Why the fold needs to look ahead
///
/// Layer 1 binds an alert to the oldest unbound trigger of its detector build
/// and confidence. That reasoning is sound *across* milliseconds — the store's
/// order is real time order there — but **not within one**: `occurred_at` is
/// millisecond-resolution and the tie-break is a random `event_id`, so among
/// events stamped the same millisecond the stored order is arbitrary. An alert
/// can therefore be stored ahead of its own trigger and behind a *rival's*,
/// at which point the fold sees exactly one candidate and binds it
/// confidently — to the wrong finding.
///
/// A streaming fold cannot see that, because the evidence (the rival trigger)
/// arrives later. So the rivals are counted in a pass *before* the fold: if
/// more than one trigger of the same `(detector, confidence)` sits within
/// [`PAIR_TOLERANCE_MS`] of the alert, no binding among them may be trusted,
/// however few candidates happened to be in the queue at the time.
///
/// This is what the property test in `tests/join_invariants.rs` exists to
/// hold: *a trusted binding is never a wrong one.*
#[derive(Debug, Default)]
pub struct TriggerIndex {
    /// `(detector triple, confidence bits)` → the millisecond of every trigger
    /// in that group, ascending.
    by_group: BTreeMap<(DetectorKey, u64), Vec<i64>>,
}

impl TriggerIndex {
    /// One pass over the window, before the fold.
    pub fn build<'a>(events: impl IntoIterator<Item = &'a EventEnvelope>) -> Self {
        let mut by_group: BTreeMap<(DetectorKey, u64), Vec<i64>> = BTreeMap::new();
        for envelope in events {
            if let DomainEvent::DetectorTriggered(trigger) = &envelope.payload {
                by_group
                    .entry((
                        detector_key(&trigger.detector),
                        confidence_bits(trigger.raw_confidence),
                    ))
                    .or_default()
                    .push(envelope.occurred_at.timestamp_millis());
            }
        }
        for millis in by_group.values_mut() {
            millis.sort_unstable();
        }
        Self { by_group }
    }

    /// How many triggers of this group are stamped close enough to `at_ms`
    /// that the stored order cannot separate them from the alert's own.
    fn rivals_near(&self, key: &(DetectorKey, u64), at_ms: i64) -> usize {
        let Some(millis) = self.by_group.get(key) else {
            return 0;
        };
        let (low, high) = (at_ms - PAIR_TOLERANCE_MS, at_ms + PAIR_TOLERANCE_MS);
        let start = millis.partition_point(|m| *m < low);
        let end = millis.partition_point(|m| *m <= high);
        end - start
    }
}

/// A confidence's exact bit pattern, so it can key a map. Exact bits are the
/// right identity here for the same reason the candidate filter uses exact
/// equality: the emitter *copies* the trigger's confidence onto the alert.
fn confidence_bits(confidence: Confidence) -> u64 {
    confidence.get().to_bits()
}

/// What one alert's simulation reported.
#[derive(Debug, Clone, Copy)]
struct SimResult {
    confirmed: bool,
    profit: f64,
    victim_loss: f64,
}

/// The fold state. Build with [`Joiner::new`], feed the replayed window in
/// order with [`Joiner::observe`], then [`Joiner::finish`].
#[derive(Debug)]
pub struct Joiner {
    chain: Chain,
    index: TriggerIndex,
    findings: Vec<Finding>,
    /// Per detector build, the indices of findings still awaiting an alert —
    /// kept ascending, so "oldest candidate" is the first match and a
    /// correction can reinsert in place.
    unbound: BTreeMap<DetectorKey, Vec<usize>>,
    /// Findings that were candidates in an ambiguous binding. A later alert
    /// that binds to one of these looks "exact" only *because* the earlier
    /// guess removed its rivals from the queue — so the doubt propagates
    /// rather than stopping at the first pair. Without this, a two-finding
    /// tie produces one honest `Ambiguous` and one falsely-confident `Exact`,
    /// and the confident one would carry a coin-flip label into training.
    contaminated: HashSet<usize>,
    /// Alerts of a `(detector, confidence)` group that arrived with **no**
    /// candidate trigger, recorded by the millisecond they arrived.
    ///
    /// The emitter always publishes a trigger before its alert, so an orphan
    /// means one of two things, and they must be told apart:
    ///
    /// - The alert's trigger is genuinely outside the window (it fell before
    ///   `from`, or the detector's stream starts mid-flight). Nothing is
    ///   wrong; later pairs in the group are still sound.
    /// - The pair got **reordered inside its millisecond**, so the trigger is
    ///   still ahead of us. This one is corrosive: that trigger will arrive,
    ///   sit in the queue, and be handed to the *next* alert — and every
    ///   binding in the group after it is shifted by one, forever. Tainting
    ///   just the one trigger is not enough; the shift cascades.
    ///
    /// The two are distinguished on arrival by the same test the pairing
    /// itself uses: a trigger within [`PAIR_TOLERANCE_MS`] of the orphaned
    /// alert could be that alert's own, so the group is marked
    /// [`desynced`](Joiner::desynced); a trigger arriving much later (the next
    /// block, say) cannot be, and costs nothing.
    pending_orphans: HashMap<(DetectorKey, u64), Vec<i64>>,
    /// Groups whose queue is known to be shifted: an orphaned alert's trigger
    /// turned up after it, so every later pairing in the group is off by one.
    /// No binding in a desynced group may be trusted for the rest of the fold.
    ///
    /// Permanent rather than "until the queue drains", because in the shifted
    /// regime the queue empties after *every* binding — it oscillates 0/1 just
    /// as it does when healthy, so emptiness carries no information.
    desynced: HashSet<(DetectorKey, u64)>,
    finding_of_alert: HashMap<AlertId, usize>,
    incident_of_alert: HashMap<AlertId, IncidentId>,
    sim: HashMap<AlertId, SimResult>,
    retracted: HashSet<IncidentId>,
    reverted: HashSet<B256>,
    stats: JoinStats,
}

impl Joiner {
    /// `index` must describe the same events this joiner will be fed — see
    /// [`TriggerIndex`] for why the fold cannot derive it as it goes.
    pub fn new(chain: Chain, index: TriggerIndex) -> Self {
        Self {
            chain,
            index,
            findings: Vec::new(),
            unbound: BTreeMap::new(),
            contaminated: HashSet::new(),
            pending_orphans: HashMap::new(),
            desynced: HashSet::new(),
            finding_of_alert: HashMap::new(),
            incident_of_alert: HashMap::new(),
            sim: HashMap::new(),
            retracted: HashSet::new(),
            reverted: HashSet::new(),
            stats: JoinStats::default(),
        }
    }

    /// Fold one envelope in. Must be called in the replay's total order — the
    /// adjacency layer of the binding depends on it (the other two layers do
    /// not).
    pub fn observe(&mut self, envelope: &EventEnvelope) {
        self.stats.events_seen += 1;
        if envelope.chain != self.chain {
            self.stats.foreign_chain_skipped += 1;
            return;
        }

        match &envelope.payload {
            DomainEvent::DetectorTriggered(trigger) => {
                let index = self.findings.len();
                self.findings.push(Finding {
                    trigger_event_id: envelope.event_id,
                    occurred_at: envelope.occurred_at,
                    chain: envelope.chain,
                    block: trigger.block,
                    detector: trigger.detector.clone(),
                    txs: trigger.txs.clone(),
                    raw_confidence: trigger.raw_confidence,
                    alert_id: None,
                    binding: Binding::Unbound,
                    // Provisional until `finish` resolves the whole window;
                    // "no alert was ever bound" is the honest starting state.
                    outcome: Outcome::Unalerted,
                });
                let key = detector_key(&trigger.detector);
                // If an earlier alert of this group is still looking for a
                // trigger and this one is close enough in time to be it, the
                // pair was reordered: the group's queue is shifted from here
                // on (see `pending_orphans`).
                let group = (key.clone(), confidence_bits(trigger.raw_confidence));
                let at = envelope.occurred_at.timestamp_millis();
                if let Some(waiting) = self.pending_orphans.get_mut(&group) {
                    if let Some(pos) = waiting
                        .iter()
                        .position(|orphan| (at - orphan).abs() <= PAIR_TOLERANCE_MS)
                    {
                        waiting.remove(pos);
                        self.desynced.insert(group);
                    }
                }
                self.unbound.entry(key).or_default().push(index);
                self.stats.triggers += 1;
            }

            DomainEvent::PreliminaryAlertCreated(alert) => {
                self.stats.alerts += 1;
                self.bind_alert(
                    alert.alert_id,
                    &alert.detector,
                    alert.confidence,
                    envelope.occurred_at.timestamp_millis(),
                );
            }

            DomainEvent::SimulationCompleted(completed) => {
                self.sim.insert(
                    completed.alert_id,
                    SimResult {
                        confirmed: completed.confirmed,
                        profit: completed.profit,
                        victim_loss: completed.victim_loss,
                    },
                );
            }

            DomainEvent::IncidentCreated(incident) => {
                self.incident_of_alert
                    .insert(incident.alert_id, incident.incident_id);
                self.reconcile_with_incident(incident.alert_id, &incident.txs);
            }

            DomainEvent::IncidentRetracted(retracted) => {
                self.retracted.insert(retracted.incident_id);
            }

            DomainEvent::BlockReverted(reverted) => {
                // A reorg can revert one block through several envelopes; the
                // stat counts distinct blocks, so it follows the set insert.
                let first_sighting = self.reverted.insert(reverted.block.hash);
                self.stats.reverted_blocks += u64::from(first_sighting);
            }

            _ => {}
        }
    }

    /// Layer 1: bind `alert_id` to the oldest unbound trigger of the same
    /// detector build carrying the same confidence.
    fn bind_alert(
        &mut self,
        alert_id: AlertId,
        detector: &DetectorRef,
        confidence: Confidence,
        alert_ms: i64,
    ) {
        let key = detector_key(detector);
        let group = (key.clone(), confidence_bits(confidence));
        // Two ways a pairing here is a guess even with a single candidate in
        // the queue: a rival stamped the same instant (see [`TriggerIndex`]),
        // or a group whose queue is already known to be shifted by an earlier
        // reorder (see [`Joiner::pending_orphans`]).
        let indistinguishable =
            self.index.rivals_near(&group, alert_ms) > 1 || self.desynced.contains(&group);
        let Some(queue) = self.unbound.get_mut(&key) else {
            self.orphan_alert(key, confidence, alert_ms);
            return;
        };

        // Exact f64 equality is the right test, not an epsilon: the emitter
        // *copies* the trigger's `raw_confidence` onto the alert, so equal
        // means equal bits. An epsilon would only widen the candidate set and
        // manufacture ambiguity.
        let matches: Vec<usize> = queue
            .iter()
            .copied()
            .filter(|&i| self.findings[i].raw_confidence == confidence)
            .collect();

        let Some(&chosen) = matches.first() else {
            self.orphan_alert(key, confidence, alert_ms);
            return;
        };

        // A single candidate is only *exact* if nothing else could have
        // produced this alert: no rival stamped the same instant, and it was
        // never a candidate in an earlier tie (see `contaminated`).
        let binding =
            if matches.len() == 1 && !indistinguishable && !self.contaminated.contains(&chosen) {
                Binding::Exact
            } else {
                self.contaminated.extend(matches.iter().copied());
                self.stats.ambiguous_bindings += 1;
                Binding::Ambiguous
            };

        queue.retain(|&i| i != chosen);
        self.findings[chosen].alert_id = Some(alert_id);
        self.findings[chosen].binding = binding;
        self.finding_of_alert.insert(alert_id, chosen);
    }

    /// An alert arrived with no candidate trigger. Record when, so that a
    /// trigger turning up close enough in time to be its own can be recognised
    /// as a reorder — see [`Joiner::pending_orphans`].
    fn orphan_alert(&mut self, key: DetectorKey, confidence: Confidence, alert_ms: i64) {
        self.stats.alerts_without_trigger += 1;
        self.pending_orphans
            .entry((key, confidence_bits(confidence)))
            .or_default()
            .push(alert_ms);
    }

    /// Layer 2: `IncidentCreated` names both the alert and the exact tx set the
    /// finding implicated — the authoritative link. Use it to repair a guess,
    /// or to record that the events contradict a binding we thought was
    /// certain.
    fn reconcile_with_incident(&mut self, alert_id: AlertId, txs: &[B256]) {
        let Some(&bound) = self.finding_of_alert.get(&alert_id) else {
            // The trigger predates the window; nothing to reconcile against.
            return;
        };
        if self.findings[bound].txs == txs {
            return; // The guess agrees with the authority.
        }

        if self.findings[bound].binding == Binding::Exact {
            // One candidate matched on confidence, yet the incident names a
            // different bundle. Something upstream is inconsistent — say so
            // rather than "fixing" it into a plausible-looking row.
            self.stats.binding_conflicts += 1;
            self.findings[bound].binding = Binding::Conflicted;
            return;
        }

        let key = detector_key(&self.findings[bound].detector);
        // The true owner of this alert: a finding of the same detector build
        // whose txs the incident names, that is either unbound or itself only
        // ambiguously bound (never steal a trusted binding).
        let target = self.findings.iter().position(|f| {
            detector_key(&f.detector) == key
                && f.txs == txs
                && (f.alert_id.is_none() || f.binding == Binding::Ambiguous)
        });
        let Some(target) = target.filter(|&t| t != bound) else {
            self.stats.binding_conflicts += 1;
            self.findings[bound].binding = Binding::Conflicted;
            return;
        };

        // Swap the two bindings: this alert moves onto `target`, and whatever
        // alert `target` held (if any) falls back onto `bound`.
        let displaced = self.findings[target].alert_id;
        let target_was_unbound = displaced.is_none();

        self.findings[target].alert_id = Some(alert_id);
        self.findings[target].binding = Binding::Corrected;
        self.finding_of_alert.insert(alert_id, target);

        self.findings[bound].alert_id = displaced;
        self.findings[bound].binding = match displaced {
            Some(other) => {
                self.finding_of_alert.insert(other, bound);
                Binding::Ambiguous
            }
            None => Binding::Unbound,
        };

        // Keep the pending queue consistent with who is actually unbound.
        let queue = self.unbound.entry(key).or_default();
        queue.retain(|&i| i != target);
        if target_was_unbound {
            let at = queue.partition_point(|&i| i < bound);
            queue.insert(at, bound);
        }

        self.stats.corrected_bindings += 1;
    }

    /// Resolve every finding's outcome and hand back the result.
    ///
    /// Resolution is deliberately done here, not incrementally: a retraction
    /// can arrive long after its confirmation, and a block can be reverted
    /// after everything on it was simulated, so only the whole window decides.
    pub fn finish(mut self) -> JoinResult {
        for finding in &mut self.findings {
            finding.outcome = if self.reverted.contains(&finding.block.hash) {
                Outcome::Reverted
            } else {
                match finding.alert_id {
                    None => Outcome::Unalerted,
                    Some(alert) => match self.sim.get(&alert) {
                        None => Outcome::Unresolved,
                        Some(result) if !result.confirmed => Outcome::Refuted,
                        Some(result) => {
                            let withdrawn = self
                                .incident_of_alert
                                .get(&alert)
                                .is_some_and(|incident| self.retracted.contains(incident));
                            if withdrawn {
                                Outcome::Retracted
                            } else {
                                Outcome::Confirmed {
                                    profit: result.profit,
                                    victim_loss: result.victim_loss,
                                }
                            }
                        }
                    },
                }
            };
        }

        self.stats.outcomes_without_finding = self
            .sim
            .keys()
            .filter(|alert| !self.finding_of_alert.contains_key(alert))
            .count() as u64;

        JoinResult {
            findings: self.findings,
            stats: self.stats,
        }
    }
}

/// Fold a whole replayed window in one call — the shape [`crate::export`] uses.
pub fn join(chain: Chain, events: &[EventEnvelope]) -> JoinResult {
    let mut joiner = Joiner::new(chain, TriggerIndex::build(events));
    for envelope in events {
        joiner.observe(envelope);
    }
    joiner.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::TimeZone;
    use events::chain::{BlockAssembled, BlockReverted};
    use events::detection::{DetectorTriggered, PreliminaryAlertCreated};
    use events::primitives::{AlertKind, Severity, SuggestedAction};
    use events::simulation::{IncidentCreated, IncidentRetracted, SimulationCompleted};

    const CHAIN: Chain = Chain::ETHEREUM;

    /// Monotonic envelope timestamps, one second apart, so the fixtures read in
    /// a definite order. A second is far wider than [`PAIR_TOLERANCE_MS`], so
    /// these events are *distinguishable in time* — the ordinary case, where
    /// adjacency pairing carries real information.
    fn envelope(seq: u32, payload: DomainEvent) -> EventEnvelope {
        EventEnvelope::with_metadata(
            Uuid::from_u128(u128::from(seq)),
            Utc.timestamp_opt(1_700_000_000 + i64::from(seq), 0)
                .unwrap(),
            CHAIN,
            payload,
        )
    }

    /// Every event stamped the **same instant**, with `seq` deciding only the
    /// stored tie-break — the case where the store's order carries no
    /// information about emission order and pairing becomes a guess.
    fn envelope_same_instant(seq: u32, payload: DomainEvent) -> EventEnvelope {
        EventEnvelope::with_metadata(
            Uuid::from_u128(u128::from(seq)),
            Utc.timestamp_millis_opt(1_700_000_000_000).unwrap(),
            CHAIN,
            payload,
        )
    }

    fn run_same_instant(events: Vec<DomainEvent>) -> JoinResult {
        let envelopes: Vec<EventEnvelope> = events
            .into_iter()
            .enumerate()
            .map(|(i, e)| envelope_same_instant(i as u32, e))
            .collect();
        join(CHAIN, &envelopes)
    }

    fn detector(id: &str) -> DetectorRef {
        DetectorRef {
            id: id.to_owned(),
            version: "1.0.0".to_owned(),
            config_hash: "cafe".to_owned(),
        }
    }

    fn block(n: u64) -> BlockRef {
        BlockRef::new(n, B256::repeat_byte(n as u8))
    }

    fn tx(b: u8) -> B256 {
        B256::repeat_byte(b)
    }

    fn trigger(det: &str, block_ref: BlockRef, txs: Vec<B256>, confidence: f64) -> DomainEvent {
        DomainEvent::DetectorTriggered(DetectorTriggered {
            detector: detector(det),
            block: block_ref,
            txs,
            raw_confidence: Confidence::new(confidence),
            evidence: serde_json::json!({}),
        })
    }

    fn alert(det: &str, alert_id: AlertId, confidence: f64) -> DomainEvent {
        DomainEvent::PreliminaryAlertCreated(PreliminaryAlertCreated {
            alert_id,
            detector: detector(det),
            addresses: vec![],
            kind: AlertKind::Sandwich,
            confidence: Confidence::new(confidence),
            provisional: true,
            impact_usd: None,
            severity: Severity::Low,
            suggested_action: SuggestedAction::Monitor,
        })
    }

    fn completed(alert_id: AlertId, confirmed: bool) -> DomainEvent {
        DomainEvent::SimulationCompleted(SimulationCompleted {
            alert_id,
            profit: if confirmed { 100.0 } else { 0.0 },
            victim_loss: if confirmed { 40.0 } else { 0.0 },
            confirmed,
        })
    }

    fn incident(incident_id: IncidentId, alert_id: AlertId, txs: Vec<B256>) -> DomainEvent {
        DomainEvent::IncidentCreated(IncidentCreated {
            incident_id,
            alert_id,
            kind: AlertKind::Sandwich,
            txs,
            profit: 100.0,
            victim_loss: 40.0,
            impact_usd: None,
            severity: Severity::High,
            suggested_action: SuggestedAction::Investigate,
            victim_address: None,
            victim_loss_usd: None,
        })
    }

    fn run(events: Vec<DomainEvent>) -> JoinResult {
        let envelopes: Vec<EventEnvelope> = events
            .into_iter()
            .enumerate()
            .map(|(i, e)| envelope(i as u32, e))
            .collect();
        join(CHAIN, &envelopes)
    }

    #[test]
    fn every_joined_event_type_is_a_live_schema_variant() {
        use strum::VariantNames;
        for name in JOINED_EVENT_TYPES {
            assert!(
                DomainEvent::VARIANTS.contains(name),
                "{name:?} is not a DomainEvent variant — the join's type list drifted \
                 from the schema"
            );
        }
    }

    // ── the happy path ────────────────────────────────────────────────

    #[test]
    fn a_confirmed_finding_is_bound_exactly_and_carries_its_figures() {
        let a = AlertId::new();
        let result = run(vec![
            trigger("sandwich", block(1), vec![tx(1), tx(2)], 0.8),
            alert("sandwich", a, 0.8),
            completed(a, true),
            incident(IncidentId::new(), a, vec![tx(1), tx(2)]),
        ]);

        assert_eq!(result.findings.len(), 1);
        let finding = &result.findings[0];
        assert_eq!(finding.binding, Binding::Exact);
        assert_eq!(finding.alert_id, Some(a));
        assert_eq!(
            finding.outcome,
            Outcome::Confirmed {
                profit: 100.0,
                victim_loss: 40.0
            }
        );
        assert_eq!(result.stats.triggers, 1);
        assert_eq!(result.stats.ambiguous_bindings, 0);
        assert_eq!(result.stats.binding_conflicts, 0);
    }

    #[test]
    fn a_refuted_alert_is_the_flywheels_hard_negative() {
        let a = AlertId::new();
        let result = run(vec![
            trigger("arb", block(1), vec![tx(1)], 0.5),
            alert("arb", a, 0.5),
            completed(a, false),
        ]);
        assert_eq!(result.findings[0].outcome, Outcome::Refuted);
    }

    #[test]
    fn a_retraction_turns_a_confirmation_into_a_negative() {
        let (a, i) = (AlertId::new(), IncidentId::new());
        let result = run(vec![
            trigger("sandwich", block(1), vec![tx(1)], 0.9),
            alert("sandwich", a, 0.9),
            completed(a, true),
            incident(i, a, vec![tx(1)]),
            DomainEvent::IncidentRetracted(IncidentRetracted {
                incident_id: i,
                reason: "block reverted".to_owned(),
            }),
        ]);
        assert_eq!(result.findings[0].outcome, Outcome::Retracted);
    }

    // ── the absences ──────────────────────────────────────────────────

    #[test]
    fn a_shadow_detectors_trigger_has_no_alert_and_so_no_ground_truth() {
        // `evidence_events` suppresses the alert for a Shadow build but still
        // emits the trigger — there is nothing to simulate, hence no label.
        let result = run(vec![trigger("shadow", block(1), vec![tx(1)], 0.7)]);
        assert_eq!(result.findings[0].binding, Binding::Unbound);
        assert_eq!(result.findings[0].outcome, Outcome::Unalerted);
    }

    #[test]
    fn an_alert_whose_simulation_lands_after_the_window_is_unresolved_not_negative() {
        let a = AlertId::new();
        let result = run(vec![
            trigger("sandwich", block(1), vec![tx(1)], 0.6),
            alert("sandwich", a, 0.6),
        ]);
        assert_eq!(result.findings[0].outcome, Outcome::Unresolved);
    }

    #[test]
    fn a_reverted_block_drops_its_findings_whatever_simulation_said() {
        let a = AlertId::new();
        let b = block(7);
        let result = run(vec![
            trigger("sandwich", b, vec![tx(1)], 0.6),
            alert("sandwich", a, 0.6),
            completed(a, true),
            DomainEvent::BlockReverted(BlockReverted {
                block: b,
                replaced_by: B256::repeat_byte(0xff),
            }),
        ]);
        assert_eq!(
            result.findings[0].outcome,
            Outcome::Reverted,
            "a confirmation on an orphaned block still describes a block that is not \
             on the canonical chain"
        );
        assert_eq!(result.stats.reverted_blocks, 1);
    }

    #[test]
    fn an_alert_whose_trigger_predates_the_window_is_counted_not_invented() {
        let result = run(vec![alert("sandwich", AlertId::new(), 0.6)]);
        assert!(result.findings.is_empty());
        assert_eq!(result.stats.alerts_without_trigger, 1);
    }

    #[test]
    fn a_simulation_result_for_no_known_finding_is_counted() {
        let result = run(vec![completed(AlertId::new(), true)]);
        assert_eq!(result.stats.outcomes_without_finding, 1);
    }

    #[test]
    fn foreign_chain_events_are_skipped_defensively() {
        let mut joiner = Joiner::new(CHAIN, TriggerIndex::default());
        let foreign = EventEnvelope::with_metadata(
            Uuid::nil(),
            Utc::now(),
            Chain(8453),
            trigger("sandwich", block(1), vec![tx(1)], 0.5),
        );
        joiner.observe(&foreign);
        let result = joiner.finish();
        assert!(result.findings.is_empty());
        assert_eq!(result.stats.foreign_chain_skipped, 1);
    }

    // ── the binding layers ────────────────────────────────────────────

    #[test]
    fn confidence_separates_two_findings_of_one_detector_on_one_block() {
        let (a1, a2) = (AlertId::new(), AlertId::new());
        let result = run(vec![
            trigger("sandwich", block(1), vec![tx(1)], 0.8),
            trigger("sandwich", block(1), vec![tx(2)], 0.4),
            alert("sandwich", a1, 0.8),
            alert("sandwich", a2, 0.4),
        ]);
        assert_eq!(result.findings[0].alert_id, Some(a1));
        assert_eq!(result.findings[1].alert_id, Some(a2));
        assert!(result.findings.iter().all(|f| f.binding == Binding::Exact));
        assert_eq!(result.stats.ambiguous_bindings, 0);
    }

    #[test]
    fn two_indistinguishable_findings_are_marked_ambiguous_not_silently_guessed() {
        let (a1, a2) = (AlertId::new(), AlertId::new());
        let result = run_same_instant(vec![
            trigger("sandwich", block(1), vec![tx(1)], 0.8),
            trigger("sandwich", block(1), vec![tx(2)], 0.8),
            alert("sandwich", a1, 0.8),
            alert("sandwich", a2, 0.8),
        ]);
        // The first alert had two candidates. The second then had only one
        // left — but only *because* of the first guess, so it inherits the
        // doubt rather than reading as confident.
        assert_eq!(result.findings[0].binding, Binding::Ambiguous);
        assert_eq!(
            result.findings[1].binding,
            Binding::Ambiguous,
            "the survivor of a tie is not exact — its rival was removed by a guess"
        );
        assert_eq!(result.stats.ambiguous_bindings, 2);
        assert!(
            result.findings.iter().all(|f| !f.binding.is_trusted()),
            "neither binding may be trusted with a label"
        );
    }

    #[test]
    fn an_incident_repairs_an_ambiguous_binding_and_the_swap_fixes_both_findings() {
        // Two identical-confidence findings at one instant, so adjacency cannot
        // separate them and binds them the wrong way round. The incident names
        // alert 1's real tx set (tx(2), the *second* trigger), so both bindings
        // must end up swapped.
        let (a1, a2) = (AlertId::new(), AlertId::new());
        let result = run_same_instant(vec![
            trigger("sandwich", block(1), vec![tx(1)], 0.8),
            trigger("sandwich", block(1), vec![tx(2)], 0.8),
            alert("sandwich", a1, 0.8), // guessed onto trigger #0
            alert("sandwich", a2, 0.8), // then onto trigger #1
            completed(a1, true),
            incident(IncidentId::new(), a1, vec![tx(2)]), // authority: a1 is #1
        ]);

        assert_eq!(
            result.findings[1].alert_id,
            Some(a1),
            "a1 moved to trigger 1"
        );
        assert_eq!(result.findings[1].binding, Binding::Corrected);
        assert_eq!(
            result.findings[0].alert_id,
            Some(a2),
            "a2 fell back onto trigger 0"
        );
        assert_eq!(result.stats.corrected_bindings, 1);

        // And the labels follow the repaired links.
        assert_eq!(
            result.findings[1].outcome,
            Outcome::Confirmed {
                profit: 100.0,
                victim_loss: 40.0
            }
        );
        assert_eq!(result.findings[0].outcome, Outcome::Unresolved);
    }

    #[test]
    fn an_incident_contradicting_an_unambiguous_binding_is_a_conflict_not_a_repair() {
        let a = AlertId::new();
        let result = run(vec![
            trigger("sandwich", block(1), vec![tx(1)], 0.8),
            alert("sandwich", a, 0.8),
            completed(a, true),
            incident(IncidentId::new(), a, vec![tx(9)]),
        ]);
        assert_eq!(result.findings[0].binding, Binding::Conflicted);
        assert_eq!(result.stats.binding_conflicts, 1);
        assert_eq!(
            result.findings[0].effective_outcome(false),
            Outcome::Unlinkable,
            "a contradicted binding must not carry a label by default"
        );
    }

    #[test]
    fn different_detector_builds_never_bind_to_each_others_findings() {
        let a = AlertId::new();
        let mut other = detector("sandwich");
        other.config_hash = "beef".to_owned();

        let result = run(vec![
            trigger("sandwich", block(1), vec![tx(1)], 0.8),
            DomainEvent::PreliminaryAlertCreated(PreliminaryAlertCreated {
                alert_id: a,
                detector: other,
                addresses: vec![],
                kind: AlertKind::Sandwich,
                confidence: Confidence::new(0.8),
                provisional: true,
                impact_usd: None,
                severity: Severity::Low,
                suggested_action: SuggestedAction::Monitor,
            }),
        ]);
        assert_eq!(result.findings[0].binding, Binding::Unbound);
        assert_eq!(result.stats.alerts_without_trigger, 1);
    }

    // ── determinism ───────────────────────────────────────────────────

    #[test]
    fn the_same_window_folds_to_the_same_findings_every_time() {
        let (a1, a2) = (AlertId::new(), AlertId::new());
        let window = || {
            vec![
                DomainEvent::BlockAssembled(BlockAssembled {
                    block: block(1),
                    tx_count: 10,
                    trace_available: false,
                }),
                trigger("sandwich", block(1), vec![tx(1)], 0.8),
                alert("sandwich", a1, 0.8),
                trigger("arb", block(1), vec![tx(3)], 0.8),
                alert("arb", a2, 0.8),
                completed(a1, true),
                completed(a2, false),
                incident(IncidentId::new(), a1, vec![tx(1)]),
            ]
        };
        assert_eq!(run(window()), run(window()));
    }

    #[test]
    fn ambiguity_policy_only_gates_untrusted_bindings() {
        let (a1, a2) = (AlertId::new(), AlertId::new());
        let result = run_same_instant(vec![
            trigger("sandwich", block(1), vec![tx(1)], 0.8),
            trigger("sandwich", block(1), vec![tx(2)], 0.8),
            alert("sandwich", a1, 0.8),
            alert("sandwich", a2, 0.8),
            completed(a1, false),
        ]);
        let ambiguous = &result.findings[0];
        assert_eq!(ambiguous.effective_outcome(false), Outcome::Unlinkable);
        assert_eq!(ambiguous.effective_outcome(true), Outcome::Refuted);

        // An unbound finding is not "ambiguous" — nothing was guessed, so its
        // honest outcome stands under either policy.
        let unalerted = run(vec![trigger("shadow", block(1), vec![tx(1)], 0.7)]);
        assert_eq!(
            unalerted.findings[0].effective_outcome(false),
            Outcome::Unalerted
        );
    }
}
