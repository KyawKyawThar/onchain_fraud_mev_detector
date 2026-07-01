//! The incident **read-model projection** (§7) — the pure, idempotent, commutative
//! fold that turns the simulation result path's domain events back into one coherent
//! incident row.
//!
//! ## Why this exists
//!
//! The worker pool acks a `sim.jobs` job *after* publishing its result, so RabbitMQ
//! (and then Kafka) is at-least-once: a crash between publish and ack re-runs the job
//! and emits a **second** `SimulationCompleted` for the same alert. Kafka only
//! guarantees order *within a partition*, and the result lifecycle is split across
//! two partition keys ([`PartitionKey::Alert`](events::PartitionKey) for
//! `SimulationCompleted`/`IncidentCreated`, [`PartitionKey::Incident`](events::PartitionKey)
//! for `IncidentRetracted`/`IncidentFinalized`, §7 t2). So a projection consuming the
//! backbone must tolerate both **duplicates** and **reordering** — which is exactly
//! §7's "ordering is reasserted at the projection, not demanded of the queue".
//!
//! [`IncidentProjection::apply`] is that reducer: a deterministic function of the
//! *set* of events it has seen, independent of the order they arrive in. No exactly-once
//! machinery is needed — the fold is idempotent and commutative by construction.
//!
//! ## How idempotency + commutativity are achieved
//!
//! Each field of an [`IncidentRecord`] has its own monotone/last-writer merge rule, so
//! re-applying an event, or applying events out of order, always converges to the same
//! row (a CRDT-shaped fold):
//!
//! - **`status`** advances only *up* a monotonic lifecycle ladder
//!   ([`IncidentStatus::rank`]): `Unconfirmed → Confirmed → Finalized → Retracted`. A
//!   stale, redelivered lower-lifecycle event can never demote a record. Retraction is
//!   the authoritative last word (it outranks finality — a §7/§15 reorg or a later
//!   contradicting run *withdraws* an incident even after its block finalized; finality
//!   means "won't reorg", not "the incident is forever valid").
//! - **Monetary figures** (`profit`/`victim_loss`) are **last-writer-by-event-time**:
//!   a re-simulation with a newer `occurred_at` overwrites; an older or redelivered one
//!   is dropped (`figures_at` watermark). A deterministic re-run reports identical
//!   numbers, so it is observably a no-op.
//! - **Identity** (`incident_id`, `kind`, `severity`, `txs`) is set **once**, from
//!   `IncidentCreated` — a duplicate `IncidentCreated` changes nothing.
//! - **Terminal detail** (retraction reason, finalized block) is last-writer-by-event-time.
//!
//! ## Correlating the two keyspaces
//!
//! `alert_id` is the one key that spans the whole lifecycle (it is on the first event,
//! and `IncidentCreated` teaches the projection the `incident_id → alert_id` link), so
//! rows are keyed by `alert_id`. `IncidentRetracted`/`IncidentFinalized` name only the
//! `incident_id`; if one arrives **before** the `IncidentCreated` that links it (a
//! cross-partition reorder), it is buffered as an orphan and replayed onto the row the
//! moment its `IncidentCreated` appears — so the terminal event is never lost and order
//! is reasserted.
//!
//! ## Scope, durability, and bounded memory (production)
//!
//! Pure and in-memory: no Kafka, no database, `assert_eq!`-testable — the same discipline
//! as [`crate::result`] and detection's `emit`. Persisting these rows (Postgres for
//! confirmed incidents, the ClickHouse analytics projection, §14) plugs a store in behind
//! this fold; the idempotency + ordering guarantees live here, once, where they can be
//! tested without infrastructure.
//!
//! Two structures have very different lifetimes, and only one is a memory hazard:
//!
//! - **`by_alert` (the read model)** grows with confirmed incidents and is *not* evicted
//!   in memory: dropping a row would silently lose an incident. Durability and unbounded
//!   scale are the **store's** job — a production deployment write-throughs to Postgres/
//!   ClickHouse and treats this map as a working set (a bounded cache re-hydrated from the
//!   store, or one instance per consumed partition). That store integration is Sprint 6 t5;
//!   this module deliberately does not fake durability with a lossy in-memory cap.
//! - **`orphans` (terminal-before-create buffer)** is pure liability, not read model, and
//!   *is* an attack surface: an `IncidentRetracted`/`IncidentFinalized` flood for
//!   `incident_id`s that never get created would grow it without bound (the same
//!   memory-exhaustion vector [`crate::cache`] guards). So it is **FIFO-bounded**
//!   ([`OrphanBuffer`]): at capacity the oldest orphaned incident is evicted (and logged,
//!   so ops can alarm — a large, non-draining orphan set means an upstream partition
//!   stalled, not normal operation). In a healthy pipeline both events flow through the
//!   same consumer within milliseconds, so the buffer stays near-empty; eviction under a
//!   flood is the correct DoS response (bounded memory over perfect retention).
//!
//! Applying one event is O(1) and never panics — a dangling internal link is logged and
//! treated as a no-op rather than crashing the consumer (§4: one event must never wedge
//! the stream). The [`Applied`] verdict plus [`IncidentProjection::len`] /
//! [`orphan_len`](IncidentProjection::orphan_len) are what the consuming shell records as
//! metrics (§19), keeping this fold exporter-agnostic.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, Utc};
use events::primitives::{AlertId, AlertKind, IncidentId, Severity};
use events::simulation::{
    IncidentCreated, IncidentFinalized, IncidentRetracted, SimulationCompleted,
};
use events::{DomainEvent, EventEnvelope};
use revm::primitives::B256;

/// Where an incident sits in its lifecycle (§7). The ladder is **monotonic**: the
/// projection only ever moves a record *up* it, so a redelivered or reordered
/// lower-lifecycle event can never regress a record's status.
///
/// The order (see [`IncidentStatus::rank`]) is `Unconfirmed < Confirmed < Finalized <
/// Retracted`. Retraction is deliberately the top of the ladder: a withdrawal (a §7/§15
/// reorg, or a later run contradicting the incident) is the authoritative correction and
/// wins even over finality — "finalized" means the block won't reorg, not that the
/// incident is forever valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentStatus {
    /// A `SimulationCompleted` with `confirmed = false`: the slow path ran and the
    /// provisional alert was dropped. Recorded as an audit outcome — there is no incident.
    Unconfirmed,
    /// A confirmed `SimulationCompleted` and/or its `IncidentCreated`: a live incident.
    Confirmed,
    /// `IncidentFinalized`: the incident's block reached finality and can no longer be
    /// reorged (§15).
    Finalized,
    /// `IncidentRetracted`: the incident was withdrawn (reorg / contradicting run, §7).
    Retracted,
}

impl IncidentStatus {
    /// Position on the monotonic lifecycle ladder. `apply` only ever raises a record's
    /// status to a strictly higher rank, which is what makes the fold order-independent.
    fn rank(self) -> u8 {
        match self {
            IncidentStatus::Unconfirmed => 0,
            IncidentStatus::Confirmed => 1,
            IncidentStatus::Finalized => 2,
            IncidentStatus::Retracted => 3,
        }
    }
}

/// One incident's read-model row — the join of every result-path event that references
/// it, folded idempotently. Keyed in the projection by `alert_id` (the id that spans the
/// whole lifecycle).
///
/// The financial and terminal-detail fields carry hidden event-time watermarks
/// (`figures_at`, `retracted_at`, `finalized_at`) so a later event can overwrite an
/// earlier one but never vice-versa; they are not part of the public read model but are
/// included in equality so two rows folded from the same event set compare equal
/// regardless of arrival order.
#[derive(Debug, Clone, PartialEq)]
pub struct IncidentRecord {
    /// The provisional alert this incident upgraded from — the correlation key.
    pub alert_id: AlertId,
    /// The confirmed incident's id, once `IncidentCreated` has been seen.
    pub incident_id: Option<IncidentId>,
    /// Where the incident sits in its lifecycle (monotonic — never regresses).
    pub status: IncidentStatus,
    /// The alert kind, from `IncidentCreated`.
    pub kind: Option<AlertKind>,
    /// The confirmed incident's severity, from `IncidentCreated`.
    pub severity: Option<Severity>,
    /// Attacker profit (USD estimate) from the latest-by-event-time result.
    pub profit: f64,
    /// Victim loss (USD estimate) from the latest-by-event-time result.
    pub victim_loss: f64,
    /// The implicated transactions, from `IncidentCreated`.
    pub txs: Vec<B256>,
    /// Why the incident was retracted, if it was.
    pub retraction_reason: Option<String>,
    /// The block that finalized the incident, if it was finalized.
    pub finalized_block: Option<B256>,

    /// Event-time of the result that last set `profit`/`victim_loss` — the
    /// last-writer-wins watermark. Older/redelivered figures are dropped.
    figures_at: DateTime<Utc>,
    /// Event-time watermark for `retraction_reason`.
    retracted_at: Option<DateTime<Utc>>,
    /// Event-time watermark for `finalized_block`.
    finalized_at: Option<DateTime<Utc>>,
}

impl IncidentRecord {
    /// Raise `status` to `new` iff it is strictly further along the lifecycle ladder.
    /// Returns whether the status actually advanced.
    fn advance_status(&mut self, new: IncidentStatus) -> bool {
        if new.rank() > self.status.rank() {
            self.status = new;
            true
        } else {
            false
        }
    }

    /// Last-writer-by-event-time update of the monetary figures. A newer result
    /// overwrites; an equal-or-older one (a redelivery, or an out-of-order stale run) is
    /// dropped. Returns whether the *observable* figures changed — a deterministic re-run
    /// carries identical numbers, so it reports no change (the §7 no-op) even though the
    /// watermark advanced.
    fn set_figures(&mut self, profit: f64, victim_loss: f64, at: DateTime<Utc>) -> bool {
        if at <= self.figures_at {
            return false;
        }
        self.figures_at = at;
        let changed = self.profit != profit || self.victim_loss != victim_loss;
        self.profit = profit;
        self.victim_loss = victim_loss;
        changed
    }

    /// Stamp the incident identity from `IncidentCreated` — **set once**. A duplicate
    /// `IncidentCreated` finds identity already present and is a no-op. Returns whether
    /// the identity was newly set.
    fn set_identity(
        &mut self,
        incident_id: IncidentId,
        kind: AlertKind,
        severity: Severity,
        txs: &[B256],
    ) -> bool {
        if self.incident_id.is_some() {
            return false;
        }
        self.incident_id = Some(incident_id);
        self.kind = Some(kind);
        self.severity = Some(severity);
        self.txs = txs.to_vec();
        true
    }

    /// Apply a terminal (retract/finalize) update: advance the status monotonically and
    /// last-writer-wins the detail field. Returns whether the row changed observably.
    fn apply_terminal(&mut self, terminal: Terminal) -> bool {
        match terminal {
            Terminal::Retract { reason, at } => {
                let mut changed = self.advance_status(IncidentStatus::Retracted);
                if self.retracted_at.is_none_or(|prev| at > prev) {
                    if self.retraction_reason.as_deref() != Some(reason.as_str()) {
                        changed = true;
                    }
                    self.retracted_at = Some(at);
                    self.retraction_reason = Some(reason);
                }
                changed
            }
            Terminal::Finalize { block_hash, at } => {
                let mut changed = self.advance_status(IncidentStatus::Finalized);
                if self.finalized_at.is_none_or(|prev| at > prev) {
                    if self.finalized_block != Some(block_hash) {
                        changed = true;
                    }
                    self.finalized_at = Some(at);
                    self.finalized_block = Some(block_hash);
                }
                changed
            }
        }
    }
}

/// A terminal (incident-keyed) update, normalized so it can be applied to a row *or*
/// buffered as an orphan until the `IncidentCreated` that links its `incident_id` arrives.
#[derive(Debug, Clone, PartialEq)]
enum Terminal {
    Retract { reason: String, at: DateTime<Utc> },
    Finalize { block_hash: B256, at: DateTime<Utc> },
}

/// Default cap on distinct orphaned incidents held by [`OrphanBuffer`]. Sized for a
/// healthy pipeline's transient reorder window (both events clear the same consumer in
/// milliseconds, so orphans rarely accumulate) while capping the memory an
/// `IncidentRetracted`/`IncidentFinalized` flood for never-created incidents could pin.
pub const DEFAULT_ORPHAN_CAPACITY: usize = 100_000;

/// FIFO-bounded buffer of terminal (incident-keyed) events awaiting the `IncidentCreated`
/// that links their `incident_id` to an alert row — the same bounded-map discipline as
/// [`crate::cache`], because an unbounded orphan map is a memory-exhaustion vector under a
/// flood of terminals for incidents that never get created.
///
/// Bounded by *distinct incident count*. At capacity the oldest orphaned incident is
/// evicted whole (its buffered terminals are dropped and a warning logged): if that
/// incident's `IncidentCreated` later arrives, its retraction/finalization is lost — an
/// accepted trade-off, since a non-draining orphan set signals upstream partition breakage
/// (surfaced by the log/metric), and bounded memory beats perfect retention under attack.
#[derive(Debug)]
struct OrphanBuffer {
    capacity: usize,
    terminals: HashMap<IncidentId, Vec<Terminal>>,
    /// First-seen order of the buffered incident ids — the FIFO eviction order.
    order: VecDeque<IncidentId>,
}

impl OrphanBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            terminals: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Buffer `terminal` under `incident_id`. Returns whether it was newly buffered — a
    /// redelivered identical terminal already held is a no-op (`false`). Buffering a
    /// *new* incident evicts the oldest first when at capacity.
    fn buffer(&mut self, incident_id: IncidentId, terminal: Terminal) -> bool {
        if let Some(existing) = self.terminals.get_mut(&incident_id) {
            if existing.contains(&terminal) {
                return false;
            }
            existing.push(terminal);
            return true;
        }

        self.evict_to_fit();
        self.terminals.insert(incident_id, vec![terminal]);
        self.order.push_back(incident_id);
        true
    }

    /// Remove and return every terminal buffered for `incident_id`, once its
    /// `IncidentCreated` links it. The stale `order` entry is reaped lazily on eviction.
    fn take(&mut self, incident_id: &IncidentId) -> Option<Vec<Terminal>> {
        self.terminals.remove(incident_id)
    }

    /// How many distinct incidents are currently orphaned — the gauge ops alarms on.
    fn len(&self) -> usize {
        self.terminals.len()
    }

    /// Drop oldest orphaned incidents until there is room for one more (capacity `0` means
    /// unbounded — a deliberate opt-out, not the default). Skips `order` entries already
    /// drained by [`take`](Self::take).
    fn evict_to_fit(&mut self) {
        if self.capacity == 0 {
            return;
        }
        while self.terminals.len() >= self.capacity {
            match self.order.pop_front() {
                Some(oldest) => {
                    if let Some(dropped) = self.terminals.remove(&oldest) {
                        tracing::warn!(
                            incident_id = %oldest,
                            dropped_terminals = dropped.len(),
                            capacity = self.capacity,
                            "incident projection orphan buffer full; evicting oldest \
                             uncorrelated incident — check for a stalled upstream partition"
                        );
                        break;
                    }
                    // Already drained by `take`: freed a slot for free, keep popping.
                }
                None => break, // order empty but map full shouldn't happen; bail safe.
            }
        }
    }
}

/// What applying one event did to the projection. Lets a consumer distinguish a real
/// update from the §7 no-op (a duplicate/stale event) for metrics and logging, and skip
/// events the projection does not model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// The event advanced the read model (new row, status change, or newer figures).
    Updated,
    /// A result-path event that changed nothing — a redelivery or a stale, out-of-order
    /// event the fold already superseded. The idempotent no-op §7 relies on.
    Duplicate,
    /// Not a simulation-result event — the projection does not model it (e.g. a chain or
    /// detection event on the same backbone), so it is skipped.
    Ignored,
}

/// The incident read model: an idempotent, commutative fold over the result-path events.
///
/// Feed it the event stream with [`apply`](Self::apply) in any order, with duplicates —
/// the resulting rows depend only on the *set* of events seen. Read rows back by alert
/// ([`record`](Self::record)) or by incident ([`record_for_incident`](Self::record_for_incident)).
#[derive(Debug)]
pub struct IncidentProjection {
    /// The rows, keyed by the provisional `alert_id` that spans the whole lifecycle. Not
    /// evicted in memory — durability/scale is the store's job (see the module docs).
    by_alert: HashMap<AlertId, IncidentRecord>,
    /// `incident_id → alert_id`, learned at `IncidentCreated`, so incident-keyed terminal
    /// events resolve to their row.
    alert_of: HashMap<IncidentId, AlertId>,
    /// Terminal events that arrived before the `IncidentCreated` naming their alert (a
    /// cross-partition reorder). FIFO-bounded, since it is an unbounded-growth attack
    /// surface otherwise. Drained onto the row when that `IncidentCreated` appears.
    orphans: OrphanBuffer,
}

impl Default for IncidentProjection {
    fn default() -> Self {
        Self::new()
    }
}

impl IncidentProjection {
    /// A fresh, empty projection with the default orphan-buffer bound
    /// ([`DEFAULT_ORPHAN_CAPACITY`]).
    pub fn new() -> Self {
        Self::with_orphan_capacity(DEFAULT_ORPHAN_CAPACITY)
    }

    /// A fresh projection whose terminal-before-create orphan buffer is bounded to
    /// `capacity` distinct incidents (`0` = unbounded — a deliberate opt-out for tests /
    /// trusted replay, never production). See [`OrphanBuffer`].
    pub fn with_orphan_capacity(capacity: usize) -> Self {
        Self {
            by_alert: HashMap::new(),
            alert_of: HashMap::new(),
            orphans: OrphanBuffer::new(capacity),
        }
    }

    /// Fold one event into the read model. Idempotent and commutative: applying the same
    /// envelope twice, or applying events out of order, converges to the same state.
    /// Non-result events are [`Applied::Ignored`].
    pub fn apply(&mut self, envelope: &EventEnvelope) -> Applied {
        let at = envelope.occurred_at;
        match &envelope.payload {
            DomainEvent::SimulationCompleted(completed) => self.apply_completed(completed, at),
            DomainEvent::IncidentCreated(created) => self.apply_created(created, at),
            DomainEvent::IncidentRetracted(retracted) => self.apply_retracted(retracted, at),
            DomainEvent::IncidentFinalized(finalized) => self.apply_finalized(finalized, at),
            _ => Applied::Ignored,
        }
    }

    /// The row for a provisional alert, if the projection has seen any of its events.
    pub fn record(&self, alert_id: &AlertId) -> Option<&IncidentRecord> {
        self.by_alert.get(alert_id)
    }

    /// The row for a confirmed incident, resolved via the `incident_id → alert_id` link.
    /// `None` until the `IncidentCreated` that establishes the link has been applied.
    pub fn record_for_incident(&self, incident_id: &IncidentId) -> Option<&IncidentRecord> {
        self.alert_of
            .get(incident_id)
            .and_then(|alert_id| self.by_alert.get(alert_id))
    }

    /// Every incident row folded so far.
    pub fn records(&self) -> impl Iterator<Item = &IncidentRecord> {
        self.by_alert.values()
    }

    /// How many incident rows the projection holds.
    pub fn len(&self) -> usize {
        self.by_alert.len()
    }

    /// Whether the projection has folded any incident rows yet.
    pub fn is_empty(&self) -> bool {
        self.by_alert.is_empty()
    }

    /// Distinct incidents currently held in the terminal-before-create orphan buffer. A
    /// healthy pipeline keeps this near zero; a growing value means an upstream partition
    /// is lagging — the gauge the consuming shell exports for alarming (§19).
    pub fn orphan_len(&self) -> usize {
        self.orphans.len()
    }

    fn apply_completed(&mut self, completed: &SimulationCompleted, at: DateTime<Utc>) -> Applied {
        let status = if completed.confirmed {
            IncidentStatus::Confirmed
        } else {
            IncidentStatus::Unconfirmed
        };
        match self.by_alert.entry(completed.alert_id) {
            Entry::Vacant(slot) => {
                slot.insert(IncidentRecord {
                    alert_id: completed.alert_id,
                    incident_id: None,
                    status,
                    kind: None,
                    severity: None,
                    profit: completed.profit,
                    victim_loss: completed.victim_loss,
                    txs: Vec::new(),
                    retraction_reason: None,
                    finalized_block: None,
                    figures_at: at,
                    retracted_at: None,
                    finalized_at: None,
                });
                Applied::Updated
            }
            Entry::Occupied(mut slot) => {
                let record = slot.get_mut();
                let mut changed = record.advance_status(status);
                changed |= record.set_figures(completed.profit, completed.victim_loss, at);
                verdict(changed)
            }
        }
    }

    fn apply_created(&mut self, created: &IncidentCreated, at: DateTime<Utc>) -> Applied {
        // Learn the incident → alert link (idempotent) so terminal events resolve here.
        self.alert_of.insert(created.incident_id, created.alert_id);

        let mut changed = match self.by_alert.entry(created.alert_id) {
            Entry::Vacant(slot) => {
                slot.insert(IncidentRecord {
                    alert_id: created.alert_id,
                    incident_id: Some(created.incident_id),
                    status: IncidentStatus::Confirmed,
                    kind: Some(created.kind),
                    severity: Some(created.severity),
                    profit: created.profit,
                    victim_loss: created.victim_loss,
                    txs: created.txs.clone(),
                    retraction_reason: None,
                    finalized_block: None,
                    figures_at: at,
                    retracted_at: None,
                    finalized_at: None,
                });
                true
            }
            Entry::Occupied(mut slot) => {
                let record = slot.get_mut();
                let mut changed = record.set_identity(
                    created.incident_id,
                    created.kind,
                    created.severity,
                    &created.txs,
                );
                changed |= record.advance_status(IncidentStatus::Confirmed);
                changed |= record.set_figures(created.profit, created.victim_loss, at);
                changed
            }
        };

        // Replay any terminal events that arrived before this link existed. The row was
        // just inserted/updated above, so `get_mut` is `Some`; guard defensively rather
        // than `expect` so no single event can ever panic the consumer (§4).
        if let Some(orphans) = self.orphans.take(&created.incident_id) {
            if let Some(record) = self.by_alert.get_mut(&created.alert_id) {
                for terminal in orphans {
                    changed |= record.apply_terminal(terminal);
                }
            }
        }

        verdict(changed)
    }

    fn apply_retracted(&mut self, retracted: &IncidentRetracted, at: DateTime<Utc>) -> Applied {
        self.apply_terminal(
            retracted.incident_id,
            Terminal::Retract {
                reason: retracted.reason.clone(),
                at,
            },
        )
    }

    fn apply_finalized(&mut self, finalized: &IncidentFinalized, at: DateTime<Utc>) -> Applied {
        self.apply_terminal(
            finalized.incident_id,
            Terminal::Finalize {
                block_hash: finalized.block_hash,
                at,
            },
        )
    }

    /// Apply a terminal update, or buffer it as an orphan if the `incident_id → alert_id`
    /// link is not known yet (a cross-partition reorder — `IncidentCreated` not seen).
    fn apply_terminal(&mut self, incident_id: IncidentId, terminal: Terminal) -> Applied {
        match self.alert_of.get(&incident_id).copied() {
            Some(alert_id) => match self.by_alert.get_mut(&alert_id) {
                Some(record) => verdict(record.apply_terminal(terminal)),
                None => {
                    // `alert_of` is only ever set alongside a `by_alert` row and neither is
                    // removed, so this is unreachable — but log and no-op rather than panic
                    // the consumer if that invariant is ever broken by a future change (§4).
                    tracing::error!(
                        incident_id = %incident_id,
                        alert_id = %alert_id,
                        "incident projection: dangling incident→alert link, dropping terminal"
                    );
                    Applied::Ignored
                }
            },
            None => {
                // Not linked yet (cross-partition reorder): buffer until IncidentCreated.
                if self.orphans.buffer(incident_id, terminal) {
                    Applied::Updated
                } else {
                    Applied::Duplicate
                }
            }
        }
    }
}

/// Map "did the fold change the row?" onto the [`Applied`] verdict for events that were
/// modelled (so the only remaining case, [`Applied::Ignored`], stays explicit at the
/// dispatch site).
fn verdict(changed: bool) -> Applied {
    if changed {
        Applied::Updated
    } else {
        Applied::Duplicate
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use events::primitives::Chain;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).expect("valid timestamp")
    }

    /// Wrap a payload with an explicit event-time (a fresh event id each call, as a live
    /// producer would mint).
    fn envelope(payload: DomainEvent, occurred_at: DateTime<Utc>) -> EventEnvelope {
        EventEnvelope::with_metadata(uuid::Uuid::new_v4(), occurred_at, Chain::ETHEREUM, payload)
    }

    fn completed(alert: AlertId, confirmed: bool, profit: f64) -> DomainEvent {
        DomainEvent::SimulationCompleted(SimulationCompleted {
            alert_id: alert,
            profit,
            victim_loss: profit / 2.0,
            confirmed,
        })
    }

    fn created(alert: AlertId, incident: IncidentId) -> DomainEvent {
        DomainEvent::IncidentCreated(IncidentCreated {
            incident_id: incident,
            alert_id: alert,
            kind: AlertKind::Sandwich,
            txs: vec![B256::repeat_byte(0x01)],
            profit: 5.0,
            victim_loss: 2.5,
            severity: Severity::High,
        })
    }

    fn retracted(incident: IncidentId, reason: &str) -> DomainEvent {
        DomainEvent::IncidentRetracted(IncidentRetracted {
            incident_id: incident,
            reason: reason.to_owned(),
        })
    }

    fn finalized(incident: IncidentId, block: u8) -> DomainEvent {
        DomainEvent::IncidentFinalized(IncidentFinalized {
            incident_id: incident,
            block_hash: B256::repeat_byte(block),
        })
    }

    #[test]
    fn confirmed_completed_then_created_build_one_incident_row() {
        let alert = AlertId::new();
        let incident = IncidentId::new();
        let mut proj = IncidentProjection::new();

        assert_eq!(
            proj.apply(&envelope(completed(alert, true, 5.0), at(10))),
            Applied::Updated
        );
        assert_eq!(
            proj.apply(&envelope(created(alert, incident), at(11))),
            Applied::Updated
        );

        assert_eq!(proj.len(), 1, "the two events fold into one incident");
        let record = proj.record(&alert).expect("row for the alert");
        assert_eq!(record.status, IncidentStatus::Confirmed);
        assert_eq!(record.incident_id, Some(incident));
        assert_eq!(record.kind, Some(AlertKind::Sandwich));
        assert_eq!(record.severity, Some(Severity::High));
        assert_eq!(record.txs, vec![B256::repeat_byte(0x01)]);
        // Resolvable by incident id via the learned link.
        assert!(std::ptr::eq(
            proj.record_for_incident(&incident).unwrap(),
            record
        ));
    }

    #[test]
    fn duplicate_simulation_completed_is_a_no_op() {
        let alert = AlertId::new();
        let mut proj = IncidentProjection::new();

        // A worker crash-then-rerun re-emits the result as a *fresh* envelope (new id),
        // but the deterministic figures are identical — it must be a no-op.
        let first = envelope(completed(alert, true, 5.0), at(10));
        assert_eq!(proj.apply(&first), Applied::Updated);
        let before = proj.record(&alert).cloned().expect("row");

        let rerun = envelope(completed(alert, true, 5.0), at(10));
        assert_eq!(
            proj.apply(&rerun),
            Applied::Duplicate,
            "a redelivered identical result changes nothing"
        );
        // And the exact same envelope redelivered is likewise a no-op.
        assert_eq!(proj.apply(&first), Applied::Duplicate);

        assert_eq!(proj.len(), 1);
        assert_eq!(proj.record(&alert), Some(&before), "state is unchanged");
    }

    #[test]
    fn re_simulation_updates_figures_last_writer_by_event_time_wins() {
        let alert = AlertId::new();
        let mut proj = IncidentProjection::new();

        proj.apply(&envelope(completed(alert, true, 5.0), at(10)));
        // A newer re-run with different numbers overwrites.
        assert_eq!(
            proj.apply(&envelope(completed(alert, true, 9.0), at(20))),
            Applied::Updated
        );
        assert_eq!(proj.record(&alert).unwrap().profit, 9.0);

        // An *older* run arriving late (out of order) is dropped — not last writer.
        assert_eq!(
            proj.apply(&envelope(completed(alert, true, 3.0), at(15))),
            Applied::Duplicate
        );
        assert_eq!(
            proj.record(&alert).unwrap().profit,
            9.0,
            "the newer figures survive a late, older event"
        );
    }

    #[test]
    fn unconfirmed_completed_records_an_outcome_without_an_incident() {
        let alert = AlertId::new();
        let mut proj = IncidentProjection::new();

        proj.apply(&envelope(completed(alert, false, 0.5), at(10)));
        let record = proj.record(&alert).expect("outcome recorded for audit");
        assert_eq!(record.status, IncidentStatus::Unconfirmed);
        assert_eq!(record.incident_id, None);
    }

    #[test]
    fn status_never_regresses_to_an_earlier_lifecycle_stage() {
        let alert = AlertId::new();
        let incident = IncidentId::new();
        let mut proj = IncidentProjection::new();

        proj.apply(&envelope(completed(alert, true, 5.0), at(10)));
        proj.apply(&envelope(created(alert, incident), at(11)));
        proj.apply(&envelope(finalized(incident, 0xaa), at(30)));
        assert_eq!(
            proj.record(&alert).unwrap().status,
            IncidentStatus::Finalized
        );

        // Stale, redelivered earlier-lifecycle events must not demote a finalized row.
        assert_eq!(
            proj.apply(&envelope(created(alert, incident), at(11))),
            Applied::Duplicate
        );
        assert_eq!(
            proj.apply(&envelope(completed(alert, true, 5.0), at(10))),
            Applied::Duplicate
        );
        assert_eq!(
            proj.record(&alert).unwrap().status,
            IncidentStatus::Finalized,
            "status stayed at the furthest lifecycle stage reached"
        );
    }

    #[test]
    fn retraction_outranks_finalization() {
        let alert = AlertId::new();
        let incident = IncidentId::new();
        let mut proj = IncidentProjection::new();

        proj.apply(&envelope(created(alert, incident), at(10)));
        proj.apply(&envelope(finalized(incident, 0xaa), at(20)));
        // A later contradicting run retracts even a finalized incident.
        assert_eq!(
            proj.apply(&envelope(retracted(incident, "reorg"), at(30))),
            Applied::Updated
        );

        let record = proj.record(&alert).unwrap();
        assert_eq!(record.status, IncidentStatus::Retracted);
        assert_eq!(record.retraction_reason.as_deref(), Some("reorg"));
        // The finalization is still recorded — retraction wins the *status*, not the audit.
        assert_eq!(record.finalized_block, Some(B256::repeat_byte(0xaa)));
    }

    #[test]
    fn a_terminal_event_before_its_creation_is_reordered_at_the_projection() {
        let alert = AlertId::new();
        let incident = IncidentId::new();
        let mut proj = IncidentProjection::new();

        // IncidentRetracted (incident-keyed) overtakes IncidentCreated (alert-keyed) across
        // partitions: it lands first, with no row to attach to yet.
        assert_eq!(
            proj.apply(&envelope(retracted(incident, "reorg"), at(20))),
            Applied::Updated
        );
        assert!(proj.record_for_incident(&incident).is_none());
        assert_eq!(
            proj.len(),
            0,
            "no row until the creating event links the alert"
        );

        // When IncidentCreated arrives, the buffered retraction is replayed onto the row.
        proj.apply(&envelope(created(alert, incident), at(10)));
        let record = proj.record(&alert).expect("row now exists");
        assert_eq!(record.status, IncidentStatus::Retracted);
        assert_eq!(record.retraction_reason.as_deref(), Some("reorg"));
    }

    #[test]
    fn a_duplicate_orphan_terminal_is_a_no_op() {
        let incident = IncidentId::new();
        let mut proj = IncidentProjection::new();

        assert_eq!(
            proj.apply(&envelope(retracted(incident, "reorg"), at(20))),
            Applied::Updated
        );
        // Same incident-keyed terminal redelivered before creation — still buffered once.
        assert_eq!(
            proj.apply(&envelope(retracted(incident, "reorg"), at(20))),
            Applied::Duplicate
        );
    }

    #[test]
    fn the_orphan_buffer_is_bounded_and_evicts_oldest_first() {
        // A flood of terminals for never-created incidents must not grow without bound.
        let mut proj = IncidentProjection::with_orphan_capacity(2);
        let oldest = IncidentId::new();
        let middle = IncidentId::new();
        let newest = IncidentId::new();

        proj.apply(&envelope(retracted(oldest, "a"), at(10)));
        proj.apply(&envelope(retracted(middle, "b"), at(11)));
        assert_eq!(proj.orphan_len(), 2, "at capacity");

        // The third distinct orphan evicts the oldest — memory stays bounded.
        proj.apply(&envelope(finalized(newest, 0xcc), at(12)));
        assert_eq!(proj.orphan_len(), 2, "still bounded after a third orphan");

        // The evicted incident's terminal is gone: its later IncidentCreated links a fresh
        // row with no retraction (the accepted trade-off, logged for ops).
        let evicted_alert = AlertId::new();
        proj.apply(&envelope(created(evicted_alert, oldest), at(20)));
        let record = proj.record(&evicted_alert).expect("row");
        assert_eq!(
            record.status,
            IncidentStatus::Confirmed,
            "retraction was evicted"
        );

        // A survivor still drains correctly onto its row.
        let survivor_alert = AlertId::new();
        proj.apply(&envelope(created(survivor_alert, newest), at(21)));
        assert_eq!(
            proj.record(&survivor_alert).unwrap().status,
            IncidentStatus::Finalized,
            "the surviving orphan replayed onto its row"
        );
    }

    #[test]
    fn draining_an_orphan_frees_its_capacity_slot() {
        // Eviction must skip already-drained ids, so a healthy drain-then-refill pipeline
        // never spuriously evicts a live orphan.
        let mut proj = IncidentProjection::with_orphan_capacity(1);
        let first = IncidentId::new();
        proj.apply(&envelope(retracted(first, "a"), at(10)));

        // Link + drain the first orphan; the buffer is now empty despite a stale order entry.
        proj.apply(&envelope(created(AlertId::new(), first), at(11)));
        assert_eq!(proj.orphan_len(), 0);

        // A new orphan fits without evicting anything spurious.
        let second = IncidentId::new();
        proj.apply(&envelope(retracted(second, "b"), at(12)));
        assert_eq!(proj.orphan_len(), 1);
        // And it still drains onto its row.
        let alert = AlertId::new();
        proj.apply(&envelope(created(alert, second), at(13)));
        assert_eq!(
            proj.record(&alert).unwrap().status,
            IncidentStatus::Retracted
        );
    }

    #[test]
    fn non_result_events_are_ignored() {
        use events::chain::BlockAssembled;
        use events::primitives::BlockRef;

        let mut proj = IncidentProjection::new();
        let event = DomainEvent::BlockAssembled(BlockAssembled {
            block: BlockRef::new(1, B256::repeat_byte(0x01)),
            tx_count: 1,
            trace_available: false,
        });
        assert_eq!(proj.apply(&envelope(event, at(10))), Applied::Ignored);
        assert!(proj.is_empty());
    }

    #[test]
    fn the_fold_is_order_independent() {
        // The whole point of §7: the same four events, applied in any order, converge to
        // the same row — ordering is reasserted at the projection, not the partition.
        let alert = AlertId::new();
        let incident = IncidentId::new();
        let events = [
            envelope(completed(alert, true, 5.0), at(10)),
            envelope(created(alert, incident), at(11)),
            envelope(finalized(incident, 0xaa), at(20)),
            envelope(retracted(incident, "reorg"), at(30)),
        ];

        // A few representative permutations, including terminals-before-creation.
        let orders = [[0, 1, 2, 3], [3, 2, 1, 0], [2, 3, 0, 1], [1, 3, 0, 2]];

        let mut canonical: Option<IncidentRecord> = None;
        for order in orders {
            let mut proj = IncidentProjection::new();
            for &i in &order {
                proj.apply(&events[i]);
            }
            let record = proj.record(&alert).expect("row").clone();
            // Retraction is the last word regardless of arrival order.
            assert_eq!(record.status, IncidentStatus::Retracted);
            match &canonical {
                None => canonical = Some(record),
                Some(first) => assert_eq!(&record, first, "order {order:?} converged differently"),
            }
        }
    }
}
