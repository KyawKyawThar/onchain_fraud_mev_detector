//! The block-production record and its pure fold (§10, Sprint 11 t1) — who
//! built and relayed each canonical block, and how much confirmed MEV it
//! carried.
//!
//! ## The record
//!
//! [`BlockProductionRecord`] is §10's struct made storable: the block, the
//! builder attribution (feeRecipient + extraData graffiti + the relay bid
//! trace's builder pubkey, named through an intelligence *label*, never a
//! hardcoded table), the relay that delivered the payload, and the confirmed
//! MEV folded in from `IncidentCreated` (§7). Monetary figures are `f64` USD —
//! the same convention as `IncidentCreated::profit` and the simulation
//! projection, in place of the §10 sketch's `Decimal` (one numeric vocabulary
//! across the result path, and these are estimates, not ledger entries).
//!
//! ## The fold ([`ProductionBook`])
//!
//! Pure and synchronous, like `simulation::projection` and detection's
//! `emit.rs`: events in, snapshots-to-persist out, no I/O — the effectful
//! consumer ([`crate::production_consumer`]) fetches header/relay facts and
//! persists what this fold returns.
//!
//! The crux is the **incident → block join**. `IncidentCreated` deliberately
//! carries no block (locked schema, §2) — only `alert_id`, `txs` and figures.
//! The block lives on the `DetectorTriggered` that started the lifecycle,
//! which implicates the *same* transactions (simulation confirms the
//! detector's tx set, §7). So the book learns `tx → block` from every
//! `DetectorTriggered` and resolves an incident through its first implicated
//! transaction — the same cross-topic learn-and-buffer correlation
//! [`crate::attribution`] does with `alert_id → addresses`, with the same
//! reorder tolerance: an incident that outruns its trigger (or its block's
//! record) is buffered, not dropped, in FIFO-bounded maps
//! ([`BookCapacity`]) so an uncorrelatable flood can't grow memory without
//! bound.
//!
//! ## Idempotency and reversal
//!
//! Every fold is keyed: a redelivered `IncidentCreated` is recognised by
//! `incident_id` (already folded → no new snapshot), a redelivered
//! `BlockCanonicalized` finds its record already open, `IncidentRetracted`
//! subtracts exactly the contribution its `incident_id` added, and
//! `BlockReverted` marks the record's final snapshot reverted (a reorged
//! block's MEV must not survive on a leaderboard, §15).

use std::collections::HashMap;

use alloy_primitives::{B256, U256};
use chrono::{DateTime, Utc};
use events::primitives::{AccountAddress, AlertKind, BlockRef, Chain, IncidentId};
use serde::{Deserialize, Serialize};

use crate::bounded::BoundedFifoMap;

/// A direct value transfer to the block's fee recipient inside its own block —
/// the classic coinbase-tip MEV payment channel (§10). Detected from the full
/// block body (`to == feeRecipient`, non-zero value); internal (trace-level)
/// coinbase transfers need execution traces the platform doesn't ingest yet,
/// a documented gap, not an oversight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinbaseTransfer {
    pub from: AccountAddress,
    /// The transferring transaction — the evidence ref.
    pub tx: B256,
    /// Transfer value in wei. Kept exact (`U256`, serialized as a `0x…` hex
    /// quantity string) — wei amounts overflow `f64` precision.
    pub value_wei: U256,
}

/// What the MEV-Boost relay data API knew about a block: which configured
/// relay reported delivering its payload, and the winning builder's BLS
/// pubkey from the bid trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAttribution {
    /// The configured relay's name (from config, never hardcoded in code).
    pub relay: String,
    /// The builder's BLS pubkey (0x-hex) from the delivered bid trace.
    pub builder_pubkey: String,
}

/// §10's `BlockProductionRecord`: one canonical block's production chain
/// (builder → relay) plus the confirmed MEV folded into it so far. This is
/// also the persisted *snapshot* shape — every fold that changes it returns a
/// clone for the store to append.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockProductionRecord {
    pub chain: Chain,
    pub block: BlockRef,
    /// The header's feeRecipient — the builder's payout address (§10).
    pub fee_recipient: AccountAddress,
    /// The header's extraData graffiti, sanitized to printable UTF-8
    /// ([`sanitize_extra_data`]). Raw evidence; naming comes from labels.
    pub extra_data: String,
    /// Relay-derived attribution, when a configured relay delivered the block.
    pub relay: Option<RelayAttribution>,
    /// The builder's display name as intelligence knows it: the active
    /// `BuilderAddress` label on [`fee_recipient`](Self::fee_recipient) at
    /// fold time (§10 — labels live in the intelligence store, the landscape
    /// shifts and hardcoding names is a maintenance trap).
    pub builder_label: Option<String>,
    /// Summed profit of folded confirmed incidents (USD, §7 figures).
    pub mev_extracted_usd: f64,
    pub sandwich_count: u32,
    pub arb_count: u32,
    /// Confirmed incidents of every other [`AlertKind`].
    pub other_mev_count: u32,
    pub coinbase_transfers: Vec<CoinbaseTransfer>,
    /// Set when the block was reverted by a reorg after the record opened —
    /// the final snapshot a reader must exclude (§15).
    pub reverted: bool,
    /// Event-time of the fold that produced this snapshot — the consumed
    /// event's `occurred_at`, never a wall clock, so replay is deterministic
    /// (§18). Latest-per-block reads key on this.
    pub snapshot_at: DateTime<Utc>,
    /// What each folded incident contributed, by id — the idempotency key for
    /// redelivered `IncidentCreated`s and the exact amount an
    /// `IncidentRetracted` takes back. Not persisted (the snapshot columns are
    /// the folded totals).
    #[serde(skip)]
    folded: HashMap<IncidentId, Contribution>,
}

/// The gathered facts a record opens with — everything the consumer assembles
/// from the chain, the relays and the label store before the fold runs. A
/// named struct rather than positional arguments on purpose: `extra_data` and
/// `builder_label` are both stringly and adjacent, and positional passing
/// would let them transpose without a compile error.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenFacts {
    /// The header's feeRecipient — the builder's payout address (§10).
    pub fee_recipient: AccountAddress,
    /// The header's extraData graffiti, already sanitized
    /// ([`sanitize_extra_data`]).
    pub extra_data: String,
    /// Relay-derived attribution, when a configured relay delivered the block.
    pub relay: Option<RelayAttribution>,
    /// The builder's display name from the label store, when one is active.
    pub builder_label: Option<String>,
    pub coinbase_transfers: Vec<CoinbaseTransfer>,
}

impl BlockProductionRecord {
    /// A freshly-opened record: header/relay/label facts in, no MEV folded yet.
    pub fn open(chain: Chain, block: BlockRef, facts: OpenFacts, at: DateTime<Utc>) -> Self {
        Self {
            chain,
            block,
            fee_recipient: facts.fee_recipient,
            extra_data: facts.extra_data,
            relay: facts.relay,
            builder_label: facts.builder_label,
            mev_extracted_usd: 0.0,
            sandwich_count: 0,
            arb_count: 0,
            other_mev_count: 0,
            coinbase_transfers: facts.coinbase_transfers,
            reverted: false,
            snapshot_at: at,
            folded: HashMap::new(),
        }
    }

    /// Fold one confirmed incident in. Returns `false` (and changes nothing)
    /// when this `incident_id` was already folded — the redelivery no-op.
    fn apply(
        &mut self,
        incident_id: IncidentId,
        contribution: Contribution,
        at: DateTime<Utc>,
    ) -> bool {
        if self.folded.contains_key(&incident_id) {
            return false;
        }
        self.count_mut(contribution.kind).increment();
        self.mev_extracted_usd += contribution.profit_usd;
        self.snapshot_at = at;
        self.folded.insert(incident_id, contribution);
        true
    }

    /// Take a previously-folded incident back out (§15 retraction). Returns
    /// `false` when the incident was never folded here.
    fn retract(&mut self, incident_id: IncidentId, at: DateTime<Utc>) -> bool {
        let Some(contribution) = self.folded.remove(&incident_id) else {
            return false;
        };
        self.count_mut(contribution.kind).decrement();
        self.mev_extracted_usd -= contribution.profit_usd;
        self.snapshot_at = at;
        true
    }

    fn count_mut(&mut self, kind: AlertKind) -> Counter<'_> {
        let counter = match kind {
            AlertKind::Sandwich => &mut self.sandwich_count,
            AlertKind::Arbitrage => &mut self.arb_count,
            _ => &mut self.other_mev_count,
        };
        Counter(counter)
    }
}

/// Saturating counter over one of the record's `u32` tallies — a retraction
/// for an incident folded before a restart must not underflow.
struct Counter<'a>(&'a mut u32);

impl Counter<'_> {
    fn increment(self) {
        *self.0 = self.0.saturating_add(1);
    }
    fn decrement(self) {
        *self.0 = self.0.saturating_sub(1);
    }
}

/// One incident's contribution to its block's record: the kind bucket and the
/// confirmed profit (§7).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Contribution {
    pub kind: AlertKind,
    pub profit_usd: f64,
}

/// An incident waiting for its correlation to resolve — either the
/// `tx → block` fact (a trigger not yet consumed) or the block's record
/// (a canonicalization not yet consumed).
#[derive(Debug, Clone, PartialEq)]
struct PendingIncident {
    incident_id: IncidentId,
    contribution: Contribution,
    at: DateTime<Utc>,
}

/// Bounds for the book's four maps. The working set covers the incident-confirm
/// lag (simulation takes seconds; 4096 blocks ≈ half a day of Ethereum), the
/// correlation maps mirror [`crate::attribution::DEFAULT_PENDING_CAPACITY`].
#[derive(Debug, Clone, Copy)]
pub struct BookCapacity {
    /// Open records (per block hash) kept in memory for later incident folds.
    pub records: usize,
    /// Learned `tx → block` facts from `DetectorTriggered`.
    pub tx_index: usize,
    /// Buffered incidents awaiting correlation (either map).
    pub pending: usize,
}

impl Default for BookCapacity {
    fn default() -> Self {
        Self {
            records: 4096,
            tx_index: 100_000,
            pending: 100_000,
        }
    }
}

/// What one fold decided. An enum (not an outcome flag beside a snapshot
/// `Vec`) so the invalid combinations — `Buffered` carrying snapshots,
/// `Applied` carrying none — are unrepresentable, and a consumer must match
/// before it can touch the snapshots.
#[derive(Debug, Clone, PartialEq)]
pub enum Folded {
    /// The event changed at least one record: every changed record's snapshot,
    /// in the order the changes happened — non-empty by construction
    /// ([`Folded::applied`]) — for the consumer to append to the store.
    Applied(Vec<BlockProductionRecord>),
    /// The incident couldn't be correlated yet and was buffered (§19 — the
    /// consumer counts these; a climbing rate means a stalled upstream
    /// partition).
    Buffered,
    /// Nothing to do: a redelivered/duplicate event, or one this book has no
    /// record for (e.g. a retraction for a block outside the working set).
    Noop,
}

impl Folded {
    /// `Applied` over a non-empty snapshot set, `Noop` otherwise — the one
    /// constructor, so "Applied means there is something to persist" holds by
    /// construction.
    fn applied(snapshots: Vec<BlockProductionRecord>) -> Self {
        if snapshots.is_empty() {
            Folded::Noop
        } else {
            Folded::Applied(snapshots)
        }
    }

    /// The snapshots to persist — empty unless `Applied`.
    pub fn into_snapshots(self) -> Vec<BlockProductionRecord> {
        match self {
            Folded::Applied(snapshots) => snapshots,
            Folded::Buffered | Folded::Noop => Vec::new(),
        }
    }
}

/// The pure block-production fold: open records keyed by block hash, the
/// learned `tx → block` index, and the two pending-incident buffers (see the
/// module docs for the correlation story). Everything is FIFO-bounded
/// ([`BookCapacity`]); an evicted entry is an accepted, logged gap — the same
/// stance as the attribution consumer's address book and the simulation
/// projection's orphan buffer.
pub struct ProductionBook {
    records: BoundedFifoMap<B256, BlockProductionRecord>,
    /// `tx → block`, learned from `DetectorTriggered` — only *implicated*
    /// transactions, a tiny fraction of the chain.
    tx_blocks: BoundedFifoMap<B256, BlockRef>,
    /// Incidents whose first tx resolved to a block, but whose record isn't
    /// open yet (canonicalization not consumed), keyed by block hash.
    awaiting_record: BoundedFifoMap<B256, Vec<PendingIncident>>,
    /// Incidents whose txs matched no learned `tx → block` fact yet, keyed by
    /// their first implicated tx (the trigger that will arrive carries the
    /// same tx set).
    awaiting_block: BoundedFifoMap<B256, Vec<PendingIncident>>,
    /// Which block each folded incident landed in — routes a retraction.
    folded_blocks: BoundedFifoMap<IncidentId, B256>,
}

impl ProductionBook {
    pub fn new(capacity: BookCapacity) -> Self {
        Self {
            records: BoundedFifoMap::new(capacity.records, "open production records"),
            tx_blocks: BoundedFifoMap::new(capacity.tx_index, "tx→block index"),
            awaiting_record: BoundedFifoMap::new(capacity.pending, "incidents awaiting record"),
            awaiting_block: BoundedFifoMap::new(capacity.pending, "incidents awaiting block"),
            folded_blocks: BoundedFifoMap::new(capacity.pending, "folded incident index"),
        }
    }

    /// Is a record for this block hash already open? The consumer checks
    /// before doing its (effectful) header/relay fetch, so a redelivered
    /// `BlockCanonicalized` costs nothing.
    pub fn is_open(&self, block_hash: &B256) -> bool {
        self.records.get(block_hash).is_some()
    }

    /// A `DetectorTriggered` was consumed: learn `tx → block` for every
    /// implicated tx, then re-drive any incidents that were waiting on exactly
    /// these facts. (An incident re-driven into a still-unopened record moves
    /// buffers rather than producing a snapshot — from this event's
    /// perspective that is a `Noop`.)
    pub fn observe_trigger(&mut self, block: BlockRef, txs: &[B256]) -> Folded {
        let mut snapshots = Vec::new();
        for tx in txs {
            self.tx_blocks.put(*tx, block);
            if let Some(pending) = self.awaiting_block.take(tx) {
                for incident in pending {
                    snapshots.extend(self.route_to_block(block.hash, incident).into_snapshots());
                }
            }
        }
        Folded::applied(snapshots)
    }

    /// A `BlockCanonicalized` was consumed and the consumer assembled the
    /// record (header + relay + label facts): open it, drain any incidents
    /// that were waiting for it, and return the opening snapshot. A block
    /// whose record is already open is a redelivery no-op.
    pub fn open_record(&mut self, record: BlockProductionRecord) -> Folded {
        let hash = record.block.hash;
        if self.is_open(&hash) {
            return Folded::Noop;
        }
        let mut snapshots = vec![record.clone()];
        self.records.put(hash, record);

        // Drain incidents that arrived before the record. Each apply mutates
        // the stored record; only the final state needs persisting, but every
        // intermediate snapshot is appended for the same audit-trail reasons
        // as incident_analytics (a snapshot per fold).
        if let Some(pending) = self.awaiting_record.take(&hash) {
            for incident in pending {
                snapshots.extend(self.route_to_block(hash, incident).into_snapshots());
            }
        }
        Folded::applied(snapshots)
    }

    /// An `IncidentCreated` was consumed: resolve its block through the first
    /// implicated tx and fold it in — or buffer it until the trigger/record
    /// it needs arrives. An incident carrying no txs can never be joined and
    /// is dropped as a no-op (the caller logs it).
    pub fn fold_incident(
        &mut self,
        incident_id: IncidentId,
        contribution: Contribution,
        txs: &[B256],
        at: DateTime<Utc>,
    ) -> Folded {
        if self.folded_blocks.get(&incident_id).is_some() {
            return Folded::Noop; // redelivered — already folded
        }
        let Some(first_tx) = txs.first() else {
            return Folded::Noop;
        };
        let incident = PendingIncident {
            incident_id,
            contribution,
            at,
        };
        match self.tx_blocks.get(first_tx).copied() {
            Some(block) => self.route_to_block(block.hash, incident),
            None => {
                self.buffer(*first_tx, incident, AwaitingWhat::Block);
                Folded::Buffered
            }
        }
    }

    /// An `IncidentRetracted` was consumed: take the incident's contribution
    /// back out of its block's record (§15). Unknown incident (never folded,
    /// evicted, or folded before a restart) → no-op; still buffered → the
    /// buffer entry is dropped so it can't fold later.
    pub fn retract_incident(&mut self, incident_id: IncidentId, at: DateTime<Utc>) -> Folded {
        if let Some(block_hash) = self.folded_blocks.take(&incident_id) {
            let Some(record) = self.records.get_mut(&block_hash) else {
                return Folded::Noop; // record evicted since — nothing to update
            };
            if record.retract(incident_id, at) {
                return Folded::Applied(vec![record.clone()]);
            }
            return Folded::Noop;
        }
        // Not folded: drop it from the pending buffers so a late trigger
        // can't resurrect a retracted incident.
        for buffer in [&mut self.awaiting_record, &mut self.awaiting_block] {
            buffer.retain_values(|pending| pending.incident_id != incident_id);
        }
        Folded::Noop
    }

    /// A `BlockReverted` was consumed: mark the record's final snapshot
    /// reverted and drop it from the working set (§15) — late incidents for a
    /// reverted block will be retracted by simulation anyway. No record open
    /// (never canonicalized here, or already evicted) → no-op.
    pub fn revert_block(&mut self, block_hash: B256, at: DateTime<Utc>) -> Folded {
        self.awaiting_record.take(&block_hash);
        let Some(mut record) = self.records.take(&block_hash) else {
            return Folded::Noop;
        };
        record.reverted = true;
        record.snapshot_at = at;
        Folded::Applied(vec![record])
    }

    /// Route an incident whose block hash is known: fold it into the open
    /// record (`Applied`, or `Noop` for a redelivered duplicate), or buffer it
    /// against the record's arrival (`Buffered`). One lookup decides both the
    /// branch and the fold — no separate "is it open" check whose answer could
    /// go stale between the ask and the use.
    fn route_to_block(&mut self, block_hash: B256, incident: PendingIncident) -> Folded {
        let Some(record) = self.records.get_mut(&block_hash) else {
            self.buffer(block_hash, incident, AwaitingWhat::Record);
            return Folded::Buffered;
        };
        if !record.apply(incident.incident_id, incident.contribution, incident.at) {
            return Folded::Noop;
        }
        let snapshot = record.clone();
        self.folded_blocks.put(incident.incident_id, block_hash);
        Folded::Applied(vec![snapshot])
    }

    fn buffer(&mut self, key: B256, incident: PendingIncident, what: AwaitingWhat) {
        let buffer = match what {
            AwaitingWhat::Record => &mut self.awaiting_record,
            AwaitingWhat::Block => &mut self.awaiting_block,
        };
        match buffer.get_mut(&key) {
            Some(pending) => {
                if !pending
                    .iter()
                    .any(|p| p.incident_id == incident.incident_id)
                {
                    pending.push(incident);
                }
            }
            None => buffer.put(key, vec![incident]),
        }
    }
}

enum AwaitingWhat {
    Record,
    Block,
}

/// Cap on the stored graffiti. Post-merge Ethereum extraData is ≤ 32 bytes,
/// but other chains (and pre-merge blocks) can carry more — this bounds the
/// column without truncating any real builder tag.
const MAX_GRAFFITI_CHARS: usize = 64;

/// Shortest graffiti accepted as a builder display name — anything shorter
/// ("", "1", "..") identifies nothing, so the pubkey fallback names better.
const MIN_GRAFFITI_CHARS: usize = 3;

/// Hex chars of the BLS pubkey kept in the fallback label value — enough to
/// be recognisable and greppable against relay data, short enough to read.
const PUBKEY_PREFIX_CHARS: usize = 12;

/// Sanitize a header's raw extraData into printable, bounded UTF-8: lossy
/// decode, control characters stripped, trimmed, capped at
/// [`MAX_GRAFFITI_CHARS`]. Builders graffiti their identity here
/// ("beaverbuild.org", "Titan (titanbuilder.xyz)") — kept as *evidence*;
/// naming still goes through labels (§10).
pub fn sanitize_extra_data(raw: &[u8]) -> String {
    let text: String = String::from_utf8_lossy(raw)
        .chars()
        .filter(|c| !c.is_control() && *c != char::REPLACEMENT_CHARACTER)
        .take(MAX_GRAFFITI_CHARS)
        .collect();
    text.trim().to_owned()
}

/// The display value for a heuristically-minted `BuilderAddress` label (§8.1
/// auto-labeling: "builder feeRecipient from relay data"): the block's own
/// graffiti when the builder stamped a meaningful one
/// (≥ [`MIN_GRAFFITI_CHARS`]), else the relay-reported BLS pubkey truncated to
/// a recognisable prefix ([`PUBKEY_PREFIX_CHARS`]). Deliberately derived from
/// *observed* facts — never a hardcoded name table (§10).
pub fn heuristic_builder_value(extra_data: &str, builder_pubkey: &str) -> String {
    if extra_data.len() >= MIN_GRAFFITI_CHARS {
        return extra_data.to_owned();
    }
    let hex = builder_pubkey.trim_start_matches("0x");
    let prefix: String = hex.chars().take(PUBKEY_PREFIX_CHARS).collect();
    format!("builder:0x{prefix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> B256 {
        B256::repeat_byte(byte)
    }

    fn block(n: u64, byte: u8) -> BlockRef {
        BlockRef::new(n, hash(byte))
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_700_000_000 + secs, 0).unwrap()
    }

    fn record(n: u64, byte: u8) -> BlockProductionRecord {
        BlockProductionRecord::open(
            Chain::ETHEREUM,
            block(n, byte),
            OpenFacts {
                fee_recipient: AccountAddress::repeat_byte(0xfe),
                extra_data: "beaverbuild.org".to_owned(),
                relay: Some(RelayAttribution {
                    relay: "flashbots".to_owned(),
                    builder_pubkey: "0xabcd".to_owned(),
                }),
                builder_label: Some("beaverbuild".to_owned()),
                coinbase_transfers: vec![],
            },
            at(0),
        )
    }

    /// Unwrap `Applied`, panicking with the actual variant otherwise.
    #[track_caller]
    fn applied(folded: Folded) -> Vec<BlockProductionRecord> {
        match folded {
            Folded::Applied(snapshots) => snapshots,
            other => panic!("expected Folded::Applied, got {other:?}"),
        }
    }

    fn sandwich(profit: f64) -> Contribution {
        Contribution {
            kind: AlertKind::Sandwich,
            profit_usd: profit,
        }
    }

    fn book() -> ProductionBook {
        ProductionBook::new(BookCapacity::default())
    }

    #[test]
    fn open_then_trigger_then_incident_folds_in_order() {
        let mut book = book();

        let opened = applied(book.open_record(record(7, 0x07)));
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].sandwich_count, 0);

        // Trigger teaches tx→block; nothing to link yet.
        let tx = hash(0x11);
        assert_eq!(book.observe_trigger(block(7, 0x07), &[tx]), Folded::Noop);

        // Incident joins through its first tx.
        let incident = IncidentId::new();
        let folded = applied(book.fold_incident(incident, sandwich(120.0), &[tx], at(5)));
        let snap = &folded[0];
        assert_eq!(snap.sandwich_count, 1);
        assert_eq!(snap.mev_extracted_usd, 120.0);
        assert_eq!(snap.snapshot_at, at(5));
    }

    #[test]
    fn incident_kinds_bucket_into_their_counters() {
        let mut book = book();
        book.open_record(record(1, 0x01));
        let tx_a = hash(0xa1);
        let tx_b = hash(0xa2);
        let tx_c = hash(0xa3);
        book.observe_trigger(block(1, 0x01), &[tx_a, tx_b, tx_c]);

        book.fold_incident(IncidentId::new(), sandwich(10.0), &[tx_a], at(1));
        book.fold_incident(
            IncidentId::new(),
            Contribution {
                kind: AlertKind::Arbitrage,
                profit_usd: 5.0,
            },
            &[tx_b],
            at(2),
        );
        let last = book.fold_incident(
            IncidentId::new(),
            Contribution {
                kind: AlertKind::Flashloan,
                profit_usd: 2.5,
            },
            &[tx_c],
            at(3),
        );

        let snap = &applied(last)[0];
        assert_eq!(
            (snap.sandwich_count, snap.arb_count, snap.other_mev_count),
            (1, 1, 1)
        );
        assert_eq!(snap.mev_extracted_usd, 17.5);
    }

    #[test]
    fn redelivered_incident_is_a_noop() {
        let mut book = book();
        book.open_record(record(1, 0x01));
        let tx = hash(0x11);
        book.observe_trigger(block(1, 0x01), &[tx]);

        let incident = IncidentId::new();
        book.fold_incident(incident, sandwich(10.0), &[tx], at(1));
        let again = book.fold_incident(incident, sandwich(10.0), &[tx], at(2));
        assert_eq!(again, Folded::Noop, "no double-count snapshot");
    }

    #[test]
    fn redelivered_open_is_a_noop_and_keeps_folded_state() {
        let mut book = book();
        book.open_record(record(1, 0x01));
        let tx = hash(0x11);
        book.observe_trigger(block(1, 0x01), &[tx]);
        book.fold_incident(IncidentId::new(), sandwich(10.0), &[tx], at(1));

        let reopened = book.open_record(record(1, 0x01));
        assert_eq!(reopened, Folded::Noop);

        // The folded incident survived the redelivered canonicalization.
        let retracted = applied(book.revert_block(hash(0x01), at(9)));
        assert_eq!(retracted[0].sandwich_count, 1);
    }

    #[test]
    fn incident_before_trigger_buffers_until_the_trigger_links_it() {
        let mut book = book();
        book.open_record(record(1, 0x01));

        let tx = hash(0x11);
        let incident = IncidentId::new();
        let early = book.fold_incident(incident, sandwich(50.0), &[tx], at(1));
        assert_eq!(early, Folded::Buffered);

        // The trigger arrives and links the buffered incident.
        let linked = applied(book.observe_trigger(block(1, 0x01), &[tx]));
        assert_eq!(linked[0].sandwich_count, 1);
        assert_eq!(linked[0].mev_extracted_usd, 50.0);
    }

    #[test]
    fn incident_before_record_buffers_until_canonicalization_opens_it() {
        let mut book = book();
        let tx = hash(0x11);
        book.observe_trigger(block(1, 0x01), &[tx]);

        let incident = IncidentId::new();
        let early = book.fold_incident(incident, sandwich(50.0), &[tx], at(1));
        assert_eq!(early, Folded::Buffered);

        let opened = applied(book.open_record(record(1, 0x01)));
        // Snapshot 0 is the bare opening, snapshot 1 carries the drained fold.
        assert_eq!(opened.len(), 2);
        assert_eq!(opened[1].sandwich_count, 1);
    }

    #[test]
    fn retraction_subtracts_exactly_what_the_incident_added() {
        let mut book = book();
        book.open_record(record(1, 0x01));
        let tx_a = hash(0xa1);
        let tx_b = hash(0xa2);
        book.observe_trigger(block(1, 0x01), &[tx_a, tx_b]);

        let keep = IncidentId::new();
        let undo = IncidentId::new();
        book.fold_incident(keep, sandwich(100.0), &[tx_a], at(1));
        book.fold_incident(undo, sandwich(40.0), &[tx_b], at(2));

        let retracted = applied(book.retract_incident(undo, at(3)));
        let snap = &retracted[0];
        assert_eq!(snap.sandwich_count, 1);
        assert_eq!(snap.mev_extracted_usd, 100.0);
        assert_eq!(snap.snapshot_at, at(3));

        // Retracting again is a no-op.
        assert_eq!(book.retract_incident(undo, at(4)), Folded::Noop);
    }

    #[test]
    fn retraction_of_a_buffered_incident_drops_it_before_it_can_fold() {
        let mut book = book();
        book.open_record(record(1, 0x01));

        let tx = hash(0x11);
        let incident = IncidentId::new();
        book.fold_incident(incident, sandwich(50.0), &[tx], at(1)); // buffered
        book.retract_incident(incident, at(2));

        // The late trigger must not resurrect the retracted incident.
        let linked = book.observe_trigger(block(1, 0x01), &[tx]);
        assert_eq!(linked, Folded::Noop);
    }

    #[test]
    fn revert_marks_the_final_snapshot_and_drops_the_record() {
        let mut book = book();
        book.open_record(record(1, 0x01));

        let reverted = applied(book.revert_block(hash(0x01), at(5)));
        assert!(reverted[0].reverted);
        assert_eq!(reverted[0].snapshot_at, at(5));

        assert!(!book.is_open(&hash(0x01)));
        assert_eq!(book.revert_block(hash(0x01), at(6)), Folded::Noop);
    }

    #[test]
    fn incident_with_no_txs_can_never_join_and_is_dropped() {
        let mut book = book();
        book.open_record(record(1, 0x01));
        let folded = book.fold_incident(IncidentId::new(), sandwich(10.0), &[], at(1));
        assert_eq!(folded, Folded::Noop);
    }

    #[test]
    fn working_set_is_bounded_and_an_evicted_block_noops() {
        let mut book = ProductionBook::new(BookCapacity {
            records: 2,
            ..BookCapacity::default()
        });
        book.open_record(record(1, 0x01));
        book.open_record(record(2, 0x02));
        book.open_record(record(3, 0x03)); // evicts block 1

        assert!(!book.is_open(&hash(0x01)));
        assert_eq!(book.revert_block(hash(0x01), at(1)), Folded::Noop);
        assert!(book.is_open(&hash(0x02)));
        assert!(book.is_open(&hash(0x03)));
    }

    #[test]
    fn counters_saturate_instead_of_underflowing() {
        // A retraction routed to a record that (through restart quirks) never
        // counted the incident must not wrap the counter. Simulated directly
        // on the record: retract after a manual folded-entry removal.
        let mut rec = record(1, 0x01);
        let incident = IncidentId::new();
        rec.apply(incident, sandwich(10.0), at(1));
        rec.sandwich_count = 0; // simulate lost count
        assert!(rec.retract(incident, at(2)));
        assert_eq!(rec.sandwich_count, 0, "saturated, not wrapped");
    }

    #[test]
    fn sanitize_extra_data_strips_control_and_caps_length() {
        assert_eq!(sanitize_extra_data(b"beaverbuild.org"), "beaverbuild.org");
        assert_eq!(sanitize_extra_data(b"\x00\x01Titan\n"), "Titan");
        assert_eq!(
            sanitize_extra_data(&[0xff, 0xfe]),
            "",
            "invalid UTF-8 → empty"
        );
        let long = vec![b'a'; 100];
        assert_eq!(sanitize_extra_data(&long).len(), 64);
    }

    #[test]
    fn heuristic_builder_value_prefers_graffiti_over_pubkey() {
        assert_eq!(
            heuristic_builder_value("beaverbuild.org", "0xdeadbeef"),
            "beaverbuild.org"
        );
        assert_eq!(
            heuristic_builder_value("", "0xa1b2c3d4e5f60718293a4b5c"),
            "builder:0xa1b2c3d4e5f6"
        );
    }
}
