//! The cross-chain finding read-model projection (§24, Sprint 17 t4) — the
//! additive, `/v1/incidents`-adjacent counterpart to
//! [`IncidentProjection`](crate::projection::IncidentProjection): folds
//! `BridgeMevDetected`/`CrossChainMevDetected`/`CrossChainFindingRetracted`
//! into one row per finding.
//!
//! ## Why this is a separate model, not a shoehorned `IncidentRecord`
//!
//! A cross-chain finding has no `alert_id` (the key `IncidentRecord` is
//! keyed by), no single flat `txs` list (it has per-chain *legs*, §24), and
//! it never reaches a "confirmed"/"finalized" status the way a simulation-
//! backed incident does — `provisional` stays `true` forever, and a finding
//! is either live or **retracted outright** (§15/§24: a finding is only as
//! final as its least-final leg). Reusing `IncidentRecord`'s columns would
//! mean inventing a fake `alert_id` and leaving half the row's meaning
//! unmodeled; `/v1/incidents` instead surfaces both read models side by side
//! (see `crate::http::list_incidents`) rather than merging their shapes.
//!
//! ## Idempotency and cross-topic reordering
//!
//! `BridgeMevDetected`/`CrossChainMevDetected` and `CrossChainFindingRetracted`
//! share one Kafka *partition key* (`PartitionKey::CrossChainFinding`, §2/§24)
//! but live on **different topics**, and Kafka gives no cross-topic ordering
//! guarantee (the same reasoning `IncidentProjection`'s module docs give for
//! `IncidentCreated` vs. its terminals). So a retraction that overtakes its
//! finding's creation is buffered as an orphan ([`OrphanRetractions`]) and
//! replayed the moment the creation lands — never dropped. Creation itself is
//! **set-once**: a finding's fields never change after `BridgeMevDetected`/
//! `CrossChainMevDetected` first lands, so a redelivered creation is a
//! `Duplicate` no-op.

use std::collections::HashMap;

use bounded_map::BoundedFifoMap;
use chrono::{DateTime, Utc};
pub use events::cross_chain::CrossChainFindingKind;
use events::cross_chain::CrossChainLegRef;
use events::primitives::{AccountAddress, Confidence, CrossChainFindingId, Severity};
use events::{DomainEvent, EventEnvelope};

use crate::projection::Applied;

/// Bound on the orphaned-retraction buffer — mirrors
/// [`crate::projection::DEFAULT_ORPHAN_CAPACITY`], scaled down: cross-chain
/// findings are a much lower-volume stream than every incident on the
/// platform, so a smaller cap still comfortably covers a healthy pipeline's
/// transient reorder window while still bounding memory under a flood of
/// retractions for findings that never get created.
pub const DEFAULT_CROSS_CHAIN_ORPHAN_CAPACITY: usize = 10_000;

/// One cross-chain finding's read-model row.
#[derive(Debug, Clone, PartialEq)]
pub struct CrossChainFindingRecord {
    pub finding_id: CrossChainFindingId,
    pub kind: CrossChainFindingKind,
    pub bridge: String,
    /// Every correlated leg (two or more, spanning at least two chains, §24).
    pub legs: Vec<CrossChainLegRef>,
    /// The behaviour-derived correlation address (§24) — a hint, never a
    /// label; see `intelligence::cross_chain_attribution`'s module docs.
    pub entity_hint: AccountAddress,
    pub profit: f64,
    /// `0.0` for `CrossChainMevDetected`, which carries no victim-loss figure
    /// of its own (only `BridgeMevDetected` prices a deposit-leg loss).
    pub victim_loss: f64,
    pub confidence: Confidence,
    pub severity: Severity,
    /// `true` once a `CrossChainFindingRetracted` withdrew this finding
    /// (§15/§24). Never reset — a finding is retracted outright, not
    /// re-confirmed.
    pub retracted: bool,
    pub retraction_reason: Option<String>,
    /// Event-time of the fold that last changed this row — creation, or the
    /// retraction (§18, replay-deterministic).
    pub observed_at: DateTime<Utc>,
}

impl CrossChainFindingRecord {
    /// Reconstruct a row read back from storage
    /// (`crate::store::PgCrossChainFindingStore::list_findings`) — the
    /// inverse of what `upsert_finding` persists.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_stored(
        finding_id: CrossChainFindingId,
        kind: CrossChainFindingKind,
        bridge: String,
        legs: Vec<CrossChainLegRef>,
        entity_hint: AccountAddress,
        profit: f64,
        victim_loss: f64,
        confidence: Confidence,
        severity: Severity,
        retracted: bool,
        retraction_reason: Option<String>,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            finding_id,
            kind,
            bridge,
            legs,
            entity_hint,
            profit,
            victim_loss,
            confidence,
            severity,
            retracted,
            retraction_reason,
            observed_at,
        }
    }
}

/// FIFO-bounded buffer of retraction reasons awaiting the creation event that
/// links their `finding_id` — a thin, policy-specific wrapper over the shared
/// [`bounded_map::BoundedFifoMap`] primitive (the same one
/// [`crate::projection`]'s `OrphanBuffer` wraps): "buffer a `(reason, at)`
/// pair, deduping an identical redelivered retraction" is this buffer's own
/// decision, not the primitive's.
#[derive(Debug)]
struct OrphanRetractions {
    inner: BoundedFifoMap<CrossChainFindingId, (String, DateTime<Utc>)>,
}

impl OrphanRetractions {
    fn new(capacity: usize) -> Self {
        Self {
            inner: BoundedFifoMap::new(capacity, "cross-chain finding orphan-retraction buffer"),
        }
    }

    /// Buffer a retraction. Returns whether it was newly buffered — an
    /// identical redelivered retraction already held is a no-op (`false`).
    fn buffer(
        &mut self,
        finding_id: CrossChainFindingId,
        reason: String,
        at: DateTime<Utc>,
    ) -> bool {
        if let Some(existing) = self.inner.get(&finding_id) {
            if existing.0 == reason && existing.1 == at {
                return false;
            }
        }
        self.inner.put(finding_id, (reason, at));
        true
    }

    fn take(&mut self, finding_id: &CrossChainFindingId) -> Option<(String, DateTime<Utc>)> {
        self.inner.take(finding_id)
    }

    fn len(&self) -> usize {
        self.inner.len()
    }
}

/// The cross-chain finding read model: an idempotent fold over
/// `BridgeMevDetected`/`CrossChainMevDetected`/`CrossChainFindingRetracted`.
#[derive(Debug)]
pub struct CrossChainFindingProjection {
    by_finding: HashMap<CrossChainFindingId, CrossChainFindingRecord>,
    orphans: OrphanRetractions,
}

impl CrossChainFindingProjection {
    pub fn new() -> Self {
        Self::with_orphan_capacity(DEFAULT_CROSS_CHAIN_ORPHAN_CAPACITY)
    }

    pub fn with_orphan_capacity(capacity: usize) -> Self {
        Self {
            by_finding: HashMap::new(),
            orphans: OrphanRetractions::new(capacity),
        }
    }

    /// Fold one event. Non-cross-chain-finding events are [`Applied::Ignored`]
    /// so a shared consumer can route the rest of the backbone through here
    /// without special-casing.
    pub fn apply(&mut self, envelope: &EventEnvelope) -> Applied {
        let at = envelope.occurred_at;
        match &envelope.payload {
            DomainEvent::BridgeMevDetected(finding) => self.create(
                finding.finding_id,
                CrossChainFindingKind::BridgeMev,
                finding.bridge.clone(),
                vec![finding.deposit_leg.clone(), finding.fill_leg.clone()],
                finding.entity_hint,
                finding.profit,
                finding.victim_loss,
                finding.confidence,
                finding.severity,
                at,
            ),
            DomainEvent::CrossChainMevDetected(finding) => self.create(
                finding.finding_id,
                CrossChainFindingKind::CrossChainMev,
                finding.bridge.clone(),
                finding.legs.clone(),
                finding.entity_hint,
                finding.profit,
                0.0,
                finding.confidence,
                finding.severity,
                at,
            ),
            DomainEvent::CrossChainFindingRetracted(retracted) => {
                self.retract(retracted.finding_id, retracted.reason.clone(), at)
            }
            _ => Applied::Ignored,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn create(
        &mut self,
        finding_id: CrossChainFindingId,
        kind: CrossChainFindingKind,
        bridge: String,
        legs: Vec<CrossChainLegRef>,
        entity_hint: AccountAddress,
        profit: f64,
        victim_loss: f64,
        confidence: Confidence,
        severity: Severity,
        at: DateTime<Utc>,
    ) -> Applied {
        if self.by_finding.contains_key(&finding_id) {
            // Set-once: a finding's fields never change post-creation, so a
            // redelivered creation is a pure no-op.
            return Applied::Duplicate;
        }
        let mut record = CrossChainFindingRecord {
            finding_id,
            kind,
            bridge,
            legs,
            entity_hint,
            profit,
            victim_loss,
            confidence,
            severity,
            retracted: false,
            retraction_reason: None,
            observed_at: at,
        };
        // A retraction that overtook this creation (cross-topic reorder,
        // see the module docs): apply it now instead of losing it.
        if let Some((reason, retracted_at)) = self.orphans.take(&finding_id) {
            record.retracted = true;
            record.retraction_reason = Some(reason);
            record.observed_at = record.observed_at.max(retracted_at);
        }
        self.by_finding.insert(finding_id, record);
        Applied::Updated
    }

    fn retract(
        &mut self,
        finding_id: CrossChainFindingId,
        reason: String,
        at: DateTime<Utc>,
    ) -> Applied {
        let Some(record) = self.by_finding.get_mut(&finding_id) else {
            return if self.orphans.buffer(finding_id, reason, at) {
                Applied::Updated
            } else {
                Applied::Duplicate
            };
        };
        if record.retracted {
            return Applied::Duplicate;
        }
        record.retracted = true;
        record.retraction_reason = Some(reason);
        record.observed_at = at;
        Applied::Updated
    }

    /// Read one finding's current row, if it's been created.
    pub fn record(&self, finding_id: &CrossChainFindingId) -> Option<&CrossChainFindingRecord> {
        self.by_finding.get(finding_id)
    }

    /// Distinct findings currently held in the terminal-before-create orphan
    /// buffer — the gauge the consuming shell can export for alarming (§19),
    /// mirroring [`crate::projection::IncidentProjection::orphan_len`].
    pub fn orphan_len(&self) -> usize {
        self.orphans.len()
    }
}

impl Default for CrossChainFindingProjection {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256};
    use events::cross_chain::{
        BridgeMevDetected, CrossChainFindingRetracted, CrossChainMevDetected,
    };
    use events::primitives::{AlertKind, BlockRef, Chain};
    use uuid::Uuid;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    fn env(payload: DomainEvent, occurred_at: DateTime<Utc>) -> EventEnvelope {
        EventEnvelope::with_metadata(Uuid::new_v4(), occurred_at, Chain::ETHEREUM, payload)
    }

    fn leg(chain: Chain, n: u64, byte: u8) -> CrossChainLegRef {
        CrossChainLegRef {
            chain,
            block: BlockRef::new(n, B256::repeat_byte(byte)),
            tx: B256::repeat_byte(byte),
        }
    }

    fn bridge_finding(finding_id: CrossChainFindingId) -> DomainEvent {
        DomainEvent::BridgeMevDetected(BridgeMevDetected {
            finding_id,
            bridge: "usdc-eth-base".into(),
            deposit_leg: leg(Chain::ETHEREUM, 100, 0x01),
            fill_leg: leg(Chain::BASE, 200, 0x02),
            entity_hint: Address::repeat_byte(0xaa),
            profit: 1_000.0,
            victim_loss: 900.0,
            confidence: Confidence::new(0.8),
            severity: Severity::Medium,
            provisional: true,
        })
    }

    #[test]
    fn a_fresh_bridge_finding_creates_a_row() {
        let mut proj = CrossChainFindingProjection::new();
        let finding_id = CrossChainFindingId::new();

        assert_eq!(
            proj.apply(&env(bridge_finding(finding_id), at(1))),
            Applied::Updated
        );
        let record = proj.record(&finding_id).expect("row created");
        assert_eq!(record.kind, CrossChainFindingKind::BridgeMev);
        assert_eq!(record.legs.len(), 2);
        assert!(!record.retracted);
    }

    #[test]
    fn a_redelivered_creation_is_a_duplicate_noop() {
        let mut proj = CrossChainFindingProjection::new();
        let finding_id = CrossChainFindingId::new();
        proj.apply(&env(bridge_finding(finding_id), at(1)));

        assert_eq!(
            proj.apply(&env(bridge_finding(finding_id), at(2))),
            Applied::Duplicate
        );
    }

    #[test]
    fn a_retraction_after_creation_marks_the_row_retracted() {
        let mut proj = CrossChainFindingProjection::new();
        let finding_id = CrossChainFindingId::new();
        proj.apply(&env(bridge_finding(finding_id), at(1)));

        let retracted = DomainEvent::CrossChainFindingRetracted(CrossChainFindingRetracted {
            finding_id,
            reason: "leg block reverted".into(),
        });
        assert_eq!(proj.apply(&env(retracted, at(2))), Applied::Updated);

        let record = proj.record(&finding_id).unwrap();
        assert!(record.retracted);
        assert_eq!(
            record.retraction_reason.as_deref(),
            Some("leg block reverted")
        );
    }

    /// A retraction that overtakes its finding's creation (cross-topic
    /// reorder, §2/§24) is buffered, not dropped, and replayed the moment the
    /// creation links it.
    #[test]
    fn a_retraction_before_creation_is_buffered_then_replayed() {
        let mut proj = CrossChainFindingProjection::new();
        let finding_id = CrossChainFindingId::new();

        let retracted = DomainEvent::CrossChainFindingRetracted(CrossChainFindingRetracted {
            finding_id,
            reason: "leg block reverted".into(),
        });
        assert_eq!(proj.apply(&env(retracted, at(5))), Applied::Updated);
        assert!(proj.record(&finding_id).is_none(), "not yet created");
        assert_eq!(proj.orphan_len(), 1);

        assert_eq!(
            proj.apply(&env(bridge_finding(finding_id), at(1))),
            Applied::Updated
        );
        let record = proj.record(&finding_id).unwrap();
        assert!(record.retracted, "the buffered retraction replayed");
        assert_eq!(proj.orphan_len(), 0);
    }

    #[test]
    fn a_redelivered_retraction_is_a_duplicate_noop() {
        let mut proj = CrossChainFindingProjection::new();
        let finding_id = CrossChainFindingId::new();
        proj.apply(&env(bridge_finding(finding_id), at(1)));

        let retracted = DomainEvent::CrossChainFindingRetracted(CrossChainFindingRetracted {
            finding_id,
            reason: "leg block reverted".into(),
        });
        proj.apply(&env(retracted.clone(), at(2)));
        assert_eq!(proj.apply(&env(retracted, at(3))), Applied::Duplicate);
    }

    #[test]
    fn a_cross_chain_mev_finding_carries_every_leg_and_zero_victim_loss() {
        let mut proj = CrossChainFindingProjection::new();
        let finding_id = CrossChainFindingId::new();
        let finding = DomainEvent::CrossChainMevDetected(CrossChainMevDetected {
            finding_id,
            kind: AlertKind::Arbitrage,
            bridge: "usdc-eth-base".into(),
            legs: vec![
                leg(Chain::ETHEREUM, 100, 0x01),
                leg(Chain::BASE, 200, 0x02),
                leg(Chain(999), 300, 0x03),
            ],
            entity_hint: Address::repeat_byte(0xaa),
            profit: 500.0,
            latency_ms: 2_500,
            confidence: Confidence::new(0.7),
            severity: Severity::Low,
            provisional: true,
        });

        proj.apply(&env(finding, at(1)));
        let record = proj.record(&finding_id).unwrap();
        assert_eq!(record.kind, CrossChainFindingKind::CrossChainMev);
        assert_eq!(record.legs.len(), 3);
        assert_eq!(record.victim_loss, 0.0);
    }

    #[test]
    fn an_unrelated_event_is_ignored() {
        let mut proj = CrossChainFindingProjection::new();
        let ignored = DomainEvent::BlockCanonicalized(events::chain::BlockCanonicalized {
            block: BlockRef::new(1, B256::repeat_byte(0x01)),
        });
        assert_eq!(proj.apply(&env(ignored, at(1))), Applied::Ignored);
    }
}
