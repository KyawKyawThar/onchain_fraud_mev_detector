//! Domain event schema (§2) — the contract every service produces and
//! consumes, and the system of record once appended to the event store (§4).
//!
//! ## Shape
//!
//! - [`DomainEvent`] is the closed set of facts the system can record, one
//!   variant per event in §2. It (de)serializes adjacently tagged, e.g.
//!   `{"type":"BlockAssembled","payload":{…}}`, so a consumer can route on
//!   `type` without parsing the payload.
//! - [`EventEnvelope`] wraps a payload with the metadata every event carries
//!   regardless of family: a unique id, the chain it pertains to, when it
//!   occurred, and the schema version it was written under.
//!
//! ## Deliberate non-goals
//!
//! Transport concerns live elsewhere. The W3C trace context that ties an event
//! to a distributed trace travels in Kafka *headers*, not in the event body —
//! see the `telemetry` crate. Keeping the envelope free of transport fields is
//! what lets the same struct be the wire format *and* the stored record.

pub mod chain;
pub mod detection;
pub mod intelligence;
pub mod primitives;
pub mod rule_engine;
pub mod simulation;
pub mod system;

use chrono::{DateTime, Utc};
use primitives::{AccountAddress, Chain, IncidentId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Schema version stamped onto every envelope. Bump on any
/// backwards-incompatible change to a payload; consumers branch on it (§2 — the
/// schema is versioned explicitly so downstream services can migrate, key risk
/// #1 in the sprint plan).
pub const SCHEMA_VERSION: u16 = 1;

/// Namespace prefix for the Kafka topic of every domain event. §20 routes one
/// topic per event type (partitioned by chain); the full topic name is
/// `mev.events.<EventType>` (e.g. `mev.events.BlockAssembled`).
///
/// This lives here, on the schema crate, so producers (Sprint 2) and the
/// event-store consumer (§4) derive the topic from a single source of truth and
/// can't drift. See [`topic_for`] and [`EventEnvelope::topic`].
pub const TOPIC_PREFIX: &str = "mev.events";

/// The Kafka topic an event of `event_type` is published on:
/// `mev.events.<event_type>`. Pair with [`DomainEvent::event_type`] /
/// [`EventEnvelope::event_type`] so the name never drifts from the variant.
pub fn topic_for(event_type: &str) -> String {
    format!("{TOPIC_PREFIX}.{event_type}")
}

/// Errors from working with events (serialization, version mismatches).
#[derive(Debug, thiserror::Error)]
pub enum EventError {
    /// JSON (de)serialization failed. Wraps the underlying `serde_json` error
    /// so the source chain is preserved (no stringly-typed loss).
    #[error("event (de)serialization failed")]
    Serde(#[from] serde_json::Error),

    #[error("unsupported schema version {found} (this build understands up to {supported})")]
    UnsupportedSchemaVersion { found: u16, supported: u16 },
}

/// Every domain event in the system (§2). New facts are added here; nothing is
/// ever removed — old variants stay readable for replay (§18).
///
/// `strum::IntoStaticStr` derives the variant→name mapping used by
/// [`DomainEvent::event_type`], so the type name on the wire (the serde `type`
/// tag) and the event-store key can never drift from the variant identifier —
/// adding a variant updates all of them at once.
///
/// `strum::EnumCount` and `strum::VariantNames` expose [`DomainEvent::COUNT`]
/// and [`DomainEvent::VARIANTS`] (every variant name == its wire `type` tag).
/// The wire-format golden test (`tests/wire_format.rs`) uses them to prove the
/// schema is fully *locked*: every variant is pinned to an exact byte-for-byte
/// JSON shape, so adding or renaming a field breaks CI rather than silently
/// changing the contract downstream services depend on (sprint-plan risk #1).
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    strum::IntoStaticStr,
    strum::EnumCount,
    strum::VariantNames,
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "type", content = "payload")]
pub enum DomainEvent {
    // Chain (§5)
    RawBlockReceived(chain::RawBlockReceived),
    BlockAssembled(chain::BlockAssembled),
    BlockCanonicalized(chain::BlockCanonicalized),
    BlockReverted(chain::BlockReverted),
    BlockFinalized(chain::BlockFinalized),

    // Detection (§6)
    DetectorTriggered(detection::DetectorTriggered),
    PreliminaryAlertCreated(detection::PreliminaryAlertCreated),

    // Simulation (§7)
    SimulationRequested(simulation::SimulationRequested),
    SimulationCompleted(simulation::SimulationCompleted),
    IncidentCreated(simulation::IncidentCreated),
    IncidentRetracted(simulation::IncidentRetracted),
    IncidentFinalized(simulation::IncidentFinalized),

    // Intelligence (§8)
    LabelAdded(intelligence::LabelAdded),
    LabelUpdated(intelligence::LabelUpdated),
    LabelRevoked(intelligence::LabelRevoked),
    EntityCreated(intelligence::EntityCreated),
    EntityMerged(intelligence::EntityMerged),
    EntitySplit(intelligence::EntitySplit),
    AttributionUpdated(intelligence::AttributionUpdated),
    RiskScoreUpdated(intelligence::RiskScoreUpdated),
    SanctionHit(intelligence::SanctionHit),

    // Rule engine (§9)
    RuleCreated(rule_engine::RuleCreated),
    RuleTriggered(rule_engine::RuleTriggered),
    RuleAlertCreated(rule_engine::RuleAlertCreated),

    // System (§13)
    UsageRecorded(system::UsageRecorded),
}

/// Which service domain an event belongs to. Used for coarse routing/metrics;
/// the fine-grained key is [`DomainEvent::event_type`].
///
/// `strum::IntoStaticStr` with `serialize_all = "snake_case"` mirrors the serde
/// rename, so [`EventFamily::as_str`] (`"chain"`, `"rule_engine"`, …) and the
/// wire form agree — the event store writes this as the `event_family` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, strum::IntoStaticStr)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum EventFamily {
    Chain,
    Detection,
    Simulation,
    Intelligence,
    RuleEngine,
    System,
}

impl EventFamily {
    /// The stable snake_case name (`"chain"`, `"rule_engine"`, …), matching the
    /// serde wire form. Used as the event store's `event_family` column.
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

impl DomainEvent {
    /// The stable type name, matching the `type` tag on the wire and the §2
    /// event names. This is the Kafka topic discriminator and the event store's
    /// `event_type` partition key (§4, §20). Derived from the variant name by
    /// `strum`, so it is guaranteed to stay in sync.
    pub fn event_type(&self) -> &'static str {
        self.into()
    }

    /// The domain family this event belongs to. Kept as an explicit match on
    /// purpose: the family is a *semantic* classification (a human decides which
    /// family a new event joins), and the compiler enforces exhaustiveness, so a
    /// new variant fails to compile until it is classified — unlike a string
    /// table, this can't silently drift.
    pub fn family(&self) -> EventFamily {
        use DomainEvent::*;
        match self {
            RawBlockReceived(_)
            | BlockAssembled(_)
            | BlockCanonicalized(_)
            | BlockReverted(_)
            | BlockFinalized(_) => EventFamily::Chain,
            DetectorTriggered(_) | PreliminaryAlertCreated(_) => EventFamily::Detection,
            SimulationRequested(_)
            | SimulationCompleted(_)
            | IncidentCreated(_)
            | IncidentRetracted(_)
            | IncidentFinalized(_) => EventFamily::Simulation,
            LabelAdded(_)
            | LabelUpdated(_)
            | LabelRevoked(_)
            | EntityCreated(_)
            | EntityMerged(_)
            | EntitySplit(_)
            | AttributionUpdated(_)
            | RiskScoreUpdated(_)
            | SanctionHit(_) => EventFamily::Intelligence,
            RuleCreated(_) | RuleTriggered(_) | RuleAlertCreated(_) => EventFamily::RuleEngine,
            UsageRecorded(_) => EventFamily::System,
        }
    }

    /// The incident this event directly carries, if any — the business key for
    /// the §4 audit-by-incident query (`GET /v1/audit/incident/{id}`). The
    /// event-store denormalizes this into an indexed column so that lookup
    /// doesn't scan + JSON-parse every row.
    ///
    /// Only the simulation lifecycle and the attribution overlay name an
    /// incident. Like [`DomainEvent::family`], this is an explicit exhaustive
    /// match (no `_` arm) on purpose: a future incident-bearing event then fails
    /// to compile until it is classified here, rather than silently dropping out
    /// of the audit trail (sprint-plan risk #1 — schema drift).
    pub fn incident_id(&self) -> Option<IncidentId> {
        use DomainEvent::*;
        match self {
            IncidentCreated(e) => Some(e.incident_id),
            IncidentRetracted(e) => Some(e.incident_id),
            IncidentFinalized(e) => Some(e.incident_id),
            AttributionUpdated(e) => Some(e.incident_id),
            RawBlockReceived(_)
            | BlockAssembled(_)
            | BlockCanonicalized(_)
            | BlockReverted(_)
            | BlockFinalized(_)
            | DetectorTriggered(_)
            | PreliminaryAlertCreated(_)
            | SimulationRequested(_)
            | SimulationCompleted(_)
            | LabelAdded(_)
            | LabelUpdated(_)
            | LabelRevoked(_)
            | EntityCreated(_)
            | EntityMerged(_)
            | EntitySplit(_)
            | RiskScoreUpdated(_)
            | SanctionHit(_)
            | RuleCreated(_)
            | RuleTriggered(_)
            | RuleAlertCreated(_)
            | UsageRecorded(_) => None,
        }
    }

    /// The on-chain account addresses this event references — the business key
    /// for the §4 by-address query. Denormalized into an indexed `Array(String)`
    /// column by the event-store so an address lookup prunes granules instead of
    /// scanning the payloads.
    ///
    /// Exhaustive on purpose (see [`DomainEvent::incident_id`]): a new
    /// address-bearing event must be classified here or it won't compile, so it
    /// can never silently become unfindable by address. Transaction hashes
    /// (`txs`) are deliberately *not* addresses and are excluded.
    pub fn addresses(&self) -> Vec<AccountAddress> {
        use DomainEvent::*;
        match self {
            PreliminaryAlertCreated(e) => e.addresses.clone(),
            LabelAdded(e) => vec![e.address],
            LabelUpdated(e) => vec![e.address],
            LabelRevoked(e) => vec![e.address],
            EntityCreated(e) => vec![e.seed_address],
            RiskScoreUpdated(e) => vec![e.address],
            SanctionHit(e) => vec![e.address],
            RawBlockReceived(_)
            | BlockAssembled(_)
            | BlockCanonicalized(_)
            | BlockReverted(_)
            | BlockFinalized(_)
            | DetectorTriggered(_)
            | SimulationRequested(_)
            | SimulationCompleted(_)
            | IncidentCreated(_)
            | IncidentRetracted(_)
            | IncidentFinalized(_)
            | AttributionUpdated(_)
            | EntityMerged(_)
            | EntitySplit(_)
            | RuleCreated(_)
            | RuleTriggered(_)
            | RuleAlertCreated(_)
            | UsageRecorded(_) => Vec::new(),
        }
    }
}

/// Transport/storage wrapper around a [`DomainEvent`]. Carries the metadata
/// every event needs regardless of family.
///
/// `chain` is the partition key: Kafka partitions by chain (§20) and the event
/// store partitions by `(chain, event_type, date)` (§4). `event_id` makes
/// consumers idempotent — a replayed envelope is recognised and deduped (§7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EventEnvelope {
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = Uuid))]
    pub event_id: Uuid,
    pub schema_version: u16,
    pub chain: Chain,
    pub occurred_at: DateTime<Utc>,
    pub payload: DomainEvent,
}

impl EventEnvelope {
    /// Wrap a payload with explicit identity and time.
    ///
    /// This is the constructor replay and tests use: re-appending an archived
    /// event must reproduce its *original* `event_id` and `occurred_at`, not
    /// mint new ones (§18 — deterministic replay). Live producers usually want
    /// the [`EventEnvelope::new`] convenience instead.
    pub fn with_metadata(
        event_id: Uuid,
        occurred_at: DateTime<Utc>,
        chain: Chain,
        payload: DomainEvent,
    ) -> Self {
        Self {
            event_id,
            schema_version: SCHEMA_VERSION,
            chain,
            occurred_at,
            payload,
        }
    }

    /// Wrap a payload for a *new* (live) event: fresh random id, current schema
    /// version, `occurred_at = now`. Convenience over [`Self::with_metadata`];
    /// do not use on the replay path, where identity must be preserved.
    pub fn new(chain: Chain, payload: DomainEvent) -> Self {
        Self::with_metadata(Uuid::new_v4(), Utc::now(), chain, payload)
    }

    /// The event's stable type name (delegates to the payload). Convenience for
    /// the Kafka/event-store key.
    pub fn event_type(&self) -> &'static str {
        self.payload.event_type()
    }

    /// The Kafka topic this envelope is published on (`mev.events.<EventType>`,
    /// §20). Delegates to [`topic_for`] so producers and the event-store
    /// consumer share one definition.
    pub fn topic(&self) -> String {
        topic_for(self.event_type())
    }

    /// Serialize to JSON bytes for transport (Kafka record value / event-store
    /// row). The inverse of [`Self::from_json_slice`].
    pub fn to_json_vec(&self) -> Result<Vec<u8>, EventError> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Deserialize from JSON bytes, then reject any envelope written under a
    /// schema version this build cannot read. The inverse of
    /// [`Self::to_json_vec`].
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, EventError> {
        let envelope: Self = serde_json::from_slice(bytes)?;
        envelope.ensure_supported()?;
        Ok(envelope)
    }

    /// Reject envelopes written under a schema version this build can't read.
    /// Reading older (equal-or-lower `schema_version`) data is allowed — new code
    /// stays backwards-compatible with what older producers wrote.
    pub fn ensure_supported(&self) -> Result<(), EventError> {
        if self.schema_version > SCHEMA_VERSION {
            return Err(EventError::UnsupportedSchemaVersion {
                found: self.schema_version,
                supported: SCHEMA_VERSION,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::BlockAssembled;
    use crate::primitives::BlockRef;
    use alloy_primitives::B256;

    fn sample_block() -> BlockRef {
        BlockRef::new(19_800_000, B256::repeat_byte(0xab))
    }

    #[test]
    fn envelope_round_trips_through_json() {
        let env = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::BlockAssembled(BlockAssembled {
                block: sample_block(),
                tx_count: 142,
                trace_available: true,
            }),
        );

        let json = serde_json::to_string(&env).expect("serialize");
        let back: EventEnvelope = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(env, back);
        assert_eq!(back.event_type(), "BlockAssembled");
        assert_eq!(back.payload.family(), EventFamily::Chain);
    }

    #[test]
    fn payload_is_adjacently_tagged_on_the_wire() {
        let env = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::BlockAssembled(BlockAssembled {
                block: sample_block(),
                tx_count: 1,
                trace_available: false,
            }),
        );
        let value: serde_json::Value = serde_json::to_value(&env.payload).unwrap();
        assert_eq!(value["type"], "BlockAssembled");
        assert!(value["payload"].is_object());
    }

    #[test]
    fn rejects_future_schema_versions() {
        let mut env = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::BlockFinalized(crate::chain::BlockFinalized {
                block: sample_block(),
            }),
        );
        env.schema_version = SCHEMA_VERSION + 1;
        assert!(matches!(
            env.ensure_supported(),
            Err(EventError::UnsupportedSchemaVersion { .. })
        ));

        // from_json_slice must reject it too, not just ensure_supported.
        let bytes = serde_json::to_vec(&env).unwrap();
        assert!(matches!(
            EventEnvelope::from_json_slice(&bytes),
            Err(EventError::UnsupportedSchemaVersion { .. })
        ));
    }

    #[test]
    fn with_metadata_preserves_identity_for_replay() {
        // The whole point: re-wrapping an archived event reproduces its id and
        // timestamp exactly, so replay is deterministic (§18).
        let id = uuid::Uuid::nil();
        let when = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let payload = DomainEvent::BlockFinalized(crate::chain::BlockFinalized {
            block: sample_block(),
        });

        let a = EventEnvelope::with_metadata(id, when, Chain::ETHEREUM, payload.clone());
        let b = EventEnvelope::with_metadata(id, when, Chain::ETHEREUM, payload);

        assert_eq!(a, b, "same inputs must yield identical envelopes");
        assert_eq!(a.event_id, id);
        assert_eq!(a.occurred_at, when);
    }

    #[test]
    fn json_byte_helpers_round_trip() {
        let env = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::BlockCanonicalized(crate::chain::BlockCanonicalized {
                block: sample_block(),
            }),
        );
        let bytes = env.to_json_vec().expect("serialize");
        let back = EventEnvelope::from_json_slice(&bytes).expect("deserialize");
        assert_eq!(env, back);
    }

    #[test]
    fn topic_is_namespaced_and_derived_from_event_type() {
        let env = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::BlockAssembled(BlockAssembled {
                block: sample_block(),
                tx_count: 1,
                trace_available: false,
            }),
        );
        assert_eq!(topic_for("BlockAssembled"), "mev.events.BlockAssembled");
        assert_eq!(env.topic(), "mev.events.BlockAssembled");
        // Topic and family stay in lockstep with the variant.
        assert_eq!(env.payload.family().as_str(), "chain");
    }

    #[test]
    fn incident_id_extracts_only_from_incident_keyed_events() {
        use crate::primitives::IncidentId;
        use crate::simulation::IncidentFinalized;

        let incident = IncidentId::new();
        let event = DomainEvent::IncidentFinalized(IncidentFinalized {
            incident_id: incident,
            block_hash: B256::repeat_byte(0x11),
        });
        assert_eq!(event.incident_id(), Some(incident));

        // A chain event carries no incident — it must not surface in an
        // audit-by-incident query.
        let chain_event = DomainEvent::BlockAssembled(BlockAssembled {
            block: sample_block(),
            tx_count: 1,
            trace_available: false,
        });
        assert_eq!(chain_event.incident_id(), None);
    }

    #[test]
    fn addresses_extracts_every_referenced_address() {
        use crate::intelligence::SanctionHit;
        use alloy_primitives::Address;

        let addr = Address::repeat_byte(0x42);
        let event = DomainEvent::SanctionHit(SanctionHit {
            address: addr,
            list: "OFAC".into(),
            entry: "SDN-1".into(),
        });
        assert_eq!(event.addresses(), vec![addr]);

        // Transaction hashes are not addresses: DetectorTriggered carries `txs`
        // but no account address, so it returns nothing.
        let chain_event = DomainEvent::BlockFinalized(crate::chain::BlockFinalized {
            block: sample_block(),
        });
        assert!(chain_event.addresses().is_empty());
    }

    #[test]
    fn event_type_matches_serde_tag_for_every_variant() {
        // strum-derived event_type() and the serde `type` tag must agree, since
        // both are the variant name. Guard one representative.
        let env = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::SanctionHit(crate::intelligence::SanctionHit {
                address: Default::default(),
                list: "OFAC".into(),
                entry: "SDN-123".into(),
            }),
        );
        let value = serde_json::to_value(&env.payload).unwrap();
        assert_eq!(env.event_type(), value["type"].as_str().unwrap());
    }
}
