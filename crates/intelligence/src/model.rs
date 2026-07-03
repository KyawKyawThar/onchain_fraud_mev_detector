//! Intelligence domain types (§8) — the rows the three stores persist, parsed
//! at the boundary so the core never re-validates ("parse, don't validate").
//!
//! These are the *storage-layer* shapes. The wire events ([`events::intelligence`])
//! deliberately carry `kind`/`source` as plain strings; this module owns the
//! closed enums and their derive-driven wire strings (the same
//! `strum(serialize_all)` + `serde(rename_all)` pairing as
//! [`AlertKind`](events::primitives::AlertKind), so the stored string and the
//! serde form can never drift apart).

use alloy_primitives::Address;
use chrono::{DateTime, Utc};
use events::primitives::{AccountAddress, Confidence, EntityId, IncidentId, LabelId};
use serde::{Deserialize, Serialize};

/// Render an address the way every intelligence store keys it: lowercase
/// 0x-hex. One function so Postgres rows, Redis keys and ClickHouse columns can
/// never disagree on the encoding.
pub fn address_key(address: &AccountAddress) -> String {
    format!("{address:#x}")
}

/// A stored/keyed address failed to parse back into the domain type — a
/// corrupt row, permanent for that value (retrying re-reads the same bytes).
#[derive(Debug, thiserror::Error)]
#[error("address {raw:?} is not 0x-hex")]
pub struct AddressKeyError {
    pub raw: String,
}

/// The inverse of [`address_key`]: parse a stored address back into the domain
/// type. Kept beside its encoder so the pair round-trips by construction (the
/// property test below pins it over the whole address space).
pub fn parse_address_key(raw: &str) -> Result<AccountAddress, AddressKeyError> {
    raw.parse().map_err(|_| AddressKeyError {
        raw: raw.to_owned(),
    })
}

/// What a label claims about an address (§8.1). A closed enum — a new kind is a
/// compile error at every `match` — with the snake_case wire/storage string
/// derive-driven.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    strum::IntoStaticStr,
    strum::EnumString,
    strum::EnumIter,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum LabelKind {
    CexWallet,
    MevBot,
    KnownScammer,
    Bridge,
    Protocol,
    Deployer,
    MixerUser,
    SanctionedEntity,
    /// Derived by association: clusters with a known scammer (§8.1), at reduced
    /// confidence.
    ScammerAssociate,
    BuilderAddress,
}

/// Where a label came from — the provenance *class* (§8.1). The specific origin
/// within the class (which feed, which heuristic, which operator) travels in
/// [`LabelRecord::source_detail`].
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    strum::IntoStaticStr,
    strum::EnumString,
    strum::EnumIter,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum LabelSource {
    /// Operator curation via the manual API.
    Manual,
    /// Auto-labeling: builder feeRecipient, code-hash match, funding cluster.
    Heuristic,
    /// Public feeds: Etherscan tags, OFAC SDN, community MEV lists, registries.
    ExternalFeed,
    /// Derived from entity clustering (the flywheel, §8.6) — e.g.
    /// [`LabelKind::ScammerAssociate`].
    EntityDerived,
}

impl LabelSource {
    /// The §8.1 default confidence per provenance class:
    /// `1.0 manual | 0.7 heuristic | 0.4 external feed`. Entity-derived labels
    /// inherit the reduced heuristic band — association is a signal, not proof.
    pub fn default_confidence(self) -> Confidence {
        match self {
            LabelSource::Manual => Confidence::new(1.0),
            LabelSource::Heuristic => Confidence::new(0.7),
            LabelSource::ExternalFeed => Confidence::new(0.4),
            LabelSource::EntityDerived => Confidence::new(0.5),
        }
    }
}

/// One wallet label with full provenance (§8.1). Conflicting labels for an
/// address coexist as separate records — a manual label outranks a heuristic
/// one at *read* time (by `source`/`confidence`), never by overwrite.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LabelRecord {
    /// Stable identity: the idempotency key for redelivered `LabelAdded`s and
    /// the reference `LabelUpdated`/`LabelRevoked` events carry.
    pub label_id: LabelId,
    pub address: AccountAddress,
    pub kind: LabelKind,
    pub value: String,
    pub confidence: Confidence,
    pub source: LabelSource,
    /// The specific origin within [`source`](Self::source): `'etherscan'`,
    /// `'ofac_sdn'`, `'funding-cluster-v1'`, an operator id — the audit trail.
    pub source_detail: String,
    pub created_at: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
}

impl LabelRecord {
    /// A label with the source's §8.1 default confidence, valid indefinitely.
    pub fn new(
        address: AccountAddress,
        kind: LabelKind,
        value: impl Into<String>,
        source: LabelSource,
        source_detail: impl Into<String>,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            label_id: LabelId::new(),
            address,
            kind,
            value: value.into(),
            confidence: source.default_confidence(),
            source,
            source_detail: source_detail.into(),
            created_at,
            valid_until: None,
        }
    }
}

/// An entity's lifecycle (§8.2). An absorbed entity is a tombstone pointing at
/// its survivor — never deleted, so historical attributions stay resolvable.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    strum::IntoStaticStr,
    strum::EnumString,
    strum::EnumIter,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum EntityStatus {
    Active,
    Absorbed,
}

/// A wallet cluster (§8.2), versioned: `version` increments on every
/// merge/split so downstream projections (risk scores, rule engine) detect
/// staleness without diffing membership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityRecord {
    pub entity_id: EntityId,
    pub version: u64,
    pub status: EntityStatus,
    /// The survivor this entity merged into, once [`EntityStatus::Absorbed`].
    pub absorbed_into: Option<EntityId>,
    /// Current membership. An address belongs to at most one active entity — a
    /// merge *moves* membership to the survivor transactionally.
    pub addresses: Vec<AccountAddress>,
    pub created_at: DateTime<Utc>,
}

/// One attribution link: this incident is the work of this entity, with the
/// evidence that says so (§8). Keyed `(incident_id, entity_id)`, so re-running
/// attribution on a redelivered `IncidentCreated` is an idempotent upsert.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttributionRecord {
    pub incident_id: IncidentId,
    pub entity_id: EntityId,
    /// How sure attribution is of *this link* (independent of any risk score —
    /// the two-axes rule, §8.3).
    pub confidence: Confidence,
    /// Evidence ref (label id, cluster edge, sim run) making the link auditable.
    pub evidence: String,
    pub attributed_at: DateTime<Utc>,
}

/// One sanctions-list designation (§8.5). Keyed `(address, list_name)` so a
/// refreshed feed re-import is an idempotent upsert; a match emits `SanctionHit`
/// immediately — the hard alert that bypasses the slow path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanctionEntry {
    pub address: AccountAddress,
    /// Which list designated it (`'ofac_sdn'`, `'eu_consolidated'`, …).
    pub list_name: String,
    /// The list's own entry (SDN name / programme), echoed into `SanctionHit`.
    pub entry: String,
    /// When the list designated the address (from the feed), if known.
    pub listed_at: Option<DateTime<Utc>>,
}

/// The clustering signal an adjacency edge records (§8.2). These are the §8.2
/// heuristics as *graph facts*: A funded B, A deployed B, A received B's
/// profit, A interacted with B.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    strum::IntoStaticStr,
    strum::EnumString,
    strum::EnumIter,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum EdgeKind {
    Funded,
    Deployed,
    ProfitReceiver,
    Interacted,
}

/// One directed edge of the address graph — an immutable observation appended
/// to the ClickHouse adjacency store (§8.2, §14). `evidence` is the tx hash (or
/// evidence ref) that witnessed the relation; edges are never updated, a
/// contradicting observation is simply a later row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdjacencyEdge {
    pub chain: events::primitives::Chain,
    pub src: AccountAddress,
    pub dst: AccountAddress,
    pub kind: EdgeKind,
    pub evidence: String,
    pub block_number: u64,
    pub observed_at: DateTime<Utc>,
}

/// A degree-capped neighborhood read (§8.2 — critical). `capped` says the walk
/// hit the hub-node cap: the address connects to *more* neighbors than
/// returned, so a graph walk must treat it as an infrastructure endpoint and
/// stop, not recurse — otherwise a CEX hot wallet collapses the graph into
/// noise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighborhood {
    pub neighbors: Vec<Address>,
    pub capped: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::str::FromStr;
    use strum::IntoEnumIterator;

    /// For every variant of a storage enum: the stored string (strum) must
    /// equal the serde wire form, and must parse back to the same variant.
    /// `EnumIter` makes this exhaustive by construction — a newly added
    /// variant is covered automatically instead of silently missing from a
    /// hand-maintained list.
    fn assert_storage_string_round_trips<T>()
    where
        T: IntoEnumIterator + serde::Serialize + FromStr + PartialEq + Copy + std::fmt::Debug,
        &'static str: From<T>,
    {
        for variant in T::iter() {
            let stored = <&'static str>::from(variant);
            assert_eq!(
                serde_json::to_string(&variant).unwrap(),
                format!("\"{stored}\""),
                "stored string and serde wire form must agree"
            );
            match stored.parse::<T>() {
                Ok(back) => assert_eq!(back, variant, "FromStr must invert IntoStaticStr"),
                Err(_) => panic!("stored string {stored:?} failed to parse back"),
            }
        }
    }

    #[test]
    fn every_storage_enum_round_trips_its_strings() {
        assert_storage_string_round_trips::<LabelKind>();
        assert_storage_string_round_trips::<LabelSource>();
        assert_storage_string_round_trips::<EntityStatus>();
        assert_storage_string_round_trips::<EdgeKind>();
    }

    #[test]
    fn unknown_storage_strings_are_rejected() {
        assert!("not_a_kind".parse::<LabelKind>().is_err());
        assert!("not_a_source".parse::<LabelSource>().is_err());
        assert!("not_a_status".parse::<EntityStatus>().is_err());
        assert!("not_an_edge".parse::<EdgeKind>().is_err());
    }

    #[test]
    fn address_key_is_lowercase_0x_hex() {
        let addr = Address::repeat_byte(0xAB);
        assert_eq!(
            address_key(&addr),
            "0xabababababababababababababababababababab"
        );
    }

    #[test]
    fn parse_address_key_rejects_garbage() {
        assert!(parse_address_key("0xnothex").is_err());
        assert!(parse_address_key("").is_err());
    }

    proptest! {
        /// The encoder/decoder pair is a bijection over the entire address
        /// space — no address can be stored that fails to read back (§18's
        /// round-trip discipline, applied to the storage key).
        #[test]
        fn address_key_round_trips(bytes in proptest::array::uniform20(any::<u8>())) {
            let addr = Address::from(bytes);
            prop_assert_eq!(parse_address_key(&address_key(&addr)).unwrap(), addr);
        }
    }

    /// §8.1 pins the confidence bands per provenance class.
    #[test]
    fn label_sources_carry_their_default_confidence() {
        assert_eq!(LabelSource::Manual.default_confidence().get(), 1.0);
        assert_eq!(LabelSource::Heuristic.default_confidence().get(), 0.7);
        assert_eq!(LabelSource::ExternalFeed.default_confidence().get(), 0.4);
        assert_eq!(LabelSource::EntityDerived.default_confidence().get(), 0.5);
    }

    #[test]
    fn label_record_new_fills_provenance_defaults() {
        let addr = Address::repeat_byte(0x01);
        let at = DateTime::<Utc>::from_timestamp(1_000, 0).unwrap();
        let label = LabelRecord::new(
            addr,
            LabelKind::MevBot,
            "jaredfromsubway.eth",
            LabelSource::ExternalFeed,
            "community_mev_list",
            at,
        );
        assert_eq!(label.confidence.get(), 0.4);
        assert_eq!(label.valid_until, None);
        assert_eq!(label.created_at, at);
    }
}
