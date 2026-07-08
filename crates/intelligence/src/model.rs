//! Intelligence domain types (§8) — the rows the three stores persist, parsed
//! at the boundary so the core never re-validates ("parse, don't validate").
//!
//! These are the *storage-layer* shapes. The wire events ([`events::intelligence`])
//! deliberately carry `kind`/`source` as plain strings; this module owns the
//! closed enums and their derive-driven wire strings (the same
//! `strum(serialize_all)` + `serde(rename_all)` pairing as
//! [`AlertKind`](events::primitives::AlertKind), so the stored string and the
//! serde form can never drift apart).

use std::collections::BTreeSet;

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
/// A split entity is likewise a tombstone, but with no single successor — its
/// former members now belong to the fresh entities the split created.
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
    /// Split back apart (§8.2) — an operator's reversal of an earlier,
    /// incorrect merge. Never re-activated.
    Split,
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

/// Stable identity for one [`MergeLogEntry`] row — the reorg-rollback join
/// key (§15). Crate-local, unlike `EntityId`/`IncidentId`/`LabelId`: a merge
/// log entry never crosses the wire (no event carries it, it only ever
/// travels between [`crate::store::EntityStore::absorb`],
/// [`crate::store::EntityStore::merges_for_incident`] and
/// [`crate::store::EntityStore::reverse_merge`]), so it deliberately skips
/// `Serialize`/`Deserialize` rather than carrying unused wire machinery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MergeId(pub uuid::Uuid);

impl MergeId {
    /// Mint a fresh random id.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

impl Default for MergeId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for MergeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One [`crate::store::EntityStore::absorb`] merge, logged so a later
/// `IncidentRetracted` can find and reverse it (§8.2, §15). `moved_addresses`
/// is exactly what `absorb` moved from `absorbed_id` to `surviving_id` — the
/// precise partition [`crate::store::EntityStore::reverse_merge`] hands back
/// to `split`. `incident_id` is `None` for operator-driven clustering (the
/// `intelligence cluster` CLI has no incident to name); such merges are never
/// candidates for reorg rollback (nothing names them for it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeLogEntry {
    pub merge_id: MergeId,
    pub surviving_id: EntityId,
    pub absorbed_id: EntityId,
    pub incident_id: Option<IncidentId>,
    pub evidence_ref: String,
    pub moved_addresses: Vec<AccountAddress>,
    pub merged_at: DateTime<Utc>,
    /// Set once a reversal has applied this entry — an idempotency guard
    /// against re-retracting the same incident twice.
    pub reverted_at: Option<DateTime<Utc>>,
}

/// Why an [`crate::store::EntityStore::reverse_merge`] attempt can't proceed
/// (§15). A closed enum rather than a free-text reason — callers (and tests)
/// match on *which* guard tripped instead of grepping a message; [`Display`](std::fmt::Display)
/// still gives the human-readable form for logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnreversibleReason {
    /// The survivor is no longer an active entity — it was itself absorbed
    /// or split since the original merge.
    SurvivorInactive,
    /// One or more of the merge's `moved_addresses` no longer belong to the
    /// survivor — a later merge or split moved them.
    AddressesMoved,
    /// The survivor has no members left over once the moved addresses are
    /// set aside — reversing would leave nothing behind.
    NoRemainingMembers,
    /// Defensive: [`plan_reversal`] found a valid split, but the store-level
    /// `split` rejected it anyway. Should be unreachable given the entity
    /// lock held since before the membership read — refusing loudly here is
    /// safer than assuming why it happened.
    SplitRejected,
}

impl std::fmt::Display for UnreversibleReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::SurvivorInactive => "survivor is no longer an active entity",
            Self::AddressesMoved => {
                "one or more merged addresses no longer belong to the survivor \
                 (a later merge or split moved them)"
            }
            Self::NoRemainingMembers => {
                "the survivor has no members left over — reversing would leave nothing behind"
            }
            Self::SplitRejected => {
                "splitting the survivor to reverse the merge was unexpectedly rejected by the store"
            }
        })
    }
}

/// What [`plan_reversal`] decided — the pure half of
/// [`crate::store::EntityStore::reverse_merge`], split out from the I/O (the
/// entity/membership reads) so it's testable with plain `BTreeSet`s, the same
/// "find root"/`plan_merge` discipline [`crate::cluster`] uses for the
/// forward merge decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReversalPlan {
    /// Split the survivor's current membership into exactly these two
    /// groups — hand straight to [`crate::store::EntityStore::split`].
    Split {
        moved: Vec<AccountAddress>,
        remaining: Vec<AccountAddress>,
    },
    Unreversible(UnreversibleReason),
}

/// Decide whether/how to reverse a merge, given the survivor's current
/// activeness and membership plus what the original merge moved. Pure: the
/// same inputs always yield the same plan, so a redelivered retraction
/// converges rather than re-litigating the decision.
pub fn plan_reversal(
    survivor_active: bool,
    current_members: &BTreeSet<AccountAddress>,
    moved_addresses: &BTreeSet<AccountAddress>,
) -> ReversalPlan {
    if !survivor_active {
        return ReversalPlan::Unreversible(UnreversibleReason::SurvivorInactive);
    }
    if !moved_addresses.is_subset(current_members) {
        return ReversalPlan::Unreversible(UnreversibleReason::AddressesMoved);
    }
    let remaining: BTreeSet<AccountAddress> = current_members
        .difference(moved_addresses)
        .copied()
        .collect();
    if remaining.is_empty() {
        return ReversalPlan::Unreversible(UnreversibleReason::NoRemainingMembers);
    }
    ReversalPlan::Split {
        moved: moved_addresses.iter().copied().collect(),
        remaining: remaining.into_iter().collect(),
    }
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
/// profit, A and B share deployed bytecode, A interacted with B.
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
    /// Two contract addresses were deployed with identical bytecode — the
    /// §8.2 "same code hash" heuristic as a graph fact between the two sites
    /// (recorded by whichever deploy-observing consumer notices the match).
    SameCodeHash,
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

    // ── plan_reversal: the pure merge-reversal decision ──────────────
    // No store, no doubles, no `async` — mirrors `cluster::plan_merge`'s tests.

    fn addr(byte: u8) -> AccountAddress {
        Address::repeat_byte(byte)
    }

    #[test]
    fn plan_reversal_splits_moved_addresses_from_the_remainder() {
        let current = BTreeSet::from([addr(1), addr(2), addr(3)]);
        let moved = BTreeSet::from([addr(2)]);

        let plan = plan_reversal(true, &current, &moved);
        assert_eq!(
            plan,
            ReversalPlan::Split {
                moved: vec![addr(2)],
                remaining: vec![addr(1), addr(3)],
            }
        );
    }

    #[test]
    fn plan_reversal_is_unreversible_when_survivor_is_inactive() {
        let current = BTreeSet::from([addr(1), addr(2)]);
        let moved = BTreeSet::from([addr(2)]);

        assert_eq!(
            plan_reversal(false, &current, &moved),
            ReversalPlan::Unreversible(UnreversibleReason::SurvivorInactive)
        );
    }

    #[test]
    fn plan_reversal_is_unreversible_when_a_moved_address_left_the_survivor() {
        let current = BTreeSet::from([addr(1)]);
        // addr(2) was moved by the original merge but no longer belongs to
        // the survivor — a later merge/split touched it.
        let moved = BTreeSet::from([addr(2)]);

        assert_eq!(
            plan_reversal(true, &current, &moved),
            ReversalPlan::Unreversible(UnreversibleReason::AddressesMoved)
        );
    }

    #[test]
    fn plan_reversal_is_unreversible_when_nothing_would_be_left_behind() {
        let current = BTreeSet::from([addr(1)]);
        let moved = BTreeSet::from([addr(1)]);

        assert_eq!(
            plan_reversal(true, &current, &moved),
            ReversalPlan::Unreversible(UnreversibleReason::NoRemainingMembers)
        );
    }

    #[test]
    fn plan_reversal_is_deterministic_regardless_of_set_construction_order() {
        let current_a = BTreeSet::from([addr(3), addr(1), addr(2)]);
        let current_b = BTreeSet::from([addr(1), addr(2), addr(3)]);
        let moved = BTreeSet::from([addr(1)]);

        assert_eq!(
            plan_reversal(true, &current_a, &moved),
            plan_reversal(true, &current_b, &moved)
        );
    }

    #[test]
    fn merge_id_displays_as_its_uuid() {
        let id = MergeId(uuid::Uuid::from_u128(0xAB));
        assert_eq!(id.to_string(), "00000000-0000-0000-0000-0000000000ab");
    }
}
