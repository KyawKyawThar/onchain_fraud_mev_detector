//! In-memory doubles for the three store seams (§8, §14) — the zero-
//! infrastructure implementations the t2–t5 consumers (and this crate's own
//! tests) run against, mirroring `simulation::test_util`.
//!
//! Each double honours the *semantics* the Postgres/Redis/ClickHouse
//! implementations promise (idempotent keyed writes, membership invariant,
//! evict-on-update, degree cap) so a test that passes here means the consumer
//! logic is right; the `#[ignore]` integration tests prove the real stores
//! honour the same contract.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::primitives::{AccountAddress, Chain, EntityId, IncidentId, LabelId};

use crate::adjacency::{AdjacencyStore, GraphError};
use crate::cache::{CacheError, CachedScore, CachedScreeningFacts, HotCache};
use crate::model::{
    plan_reversal, AddressEdge, AdjacencyEdge, AttributionRecord, EdgeHistory, EntityRecord,
    EntityStatus, LabelRecord, MergeId, MergeLogEntry, Neighborhood, ReversalPlan, SanctionEntry,
};
use crate::store::{
    AttributionStore, CreateOutcome, EntityStore, LabelStore, LinkOutcome, MergeOutcome,
    ReversalOutcome, SanctionsStore, SplitOutcome, StoreError,
};

/// In-memory implementation of all four Postgres seams.
#[derive(Default)]
pub struct InMemoryIntelligenceStore {
    inner: Mutex<StoreState>,
}

#[derive(Default)]
struct StoreState {
    labels: Vec<LabelRecord>,
    revoked: HashSet<LabelId>,
    entities: HashMap<EntityId, EntityMeta>,
    /// The membership invariant: an address belongs to at most one entity.
    memberships: HashMap<AccountAddress, EntityId>,
    attributions: HashMap<(IncidentId, EntityId), AttributionRecord>,
    sanctions: HashMap<(AccountAddress, String), SanctionEntry>,
    /// The merge log (§15) — one entry per `absorb` call, mirroring the
    /// `entity_merges` table.
    merges: Vec<MergeLogEntry>,
}

struct EntityMeta {
    version: u64,
    status: EntityStatus,
    absorbed_into: Option<EntityId>,
    created_at: DateTime<Utc>,
}

impl InMemoryIntelligenceStore {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Bundle one shared [`InMemoryIntelligenceStore`] into a [`crate::store::StoreSeams`]
/// — every consumer test (`attribution`, `risk_scorer`, `reorg`) needs all
/// four seams pointed at the same double; [`crate::store::StoreSeams::single`]
/// is the one place that assembly happens, shared with production wiring.
pub fn store_seams(store: &Arc<InMemoryIntelligenceStore>) -> crate::store::StoreSeams {
    crate::store::StoreSeams::single(store.clone())
}

#[async_trait]
impl LabelStore for InMemoryIntelligenceStore {
    async fn add_label(&self, label: &LabelRecord) -> Result<bool, StoreError> {
        let mut state = self.inner.lock().expect("store lock");
        if state.labels.iter().any(|l| l.label_id == label.label_id) {
            return Ok(false);
        }
        state.labels.push(label.clone());
        Ok(true)
    }

    async fn labels_for(
        &self,
        address: &AccountAddress,
        as_of: DateTime<Utc>,
    ) -> Result<Vec<LabelRecord>, StoreError> {
        let state = self.inner.lock().expect("store lock");
        Ok(state
            .labels
            .iter()
            .filter(|l| {
                l.address == *address
                    && !state.revoked.contains(&l.label_id)
                    && l.created_at <= as_of
                    && l.valid_until.is_none_or(|until| until > as_of)
            })
            .cloned()
            .collect())
    }

    async fn revoke_label(
        &self,
        label_id: LabelId,
        _reason: &str,
        _at: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        let mut state = self.inner.lock().expect("store lock");
        if !state.labels.iter().any(|l| l.label_id == label_id) {
            return Ok(false);
        }
        Ok(state.revoked.insert(label_id))
    }

    async fn label(&self, label_id: LabelId) -> Result<Option<LabelRecord>, StoreError> {
        let state = self.inner.lock().expect("store lock");
        Ok(state
            .labels
            .iter()
            .find(|l| l.label_id == label_id)
            .cloned())
    }

    async fn update_label_value(
        &self,
        label_id: LabelId,
        new_value: &str,
    ) -> Result<Option<LabelRecord>, StoreError> {
        let mut state = self.inner.lock().expect("store lock");
        if state.revoked.contains(&label_id) {
            return Ok(None);
        }
        let Some(label) = state.labels.iter_mut().find(|l| l.label_id == label_id) else {
            return Ok(None);
        };
        let before = label.clone();
        label.value = new_value.to_owned();
        Ok(Some(before))
    }
}

#[async_trait]
impl EntityStore for InMemoryIntelligenceStore {
    async fn create_entity(
        &self,
        entity_id: EntityId,
        seed: &AccountAddress,
        _evidence: &str,
        at: DateTime<Utc>,
    ) -> Result<CreateOutcome, StoreError> {
        let mut state = self.inner.lock().expect("store lock");
        if state.entities.contains_key(&entity_id) {
            return Ok(CreateOutcome::AlreadyExists);
        }
        if let Some(owner) = state.memberships.get(seed) {
            return Ok(CreateOutcome::SeedOwnedBy(*owner));
        }
        state.entities.insert(
            entity_id,
            EntityMeta {
                version: 1,
                status: EntityStatus::Active,
                absorbed_into: None,
                created_at: at,
            },
        );
        state.memberships.insert(*seed, entity_id);
        Ok(CreateOutcome::Created)
    }

    async fn link_address(
        &self,
        entity_id: EntityId,
        address: &AccountAddress,
        _evidence: &str,
        _at: DateTime<Utc>,
    ) -> Result<LinkOutcome, StoreError> {
        let mut state = self.inner.lock().expect("store lock");
        match state.entities.get(&entity_id) {
            Some(meta) if meta.status == EntityStatus::Active => {}
            _ => return Ok(LinkOutcome::TargetInactive),
        }
        match state.memberships.get(address) {
            Some(owner) if *owner == entity_id => Ok(LinkOutcome::AlreadyMember),
            Some(owner) => Ok(LinkOutcome::OwnedBy(*owner)),
            None => {
                state.memberships.insert(*address, entity_id);
                Ok(LinkOutcome::Linked)
            }
        }
    }

    async fn entity(&self, entity_id: EntityId) -> Result<Option<EntityRecord>, StoreError> {
        let state = self.inner.lock().expect("store lock");
        let Some(meta) = state.entities.get(&entity_id) else {
            return Ok(None);
        };
        let mut addresses: Vec<AccountAddress> = state
            .memberships
            .iter()
            .filter(|(_, owner)| **owner == entity_id)
            .map(|(addr, _)| *addr)
            .collect();
        addresses.sort();
        Ok(Some(EntityRecord {
            entity_id,
            version: meta.version,
            status: meta.status,
            absorbed_into: meta.absorbed_into,
            addresses,
            created_at: meta.created_at,
        }))
    }

    async fn entity_for_address(
        &self,
        address: &AccountAddress,
    ) -> Result<Option<EntityId>, StoreError> {
        let state = self.inner.lock().expect("store lock");
        Ok(state.memberships.get(address).copied())
    }

    async fn absorb(
        &self,
        surviving: EntityId,
        absorbed: EntityId,
        incident_id: Option<IncidentId>,
        evidence_ref: &str,
        at: DateTime<Utc>,
    ) -> Result<MergeOutcome, StoreError> {
        if surviving == absorbed {
            return Ok(MergeOutcome::SelfMerge);
        }
        let mut state = self.inner.lock().expect("store lock");
        match state.entities.get(&absorbed) {
            Some(meta) if meta.status == EntityStatus::Active => {}
            _ => return Ok(MergeOutcome::AbsorbedInactive),
        }
        match state.entities.get(&surviving) {
            Some(meta) if meta.status == EntityStatus::Active => {}
            _ => return Ok(MergeOutcome::SurvivorInactive),
        }

        // Capture exactly which addresses are about to move, for the merge
        // log — mirrors the Postgres impl reading this before the UPDATE.
        let mut moved_addresses: Vec<AccountAddress> = state
            .memberships
            .iter()
            .filter(|(_, owner)| **owner == absorbed)
            .map(|(addr, _)| *addr)
            .collect();
        moved_addresses.sort();

        let absorbed_meta = state.entities.get_mut(&absorbed).expect("checked above");
        absorbed_meta.status = EntityStatus::Absorbed;
        absorbed_meta.absorbed_into = Some(surviving);
        absorbed_meta.version += 1;

        for owner in state.memberships.values_mut() {
            if *owner == absorbed {
                *owner = surviving;
            }
        }

        let survivor_meta = state.entities.get_mut(&surviving).expect("checked above");
        survivor_meta.version += 1;
        let survivor_version = survivor_meta.version;

        state.merges.push(MergeLogEntry {
            merge_id: MergeId::new(),
            surviving_id: surviving,
            absorbed_id: absorbed,
            incident_id,
            evidence_ref: evidence_ref.to_owned(),
            moved_addresses,
            merged_at: at,
            reverted_at: None,
        });

        Ok(MergeOutcome::Merged { survivor_version })
    }

    async fn split(
        &self,
        entity_id: EntityId,
        groups: &[Vec<AccountAddress>],
        _evidence: &str,
        at: DateTime<Utc>,
    ) -> Result<SplitOutcome, StoreError> {
        let mut state = self.inner.lock().expect("store lock");
        Ok(split_locked(&mut state, entity_id, groups, at))
    }

    async fn merges_for_incident(
        &self,
        incident_id: IncidentId,
    ) -> Result<Vec<MergeLogEntry>, StoreError> {
        let state = self.inner.lock().expect("store lock");
        Ok(state
            .merges
            .iter()
            .filter(|m| m.incident_id == Some(incident_id) && m.reverted_at.is_none())
            .cloned()
            .collect())
    }

    async fn reverse_merge(
        &self,
        merge_id: MergeId,
        at: DateTime<Utc>,
    ) -> Result<ReversalOutcome, StoreError> {
        let mut state = self.inner.lock().expect("store lock");
        let Some(index) = state.merges.iter().position(|m| m.merge_id == merge_id) else {
            return Ok(ReversalOutcome::AlreadyReverted);
        };
        if state.merges[index].reverted_at.is_some() {
            return Ok(ReversalOutcome::AlreadyReverted);
        }
        let surviving = state.merges[index].surviving_id;
        let moved: BTreeSet<AccountAddress> = state.merges[index]
            .moved_addresses
            .iter()
            .copied()
            .collect();

        let is_active = matches!(
            state.entities.get(&surviving),
            Some(meta) if meta.status == EntityStatus::Active
        );
        let current: BTreeSet<AccountAddress> = state
            .memberships
            .iter()
            .filter(|(_, owner)| **owner == surviving)
            .map(|(addr, _)| *addr)
            .collect();

        let (moved_group, remaining_group) = match plan_reversal(is_active, &current, &moved) {
            ReversalPlan::Unreversible(reason) => return Ok(ReversalOutcome::Unreversible(reason)),
            ReversalPlan::Split { moved, remaining } => (moved, remaining),
        };
        let groups = [moved_group, remaining_group];

        let outcome = split_locked(&mut state, surviving, &groups, at);
        let SplitOutcome::Split { new_ids } = outcome else {
            // `plan_reversal` just confirmed this partition is valid against
            // the membership read above — this is defensive, not expected.
            return Ok(ReversalOutcome::Unreversible(
                crate::model::UnreversibleReason::SplitRejected,
            ));
        };
        let [split_id, continuing_id] = new_ids[..] else {
            unreachable!("split_locked was called with exactly two groups");
        };

        state.merges[index].reverted_at = Some(at);

        Ok(ReversalOutcome::Reversed {
            split_id,
            continuing_id,
        })
    }
}

/// The guts of [`EntityStore::split`], operating on an already-locked
/// [`StoreState`] so [`InMemoryIntelligenceStore::reverse_merge`] can share it
/// — mirrors the Postgres double's `split_within_tx`.
fn split_locked(
    state: &mut StoreState,
    entity_id: EntityId,
    groups: &[Vec<AccountAddress>],
    at: DateTime<Utc>,
) -> SplitOutcome {
    match state.entities.get(&entity_id) {
        Some(meta) if meta.status == EntityStatus::Active => {}
        _ => return SplitOutcome::NotActive,
    }

    let current: BTreeSet<AccountAddress> = state
        .memberships
        .iter()
        .filter(|(_, owner)| **owner == entity_id)
        .map(|(addr, _)| *addr)
        .collect();

    let mut proposed: BTreeSet<AccountAddress> = BTreeSet::new();
    for group in groups {
        if group.is_empty() {
            return SplitOutcome::Invalid;
        }
        for address in group {
            if !proposed.insert(*address) {
                return SplitOutcome::Invalid;
            }
        }
    }
    if proposed != current {
        return SplitOutcome::Invalid;
    }

    let meta = state.entities.get_mut(&entity_id).expect("checked above");
    meta.status = EntityStatus::Split;
    meta.version += 1;

    let mut new_ids = Vec::with_capacity(groups.len());
    for group in groups {
        let new_id = EntityId::new();
        state.entities.insert(
            new_id,
            EntityMeta {
                version: 1,
                status: EntityStatus::Active,
                absorbed_into: None,
                created_at: at,
            },
        );
        for address in group {
            state.memberships.insert(*address, new_id);
        }
        new_ids.push(new_id);
    }

    SplitOutcome::Split { new_ids }
}

#[async_trait]
impl AttributionStore for InMemoryIntelligenceStore {
    async fn record_attribution(&self, attribution: &AttributionRecord) -> Result<(), StoreError> {
        let mut state = self.inner.lock().expect("store lock");
        state.attributions.insert(
            (attribution.incident_id, attribution.entity_id),
            attribution.clone(),
        );
        Ok(())
    }

    async fn attributions_for_incident(
        &self,
        incident_id: IncidentId,
    ) -> Result<Vec<AttributionRecord>, StoreError> {
        let state = self.inner.lock().expect("store lock");
        Ok(state
            .attributions
            .values()
            .filter(|a| a.incident_id == incident_id)
            .cloned()
            .collect())
    }

    async fn attributions_for_entity(
        &self,
        entity_id: EntityId,
    ) -> Result<Vec<AttributionRecord>, StoreError> {
        let state = self.inner.lock().expect("store lock");
        Ok(state
            .attributions
            .values()
            .filter(|a| a.entity_id == entity_id)
            .cloned()
            .collect())
    }

    async fn retract_attributions_for_incident(
        &self,
        incident_id: IncidentId,
    ) -> Result<Vec<EntityId>, StoreError> {
        let mut state = self.inner.lock().expect("store lock");
        let entity_ids: Vec<EntityId> = state
            .attributions
            .keys()
            .filter(|(inc, _)| *inc == incident_id)
            .map(|(_, entity_id)| *entity_id)
            .collect();
        for entity_id in &entity_ids {
            state.attributions.remove(&(incident_id, *entity_id));
        }
        Ok(entity_ids)
    }
}

#[async_trait]
impl SanctionsStore for InMemoryIntelligenceStore {
    async fn seed_sanctions(&self, entries: &[SanctionEntry]) -> Result<u64, StoreError> {
        let mut state = self.inner.lock().expect("store lock");
        for entry in entries {
            state
                .sanctions
                .insert((entry.address, entry.list_name.clone()), entry.clone());
        }
        Ok(entries.len() as u64)
    }

    async fn sanction_matches(
        &self,
        address: &AccountAddress,
    ) -> Result<Vec<SanctionEntry>, StoreError> {
        let state = self.inner.lock().expect("store lock");
        let mut matches: Vec<SanctionEntry> = state
            .sanctions
            .values()
            .filter(|e| e.address == *address)
            .cloned()
            .collect();
        matches.sort_by(|a, b| a.list_name.cmp(&b.list_name));
        Ok(matches)
    }
}

/// In-memory [`HotCache`]. TTLs are not simulated — the double tests the
/// *eviction* semantics (the correctness path); the TTL backstop belongs to
/// the real Redis and its integration test.
#[derive(Default)]
pub struct InMemoryHotCache {
    inner: Mutex<CacheState>,
}

#[derive(Default)]
struct CacheState {
    labels: HashMap<AccountAddress, Vec<LabelRecord>>,
    scores: HashMap<(AccountAddress, String), CachedScore>,
    screening: HashMap<AccountAddress, CachedScreeningFacts>,
}

impl InMemoryHotCache {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl HotCache for InMemoryHotCache {
    async fn labels(
        &self,
        address: &AccountAddress,
    ) -> Result<Option<Vec<LabelRecord>>, CacheError> {
        let state = self.inner.lock().expect("cache lock");
        Ok(state.labels.get(address).cloned())
    }

    async fn put_labels(
        &self,
        address: &AccountAddress,
        labels: &[LabelRecord],
    ) -> Result<(), CacheError> {
        let mut state = self.inner.lock().expect("cache lock");
        state.labels.insert(*address, labels.to_vec());
        Ok(())
    }

    async fn score(
        &self,
        address: &AccountAddress,
        model_version: &str,
    ) -> Result<Option<CachedScore>, CacheError> {
        let state = self.inner.lock().expect("cache lock");
        Ok(state
            .scores
            .get(&(*address, model_version.to_owned()))
            .cloned())
    }

    async fn put_score(
        &self,
        address: &AccountAddress,
        score: &CachedScore,
    ) -> Result<(), CacheError> {
        let mut state = self.inner.lock().expect("cache lock");
        state
            .scores
            .insert((*address, score.model_version.clone()), score.clone());
        Ok(())
    }

    async fn screening_facts(
        &self,
        address: &AccountAddress,
    ) -> Result<Option<CachedScreeningFacts>, CacheError> {
        let state = self.inner.lock().expect("cache lock");
        Ok(state.screening.get(address).cloned())
    }

    async fn put_screening_facts(
        &self,
        address: &AccountAddress,
        facts: &CachedScreeningFacts,
    ) -> Result<(), CacheError> {
        let mut state = self.inner.lock().expect("cache lock");
        state.screening.insert(*address, facts.clone());
        Ok(())
    }

    async fn evict(&self, address: &AccountAddress) -> Result<(), CacheError> {
        let mut state = self.inner.lock().expect("cache lock");
        state.labels.remove(address);
        state.scores.retain(|(addr, _), _| addr != address);
        state.screening.remove(address);
        Ok(())
    }
}

/// In-memory [`AdjacencyStore`], honouring the degree cap and the undirected
/// neighborhood read.
#[derive(Default)]
pub struct InMemoryAdjacency {
    edges: Mutex<Vec<AdjacencyEdge>>,
}

impl InMemoryAdjacency {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AdjacencyStore for InMemoryAdjacency {
    async fn append(&self, new_edges: &[AdjacencyEdge]) -> Result<(), GraphError> {
        let mut edges = self.edges.lock().expect("graph lock");
        edges.extend_from_slice(new_edges);
        Ok(())
    }

    async fn neighbors(
        &self,
        chain: Chain,
        address: &AccountAddress,
        cap: u32,
    ) -> Result<Neighborhood, GraphError> {
        let edges = self.edges.lock().expect("graph lock");
        let mut set = BTreeSet::new();
        for edge in edges.iter().filter(|e| e.chain == chain) {
            if edge.src == *address {
                set.insert(edge.dst);
            } else if edge.dst == *address {
                set.insert(edge.src);
            }
        }
        let capped = set.len() > cap as usize;
        Ok(Neighborhood {
            neighbors: set.into_iter().take(cap as usize).collect(),
            capped,
        })
    }

    async fn degree(&self, chain: Chain, address: &AccountAddress) -> Result<u64, GraphError> {
        let edges = self.edges.lock().expect("graph lock");
        let mut set = BTreeSet::new();
        for edge in edges.iter().filter(|e| e.chain == chain) {
            if edge.src == *address {
                set.insert(edge.dst);
            } else if edge.dst == *address {
                set.insert(edge.src);
            }
        }
        Ok(set.len() as u64)
    }

    async fn clustering_neighbors(
        &self,
        chain: Chain,
        address: &AccountAddress,
        kinds: &[crate::model::EdgeKind],
        cap: u32,
    ) -> Result<Neighborhood, GraphError> {
        let edges = self.edges.lock().expect("graph lock");
        let mut set = BTreeSet::new();
        for edge in edges
            .iter()
            .filter(|e| e.chain == chain && kinds.contains(&e.kind))
        {
            if edge.src == *address {
                set.insert(edge.dst);
            } else if edge.dst == *address {
                set.insert(edge.src);
            }
        }
        let capped = set.len() > cap as usize;
        Ok(Neighborhood {
            neighbors: set.into_iter().take(cap as usize).collect(),
            capped,
        })
    }

    /// Mirrors the ClickHouse query's contract exactly: subject-relative,
    /// de-duplicated by whole observation, most recent first with the same
    /// tie-breakers, and `truncated` when more existed than the cap.
    async fn edge_history(
        &self,
        chain: Chain,
        address: &AccountAddress,
        cap: u32,
    ) -> Result<EdgeHistory, GraphError> {
        let edges = self.edges.lock().expect("graph lock");
        // De-duplicate on the full observation (evidence included) the same way
        // the store's `SELECT DISTINCT` does, so a re-appended edge is one
        // observation here too — otherwise a double would let a bug through
        // that production collapses.
        // A `HashSet` rather than a `BTreeSet`: `EdgeKind` is `Hash` but
        // deliberately not `Ord` (its variants have no ranking), and inventing
        // one here just to de-duplicate would be a meaning the enum doesn't
        // have.
        let mut seen = HashSet::new();
        let mut history: Vec<AddressEdge> = Vec::new();
        for edge in edges.iter().filter(|e| e.chain == chain) {
            let outbound = if edge.src == *address {
                true
            } else if edge.dst == *address {
                false
            } else {
                continue;
            };
            let key = (
                if outbound { edge.dst } else { edge.src },
                edge.kind,
                outbound,
                edge.evidence.clone(),
                edge.block_number,
                edge.observed_at,
            );
            if !seen.insert(key) {
                continue;
            }
            history.push(AddressEdge {
                counterparty: if outbound { edge.dst } else { edge.src },
                kind: edge.kind,
                outbound,
                block_number: edge.block_number,
                observed_at: edge.observed_at,
            });
        }
        history.sort_by(|a, b| {
            b.observed_at
                .cmp(&a.observed_at)
                .then_with(|| b.block_number.cmp(&a.block_number))
                .then_with(|| a.counterparty.cmp(&b.counterparty))
                .then_with(|| <&str>::from(a.kind).cmp(<&str>::from(b.kind)))
                .then_with(|| b.outbound.cmp(&a.outbound))
        });
        let truncated = history.len() > cap as usize;
        history.truncate(cap as usize);
        Ok(EdgeHistory {
            edges: history,
            truncated,
        })
    }

    async fn active_addresses(
        &self,
        chain: Chain,
        since: DateTime<Utc>,
        after: Option<AccountAddress>,
        limit: u32,
        shard: crate::adjacency::Shard,
    ) -> Result<Vec<AccountAddress>, GraphError> {
        let edges = self.edges.lock().expect("graph lock");
        let mut set = BTreeSet::new();
        for edge in edges
            .iter()
            .filter(|e| e.chain == chain && e.observed_at >= since)
        {
            set.insert(edge.src);
            set.insert(edge.dst);
        }
        Ok(set
            .into_iter()
            .filter(|address| after.is_none_or(|cursor| *address > cursor))
            .filter(|address| shard_contains(shard, address))
            .take(limit as usize)
            .collect())
    }
}

/// Stand-in for the ClickHouse `cityHash64(address) % total = index` predicate.
///
/// A double cannot reproduce ClickHouse's hash, and pretending otherwise would
/// make a sharded test assert against a partition production doesn't use. What
/// *is* reproducible — and is what the sharding contract actually promises — is
/// that the shards **partition** the keyspace: every address lands in exactly
/// one, and their union is the whole set. So the double uses its own stable
/// hash and the tests assert that partition property, not which specific shard
/// an address falls in.
fn shard_contains(shard: crate::adjacency::Shard, address: &AccountAddress) -> bool {
    if shard.is_single() {
        return true;
    }
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    address.hash(&mut hasher);
    (hasher.finish() % u64::from(shard.total())) == u64::from(shard.index())
}

// ── Behavior-embedding double (§20.3, Sprint 19 t1) ──────────────────────────

use crate::embedding::baseline::BehaviorBaseline;
use crate::embedding::BehaviorVector;
use crate::embedding_store::{
    CachedNeighbors, EmbeddingRow, EmbeddingStore, EmbeddingStoreError, NeighborsRow,
    StoredEmbedding,
};

/// [`EmbeddingStore`] double: an append-only log of everything written, plus a
/// transient-failure toggle for retry tests.
///
/// `latest` answers off the same log rather than a second map, so the double
/// cannot disagree with itself about what was written — and it round-trips
/// each vector through [`EmbeddingRow`] on the way out, so an encoding bug
/// (a factor blob that doesn't decode, an entity id that doesn't parse) fails
/// in a unit test instead of only against a live ClickHouse.
#[derive(Default)]
pub struct RecordingEmbeddingStore {
    appended: Mutex<Vec<(Chain, BehaviorVector)>>,
    baselines: Mutex<Vec<(Chain, BehaviorBaseline)>>,
    /// Materialized neighbour rankings, keyed like the real table.
    neighbors: Mutex<HashMap<(u64, String, String), CachedNeighbors>>,
    fail_next: Mutex<bool>,
}

impl RecordingEmbeddingStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything appended so far, in write order.
    pub fn appended(&self) -> Vec<BehaviorVector> {
        self.appended
            .lock()
            .expect("embedding lock")
            .iter()
            .map(|(_, vector)| vector.clone())
            .collect()
    }

    /// Make the next `append` fail transiently.
    pub fn fail_next(&self) {
        *self.fail_next.lock().expect("embedding lock") = true;
    }

    /// How many neighbour rankings have been materialized — lets a test prove
    /// a cache hit did no write, and a miss did exactly one.
    pub fn materialized_count(&self) -> usize {
        self.neighbors.lock().expect("embedding lock").len()
    }
}

#[async_trait]
impl EmbeddingStore for RecordingEmbeddingStore {
    async fn append(
        &self,
        chain: Chain,
        vectors: &[BehaviorVector],
    ) -> Result<(), EmbeddingStoreError> {
        let mut fail = self.fail_next.lock().expect("embedding lock");
        if *fail {
            *fail = false;
            return Err(EmbeddingStoreError::Clickhouse(
                clickhouse::error::Error::Custom("injected".into()),
            ));
        }
        let mut appended = self.appended.lock().expect("embedding lock");
        for vector in vectors {
            appended.push((chain, vector.clone()));
        }
        Ok(())
    }

    async fn latest(
        &self,
        chain: Chain,
        address: &AccountAddress,
        embedding_version: &str,
    ) -> Result<Option<StoredEmbedding>, EmbeddingStoreError> {
        let appended = self.appended.lock().expect("embedding lock");
        let latest = appended
            .iter()
            .filter(|(stored_chain, vector)| {
                *stored_chain == chain
                    && vector.address == *address
                    && vector.embedding_version() == embedding_version
            })
            .max_by_key(|(_, vector)| vector.computed_at);
        latest
            .map(|(chain, vector)| {
                StoredEmbedding::try_from(EmbeddingRow::from_vector(*chain, vector))
            })
            .transpose()
    }

    async fn nearest_candidates(
        &self,
        chain: Chain,
        embedding_version: &str,
        query: &[f32],
        exclude: &AccountAddress,
        limit: usize,
    ) -> Result<Vec<StoredEmbedding>, EmbeddingStoreError> {
        // Brute-force raw cosine over everything appended — the *exact* answer
        // the ClickHouse read approximates. Deliberately: a double that only
        // promised the same shape would let a ranking bug hide behind "well,
        // it's approximate". Rows are returned uncollapsed, superseded ones
        // included, because collapsing them here would hide the caller's
        // latest-wins rule from every unit test that uses this double.
        let appended = self.appended.lock().expect("embedding lock");
        let mut scored: Vec<(f64, StoredEmbedding)> = Vec::new();
        for (stored_chain, vector) in appended.iter() {
            if *stored_chain != chain
                || vector.embedding_version() != embedding_version
                || vector.address == *exclude
            {
                continue;
            }
            let stored = StoredEmbedding::try_from(EmbeddingRow::from_vector(chain, vector))?;
            scored.push((cosine_distance(query, &stored.values), stored));
        }
        // Nearest first, ties broken by address so the shortlist is stable.
        scored.sort_by(|a, b| {
            a.0.partial_cmp(&b.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.1.address.cmp(&b.1.address))
        });
        Ok(scored
            .into_iter()
            .take(limit)
            .map(|(_, stored)| stored)
            .collect())
    }

    async fn cached_neighbors(
        &self,
        chain: Chain,
        address: &AccountAddress,
        embedding_version: &str,
    ) -> Result<Option<CachedNeighbors>, EmbeddingStoreError> {
        let key = (
            chain.id(),
            crate::model::address_key(address),
            embedding_version.to_owned(),
        );
        let stored = self
            .neighbors
            .lock()
            .expect("embedding lock")
            .get(&key)
            .cloned();
        // Round-tripped through the row form so an encoding bug surfaces in a
        // unit test rather than only against a real ClickHouse — the same
        // stance the vector double takes.
        stored
            .map(|entry| CachedNeighbors::try_from(NeighborsRow::from_entry(chain, &entry)))
            .transpose()
    }

    async fn put_neighbors(
        &self,
        chain: Chain,
        entry: &CachedNeighbors,
    ) -> Result<(), EmbeddingStoreError> {
        let key = (
            chain.id(),
            crate::model::address_key(&entry.address),
            entry.embedding_version.clone(),
        );
        self.neighbors
            .lock()
            .expect("embedding lock")
            .insert(key, entry.clone());
        Ok(())
    }

    async fn sample_vectors(
        &self,
        chain: Chain,
        embedding_version: &str,
        limit: u32,
    ) -> Result<Vec<Vec<f32>>, EmbeddingStoreError> {
        use std::collections::BTreeMap;

        // Latest per address, then a deterministic address-ordered prefix —
        // the same collapse-then-bound the ClickHouse read performs.
        let appended = self.appended.lock().expect("embedding lock");
        let mut latest: BTreeMap<AccountAddress, &BehaviorVector> = BTreeMap::new();
        for (stored_chain, vector) in appended.iter() {
            if *stored_chain != chain || vector.embedding_version() != embedding_version {
                continue;
            }
            latest
                .entry(vector.address)
                .and_modify(|current| {
                    if vector.computed_at >= current.computed_at {
                        *current = vector;
                    }
                })
                .or_insert(vector);
        }
        Ok(latest
            .into_values()
            .take(limit as usize)
            .map(|vector| vector.values.clone())
            .collect())
    }

    async fn put_baseline(
        &self,
        chain: Chain,
        baseline: &BehaviorBaseline,
    ) -> Result<(), EmbeddingStoreError> {
        self.baselines
            .lock()
            .expect("embedding lock")
            .push((chain, baseline.clone()));
        Ok(())
    }

    async fn latest_baseline(
        &self,
        chain: Chain,
        embedding_version: &str,
    ) -> Result<Option<BehaviorBaseline>, EmbeddingStoreError> {
        Ok(self
            .baselines
            .lock()
            .expect("embedding lock")
            .iter()
            .filter(|(stored_chain, baseline)| {
                *stored_chain == chain && baseline.embedding_version == embedding_version
            })
            .max_by_key(|(_, baseline)| baseline.computed_at)
            .map(|(_, baseline)| baseline.clone()))
    }
}

/// ClickHouse's `cosineDistance` (`1 - cos`), for the double's brute-force
/// shortlist. A zero-norm operand yields `NaN` there too — kept faithful
/// rather than clamped, so the caller's own zero-vector guard is what tests
/// exercise, not a kindness the real store does not perform.
fn cosine_distance(a: &[f32], b: &[f32]) -> f64 {
    let dot: f64 = a
        .iter()
        .zip(b.iter())
        .map(|(x, y)| f64::from(*x) * f64::from(*y))
        .sum();
    let norm = |v: &[f32]| -> f64 {
        v.iter()
            .map(|x| f64::from(*x) * f64::from(*x))
            .sum::<f64>()
            .sqrt()
    };
    1.0 - dot / (norm(a) * norm(b))
}

// ── Clustering-signal doubles (§20.3, Sprint 19 t3) ──────────────────────────

use crate::link_candidate::{
    canonical_pair, Decision, LinkCandidateStore, LinkStatus, Proposal, ProposalOutcome, StoredLink,
};
use events::primitives::LinkCandidateId;

/// In-memory [`LinkCandidateStore`]. Honours the four semantics the Postgres
/// impl promises — keyed by the deterministic `candidate_id`, a refresh that
/// re-scores an open proposal, a **decided** proposal left untouched, and an
/// unannounced row that still owes its event — so a consumer test that passes
/// here means the idempotency *and* the crash-recovery argument hold, not just
/// the happy path.
#[derive(Default)]
pub struct InMemoryLinkCandidateStore {
    inner: Mutex<HashMap<LinkCandidateId, StoredLink>>,
}

impl InMemoryLinkCandidateStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// How many proposals are stored — the "one row, not two" assertion.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("link lock").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every stored proposal, strongest first.
    pub fn all(&self) -> Vec<StoredLink> {
        let mut all: Vec<StoredLink> = self
            .inner
            .lock()
            .expect("link lock")
            .values()
            .cloned()
            .collect();
        sort_strongest_first(&mut all);
        all
    }

    /// Clear `announced_at` on every row — simulating the crash window: the
    /// proposal committed, the process died before the event went out. Lets a
    /// test drive the `ReAnnounce` path without a real crash.
    pub fn forget_announcements(&self) {
        for link in self.inner.lock().expect("link lock").values_mut() {
            link.announced_at = None;
        }
    }
}

fn sort_strongest_first(rows: &mut [StoredLink]) {
    rows.sort_by(|a, b| {
        b.similarity
            .partial_cmp(&a.similarity)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.candidate_id.0.cmp(&b.candidate_id.0))
    });
}

#[async_trait]
impl LinkCandidateStore for InMemoryLinkCandidateStore {
    async fn propose_link(&self, proposal: &Proposal) -> Result<ProposalOutcome, StoreError> {
        let mut stored = self.inner.lock().expect("link lock");
        match stored.get_mut(&proposal.candidate_id) {
            None => {
                // Canonicalized on the way in, like the table's CHECK
                // constraint — a double that accepted a mis-ordered pair would
                // let a bug through that Postgres would reject.
                let (a, b) = canonical_pair(&proposal.address_a, &proposal.address_b);
                assert_eq!(
                    (
                        crate::model::address_key(&proposal.address_a),
                        crate::model::address_key(&proposal.address_b)
                    ),
                    (a, b),
                    "candidate pair is not canonically ordered"
                );
                stored.insert(
                    proposal.candidate_id,
                    StoredLink {
                        proposal: proposal.clone(),
                        status: LinkStatus::Proposed,
                        decision: None,
                        announced_at: None,
                    },
                );
                Ok(ProposalOutcome::New)
            }
            Some(existing) if existing.status == LinkStatus::Proposed => {
                let owed = existing.announced_at.is_none();
                let announced_at = existing.announced_at;
                existing.proposal = Proposal {
                    // The claim is re-scored; its identity and first sighting
                    // are not (the Postgres upsert leaves `proposed_at` alone).
                    proposed_at: existing.proposal.proposed_at,
                    ..proposal.clone()
                };
                existing.announced_at = announced_at;
                Ok(if owed {
                    ProposalOutcome::ReAnnounce
                } else {
                    ProposalOutcome::Refreshed
                })
            }
            Some(_) => Ok(ProposalOutcome::Decided),
        }
    }

    async fn mark_announced(
        &self,
        id: LinkCandidateId,
        at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        if let Some(link) = self.inner.lock().expect("link lock").get_mut(&id) {
            link.announced_at = Some(at);
        }
        Ok(())
    }

    async fn unannounced_links(&self, limit: usize) -> Result<Vec<Proposal>, StoreError> {
        let mut rows: Vec<StoredLink> = self
            .inner
            .lock()
            .expect("link lock")
            .values()
            .filter(|row| row.announced_at.is_none())
            .cloned()
            .collect();
        rows.sort_by_key(|row| row.proposed_at);
        rows.truncate(limit);
        Ok(rows.into_iter().map(|row| row.proposal).collect())
    }

    async fn links_for_address(
        &self,
        address: &AccountAddress,
        limit: usize,
    ) -> Result<Vec<StoredLink>, StoreError> {
        let mut rows: Vec<StoredLink> = self
            .inner
            .lock()
            .expect("link lock")
            .values()
            .filter(|row| row.address_a == *address || row.address_b == *address)
            .cloned()
            .collect();
        sort_strongest_first(&mut rows);
        rows.truncate(limit);
        Ok(rows)
    }

    async fn link(&self, id: LinkCandidateId) -> Result<Option<StoredLink>, StoreError> {
        Ok(self.inner.lock().expect("link lock").get(&id).cloned())
    }

    async fn decide_link(
        &self,
        id: LinkCandidateId,
        status: LinkStatus,
        decision: &Decision,
    ) -> Result<Option<StoredLink>, StoreError> {
        let mut stored = self.inner.lock().expect("link lock");
        let Some(existing) = stored.get_mut(&id) else {
            return Ok(None);
        };
        let before = existing.clone();
        existing.status = status;
        existing.decision = Some(decision.clone());
        Ok(Some(before))
    }

    async fn open_links(&self, limit: usize) -> Result<Vec<StoredLink>, StoreError> {
        let mut rows: Vec<StoredLink> = self
            .inner
            .lock()
            .expect("link lock")
            .values()
            .filter(|row| row.status == LinkStatus::Proposed)
            .cloned()
            .collect();
        sort_strongest_first(&mut rows);
        rows.truncate(limit);
        Ok(rows)
    }
}

// ── Block-production doubles (§10, Sprint 11 t1) ─────────────────────────────

use alloy_primitives::B256;

use crate::production::{BlockProductionRecord, RelayAttribution};
use crate::production_source::{BlockFacts, BlockFactsSource, RelaySource, SourceFault};
use crate::production_store::{BlockProductionStore, ProductionStoreError};

/// [`BlockFactsSource`] double: a fixed `block hash → facts` map, plus a
/// transient-failure toggle for retry tests. An unmapped hash answers `None`
/// (the "node doesn't know it yet" case).
#[derive(Default)]
pub struct FixedBlockFacts {
    facts: Mutex<HashMap<B256, BlockFacts>>,
    fail_next: Mutex<bool>,
}

impl FixedBlockFacts {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, block_hash: B256, facts: BlockFacts) {
        self.facts
            .lock()
            .expect("facts lock")
            .insert(block_hash, facts);
    }

    /// Make the next `block_facts` call fail transiently (an RPC blip).
    pub fn fail_next(&self) {
        *self.fail_next.lock().expect("facts lock") = true;
    }
}

#[async_trait]
impl BlockFactsSource for FixedBlockFacts {
    async fn block_facts(
        &self,
        block: events::primitives::BlockRef,
    ) -> Result<Option<BlockFacts>, SourceFault> {
        if std::mem::take(&mut *self.fail_next.lock().expect("facts lock")) {
            return Err(SourceFault::Rpc("injected RPC blip".into()));
        }
        Ok(self
            .facts
            .lock()
            .expect("facts lock")
            .get(&block.hash)
            .cloned())
    }
}

/// [`RelaySource`] double: a fixed `block hash → attribution` map; an unmapped
/// hash means no configured relay delivered it.
#[derive(Default)]
pub struct FixedRelaySource {
    attributions: Mutex<HashMap<B256, RelayAttribution>>,
}

impl FixedRelaySource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, block_hash: B256, attribution: RelayAttribution) {
        self.attributions
            .lock()
            .expect("relay lock")
            .insert(block_hash, attribution);
    }
}

#[async_trait]
impl RelaySource for FixedRelaySource {
    async fn attribution_for(
        &self,
        block: events::primitives::BlockRef,
    ) -> Option<RelayAttribution> {
        self.attributions
            .lock()
            .expect("relay lock")
            .get(&block.hash)
            .cloned()
    }
}

/// [`BlockProductionStore`] double: records every appended snapshot in order,
/// with a transient-failure toggle so tests can prove the pending-writes queue
/// survives a failed flush.
#[derive(Default)]
pub struct RecordingProductionStore {
    appended: Mutex<Vec<BlockProductionRecord>>,
    fail_next: Mutex<bool>,
}

impl RecordingProductionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every snapshot appended so far, in append order.
    pub fn appended(&self) -> Vec<BlockProductionRecord> {
        self.appended.lock().expect("store lock").clone()
    }

    /// Make the next `append` call fail transiently (a ClickHouse blip).
    pub fn fail_next(&self) {
        *self.fail_next.lock().expect("store lock") = true;
    }
}

#[async_trait]
impl BlockProductionStore for RecordingProductionStore {
    async fn append(
        &self,
        snapshots: &[BlockProductionRecord],
    ) -> Result<(), ProductionStoreError> {
        if std::mem::take(&mut *self.fail_next.lock().expect("store lock")) {
            return Err(ProductionStoreError::Clickhouse(
                clickhouse::error::Error::Custom("injected ClickHouse blip".into()),
            ));
        }
        self.appended
            .lock()
            .expect("store lock")
            .extend_from_slice(snapshots);
        Ok(())
    }
}

// ── Leaderboard double (§10, Sprint 11 t2) ───────────────────────────────────

use crate::leaderboard::{Leaderboard, LeaderboardError, LeaderboardQuery, LeaderboardStore};

/// [`LeaderboardStore`] double: returns a preset [`Leaderboard`] and records the
/// last query it was asked, so a gRPC test can assert the request mapping
/// without a live ClickHouse.
#[derive(Default)]
pub struct FixedLeaderboard {
    board: Mutex<Leaderboard>,
    last_query: Mutex<Option<LeaderboardQuery>>,
}

impl FixedLeaderboard {
    /// A double answering with `board` for every query.
    pub fn new(board: Leaderboard) -> Self {
        Self {
            board: Mutex::new(board),
            last_query: Mutex::new(None),
        }
    }

    /// The chain/limit/since of the most recent `leaderboard` call (for
    /// request-mapping assertions).
    pub fn last_query(&self) -> Option<LeaderboardQuery> {
        self.last_query.lock().expect("leaderboard lock").clone()
    }
}

#[async_trait]
impl LeaderboardStore for FixedLeaderboard {
    async fn leaderboard(&self, query: &LeaderboardQuery) -> Result<Leaderboard, LeaderboardError> {
        *self.last_query.lock().expect("leaderboard lock") = Some(query.clone());
        Ok(self.board.lock().expect("leaderboard lock").clone())
    }
}
