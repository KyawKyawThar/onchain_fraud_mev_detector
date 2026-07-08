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
use crate::cache::{CacheError, CachedScore, HotCache};
use crate::model::{
    AdjacencyEdge, AttributionRecord, EntityRecord, EntityStatus, LabelRecord, Neighborhood,
    SanctionEntry,
};
use crate::store::{
    AttributionStore, CreateOutcome, EntityStore, LabelStore, LinkOutcome, MergeOutcome,
    SanctionsStore, SplitOutcome, StoreError,
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
/// four times — every consumer test (`attribution`, `risk_scorer`) needs all
/// four seams pointed at the same double, so this is the one place that shape
/// is assembled.
pub fn store_seams(store: &Arc<InMemoryIntelligenceStore>) -> crate::store::StoreSeams {
    crate::store::StoreSeams {
        labels: store.clone(),
        entities: store.clone(),
        attributions: store.clone(),
        sanctions: store.clone(),
    }
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
        Ok(MergeOutcome::Merged {
            survivor_version: survivor_meta.version,
        })
    }

    async fn split(
        &self,
        entity_id: EntityId,
        groups: &[Vec<AccountAddress>],
        _evidence: &str,
        at: DateTime<Utc>,
    ) -> Result<SplitOutcome, StoreError> {
        let mut state = self.inner.lock().expect("store lock");
        match state.entities.get(&entity_id) {
            Some(meta) if meta.status == EntityStatus::Active => {}
            _ => return Ok(SplitOutcome::NotActive),
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
                return Ok(SplitOutcome::Invalid);
            }
            for address in group {
                if !proposed.insert(*address) {
                    return Ok(SplitOutcome::Invalid);
                }
            }
        }
        if proposed != current {
            return Ok(SplitOutcome::Invalid);
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

        Ok(SplitOutcome::Split { new_ids })
    }
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

    async fn evict(&self, address: &AccountAddress) -> Result<(), CacheError> {
        let mut state = self.inner.lock().expect("cache lock");
        state.labels.remove(address);
        state.scores.retain(|(addr, _), _| addr != address);
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
}
