//! Basic entity clustering (§8.2, Sprint 7 t3): groups addresses into one
//! [`EntityRecord`](crate::model::EntityRecord) using four graph facts already
//! recorded in the adjacency store — common funder, common deployer, shared
//! profit receiver, same deployed code hash ([`CLUSTER_EDGE_KINDS`]) — and
//! nothing else. `Interacted` edges are deliberately excluded: merely
//! transacting with an address is not evidence of common ownership (that
//! weaker signal belongs to the rule engine's hop-distance matcher, not
//! identity clustering, §9).
//!
//! **The hub-node degree cap is enforced at the point the walk decides
//! whether to cross a node** (§8.2 — critical): an address whose
//! cluster-relevant degree exceeds the cap is treated as an infrastructure
//! endpoint (a CEX hot wallet, a popular deployer factory, a bridge) and is
//! excluded from the cluster outright — not merely "not recursed through". If
//! a hub were included as a member, every address it ever funded/deployed
//! would collapse into one entity the first time two of them were clustered;
//! excluding it keeps it a boundary instead of a bridge. The walk is also
//! hop-bounded ([`ClusterLimits::max_hops`]) as an independent safety valve:
//! this is bounded, in-memory subgraph analysis — load, analyze, discard —
//! never an unbounded crawl of the whole graph.
//!
//! Once a bounded component is known, [`cluster_address`] applies it to the
//! [`EntityStore`] idempotently: existing entities among the component's
//! members are unified by absorbing every one but a deterministic survivor
//! (lowest [`EntityId`], stable across re-runs), and every still-unowned
//! member is linked to it. Re-running the same cluster pass is therefore a
//! no-op — the same at-least-once discipline as the rest of the service.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use chrono::{DateTime, Utc};
use event_bus::Transience;
use events::primitives::{AccountAddress, Chain, EntityId, IncidentId};

use crate::adjacency::{AdjacencyStore, GraphError};
use crate::merge_actor::{EntityGuard, MergeActorError, MergeActorHandle};
use crate::model::EdgeKind;
use crate::store::{CreateOutcome, EntityStore, LinkOutcome, MergeOutcome, StoreError};

/// The edge kinds strong enough to be an identity signal (§8.2's four
/// heuristics). `Interacted` is excluded on purpose — see the module docs.
pub const CLUSTER_EDGE_KINDS: &[EdgeKind] = &[
    EdgeKind::Funded,
    EdgeKind::Deployed,
    EdgeKind::ProfitReceiver,
    EdgeKind::SameCodeHash,
];

/// Degree cap and hop bound for one clustering walk (§8.2). §8.2 doesn't pin
/// exact numbers, so [`Default`] picks conservative ones: a genuine
/// personally-controlled cluster (a few funding/deploy wallets) sits well
/// under 25 cluster-relevant edges, while any real infrastructure endpoint
/// (CEX hot wallet, bridge, popular factory) clears it immediately.
#[derive(Debug, Clone, Copy)]
pub struct ClusterLimits {
    pub degree_cap: u32,
    pub max_hops: u32,
}

impl Default for ClusterLimits {
    fn default() -> Self {
        Self {
            degree_cap: 25,
            max_hops: 3,
        }
    }
}

/// A failure walking the graph or writing the resulting entity. Wraps the two
/// seam errors and forwards nothing new — callers already handle
/// [`GraphError`]/[`StoreError`]'s own retry-vs-skip classification.
#[derive(Debug, thiserror::Error)]
pub enum ClusterError {
    #[error(transparent)]
    Graph(#[from] GraphError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    MergeActor(#[from] MergeActorError),
}

impl Transience for ClusterError {
    /// Whether retrying the same pass could plausibly succeed — the shared
    /// retry/skip contract every store/graph error carries. A gone merge
    /// actor means the coordinator task died with the process (or is mid
    /// shutdown); a redelivered pass against a freshly booted process gets a
    /// fresh actor, so it's transient like the rest.
    fn is_transient(&self) -> bool {
        match self {
            ClusterError::Graph(err) => err.is_transient(),
            ClusterError::Store(err) => err.is_transient(),
            ClusterError::MergeActor(_) => true,
        }
    }
}

/// What one [`cluster_address`] pass did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterOutcome {
    /// The entity every component member now belongs to.
    pub entity_id: EntityId,
    /// Addresses newly linked to `entity_id` this run (already-members and
    /// the seed's own creation are excluded — this is the *delta*).
    pub linked: Vec<AccountAddress>,
    /// Other entities absorbed into `entity_id` to unify the component.
    pub absorbed: Vec<EntityId>,
    /// Addresses reachable from the seed but excluded from the component
    /// because their cluster-relevant degree exceeded the cap (§8.2) —
    /// infrastructure endpoints, not members.
    pub hubs: Vec<AccountAddress>,
    /// The address `entity_id` was freshly seeded from, if this pass *created*
    /// a new entity (`None` when the component already had an owner, or a
    /// concurrent writer raced the create — see [`CreateOutcome::SeedOwnedBy`]).
    /// The `IncidentCreated` attribution consumer (t4) uses this to know
    /// whether to emit `EntityCreated`.
    pub created_seed: Option<AccountAddress>,
}

/// A bounded, in-memory view of the graph around one seed (§8: "load 3-hop
/// neighborhood, analyze, discard").
struct Subgraph {
    members: BTreeSet<AccountAddress>,
    hubs: BTreeSet<AccountAddress>,
}

/// Walk outward from `seed` over [`CLUSTER_EDGE_KINDS`] only, stopping at any
/// node whose filtered degree exceeds `limits.degree_cap` or whose hop count
/// exceeds `limits.max_hops`. The returned `members` set is exactly the
/// connected component containing `seed` under these two bounds.
async fn bounded_component(
    graph: &dyn AdjacencyStore,
    chain: Chain,
    seed: AccountAddress,
    limits: ClusterLimits,
) -> Result<Subgraph, GraphError> {
    let mut members = BTreeSet::new();
    let mut hubs = BTreeSet::new();
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back((seed, 0u32));
    visited.insert(seed);

    while let Some((address, hop)) = queue.pop_front() {
        let neighborhood = graph
            .clustering_neighbors(chain, &address, CLUSTER_EDGE_KINDS, limits.degree_cap)
            .await?;
        if neighborhood.capped {
            // Infrastructure endpoint: a stop signal, not a member — crossing
            // it would bridge every address it ever touched into one entity.
            hubs.insert(address);
            continue;
        }
        members.insert(address);
        if hop >= limits.max_hops {
            continue;
        }
        for neighbor in neighborhood.neighbors {
            if visited.insert(neighbor) {
                queue.push_back((neighbor, hop + 1));
            }
        }
    }
    Ok(Subgraph { members, hubs })
}

/// How to unify a bounded component into one entity — the pure decision half
/// of [`cluster_address`], split out from the I/O that carries it out. This is
/// the "find root" step of a union-find, phrased as data instead of an
/// action, which is what makes it testable with plain values (no store, no
/// `async`).
#[derive(Debug, Clone, PartialEq, Eq)]
enum MergePlan {
    /// At least one member already belongs to an entity: `survivor` is the
    /// deterministic (lowest `EntityId`) pick among them; `absorb` are the
    /// other distinct entities that must merge into it.
    UseExisting {
        survivor: EntityId,
        absorb: Vec<EntityId>,
    },
    /// No member owns an entity yet: seed a fresh one at the lowest address
    /// (deterministic given `members`' `BTreeSet` order).
    CreateNew { seed: AccountAddress },
}

/// Decide how to unify `members` given which entity (if any) already owns
/// each. Pure: same inputs always yield the same plan, so a redelivered/
/// re-run cluster pass converges instead of re-litigating the survivor.
fn plan_merge(
    owners: &HashMap<AccountAddress, EntityId>,
    members: &BTreeSet<AccountAddress>,
) -> MergePlan {
    let mut distinct_ids: Vec<EntityId> = owners
        .values()
        .copied()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    // Deterministic across re-runs: `Uuid` (unlike `EntityId`) is `Ord`.
    distinct_ids.sort_by_key(|id| id.0);

    match distinct_ids.split_first() {
        Some((&survivor, rest)) => MergePlan::UseExisting {
            survivor,
            absorb: rest.to_vec(),
        },
        None => MergePlan::CreateNew {
            seed: *members.iter().next().expect("non-empty, checked by caller"),
        },
    }
}

/// Which existing entity, if any, already owns each member — a live snapshot
/// at call time. On its own this can go stale by the time a caller acts on
/// it; [`cluster_address`]'s converge-then-lock loop is what closes that
/// window, not this helper.
async fn read_owners(
    entities: &dyn EntityStore,
    members: &BTreeSet<AccountAddress>,
) -> Result<HashMap<AccountAddress, EntityId>, ClusterError> {
    let mut owners = HashMap::new();
    for member in members {
        if let Some(owner) = entities.entity_for_address(member).await? {
            owners.insert(*member, owner);
        }
    }
    Ok(owners)
}

/// The three collaborators one [`cluster_address`] pass needs — bundled to
/// stay under clippy's argument-count gate without collapsing the
/// object-safe seam split (mirrors [`crate::store::StoreSeams`]).
pub struct ClusterSeams<'a> {
    pub graph: &'a dyn AdjacencyStore,
    pub entities: &'a dyn EntityStore,
    pub merge_actor: &'a MergeActorHandle,
}

/// Cluster the bounded component around `seed` and apply it to the
/// [`EntityStore`] (§8.2). Returns `Ok(None)` when the seed itself is an
/// infrastructure endpoint (capped at hop 0) — there is no cluster to form,
/// which is the correct, non-exceptional outcome for e.g. seeding on a known
/// CEX hot wallet.
///
/// Idempotent: re-running against an unchanged graph and store re-derives the
/// same component and the same [`plan_merge`] decision, finds every member
/// already owned by the same survivor entity, and returns an outcome with
/// empty `linked`/`absorbed`.
pub async fn cluster_address(
    seams: ClusterSeams<'_>,
    chain: Chain,
    seed: &AccountAddress,
    evidence: &str,
    incident_id: Option<IncidentId>,
    at: DateTime<Utc>,
    limits: ClusterLimits,
) -> Result<Option<ClusterOutcome>, ClusterError> {
    let ClusterSeams {
        graph,
        entities,
        merge_actor,
    } = seams;
    let subgraph = bounded_component(graph, chain, *seed, limits).await?;
    let hubs: Vec<AccountAddress> = subgraph.hubs.into_iter().collect();
    if subgraph.members.is_empty() {
        return Ok(None);
    }

    // Hold every entity id this pass reads as an owner for the rest of this
    // function (§17, the t5 merge actor) — without this, a concurrent
    // in-process pass could tombstone one of them between this read and the
    // writes below, and we'd either silently drop a link
    // (`LinkOutcome::TargetInactive`, only the `Linked` arm does anything
    // below) or hand the caller a since-absorbed entity id. Converges by
    // re-reading owners after each lock: if the locked set turns out stale
    // (a concurrent pass changed ownership before we got here), the newly
    // discovered id(s) fold into `needed` and we retry.
    let mut guard: Option<EntityGuard> = None;
    let owners = loop {
        let owners = read_owners(entities, &subgraph.members).await?;
        let needed: HashSet<EntityId> = owners.values().copied().collect();
        if guard.as_ref().is_some_and(|g| g.matches(&needed)) {
            break owners;
        }
        // Drop whatever we're currently holding *before* requesting the new
        // set — a stale guard can share an id with `needed` (that id didn't
        // change), and a plain reassignment would only drop the old value
        // after the new `lock` call resolves, i.e. after we've already
        // asked to acquire an id we still hold ourselves. Self-deadlock.
        drop(guard.take());
        guard = Some(merge_actor.lock(needed).await?);
    };
    let _guard = guard; // held until this function returns.

    let (survivor, to_absorb, created_seed) = match plan_merge(&owners, &subgraph.members) {
        MergePlan::UseExisting { survivor, absorb } => (survivor, absorb, None),
        MergePlan::CreateNew { seed: seed_addr } => {
            let new_id = EntityId::new();
            let (survivor, created_seed) = match entities
                .create_entity(new_id, &seed_addr, evidence, at)
                .await?
            {
                CreateOutcome::Created => (new_id, Some(seed_addr)),
                CreateOutcome::AlreadyExists => {
                    unreachable!("freshly minted EntityId can't already exist")
                }
                // Raced with a concurrent writer since the `owners` read
                // above; adopt whoever won instead of erroring the pass out —
                // that writer's pass is the one that "created" it.
                CreateOutcome::SeedOwnedBy(owner) => (owner, None),
            };
            (survivor, Vec::new(), created_seed)
        }
    };

    let mut absorbed = Vec::new();
    for other in to_absorb {
        if let MergeOutcome::Merged { .. } = entities
            .absorb(survivor, other, incident_id, evidence, at)
            .await?
        {
            absorbed.push(other);
        }
        // `AbsorbedInactive`/`SurvivorInactive` mean a concurrent pass already
        // resolved this pair — nothing left to do.
    }

    let mut linked = Vec::new();
    for member in &subgraph.members {
        if owners.get(member).copied() == Some(survivor) {
            continue;
        }
        // Unowned, or owned by an entity just absorbed above (`absorb` already
        // moved its membership, so this lands `AlreadyMember`) — either way
        // idempotent.
        if let LinkOutcome::Linked = entities
            .link_address(survivor, member, evidence, at)
            .await?
        {
            linked.push(*member);
        }
    }

    Ok(Some(ClusterOutcome {
        entity_id: survivor,
        linked,
        absorbed,
        hubs,
        created_seed,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge_actor::MergeActor;
    use crate::model::{AdjacencyEdge, EntityRecord, EntityStatus};
    use crate::store::SplitOutcome;
    use crate::test_util::{InMemoryAdjacency, InMemoryIntelligenceStore};
    use alloy_primitives::Address;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Notify;
    use uuid::Uuid;

    fn addr(byte: u8) -> AccountAddress {
        Address::repeat_byte(byte)
    }

    /// A fresh actor for a test that doesn't care about sharing one across
    /// calls — every production caller shares a single per-process handle
    /// ([`crate::attribution::Attributor`], the `cluster` CLI subcommand),
    /// but most of these tests only exercise one `cluster_address` call at a
    /// time, so a throwaway per-test actor keeps the signature simple.
    fn actor() -> MergeActorHandle {
        MergeActor::spawn()
    }

    // ── plan_merge: the pure decision, tested with plain values ──────
    // No store, no doubles, no `async` — this is the payoff of splitting the
    // decision out of `cluster_address`'s I/O shell.

    #[test]
    fn plan_merge_creates_new_at_the_lowest_address_when_nothing_is_owned() {
        let owners = HashMap::new();
        let members = BTreeSet::from([addr(2), addr(1), addr(3)]);
        assert_eq!(
            plan_merge(&owners, &members),
            MergePlan::CreateNew { seed: addr(1) }
        );
    }

    #[test]
    fn plan_merge_survives_the_lowest_entity_id_and_absorbs_the_rest() {
        let low = EntityId(Uuid::from_u128(1));
        let high = EntityId(Uuid::from_u128(2));
        let mut owners = HashMap::new();
        owners.insert(addr(1), high);
        owners.insert(addr(2), low);
        let members = BTreeSet::from([addr(1), addr(2)]);

        assert_eq!(
            plan_merge(&owners, &members),
            MergePlan::UseExisting {
                survivor: low,
                absorb: vec![high],
            }
        );
    }

    #[test]
    fn plan_merge_with_one_owner_absorbs_nothing() {
        let only = EntityId(Uuid::from_u128(1));
        let mut owners = HashMap::new();
        owners.insert(addr(1), only);
        let members = BTreeSet::from([addr(1), addr(2)]);

        assert_eq!(
            plan_merge(&owners, &members),
            MergePlan::UseExisting {
                survivor: only,
                absorb: vec![],
            }
        );
    }

    #[test]
    fn plan_merge_is_deterministic_regardless_of_hashmap_iteration_order() {
        let owners = HashMap::new();
        let members = BTreeSet::from([addr(5), addr(9), addr(1)]);
        let first = plan_merge(&owners, &members);
        let second = plan_merge(&owners, &members);
        assert_eq!(first, second);
        assert_eq!(first, MergePlan::CreateNew { seed: addr(1) });
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    fn edge(src: AccountAddress, dst: AccountAddress, kind: EdgeKind) -> AdjacencyEdge {
        AdjacencyEdge {
            chain: Chain::ETHEREUM,
            src,
            dst,
            kind,
            evidence: "0xtx".into(),
            block_number: 1,
            observed_at: at(1),
        }
    }

    /// A funder connects three fresh wallets: they all end up in one entity.
    #[tokio::test]
    async fn common_funder_clusters_into_one_entity() {
        let graph = InMemoryAdjacency::new();
        let store = InMemoryIntelligenceStore::new();
        let merge_actor = actor();
        let funder = addr(0xF0);
        graph
            .append(&[
                edge(funder, addr(1), EdgeKind::Funded),
                edge(funder, addr(2), EdgeKind::Funded),
                edge(funder, addr(3), EdgeKind::Funded),
            ])
            .await
            .unwrap();

        let outcome = cluster_address(
            ClusterSeams {
                graph: &graph,
                entities: &store,
                merge_actor: &merge_actor,
            },
            Chain::ETHEREUM,
            &addr(1),
            "test",
            None,
            at(100),
            ClusterLimits::default(),
        )
        .await
        .unwrap()
        .expect("a cluster forms");

        assert!(outcome.hubs.is_empty());
        assert_eq!(
            outcome.created_seed,
            Some(addr(1)),
            "no member owned an entity yet, so this pass created one, seeded at the lowest address"
        );
        let entity = store.entity(outcome.entity_id).await.unwrap().unwrap();
        let mut members = entity.addresses.clone();
        members.sort();
        assert_eq!(members, vec![addr(1), addr(2), addr(3), funder]);
    }

    /// A funder above the degree cap is a stop signal: its funded addresses
    /// must NOT collapse into one entity through it.
    #[tokio::test]
    async fn hub_funder_does_not_bridge_unrelated_addresses() {
        let graph = InMemoryAdjacency::new();
        let store = InMemoryIntelligenceStore::new();
        let merge_actor = actor();
        let hub = addr(0xAA);
        let limits = ClusterLimits {
            degree_cap: 3,
            max_hops: 3,
        };
        // The hub funds five distinct addresses — over the cap.
        let edges: Vec<_> = (1..=5)
            .map(|n| edge(hub, addr(n), EdgeKind::Funded))
            .collect();
        graph.append(&edges).await.unwrap();

        let outcome = cluster_address(
            ClusterSeams {
                graph: &graph,
                entities: &store,
                merge_actor: &merge_actor,
            },
            Chain::ETHEREUM,
            &addr(1),
            "test",
            None,
            at(100),
            limits,
        )
        .await
        .unwrap()
        .expect("the seed itself forms a singleton cluster");

        assert_eq!(outcome.hubs, vec![hub], "hub excluded, not merged in");
        let entity = store.entity(outcome.entity_id).await.unwrap().unwrap();
        assert_eq!(entity.addresses, vec![addr(1)], "no bridging through hub");

        // addr(2) independently clusters into its OWN entity, not addr(1)'s.
        let other = cluster_address(
            ClusterSeams {
                graph: &graph,
                entities: &store,
                merge_actor: &merge_actor,
            },
            Chain::ETHEREUM,
            &addr(2),
            "test",
            None,
            at(100),
            limits,
        )
        .await
        .unwrap()
        .expect("addr(2) also forms a singleton");
        assert_ne!(other.entity_id, outcome.entity_id);
    }

    /// Seeding directly on a hub yields no cluster at all.
    #[tokio::test]
    async fn seed_that_is_itself_a_hub_forms_no_cluster() {
        let graph = InMemoryAdjacency::new();
        let store = InMemoryIntelligenceStore::new();
        let merge_actor = actor();
        let hub = addr(0xAA);
        let limits = ClusterLimits {
            degree_cap: 2,
            max_hops: 3,
        };
        let edges: Vec<_> = (1..=5)
            .map(|n| edge(hub, addr(n), EdgeKind::Funded))
            .collect();
        graph.append(&edges).await.unwrap();

        let outcome = cluster_address(
            ClusterSeams {
                graph: &graph,
                entities: &store,
                merge_actor: &merge_actor,
            },
            Chain::ETHEREUM,
            &hub,
            "test",
            None,
            at(1),
            limits,
        )
        .await
        .unwrap();
        assert_eq!(outcome, None);
    }

    /// `Interacted` edges are not a clustering signal.
    #[tokio::test]
    async fn interacted_edges_do_not_cluster() {
        let graph = InMemoryAdjacency::new();
        let store = InMemoryIntelligenceStore::new();
        let merge_actor = actor();
        graph
            .append(&[edge(addr(1), addr(2), EdgeKind::Interacted)])
            .await
            .unwrap();

        let outcome = cluster_address(
            ClusterSeams {
                graph: &graph,
                entities: &store,
                merge_actor: &merge_actor,
            },
            Chain::ETHEREUM,
            &addr(1),
            "test",
            None,
            at(1),
            ClusterLimits::default(),
        )
        .await
        .unwrap()
        .expect("a singleton cluster still forms for the seed");
        let entity = store.entity(outcome.entity_id).await.unwrap().unwrap();
        assert_eq!(entity.addresses, vec![addr(1)]);
    }

    /// Two previously-separate entities discovered in the same component are
    /// merged into a deterministic survivor.
    #[tokio::test]
    async fn merges_pre_existing_entities_in_the_component() {
        let graph = InMemoryAdjacency::new();
        let store = InMemoryIntelligenceStore::new();
        let merge_actor = actor();
        graph
            .append(&[edge(addr(1), addr(2), EdgeKind::Deployed)])
            .await
            .unwrap();

        // Two addresses already belong to two different entities before the
        // clustering signal (a funder edge) links them.
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        store
            .create_entity(e1, &addr(1), "prior", at(1))
            .await
            .unwrap();
        store
            .create_entity(e2, &addr(2), "prior", at(1))
            .await
            .unwrap();

        let outcome = cluster_address(
            ClusterSeams {
                graph: &graph,
                entities: &store,
                merge_actor: &merge_actor,
            },
            Chain::ETHEREUM,
            &addr(1),
            "test",
            None,
            at(100),
            ClusterLimits::default(),
        )
        .await
        .unwrap()
        .expect("a cluster forms");

        let survivor = std::cmp::min_by_key(e1, e2, |id| id.0);
        let absorbed_id = if survivor == e1 { e2 } else { e1 };
        assert_eq!(outcome.entity_id, survivor);
        assert_eq!(outcome.absorbed, vec![absorbed_id]);
        assert_eq!(
            outcome.created_seed, None,
            "both members already owned an entity — this pass merged, it didn't create"
        );

        let entity = store.entity(survivor).await.unwrap().unwrap();
        let mut members = entity.addresses.clone();
        members.sort();
        assert_eq!(members, vec![addr(1), addr(2)]);
    }

    /// Re-running the same pass against an unchanged graph/store is a no-op.
    #[tokio::test]
    async fn re_running_a_cluster_pass_is_idempotent() {
        let graph = InMemoryAdjacency::new();
        let store = InMemoryIntelligenceStore::new();
        let merge_actor = actor();
        graph
            .append(&[edge(addr(0xF0), addr(1), EdgeKind::Funded)])
            .await
            .unwrap();

        let first = cluster_address(
            ClusterSeams {
                graph: &graph,
                entities: &store,
                merge_actor: &merge_actor,
            },
            Chain::ETHEREUM,
            &addr(1),
            "test",
            None,
            at(1),
            ClusterLimits::default(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!first.linked.is_empty());
        assert_eq!(first.created_seed, Some(addr(1)));

        let second = cluster_address(
            ClusterSeams {
                graph: &graph,
                entities: &store,
                merge_actor: &merge_actor,
            },
            Chain::ETHEREUM,
            &addr(1),
            "test",
            None,
            at(2),
            ClusterLimits::default(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(second.entity_id, first.entity_id);
        assert!(second.linked.is_empty());
        assert!(second.absorbed.is_empty());
        assert_eq!(
            second.created_seed, None,
            "a re-run finds the entity already owned — it must not report a fresh create"
        );
    }

    // ── merge actor (§17, t5): the race it closes ─────────────────────

    /// Delegates every [`EntityStore`] call straight through to `inner`,
    /// except that the *first* `entity_for_address` call for `pause_at`
    /// notifies `paused` and then blocks on `resume` before returning — lets
    /// a test drive a second `cluster_address` pass to completion while this
    /// one is parked mid owners-read, deterministically reproducing the race
    /// the merge actor exists to close.
    struct PausingStore<'a> {
        inner: &'a InMemoryIntelligenceStore,
        pause_at: AccountAddress,
        fired: AtomicBool,
        paused: Arc<Notify>,
        resume: Arc<Notify>,
    }

    #[async_trait::async_trait]
    impl EntityStore for PausingStore<'_> {
        async fn create_entity(
            &self,
            entity_id: EntityId,
            seed: &AccountAddress,
            evidence: &str,
            at: DateTime<Utc>,
        ) -> Result<CreateOutcome, StoreError> {
            self.inner
                .create_entity(entity_id, seed, evidence, at)
                .await
        }

        async fn link_address(
            &self,
            entity_id: EntityId,
            address: &AccountAddress,
            evidence: &str,
            at: DateTime<Utc>,
        ) -> Result<LinkOutcome, StoreError> {
            self.inner
                .link_address(entity_id, address, evidence, at)
                .await
        }

        async fn entity(&self, entity_id: EntityId) -> Result<Option<EntityRecord>, StoreError> {
            self.inner.entity(entity_id).await
        }

        async fn entity_for_address(
            &self,
            address: &AccountAddress,
        ) -> Result<Option<EntityId>, StoreError> {
            let result = self.inner.entity_for_address(address).await;
            if *address == self.pause_at && !self.fired.swap(true, Ordering::SeqCst) {
                self.paused.notify_one();
                self.resume.notified().await;
            }
            result
        }

        async fn absorb(
            &self,
            surviving: EntityId,
            absorbed: EntityId,
            incident_id: Option<IncidentId>,
            evidence_ref: &str,
            at: DateTime<Utc>,
        ) -> Result<MergeOutcome, StoreError> {
            self.inner
                .absorb(surviving, absorbed, incident_id, evidence_ref, at)
                .await
        }

        async fn split(
            &self,
            entity_id: EntityId,
            groups: &[Vec<AccountAddress>],
            evidence: &str,
            at: DateTime<Utc>,
        ) -> Result<SplitOutcome, StoreError> {
            self.inner.split(entity_id, groups, evidence, at).await
        }

        async fn merges_for_incident(
            &self,
            incident_id: IncidentId,
        ) -> Result<Vec<crate::model::MergeLogEntry>, StoreError> {
            self.inner.merges_for_incident(incident_id).await
        }

        async fn reverse_merge(
            &self,
            merge_id: crate::model::MergeId,
            at: DateTime<Utc>,
        ) -> Result<crate::store::ReversalOutcome, StoreError> {
            self.inner.reverse_merge(merge_id, at).await
        }
    }

    /// The regression this whole module exists for: two overlapping-but-not-
    /// identical components discovered concurrently must never leave a pass
    /// reporting a since-tombstoned entity id.
    ///
    /// Setup: `e1` owns A, `e2` owns B, `e3` owns C, with `Funded` edges
    /// A–B and B–C (so with `max_hops: 1`, a pass seeded at A sees only
    /// {A, B} and a pass seeded at C sees only {B, C} — they overlap at B
    /// without being the same component). Pass 2 (seeded at C) is paused via
    /// `PausingStore` right after it reads B's *stale* owner (`e2`, before
    /// pass 1 runs); pass 1 (seeded at A) then runs to completion via the
    /// same actor, merging `e2` into `e1` (`e1 < e2` by construction) —
    /// tombstoning the very entity pass 2's stale read named. Without the
    /// actor's converge-then-lock loop, pass 2 would go on to compute
    /// `survivor = e2` from its stale read, hit `MergeOutcome::SurvivorInactive`
    /// on the absorb and `LinkOutcome::TargetInactive` on the link, and hand
    /// its caller a dead entity id. With it, pass 2 re-reads under lock,
    /// discovers `e2` is gone, and converges onto the same live entity as
    /// pass 1.
    #[tokio::test]
    async fn concurrent_passes_on_overlapping_components_never_surface_a_tombstoned_entity() {
        let graph = InMemoryAdjacency::new();
        let store = InMemoryIntelligenceStore::new();
        let merge_actor = actor();
        let limits = ClusterLimits {
            degree_cap: 25,
            max_hops: 1,
        };

        let e1 = EntityId(Uuid::from_u128(1));
        let e2 = EntityId(Uuid::from_u128(2));
        let e3 = EntityId(Uuid::from_u128(3));
        store
            .create_entity(e1, &addr(1), "prior", at(1))
            .await
            .unwrap();
        store
            .create_entity(e2, &addr(2), "prior", at(1))
            .await
            .unwrap();
        store
            .create_entity(e3, &addr(3), "prior", at(1))
            .await
            .unwrap();
        graph
            .append(&[
                edge(addr(1), addr(2), EdgeKind::Funded),
                edge(addr(2), addr(3), EdgeKind::Funded),
            ])
            .await
            .unwrap();

        let paused = Arc::new(Notify::new());
        let resume = Arc::new(Notify::new());
        let pausing = PausingStore {
            inner: &store,
            pause_at: addr(2),
            fired: AtomicBool::new(false),
            paused: paused.clone(),
            resume: resume.clone(),
        };

        let seed2 = addr(3);
        let pass2 = cluster_address(
            ClusterSeams {
                graph: &graph,
                entities: &pausing,
                merge_actor: &merge_actor,
            },
            Chain::ETHEREUM,
            &seed2,
            "pass2",
            None,
            at(200),
            limits,
        );
        let seed1 = addr(1);
        let controller = async {
            paused.notified().await;
            let outcome1 = cluster_address(
                ClusterSeams {
                    graph: &graph,
                    entities: &store,
                    merge_actor: &merge_actor,
                },
                Chain::ETHEREUM,
                &seed1,
                "pass1",
                None,
                at(100),
                limits,
            )
            .await
            .unwrap()
            .expect("pass1 forms a cluster");
            resume.notify_one();
            outcome1
        };

        let (pass2_result, outcome1) =
            tokio::time::timeout(Duration::from_secs(5), join_both(pass2, controller))
                .await
                .expect("both passes must complete without deadlocking");
        let outcome2 = pass2_result.unwrap().expect("pass2 forms a cluster");

        // The crux: pass2 must never report an entity that's since been
        // tombstoned, even though its owners-read raced pass1's absorb.
        let reported = store.entity(outcome2.entity_id).await.unwrap().unwrap();
        assert_eq!(
            reported.status,
            EntityStatus::Active,
            "pass2 must not surface a since-absorbed entity id"
        );

        // Every address in the shared component converges onto one live entity.
        let owner1 = store.entity_for_address(&addr(1)).await.unwrap().unwrap();
        let owner2 = store.entity_for_address(&addr(2)).await.unwrap().unwrap();
        let owner3 = store.entity_for_address(&addr(3)).await.unwrap().unwrap();
        assert_eq!(owner1, owner2);
        assert_eq!(owner2, owner3);
        assert_eq!(outcome1.entity_id, owner1);
        assert_eq!(outcome2.entity_id, owner1);
    }

    /// `tokio::join!` resolves inline rather than returning a `Future`, so it
    /// can't be passed to `tokio::time::timeout` directly — this wraps it in
    /// one so the test fails fast with a clear panic instead of hanging if
    /// the actor ever deadlocks.
    async fn join_both<A, B>(
        a: impl std::future::Future<Output = A>,
        b: impl std::future::Future<Output = B>,
    ) -> (A, B) {
        tokio::join!(a, b)
    }
}
