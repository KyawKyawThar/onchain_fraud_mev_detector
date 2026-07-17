//! Entity-graph hop queries (§8.2, §11): the read behind
//! `GET /v1/entity/{id}/graph?hops=3` — the addresses connected to an entity's
//! members, out to `hops` levels, as a **degree-capped** subgraph.
//!
//! This is the *visualization/exploration* read, and it is deliberately built
//! on the same hub-node discipline as [`crate::cluster`] (§8.2 — critical): a
//! node whose degree exceeds the cap is an infrastructure endpoint (a CEX hot
//! wallet, a bridge, a router) and is a **stop signal**, not a recursion point.
//! We keep the hub in the result as a labelled boundary node (`is_hub`) so a
//! caller can see the walk reached it, but we never expand through it —
//! crossing one would pull millions of unrelated addresses into the graph and
//! collapse it into noise.
//!
//! Unlike clustering (which reads only the four identity edge kinds), the graph
//! read uses the *full* undirected neighborhood ([`AdjacencyStore::neighbors`]):
//! §11 asks for "connected addresses", every kind of connection, and the degree
//! cap is evaluated against that full degree — the same measure that decides
//! hub-ness everywhere else.
//!
//! # Bounded three ways, and level-synchronous
//!
//! The walk can never produce an unbounded response: the per-node **degree
//! cap**, the **hop bound** ([`GraphLimits::max_hops`]), and a total **node
//! budget** ([`GraphLimits::max_nodes`]) — load, analyze, discard (§8), never a
//! crawl of the whole graph.
//!
//! It is a **level-synchronous BFS**: each hop expands the whole current
//! frontier in **one** [`AdjacencyStore::neighbors_many`] round-trip (a single
//! `LIMIT … BY source` ClickHouse query), not one query per node in series.
//! So a `hops=3` walk costs at most three network latencies regardless of how
//! wide the frontier is. Results are integrated in a deterministic (sorted)
//! order, so the same store state always yields byte-identical output.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use event_bus::Transience;
use events::primitives::{AccountAddress, Chain, EntityId};

use crate::adjacency::{AdjacencyStore, GraphError};
use crate::store::{EntityStore, StoreError};

/// The bounds one entity-graph walk respects (§8.2). §8.2 doesn't pin exact
/// numbers; [`Default`] picks conservative ones — a `degree_cap` that any real
/// infrastructure endpoint clears immediately, a shallow `max_hops` (the spec's
/// own example is `hops=3`), and a `max_nodes` budget that keeps a response
/// renderable even before a hub is hit. `degree_cap`/`max_nodes` are
/// operator-tunable (wired from config in `main`); `max_hops` is set per
/// request from the clamped `hops` query param.
#[derive(Debug, Clone, Copy)]
pub struct GraphLimits {
    /// Per-node degree cap: a node with more neighbors than this is a hub — a
    /// boundary the walk stops at rather than crosses.
    pub degree_cap: u32,
    /// How many hops out from the entity's members to walk.
    pub max_hops: u32,
    /// Total node budget across the whole walk — a hard ceiling on the
    /// response size independent of the per-node cap and hop bound.
    pub max_nodes: usize,
}

impl Default for GraphLimits {
    fn default() -> Self {
        Self {
            degree_cap: 50,
            max_hops: Self::DEFAULT_HOPS,
            max_nodes: 500,
        }
    }
}

impl GraphLimits {
    /// Hop bound a caller gets when they don't ask for one (the spec's example).
    pub const DEFAULT_HOPS: u32 = 3;
    /// Hard hop ceiling — each hop multiplies the frontier by up to
    /// `degree_cap`, so this bounds the blast radius even before `max_nodes`.
    pub const MAX_HOPS: u32 = 5;

    /// Apply a caller-supplied hop request to these limits, clamped into
    /// `[0, MAX_HOPS]` (`0` — the proto's "unset" — becomes [`Self::DEFAULT_HOPS`]).
    /// Clamps rather than rejects: an over-eager `hops` is a reasonable request
    /// we serve at the ceiling, the same stance [`crate::leaderboard::Limit`]
    /// takes. Consumes `self` so the configured `degree_cap`/`max_nodes` carry
    /// through — the handler applies it to the service's base limits.
    pub fn clamp_hops(self, requested: u32) -> Self {
        let max_hops = match requested {
            0 => Self::DEFAULT_HOPS,
            n => n.min(Self::MAX_HOPS),
        };
        Self { max_hops, ..self }
    }

    /// Default limits with the hop request applied — the shorthand tests use.
    pub fn with_hops(requested: u32) -> Self {
        Self::default().clamp_hops(requested)
    }
}

/// Why a walk returned less than the full neighborhood — a closed set rather
/// than a bare "truncated" bool, so a caller can tell "stopped at a hub" (a
/// dead end) from "more hops exist" (fetch deeper) from "too big" (narrow the
/// query), and ops can alert on the rates independently.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, strum::IntoStaticStr, strum::EnumIter,
)]
#[strum(serialize_all = "snake_case")]
pub enum TruncationReason {
    /// The walk reached a degree-capped hub and stopped there (§8.2).
    HubBoundary,
    /// A node sits at the hop bound with unexplored neighbors beyond it.
    HopBoundary,
    /// The node budget was exhausted before the neighborhood was fully walked.
    NodeBudget,
}

/// One address in the returned subgraph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphNode {
    pub address: AccountAddress,
    /// Distance from the nearest entity member (`0` for a member itself).
    pub hop: u32,
    /// This address is one of the entity's own members (a walk seed).
    pub is_seed: bool,
    /// This address is a degree-capped infrastructure endpoint — the walk
    /// stopped here rather than expanding through it (§8.2).
    pub is_hub: bool,
}

/// One undirected connection between two addresses in the subgraph. `from` is
/// always the lexicographically smaller address, so an edge has one canonical
/// form regardless of which side the walk discovered first.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GraphEdge {
    pub from: AccountAddress,
    pub to: AccountAddress,
}

impl GraphEdge {
    /// Canonicalize an unordered pair into `(min, max)` so the two discovery
    /// directions collapse to one edge.
    fn between(a: AccountAddress, b: AccountAddress) -> Self {
        if a <= b {
            Self { from: a, to: b }
        } else {
            Self { from: b, to: a }
        }
    }
}

/// The degree-capped neighborhood of one entity (§8.2, §11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityGraph {
    pub entity_id: EntityId,
    /// The entity's member addresses — the walk's hop-0 seeds.
    pub seeds: Vec<AccountAddress>,
    /// Every discovered address, seeds included, sorted by address.
    pub nodes: Vec<GraphNode>,
    /// Every discovered connection, canonicalized and sorted.
    pub edges: Vec<GraphEdge>,
    /// The distinct reasons the walk stopped short, sorted. Empty means the
    /// whole reachable neighborhood fit within the bounds — a complete graph.
    pub truncation: Vec<TruncationReason>,
}

impl EntityGraph {
    /// Whether the walk stopped short of the full neighborhood (any reason).
    pub fn truncated(&self) -> bool {
        !self.truncation.is_empty()
    }
}

/// A failure resolving the entity or walking the graph. Wraps the two seam
/// errors and forwards their retry/skip classification unchanged.
#[derive(Debug, thiserror::Error)]
pub enum EntityGraphError {
    #[error(transparent)]
    Graph(#[from] GraphError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl Transience for EntityGraphError {
    fn is_transient(&self) -> bool {
        match self {
            EntityGraphError::Graph(err) => err.is_transient(),
            EntityGraphError::Store(err) => err.is_transient(),
        }
    }
}

/// The two collaborators an entity-graph walk needs. `graph` is owned
/// (`Arc`-cheap) — the service already holds one, and a batched read per hop
/// keeps its own handle; `entities` is only touched once, up front, so it stays
/// a borrow.
pub struct GraphSeams<'a> {
    pub graph: Arc<dyn AdjacencyStore>,
    pub entities: &'a dyn EntityStore,
}

/// A node the walk knows about, with the state we mutate as it's expanded.
struct NodeState {
    hop: u32,
    is_seed: bool,
    is_hub: bool,
}

/// Walk the degree-capped neighborhood of `entity_id` on `chain`, out to
/// `limits.max_hops`. Returns `Ok(None)` when the entity is unknown (the edge
/// maps that to a 404); an entity with no members yields an empty graph.
#[tracing::instrument(
    skip_all,
    fields(%entity_id, chain = chain.id(), max_hops = limits.max_hops)
)]
pub async fn entity_graph(
    seams: GraphSeams<'_>,
    chain: Chain,
    entity_id: EntityId,
    limits: GraphLimits,
) -> Result<Option<EntityGraph>, EntityGraphError> {
    let GraphSeams { graph, entities } = seams;

    let Some(entity) = entities.entity(entity_id).await? else {
        return Ok(None);
    };

    // Seeds are the entity's members. `entity.addresses` already comes back
    // sorted from the store, but sort defensively so the walk order can't
    // depend on a store's iteration quirk.
    let mut seeds = entity.addresses.clone();
    seeds.sort();

    let mut known: HashMap<AccountAddress, NodeState> = HashMap::new();
    let mut edges: BTreeSet<GraphEdge> = BTreeSet::new();
    let mut truncation: BTreeSet<TruncationReason> = BTreeSet::new();

    for seed in &seeds {
        known.entry(*seed).or_insert(NodeState {
            hop: 0,
            is_seed: true,
            is_hub: false,
        });
    }

    // Level-synchronous BFS: expand one hop at a time so a node's hop is always
    // its true distance from the nearest seed. The whole frontier's neighbors
    // come back in a single batched read per hop (not one query per node), and
    // `frontier` is kept sorted so budget admission is reproducible.
    let mut frontier: Vec<AccountAddress> = seeds.clone();
    for hop in 0..limits.max_hops {
        if frontier.is_empty() {
            break;
        }

        let mut neighborhoods = graph
            .neighbors_many(chain, &frontier, limits.degree_cap)
            .await?;

        let mut next: Vec<AccountAddress> = Vec::new();
        for address in &frontier {
            // `neighbors_many` returns one entry per frontier node; the
            // `unwrap_or_default` is a defensive belt (an empty neighborhood is
            // the same "no edges" outcome).
            let neighborhood = neighborhoods.remove(address).unwrap_or_default();
            if neighborhood.capped {
                // Infrastructure endpoint (§8.2): a boundary, not a recursion
                // point. Its returned `cap` neighbors are an arbitrary subset,
                // so surfacing them as edges would misrepresent the graph.
                known
                    .get_mut(address)
                    .expect("frontier node is known")
                    .is_hub = true;
                truncation.insert(TruncationReason::HubBoundary);
                continue;
            }
            for neighbor in neighborhood.neighbors {
                if known.contains_key(&neighbor) {
                    // Already a node — record the connection between the two.
                    edges.insert(GraphEdge::between(*address, neighbor));
                    continue;
                }
                if known.len() >= limits.max_nodes {
                    // Budget spent: don't admit the neighbor, and don't record a
                    // dangling edge to a node that won't appear. Every returned
                    // edge still connects two returned nodes.
                    truncation.insert(TruncationReason::NodeBudget);
                    continue;
                }
                known.insert(
                    neighbor,
                    NodeState {
                        hop: hop + 1,
                        is_seed: false,
                        is_hub: false,
                    },
                );
                next.push(neighbor);
                edges.insert(GraphEdge::between(*address, neighbor));
            }
        }
        frontier = next;
    }

    // A non-empty frontier left over means there were nodes at exactly
    // `max_hops` we admitted but did not expand — the walk stopped at the hop
    // boundary. (`frontier` is only non-empty here when `max_hops > 0`.)
    if !frontier.is_empty() {
        truncation.insert(TruncationReason::HopBoundary);
    }

    let mut nodes: Vec<GraphNode> = known
        .into_iter()
        .map(|(address, state)| GraphNode {
            address,
            hop: state.hop,
            is_seed: state.is_seed,
            is_hub: state.is_hub,
        })
        .collect();
    nodes.sort_by_key(|n| n.address);

    tracing::debug!(
        nodes = nodes.len(),
        edges = edges.len(),
        truncation = ?truncation,
        "entity graph walked"
    );

    Ok(Some(EntityGraph {
        entity_id,
        seeds,
        nodes,
        edges: edges.into_iter().collect(),
        truncation: truncation.into_iter().collect(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AdjacencyEdge, EdgeKind};
    use crate::store::EntityStore;
    use crate::test_util::{InMemoryAdjacency, InMemoryIntelligenceStore};
    use alloy_primitives::Address;
    use chrono::{DateTime, Utc};

    fn addr(byte: u8) -> AccountAddress {
        Address::repeat_byte(byte)
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    fn edge(src: AccountAddress, dst: AccountAddress) -> AdjacencyEdge {
        AdjacencyEdge {
            chain: Chain::ETHEREUM,
            src,
            dst,
            kind: EdgeKind::Interacted,
            evidence: "0xtx".into(),
            block_number: 1,
            observed_at: at(1),
        }
    }

    /// Seed one entity owning `members` and return its id.
    async fn seed_entity(
        store: &InMemoryIntelligenceStore,
        members: &[AccountAddress],
    ) -> EntityId {
        let id = EntityId::new();
        store
            .create_entity(id, &members[0], "test", at(1))
            .await
            .unwrap();
        for member in &members[1..] {
            store.link_address(id, member, "test", at(1)).await.unwrap();
        }
        id
    }

    fn node(g: &EntityGraph, a: AccountAddress) -> &GraphNode {
        g.nodes
            .iter()
            .find(|n| n.address == a)
            .expect("node present")
    }

    #[tokio::test]
    async fn unknown_entity_is_none() {
        let graph = Arc::new(InMemoryAdjacency::new());
        let store = InMemoryIntelligenceStore::new();
        let out = entity_graph(
            GraphSeams {
                graph: graph.clone(),
                entities: &store,
            },
            Chain::ETHEREUM,
            EntityId::new(),
            GraphLimits::default(),
        )
        .await
        .unwrap();
        assert!(out.is_none(), "an unknown entity maps to a 404 at the edge");
    }

    #[tokio::test]
    async fn walks_out_to_the_hop_bound_and_labels_seeds() {
        let graph = Arc::new(InMemoryAdjacency::new());
        let store = InMemoryIntelligenceStore::new();
        // seed(1) — 2 — 3 — 4 — 5 (a chain). Entity owns just addr(1).
        graph
            .append(&[
                edge(addr(1), addr(2)),
                edge(addr(2), addr(3)),
                edge(addr(3), addr(4)),
                edge(addr(4), addr(5)),
            ])
            .await
            .unwrap();
        let id = seed_entity(&store, &[addr(1)]).await;

        let g = entity_graph(
            GraphSeams {
                graph: graph.clone(),
                entities: &store,
            },
            Chain::ETHEREUM,
            id,
            GraphLimits::with_hops(2),
        )
        .await
        .unwrap()
        .unwrap();

        // hops=2 from addr(1) reaches {1,2,3}; addr(4)/addr(5) are past the bound.
        let reached: Vec<u8> = g.nodes.iter().map(|n| n.address.0[0]).collect();
        assert_eq!(reached, vec![1, 2, 3]);
        assert_eq!(node(&g, addr(1)).hop, 0);
        assert!(node(&g, addr(1)).is_seed);
        assert_eq!(node(&g, addr(2)).hop, 1);
        assert_eq!(node(&g, addr(3)).hop, 2);
        assert!(!node(&g, addr(2)).is_seed);
        // addr(3) sits at the hop bound with addr(4) beyond it → hop-boundary.
        assert_eq!(g.truncation, vec![TruncationReason::HopBoundary]);
        assert!(g.truncated());
        assert_eq!(g.seeds, vec![addr(1)]);
    }

    #[tokio::test]
    async fn edges_are_canonical_and_deduplicated() {
        let graph = Arc::new(InMemoryAdjacency::new());
        let store = InMemoryIntelligenceStore::new();
        // A triangle: 1–2, 2–3, 1–3. Each edge is discovered from both ends.
        graph
            .append(&[
                edge(addr(1), addr(2)),
                edge(addr(2), addr(3)),
                edge(addr(3), addr(1)),
            ])
            .await
            .unwrap();
        let id = seed_entity(&store, &[addr(1)]).await;

        let g = entity_graph(
            GraphSeams {
                graph: graph.clone(),
                entities: &store,
            },
            Chain::ETHEREUM,
            id,
            GraphLimits::with_hops(3),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            g.edges,
            vec![
                GraphEdge {
                    from: addr(1),
                    to: addr(2)
                },
                GraphEdge {
                    from: addr(1),
                    to: addr(3)
                },
                GraphEdge {
                    from: addr(2),
                    to: addr(3)
                },
            ],
            "each undirected edge appears once, in canonical (min,max) form"
        );
        // The whole component fits inside the hop bound → complete.
        assert!(!g.truncated());
    }

    #[tokio::test]
    async fn a_hub_is_a_boundary_not_a_bridge() {
        let graph = Arc::new(InMemoryAdjacency::new());
        let store = InMemoryIntelligenceStore::new();
        // seed(1) — hub(0xAA), and the hub also touches 10 other addresses.
        let hub = addr(0xAA);
        let mut edges = vec![edge(addr(1), hub)];
        for n in 10..20 {
            edges.push(edge(hub, addr(n)));
        }
        graph.append(&edges).await.unwrap();
        let id = seed_entity(&store, &[addr(1)]).await;

        let g = entity_graph(
            GraphSeams {
                graph: graph.clone(),
                entities: &store,
            },
            Chain::ETHEREUM,
            id,
            GraphLimits {
                degree_cap: 3,
                max_hops: 3,
                max_nodes: 500,
            },
        )
        .await
        .unwrap()
        .unwrap();

        // The hub is present as a labelled boundary, but none of its 10 other
        // neighbors leaked into the graph — it was not crossed.
        assert!(node(&g, hub).is_hub, "the hub is flagged");
        assert_eq!(g.truncation, vec![TruncationReason::HubBoundary]);
        let addrs: Vec<u8> = g.nodes.iter().map(|n| n.address.0[0]).collect();
        assert_eq!(addrs, vec![1, 0xAA], "no bridging through the hub");
        assert_eq!(g.edges, vec![GraphEdge::between(addr(1), hub)]);
    }

    #[tokio::test]
    async fn the_node_budget_caps_the_response() {
        let graph = Arc::new(InMemoryAdjacency::new());
        let store = InMemoryIntelligenceStore::new();
        // A star: seed(1) connects to 40 leaves, none of them hubs.
        let edges: Vec<_> = (2..=41).map(|n| edge(addr(1), addr(n))).collect();
        graph.append(&edges).await.unwrap();
        let id = seed_entity(&store, &[addr(1)]).await;

        let g = entity_graph(
            GraphSeams {
                graph: graph.clone(),
                entities: &store,
            },
            Chain::ETHEREUM,
            id,
            GraphLimits {
                degree_cap: 100, // seed is under the cap — not a hub
                max_hops: 2,
                max_nodes: 10,
            },
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(g.nodes.len(), 10, "the node budget is a hard ceiling");
        assert!(
            g.truncation.contains(&TruncationReason::NodeBudget),
            "budget exhaustion is reported: {:?}",
            g.truncation
        );
    }

    #[tokio::test]
    async fn multiple_seeds_share_one_graph_and_hop_is_the_nearest_seed() {
        let graph = Arc::new(InMemoryAdjacency::new());
        let store = InMemoryIntelligenceStore::new();
        // Two members 1 and 5, bridged by 3: 1–2–3–4–5.
        graph
            .append(&[
                edge(addr(1), addr(2)),
                edge(addr(2), addr(3)),
                edge(addr(3), addr(4)),
                edge(addr(4), addr(5)),
            ])
            .await
            .unwrap();
        let id = seed_entity(&store, &[addr(1), addr(5)]).await;

        let g = entity_graph(
            GraphSeams {
                graph: graph.clone(),
                entities: &store,
            },
            Chain::ETHEREUM,
            id,
            GraphLimits::with_hops(1),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(g.seeds, vec![addr(1), addr(5)]);
        assert!(node(&g, addr(1)).is_seed && node(&g, addr(1)).hop == 0);
        assert!(node(&g, addr(5)).is_seed && node(&g, addr(5)).hop == 0);
        // addr(2) is hop 1 from seed 1; addr(4) is hop 1 from seed 5.
        assert_eq!(node(&g, addr(2)).hop, 1);
        assert_eq!(node(&g, addr(4)).hop, 1);
    }

    #[tokio::test]
    async fn chain_scoped_edges_do_not_leak_across_chains() {
        let graph = Arc::new(InMemoryAdjacency::new());
        let store = InMemoryIntelligenceStore::new();
        let mut e = edge(addr(1), addr(2));
        e.chain = Chain(8453); // Base, not Ethereum
        graph.append(&[e]).await.unwrap();
        let id = seed_entity(&store, &[addr(1)]).await;

        let g = entity_graph(
            GraphSeams {
                graph: graph.clone(),
                entities: &store,
            },
            Chain::ETHEREUM,
            id,
            GraphLimits::with_hops(3),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            g.nodes.len(),
            1,
            "only the seed — the edge is on another chain"
        );
        assert!(g.edges.is_empty());
    }

    /// The batched `neighbors_many` the walk relies on must agree, per address,
    /// with looping single `neighbors` — the property the ClickHouse override
    /// has to preserve (checked here against the double's default impl so the
    /// walk's contract is pinned without a live database).
    #[tokio::test]
    async fn neighbors_many_agrees_with_looping_single_neighbors() {
        use crate::adjacency::AdjacencyStore;

        let graph = InMemoryAdjacency::new();
        // A hub (over cap) and a normal node, plus an address with no edges.
        let mut edges = vec![edge(addr(1), addr(2)), edge(addr(1), addr(3))];
        for n in 10..20 {
            edges.push(edge(addr(9), addr(n)));
        }
        graph.append(&edges).await.unwrap();

        let frontier = [addr(1), addr(9), addr(0xFF)];
        let batched = graph
            .neighbors_many(Chain::ETHEREUM, &frontier, 4)
            .await
            .unwrap();

        for a in frontier {
            let single = graph.neighbors(Chain::ETHEREUM, &a, 4).await.unwrap();
            assert_eq!(batched[&a], single, "mismatch for {a}");
        }
        assert!(batched[&addr(9)].capped, "the hub is capped");
        assert!(
            !batched[&addr(0xFF)].capped,
            "an edgeless address is empty, not capped"
        );
    }

    #[test]
    fn with_hops_clamps_and_defaults() {
        assert_eq!(
            GraphLimits::with_hops(0).max_hops,
            GraphLimits::DEFAULT_HOPS
        );
        assert_eq!(GraphLimits::with_hops(2).max_hops, 2);
        assert_eq!(GraphLimits::with_hops(99).max_hops, GraphLimits::MAX_HOPS);
    }
}
