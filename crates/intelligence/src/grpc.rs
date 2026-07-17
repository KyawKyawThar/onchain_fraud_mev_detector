//! The `IntelligenceRead` gRPC service (§11): the synchronous read lookups a
//! caller reaches in-network — an address's current risk score, its active
//! labels, and the §10 builder/relay leaderboard (`GetBuilderLeaderboard`,
//! Sprint 11 t2).
//!
//! The risk/labels lookups are cache-aside over the exact seams already built
//! for this: a
//! [`HotCache`] hit answers immediately; a miss computes live via the same
//! path the `score` consumer and `intelligence risk` CLI subcommand use
//! ([`risk_scorer::load_risk_inputs`] → [`risk::score`], or
//! [`LabelStore::labels_for`]) and repopulates the cache for next time. A
//! cache *fault* (as opposed to a clean miss) is treated the same as a miss —
//! [`cache`]'s rule that the cache is "an optimization, never the record"
//! applies here too, so a Redis blip degrades this RPC's latency, not its
//! correctness.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use events::primitives::{AccountAddress, Chain, EntityId};
use tonic::{Request, Response, Status};

use crate::adjacency::AdjacencyStore;
use crate::cache::{CachedScore, HotCache};
use crate::graph::{self, GraphLimits, GraphSeams};
use crate::leaderboard::{self, LeaderboardQuery, LeaderboardStore, Limit};
use crate::model::{self, LabelRecord};
use crate::pb::intelligence_read_server::IntelligenceRead;
use crate::pb::{
    BuilderLeaderboardReply, BuilderLeaderboardRequest, BuilderStats, EntityGraphReply,
    EntityGraphRequest, EntityTimelineReply, EntityTimelineRequest, GraphEdge, GraphNode, Label,
    LabelsReply, LabelsRequest, RelayStats, RiskScoreReply, RiskScoreRequest, TimelineMilestone,
};
use crate::risk::{self, MODEL_VERSION};
use crate::risk_scorer;
use crate::store::StoreSeams;
use crate::timeline;

/// The service implementation. Cheap to clone — every field is `Arc`-backed —
/// which is what tonic requires to hand the service to each connection.
#[derive(Clone)]
pub struct IntelligenceReadService {
    stores: StoreSeams,
    cache: Arc<dyn HotCache>,
    leaderboard: Arc<dyn LeaderboardStore>,
    /// The ClickHouse adjacency store behind the entity-graph hop query (§8.2).
    graph: Arc<dyn AdjacencyStore>,
    /// Operator-tuned base bounds for the entity-graph walk; the per-request
    /// `hops` is clamped onto these.
    graph_limits: GraphLimits,
}

impl IntelligenceReadService {
    pub fn new(
        stores: StoreSeams,
        cache: Arc<dyn HotCache>,
        leaderboard: Arc<dyn LeaderboardStore>,
        graph: Arc<dyn AdjacencyStore>,
        graph_limits: GraphLimits,
    ) -> Self {
        Self {
            stores,
            cache,
            leaderboard,
            graph,
            graph_limits,
        }
    }
}

// ── §19 read-path metrics ────────────────────────────────────────────────────
// Counters + a size histogram for the two entity reads. Labelled so rates
// (found vs. 404, truncation reasons) are derived in PromQL, not stored — the
// same stance as the per-detector metrics design.

/// Entity-graph requests, labelled `found` = `"true"`/`"false"`.
const ENTITY_GRAPH_REQUESTS: &str = "intelligence_entity_graph_requests_total";
/// Entity-graph walks that stopped short, labelled `reason` (one increment per
/// distinct [`graph::TruncationReason`] hit).
const ENTITY_GRAPH_TRUNCATIONS: &str = "intelligence_entity_graph_truncations_total";
/// Distribution of the node count a walk returned.
const ENTITY_GRAPH_NODES: &str = "intelligence_entity_graph_nodes";
/// Entity-timeline requests, labelled `found` = `"true"`/`"false"`.
const ENTITY_TIMELINE_REQUESTS: &str = "intelligence_entity_timeline_requests_total";
/// Distribution of the milestone count a timeline returned.
const ENTITY_TIMELINE_MILESTONES: &str = "intelligence_entity_timeline_milestones";

/// Parse the wire address via the crate's canonical [`model::parse_address_key`]
/// (the same mapping Postgres rows/Redis keys/ClickHouse columns use), mapping
/// a bad value to `INVALID_ARGUMENT` rather than the `INTERNAL` a store/cache
/// failure gets.
fn parse_address(raw: &str) -> Result<AccountAddress, Status> {
    model::parse_address_key(raw).map_err(|err| Status::invalid_argument(err.to_string()))
}

/// Parse a wire entity id (a UUID string), mapping a bad value to
/// `INVALID_ARGUMENT` — the same boundary discipline as [`parse_address`].
fn parse_entity_id(raw: &str) -> Result<EntityId, Status> {
    uuid::Uuid::parse_str(raw)
        .map(EntityId)
        .map_err(|err| Status::invalid_argument(format!("invalid entity id: {err}")))
}

fn millis(at: DateTime<Utc>) -> i64 {
    at.timestamp_millis()
}

/// Map an internal read failure onto a gRPC status by its transient/permanent
/// classification — the workspace-wide [`event_bus::Transience`] contract,
/// reused rather than re-decided here. A transient fault (a Postgres/ClickHouse
/// blip, a pool timeout) becomes `UNAVAILABLE`, the status a gRPC client's
/// standard retry policy acts on; a permanent one (a decode/logic error) stays
/// `INTERNAL`, where a retry would only fail again the same way.
fn status_for(err: impl event_bus::Transience + std::fmt::Display) -> Status {
    if err.is_transient() {
        Status::unavailable(err.to_string())
    } else {
        Status::internal(err.to_string())
    }
}

fn to_pb_builder(stats: leaderboard::BuilderStats) -> BuilderStats {
    BuilderStats {
        fee_recipient: stats.fee_recipient,
        builder_label: stats.builder_label,
        blocks_produced: stats.blocks_produced,
        sandwich_count: stats.sandwich_count,
        arb_count: stats.arb_count,
        other_mev_count: stats.other_mev_count,
        mev_extracted_usd: stats.mev_extracted_usd,
    }
}

fn to_pb_relay(stats: leaderboard::RelayStats) -> RelayStats {
    RelayStats {
        relay: stats.relay,
        blocks_delivered: stats.blocks_delivered,
        sandwich_count: stats.sandwich_count,
        arb_count: stats.arb_count,
        other_mev_count: stats.other_mev_count,
        mev_extracted_usd: stats.mev_extracted_usd,
        sandwich_share: stats.sandwich_share,
        arb_share: stats.arb_share,
        other_mev_share: stats.other_mev_share,
    }
}

fn to_pb_label(label: &LabelRecord) -> Label {
    Label {
        label_id: label.label_id.to_string(),
        kind: <&'static str>::from(label.kind).to_owned(),
        value: label.value.clone(),
        confidence: label.confidence.get(),
        source: <&'static str>::from(label.source).to_owned(),
        source_detail: label.source_detail.clone(),
        created_at_unix_millis: millis(label.created_at),
        valid_until_unix_millis: label.valid_until.map(millis),
    }
}

#[tonic::async_trait]
impl IntelligenceRead for IntelligenceReadService {
    async fn get_risk_score(
        &self,
        request: Request<RiskScoreRequest>,
    ) -> Result<Response<RiskScoreReply>, Status> {
        let address = parse_address(&request.into_inner().address)?;

        if let Ok(Some(cached)) = self.cache.score(&address, MODEL_VERSION).await {
            return Ok(Response::new(RiskScoreReply {
                score: u32::from(cached.score),
                confidence: cached.confidence.get(),
                model_version: cached.model_version,
                computed_at_unix_millis: millis(cached.computed_at),
            }));
        }

        let as_of = Utc::now();
        let (entity_id, inputs) = risk_scorer::load_risk_inputs(&self.stores, &address, as_of)
            .await
            .map_err(status_for)?;
        let result = risk::score(address, entity_id, &inputs, as_of);

        // Best-effort repopulate — a failed cache write never fails the read,
        // but it's worth knowing about (an ops-visible Redis blip), not silent.
        if let Err(err) = self
            .cache
            .put_score(
                &address,
                &CachedScore {
                    score: result.score,
                    confidence: result.confidence,
                    model_version: result.model_version.clone(),
                    computed_at: as_of,
                },
            )
            .await
        {
            tracing::warn!(
                error = %err,
                address = %model::address_key(&address),
                "failed to populate the risk-score cache after a live compute"
            );
        }

        Ok(Response::new(RiskScoreReply {
            score: u32::from(result.score),
            confidence: result.confidence.get(),
            model_version: result.model_version,
            computed_at_unix_millis: millis(as_of),
        }))
    }

    async fn get_labels(
        &self,
        request: Request<LabelsRequest>,
    ) -> Result<Response<LabelsReply>, Status> {
        let address = parse_address(&request.into_inner().address)?;

        if let Ok(Some(cached)) = self.cache.labels(&address).await {
            return Ok(Response::new(LabelsReply {
                labels: cached.iter().map(to_pb_label).collect(),
            }));
        }

        let labels = self
            .stores
            .labels
            .labels_for(&address, Utc::now())
            .await
            .map_err(status_for)?;

        if let Err(err) = self.cache.put_labels(&address, &labels).await {
            tracing::warn!(
                error = %err,
                address = %model::address_key(&address),
                "failed to populate the labels cache after a live read"
            );
        }

        Ok(Response::new(LabelsReply {
            labels: labels.iter().map(to_pb_label).collect(),
        }))
    }

    async fn get_builder_leaderboard(
        &self,
        request: Request<BuilderLeaderboardRequest>,
    ) -> Result<Response<BuilderLeaderboardReply>, Status> {
        let request = request.into_inner();
        let query = LeaderboardQuery {
            chain: events::primitives::Chain(request.chain),
            limit: Limit::new(request.limit),
            since: request
                .since_unix_millis
                .and_then(DateTime::<Utc>::from_timestamp_millis),
        };

        let board = self
            .leaderboard
            .leaderboard(&query)
            .await
            .map_err(status_for)?;

        Ok(Response::new(BuilderLeaderboardReply {
            builders: board.builders.into_iter().map(to_pb_builder).collect(),
            relays: board.relays.into_iter().map(to_pb_relay).collect(),
        }))
    }

    async fn get_entity_graph(
        &self,
        request: Request<EntityGraphRequest>,
    ) -> Result<Response<EntityGraphReply>, Status> {
        let request = request.into_inner();
        let entity_id = parse_entity_id(&request.entity_id)?;
        let chain = Chain(request.chain);
        let limits = self.graph_limits.clamp_hops(request.hops);

        let walked = graph::entity_graph(
            GraphSeams {
                graph: self.graph.clone(),
                entities: self.stores.entities.as_ref(),
            },
            chain,
            entity_id,
            limits,
        )
        .await
        .map_err(status_for)?;

        let Some(g) = walked else {
            // Unknown entity — reported as `found = false` so the edge answers
            // a clean 404 (not an error status a retry policy would act on).
            metrics::counter!(ENTITY_GRAPH_REQUESTS, "found" => "false").increment(1);
            return Ok(Response::new(EntityGraphReply {
                found: false,
                ..Default::default()
            }));
        };

        metrics::counter!(ENTITY_GRAPH_REQUESTS, "found" => "true").increment(1);
        metrics::histogram!(ENTITY_GRAPH_NODES).record(g.nodes.len() as f64);
        for reason in &g.truncation {
            metrics::counter!(ENTITY_GRAPH_TRUNCATIONS, "reason" => <&'static str>::from(*reason))
                .increment(1);
        }

        let truncated = g.truncated();
        Ok(Response::new(EntityGraphReply {
            found: true,
            seeds: g.seeds.iter().map(model::address_key).collect(),
            nodes: g
                .nodes
                .into_iter()
                .map(|n| GraphNode {
                    address: model::address_key(&n.address),
                    hop: n.hop,
                    is_seed: n.is_seed,
                    is_hub: n.is_hub,
                })
                .collect(),
            edges: g
                .edges
                .into_iter()
                .map(|e| GraphEdge {
                    from: model::address_key(&e.from),
                    to: model::address_key(&e.to),
                })
                .collect(),
            truncated,
            truncation_reasons: g
                .truncation
                .iter()
                .map(|r| <&'static str>::from(*r).to_owned())
                .collect(),
        }))
    }

    async fn get_entity_timeline(
        &self,
        request: Request<EntityTimelineRequest>,
    ) -> Result<Response<EntityTimelineReply>, Status> {
        let entity_id = parse_entity_id(&request.into_inner().entity_id)?;

        let milestones = timeline::entity_timeline(&self.stores, entity_id)
            .await
            .map_err(status_for)?;

        let Some(milestones) = milestones else {
            metrics::counter!(ENTITY_TIMELINE_REQUESTS, "found" => "false").increment(1);
            return Ok(Response::new(EntityTimelineReply {
                found: false,
                ..Default::default()
            }));
        };

        metrics::counter!(ENTITY_TIMELINE_REQUESTS, "found" => "true").increment(1);
        metrics::histogram!(ENTITY_TIMELINE_MILESTONES).record(milestones.len() as f64);

        Ok(Response::new(EntityTimelineReply {
            found: true,
            milestones: milestones
                .into_iter()
                .map(|m| TimelineMilestone {
                    kind: <&'static str>::from(m.kind).to_owned(),
                    occurred_at_unix_millis: millis(m.occurred_at),
                    address: m.address.as_ref().map(model::address_key).unwrap_or_default(),
                    summary: m.summary,
                    reference: m.reference.unwrap_or_default(),
                })
                .collect(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_primitives::Address;

    use super::*;
    use crate::cache::HotCache;
    use crate::leaderboard::Leaderboard;
    use crate::model::{AdjacencyEdge, EdgeKind, LabelKind, LabelRecord, LabelSource};
    use crate::store::{EntityStore, LabelStore};
    use crate::test_util::{
        store_seams, FixedLeaderboard, InMemoryAdjacency, InMemoryHotCache,
        InMemoryIntelligenceStore,
    };

    fn service() -> (
        IntelligenceReadService,
        Arc<InMemoryIntelligenceStore>,
        Arc<InMemoryHotCache>,
    ) {
        let store = Arc::new(InMemoryIntelligenceStore::new());
        let cache = Arc::new(InMemoryHotCache::new());
        let leaderboard = Arc::new(FixedLeaderboard::new(Leaderboard::default()));
        let graph = Arc::new(InMemoryAdjacency::new());
        let service = IntelligenceReadService::new(
            store_seams(&store),
            cache.clone(),
            leaderboard,
            graph,
            GraphLimits::default(),
        );
        (service, store, cache)
    }

    /// A service wired to a leaderboard double so the RPC's request mapping and
    /// reply mapping can be asserted without a live ClickHouse.
    fn service_with_leaderboard(
        board: Leaderboard,
    ) -> (IntelligenceReadService, Arc<FixedLeaderboard>) {
        let store = Arc::new(InMemoryIntelligenceStore::new());
        let cache = Arc::new(InMemoryHotCache::new());
        let leaderboard = Arc::new(FixedLeaderboard::new(board));
        let graph = Arc::new(InMemoryAdjacency::new());
        let service = IntelligenceReadService::new(
            store_seams(&store),
            cache,
            leaderboard.clone(),
            graph,
            GraphLimits::default(),
        );
        (service, leaderboard)
    }

    /// A service sharing one store + one adjacency double, so an entity-graph
    /// RPC test can seed both the membership and the edges it walks.
    fn service_with_graph() -> (
        IntelligenceReadService,
        Arc<InMemoryIntelligenceStore>,
        Arc<InMemoryAdjacency>,
    ) {
        let store = Arc::new(InMemoryIntelligenceStore::new());
        let cache = Arc::new(InMemoryHotCache::new());
        let leaderboard = Arc::new(FixedLeaderboard::new(Leaderboard::default()));
        let graph = Arc::new(InMemoryAdjacency::new());
        let service = IntelligenceReadService::new(
            store_seams(&store),
            cache,
            leaderboard,
            graph.clone(),
            GraphLimits::default(),
        );
        (service, store, graph)
    }

    #[tokio::test]
    async fn risk_score_cache_hit_skips_the_store() {
        let (service, _store, cache) = service();
        let address = Address::repeat_byte(0xAB);
        let cached = CachedScore {
            score: 42,
            confidence: events::primitives::Confidence::new(0.9),
            model_version: MODEL_VERSION.to_owned(),
            computed_at: Utc::now(),
        };
        cache.put_score(&address, &cached).await.unwrap();

        let reply = service
            .get_risk_score(Request::new(RiskScoreRequest {
                address: format!("{address:#x}"),
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(reply.score, 42);
        assert_eq!(reply.model_version, MODEL_VERSION);
    }

    #[tokio::test]
    async fn risk_score_cache_miss_computes_live_and_populates_cache() {
        let (service, _store, cache) = service();
        let address = Address::repeat_byte(0xCD);

        // No labels/sanctions/entity on record: the pure kernel's documented
        // "no evidence" answer is 0/100 at confidence 0.0.
        let reply = service
            .get_risk_score(Request::new(RiskScoreRequest {
                address: format!("{address:#x}"),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reply.score, 0);
        assert_eq!(reply.model_version, MODEL_VERSION);

        let cached = cache.score(&address, MODEL_VERSION).await.unwrap();
        assert!(cached.is_some(), "a cache miss should populate the cache");
    }

    #[tokio::test]
    async fn labels_cache_miss_reads_the_store_and_populates_cache() {
        let (service, store, cache) = service();
        let address = Address::repeat_byte(0xEF);
        let label = LabelRecord::new(
            address,
            LabelKind::MevBot,
            "known bot",
            LabelSource::Manual,
            "operator:test",
            Utc::now(),
        );
        store.add_label(&label).await.unwrap();

        let reply = service
            .get_labels(Request::new(LabelsRequest {
                address: format!("{address:#x}"),
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(reply.labels.len(), 1);
        assert_eq!(reply.labels[0].value, "known bot");

        let cached = cache.labels(&address).await.unwrap();
        assert!(cached.is_some(), "a cache miss should populate the cache");
    }

    #[tokio::test]
    async fn labels_cache_hit_skips_the_store() {
        let (service, _store, cache) = service();
        let address = Address::repeat_byte(0x12);
        let label = LabelRecord::new(
            address,
            LabelKind::CexWallet,
            "cached label",
            LabelSource::Manual,
            "operator:test",
            Utc::now(),
        );
        cache.put_labels(&address, &[label]).await.unwrap();

        let reply = service
            .get_labels(Request::new(LabelsRequest {
                address: format!("{address:#x}"),
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(reply.labels.len(), 1);
        assert_eq!(reply.labels[0].value, "cached label");
    }

    #[test]
    fn invalid_address_is_rejected() {
        assert!(parse_address("not-an-address").is_err());
    }

    #[test]
    fn status_for_maps_transient_to_unavailable_and_permanent_to_internal() {
        use crate::store::StoreError;

        // A pool timeout is transient — a retryable UNAVAILABLE.
        let transient = status_for(StoreError::Postgres(sqlx::Error::PoolTimedOut));
        assert_eq!(transient.code(), tonic::Code::Unavailable);

        // A missing column is permanent — INTERNAL (retrying won't help).
        let permanent = status_for(StoreError::Postgres(sqlx::Error::ColumnNotFound(
            "nope".into(),
        )));
        assert_eq!(permanent.code(), tonic::Code::Internal);
    }

    #[tokio::test]
    async fn builder_leaderboard_maps_request_and_reply() {
        use crate::leaderboard::{BuilderStats, RelayStats};

        let board = Leaderboard {
            builders: vec![BuilderStats {
                fee_recipient: "0xbeaver".to_owned(),
                builder_label: "beaverbuild".to_owned(),
                blocks_produced: 100,
                sandwich_count: 42,
                arb_count: 30,
                other_mev_count: 5,
                mev_extracted_usd: 123_456.0,
            }],
            relays: vec![RelayStats {
                relay: "flashbots".to_owned(),
                blocks_delivered: 80,
                sandwich_count: 40,
                arb_count: 20,
                other_mev_count: 3,
                mev_extracted_usd: 90_000.0,
                sandwich_share: 0.8,
                arb_share: 0.5,
                other_mev_share: 0.6,
            }],
        };
        let (service, double) = service_with_leaderboard(board);

        let reply = service
            .get_builder_leaderboard(Request::new(BuilderLeaderboardRequest {
                chain: 1,
                limit: 10,
                since_unix_millis: Some(1_700_000_000_000),
            }))
            .await
            .unwrap()
            .into_inner();

        // Request mapping reached the store verbatim.
        let query = double.last_query().expect("the RPC queried the store");
        assert_eq!(query.chain.id(), 1);
        assert_eq!(query.limit.get(), 10);
        assert_eq!(query.since.unwrap().timestamp_millis(), 1_700_000_000_000);

        // Reply mapping preserved every field.
        assert_eq!(reply.builders.len(), 1);
        assert_eq!(reply.builders[0].fee_recipient, "0xbeaver");
        assert_eq!(reply.builders[0].builder_label, "beaverbuild");
        assert_eq!(reply.builders[0].sandwich_count, 42);
        assert_eq!(reply.relays.len(), 1);
        assert_eq!(reply.relays[0].relay, "flashbots");
        assert!((reply.relays[0].sandwich_share - 0.8).abs() < 1e-9);
    }

    #[tokio::test]
    async fn builder_leaderboard_without_since_is_all_history() {
        let (service, double) = service_with_leaderboard(Leaderboard::default());

        service
            .get_builder_leaderboard(Request::new(BuilderLeaderboardRequest {
                chain: 1,
                limit: 0,
                since_unix_millis: None,
            }))
            .await
            .unwrap();

        assert!(double.last_query().unwrap().since.is_none());
    }

    // ── entity graph + timeline (§8.2/§11) ───────────────────────────

    /// Seed a fresh entity owning `seed` and return its id.
    async fn seed_entity(store: &InMemoryIntelligenceStore, seed: Address) -> EntityId {
        let id = EntityId::new();
        store
            .create_entity(id, &seed, "test", Utc::now())
            .await
            .unwrap();
        id
    }

    #[tokio::test]
    async fn entity_graph_walks_membership_and_maps_the_reply() {
        use crate::adjacency::AdjacencyStore;
        use chrono::DateTime;

        let (service, store, graph) = service_with_graph();
        let seed = Address::repeat_byte(0x01);
        let neighbor = Address::repeat_byte(0x02);

        let entity_id = seed_entity(&store, seed).await;
        graph
            .append(&[AdjacencyEdge {
                chain: events::primitives::Chain::ETHEREUM,
                src: seed,
                dst: neighbor,
                kind: EdgeKind::Interacted,
                evidence: "0xtx".into(),
                block_number: 1,
                observed_at: DateTime::<Utc>::from_timestamp(1, 0).unwrap(),
            }])
            .await
            .unwrap();

        let reply = service
            .get_entity_graph(Request::new(EntityGraphRequest {
                entity_id: entity_id.to_string(),
                chain: 1,
                hops: 1,
            }))
            .await
            .unwrap()
            .into_inner();

        assert!(reply.found);
        assert_eq!(reply.seeds, vec![model::address_key(&seed)]);
        assert_eq!(reply.nodes.len(), 2);
        let seed_node = reply
            .nodes
            .iter()
            .find(|n| n.address == model::address_key(&seed))
            .unwrap();
        assert!(seed_node.is_seed && seed_node.hop == 0);
        assert_eq!(reply.edges.len(), 1);
        assert_eq!(reply.edges[0].from, model::address_key(&seed));
        assert_eq!(reply.edges[0].to, model::address_key(&neighbor));
    }

    #[tokio::test]
    async fn entity_graph_unknown_entity_is_found_false() {
        let (service, _store, _graph) = service_with_graph();
        let reply = service
            .get_entity_graph(Request::new(EntityGraphRequest {
                entity_id: EntityId::new().to_string(),
                chain: 1,
                hops: 3,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!reply.found);
        assert!(reply.nodes.is_empty());
    }

    #[tokio::test]
    async fn entity_timeline_projects_first_seen_and_maps_the_reply() {
        let (service, store, _graph) = service_with_graph();
        let seed = Address::repeat_byte(0x01);
        let entity_id = seed_entity(&store, seed).await;
        let label = LabelRecord::new(
            seed,
            LabelKind::MevBot,
            "jared",
            LabelSource::ExternalFeed,
            "feed",
            Utc::now(),
        );
        store.add_label(&label).await.unwrap();

        let reply = service
            .get_entity_timeline(Request::new(EntityTimelineRequest {
                entity_id: entity_id.to_string(),
            }))
            .await
            .unwrap()
            .into_inner();

        assert!(reply.found);
        assert_eq!(reply.milestones[0].kind, "first_seen");
        assert!(reply.milestones.iter().any(|m| m.kind == "labeled"
            && m.address == model::address_key(&seed)
            && m.summary.contains("mev_bot")));
    }

    #[tokio::test]
    async fn entity_timeline_unknown_entity_is_found_false() {
        let (service, _store, _graph) = service_with_graph();
        let reply = service
            .get_entity_timeline(Request::new(EntityTimelineRequest {
                entity_id: EntityId::new().to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!reply.found);
    }

    #[test]
    fn invalid_entity_id_is_rejected() {
        assert_eq!(
            parse_entity_id("not-a-uuid").unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }
}
