//! The `IntelligenceRead` gRPC service (§11): the synchronous read lookups a
//! caller reaches in-network — an address's current risk score, its active
//! labels, the single-round-trip screening bundle behind
//! `POST /v1/address/{addr}/screen` (`GetScreeningFacts`, Sprint 14 t1), and
//! the §10 builder/relay leaderboard (`GetBuilderLeaderboard`, Sprint 11 t2).
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
use events::intelligence::{RiskFactor, RiskScoreUpdated};
use events::primitives::{AccountAddress, Chain, EntityId};
use tonic::{Request, Response, Status};

use crate::adjacency::AdjacencyStore;
use crate::baseline_cache::BaselineSnapshot;
use crate::cache::{CacheError, CachedScore, CachedScreeningFacts, HotCache};
use crate::embedding::BehaviorSchema;
use crate::embedding_store::EmbeddingStore;
use crate::graph::{self, GraphLimits, GraphSeams};
use crate::leaderboard::{self, LeaderboardQuery, LeaderboardStore, Limit};
use crate::link_candidate::{LinkCandidateStore, StoredLink};
use crate::model::{self, LabelRecord, SanctionEntry};
use crate::pb::intelligence_read_server::IntelligenceRead;
use crate::pb::{
    BuilderLeaderboardReply, BuilderLeaderboardRequest, BuilderStats, EntityGraphReply,
    EntityGraphRequest, EntityTimelineReply, EntityTimelineRequest, GraphEdge, GraphNode, Label,
    LabelsReply, LabelsRequest, LinkCandidate as PbLinkCandidate, LinkCandidatesReply,
    LinkCandidatesRequest, LinkFactor as PbLinkFactor, RelayStats, RiskFactor as PbRiskFactor,
    RiskScoreReply, RiskScoreRequest, SanctionMatch, ScreeningFactsReply, ScreeningFactsRequest,
    SimilarAddress as PbSimilarAddress, SimilarAddressesReply, SimilarAddressesRequest,
    SimilarityFactor as PbSimilarityFactor, TimelineMilestone,
};
use crate::risk::{self, MODEL_VERSION};
use crate::risk_scorer;
use crate::similarity::{self, SimilarityLimits};
use crate::store::StoreSeams;
use crate::timeline;

/// One stored candidate link → its wire form.
///
/// A free function taking the value by move, not a closure inside the handler:
/// [`StoredLink`] derefs to its [`Proposal`] for *reads*, which is what makes
/// listings readable, but a wire mapping moves every `String` out — so it
/// destructures explicitly rather than fighting the deref.
fn link_candidate_to_wire(row: StoredLink) -> PbLinkCandidate {
    let StoredLink {
        proposal,
        status,
        decision,
        // Not on the wire: whether the *event* went out is this service's
        // internal delivery bookkeeping, not a fact about the link. A caller
        // reading a proposal has already received it by another route.
        announced_at: _,
    } = row;
    PbLinkCandidate {
        candidate_id: proposal.candidate_id.to_string(),
        address_a: model::address_key(&proposal.address_a),
        address_b: model::address_key(&proposal.address_b),
        anchor: model::address_key(&proposal.anchor),
        anchor_labels: proposal
            .anchor_labels
            .iter()
            .map(|kind| <&str>::from(*kind).to_owned())
            .collect(),
        // `''` is the wire's absent-entity flattening; a blank uuid string
        // would read as an entity whose id happens to be empty.
        entity_a: proposal
            .entity_a
            .map(|id| id.to_string())
            .unwrap_or_default(),
        entity_b: proposal
            .entity_b
            .map(|id| id.to_string())
            .unwrap_or_default(),
        similarity: proposal.similarity.get(),
        confidence: proposal.confidence.get(),
        embedding_version: proposal.embedding_version,
        schema_hash: proposal.schema_hash,
        factors: proposal
            .factors
            .into_iter()
            .map(|factor| PbLinkFactor {
                feature: factor.feature,
                subject_value: factor.subject_value,
                candidate_value: factor.candidate_value,
                contribution: factor.contribution,
            })
            .collect(),
        status: <&str>::from(status).to_owned(),
        proposed_at_unix_millis: millis(proposal.proposed_at),
        last_seen_at_unix_millis: millis(proposal.last_seen_at),
        // One `Option<Decision>` flattens into the wire's three absent-value
        // defaults — rather than three independently nullable fields that could
        // disagree with each other about whether a decision exists.
        decided_at_unix_millis: decision.as_ref().map(|d| millis(d.at)).unwrap_or_default(),
        decided_by: decision.as_ref().map(|d| d.by.clone()).unwrap_or_default(),
        decision_note: decision.and_then(|d| d.note).unwrap_or_default(),
    }
}

/// Everything the §20.3 similarity read needs, bundled so the service
/// constructor keeps one parameter per subsystem rather than three per one.
///
/// `schema` pins the **one** version this node serves comparisons under. The
/// roster can hold several (a v2 shadow rollout writes both), but a score is
/// only meaningful within a single feature space, so cutting the read over is
/// a deliberate config change here — never a per-request choice, and never a
/// silent "whatever is newest".
#[derive(Clone)]
pub struct SimilaritySeams {
    pub embeddings: Arc<dyn EmbeddingStore>,
    pub schema: &'static BehaviorSchema,
    pub limits: SimilarityLimits,
    /// The process-wide population baseline, refreshed on a timer rather than
    /// read per request — see [`crate::baseline_cache`]. Shared, so a
    /// background refresh is visible to every in-flight handler.
    pub baseline: Arc<BaselineSnapshot>,
    /// Bounds how many similarity searches run concurrently — the **bulkhead**.
    ///
    /// This endpoint is the most expensive read the service serves (an ANN
    /// scan plus a bounded re-rank), and it shares a ClickHouse and a gRPC
    /// server with `GetScreeningFacts`, which carries a p50 < 100ms SLO (§19).
    /// Without a ceiling, a burst here degrades *that* — an endpoint taking
    /// down a neighbour it has no relationship with. Shedding beyond the limit
    /// keeps the blast radius inside this RPC.
    pub permits: Arc<tokio::sync::Semaphore>,
}

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
    /// The §20.3 behavioral-similarity read: the embedding store, the schema
    /// version comparisons are served under, and the search bounds.
    similarity: SimilaritySeams,
    /// The §20.3 clustering signal's proposal table — a plain keyed read, not
    /// a computation: the expensive part already happened in the `link-signal`
    /// consumer, which is exactly why the proposals are materialized.
    links: Arc<dyn LinkCandidateStore>,
}

impl IntelligenceReadService {
    pub fn new(
        stores: StoreSeams,
        cache: Arc<dyn HotCache>,
        leaderboard: Arc<dyn LeaderboardStore>,
        graph: Arc<dyn AdjacencyStore>,
        graph_limits: GraphLimits,
        similarity: SimilaritySeams,
        links: Arc<dyn LinkCandidateStore>,
    ) -> Self {
        Self {
            stores,
            cache,
            leaderboard,
            graph,
            graph_limits,
            similarity,
            links,
        }
    }

    /// The shared cache-miss path: fetch every input, run the pure kernel,
    /// record the recompute histogram. Both `get_risk_score` and
    /// `get_screening_facts` answer their misses through this one method so
    /// the load-inputs → score → metrics sequence can never drift between
    /// them (which caches each repopulates from the result stays their own
    /// decision).
    async fn recompute_risk(&self, address: &AccountAddress) -> Result<Recomputed, Status> {
        let as_of = Utc::now();
        let recompute_started = std::time::Instant::now();
        let (entity_id, inputs) = risk_scorer::load_risk_inputs(&self.stores, address, as_of)
            .await
            .map_err(status_for)?;
        let result = risk::score(*address, entity_id, &inputs, as_of);
        metrics::histogram!(SCORE_RECOMPUTE_DURATION_SECONDS)
            .record(recompute_started.elapsed().as_secs_f64());
        Ok(Recomputed {
            as_of,
            entity_id,
            inputs,
            result,
        })
    }
}

/// The product of one live risk recompute — the scored result plus the raw
/// inputs it was computed from (the screening path caches those too).
struct Recomputed {
    as_of: DateTime<Utc>,
    entity_id: Option<EntityId>,
    inputs: risk::RiskInputs,
    result: RiskScoreUpdated,
}

/// The score-cache entry for a freshly computed result.
fn cached_score(result: &RiskScoreUpdated, computed_at: DateTime<Utc>) -> CachedScore {
    CachedScore {
        score: result.score,
        confidence: result.confidence,
        model_version: result.model_version.clone(),
        computed_at,
    }
}

/// Best-effort cache repopulation after a live compute: a failed write never
/// fails the read, but it is an ops-visible Redis fault, not something to
/// swallow silently.
fn warn_on_cache_fault(
    result: Result<(), CacheError>,
    cache: &'static str,
    address: &AccountAddress,
) {
    if let Err(err) = result {
        tracing::warn!(
            error = %err,
            cache,
            address = %model::address_key(address),
            "failed to populate a hot cache after a live compute"
        );
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
/// Similarity searches, labelled `outcome`: `served` (a ranking was produced),
/// `shed` (rejected by the concurrency bulkhead), `not_found` (the subject has
/// never been embedded), or the
/// [`Unavailable`](similarity::Unavailable) reason the search could not run
/// (`no_baseline`/`no_signal`). `no_baseline` climbing is the alert that the
/// `embedding-baseline` run mode has stopped — the one failure here that looks
/// like a normal empty answer from the outside.
/// Candidate-link listings served — cheap (a keyed read), counted anyway so
/// the §20.3 investigation surface's usage is visible beside the search's.
const LINK_CANDIDATE_REQUESTS: &str = "intelligence_link_candidate_requests_total";

/// Proposals returned per listing. The distribution says whether the signal is
/// producing a usable triage queue or a firehose.
const LINK_CANDIDATE_RESULTS: &str = "intelligence_link_candidate_results";

/// Proposals returned when the caller names no limit.
const LINK_CANDIDATES_DEFAULT: u32 = 20;

/// Hard ceiling on one listing — a bounded investigation read, not a dump of
/// the proposal table.
const LINK_CANDIDATES_MAX: u32 = 200;

const SIMILARITY_REQUESTS: &str = "intelligence_similarity_requests_total";
/// Distribution of the neighbour count a search returned.
const SIMILARITY_RESULTS: &str = "intelligence_similarity_results";
/// Searches whose candidate shortlist filled its cap, so a better neighbour
/// may have been missed — the recall knob's feedback signal. Rate against
/// `SIMILARITY_REQUESTS{outcome="served"}` in PromQL.
const SIMILARITY_APPROXIMATE: &str = "intelligence_similarity_approximate_total";
/// Risk-score/labels cache reads, labelled `cache` (`risk_score`/`labels`) and
/// `outcome` (`hit`/`miss`) — the §19 "label cache hit rate" panel, derived in
/// PromQL as `hit / (hit + miss)` per `cache` label.
const CACHE_REQUESTS_TOTAL: &str = "intelligence_cache_requests_total";
/// Wall-clock latency of a live risk-score recompute (`risk_scorer::load_risk_inputs`
/// + `risk::score`) — only sampled on a cache miss, since a hit never reaches it.
const SCORE_RECOMPUTE_DURATION_SECONDS: &str = "intelligence_score_recompute_duration_seconds";

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

fn to_pb_sanction(entry: &SanctionEntry) -> SanctionMatch {
    SanctionMatch {
        list: entry.list_name.clone(),
        entry: entry.entry.clone(),
    }
}

fn to_pb_risk_factor(factor: &RiskFactor) -> PbRiskFactor {
    PbRiskFactor {
        name: factor.name.clone(),
        delta: factor.delta,
        evidence_ref: factor.evidence_ref.clone(),
    }
}

fn to_pb_screening(facts: &CachedScreeningFacts) -> ScreeningFactsReply {
    ScreeningFactsReply {
        score: u32::from(facts.score),
        confidence: facts.confidence.get(),
        model_version: facts.model_version.clone(),
        computed_at_unix_millis: millis(facts.computed_at),
        sanctions: facts.sanctions.iter().map(to_pb_sanction).collect(),
        labels: facts.labels.iter().map(to_pb_label).collect(),
        entity_id: facts.entity_id.map(|id| id.to_string()),
        entity_size: facts.entity_size,
        factors: facts.factors.iter().map(to_pb_risk_factor).collect(),
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
            metrics::counter!(CACHE_REQUESTS_TOTAL, "cache" => "risk_score", "outcome" => "hit")
                .increment(1);
            return Ok(Response::new(RiskScoreReply {
                score: u32::from(cached.score),
                confidence: cached.confidence.get(),
                model_version: cached.model_version,
                computed_at_unix_millis: millis(cached.computed_at),
            }));
        }
        metrics::counter!(CACHE_REQUESTS_TOTAL, "cache" => "risk_score", "outcome" => "miss")
            .increment(1);

        let recomputed = self.recompute_risk(&address).await?;
        warn_on_cache_fault(
            self.cache
                .put_score(
                    &address,
                    &cached_score(&recomputed.result, recomputed.as_of),
                )
                .await,
            "risk_score",
            &address,
        );

        Ok(Response::new(RiskScoreReply {
            score: u32::from(recomputed.result.score),
            confidence: recomputed.result.confidence.get(),
            model_version: recomputed.result.model_version,
            computed_at_unix_millis: millis(recomputed.as_of),
        }))
    }

    async fn get_labels(
        &self,
        request: Request<LabelsRequest>,
    ) -> Result<Response<LabelsReply>, Status> {
        let address = parse_address(&request.into_inner().address)?;

        if let Ok(Some(cached)) = self.cache.labels(&address).await {
            metrics::counter!(CACHE_REQUESTS_TOTAL, "cache" => "labels", "outcome" => "hit")
                .increment(1);
            return Ok(Response::new(LabelsReply {
                labels: cached.iter().map(to_pb_label).collect(),
            }));
        }
        metrics::counter!(CACHE_REQUESTS_TOTAL, "cache" => "labels", "outcome" => "miss")
            .increment(1);

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

    /// The §11 screening lookup: every decision input for one address in a
    /// single round-trip. A [`HotCache::screening_facts`] hit answers from
    /// one Redis `GET` (the p50 < 100ms path); a miss runs the same
    /// [`risk_scorer::load_risk_inputs`] → [`risk::score`] pass as
    /// `get_risk_score` — which fetches the labels/sanctions/entity anyway —
    /// and repopulates both the bundle and the plain score cache from that
    /// one store pass. Facts only: the allow/review/block decision (and the
    /// §8.5 hard-block override) belongs to the caller's policy layer.
    async fn get_screening_facts(
        &self,
        request: Request<ScreeningFactsRequest>,
    ) -> Result<Response<ScreeningFactsReply>, Status> {
        let address = parse_address(&request.into_inner().address)?;

        if let Ok(Some(cached)) = self.cache.screening_facts(&address).await {
            metrics::counter!(CACHE_REQUESTS_TOTAL, "cache" => "screening_facts", "outcome" => "hit")
                .increment(1);
            return Ok(Response::new(to_pb_screening(&cached)));
        }
        metrics::counter!(CACHE_REQUESTS_TOTAL, "cache" => "screening_facts", "outcome" => "miss")
            .increment(1);

        let recomputed = self.recompute_risk(&address).await?;
        let facts = CachedScreeningFacts {
            score: recomputed.result.score,
            confidence: recomputed.result.confidence,
            model_version: recomputed.result.model_version.clone(),
            computed_at: recomputed.as_of,
            entity_id: recomputed.entity_id,
            entity_size: recomputed
                .inputs
                .entity
                .as_ref()
                .map(|e| e.addresses.len() as u32)
                .unwrap_or(0),
            sanctions: recomputed.inputs.sanctions,
            labels: recomputed.inputs.labels,
            factors: recomputed.result.factors.clone(),
        };

        // Best-effort repopulate of the bundle *and* the plain score cache —
        // the miss just computed a fresh score, so `get_risk_score` may as
        // well benefit.
        warn_on_cache_fault(
            self.cache.put_screening_facts(&address, &facts).await,
            "screening_facts",
            &address,
        );
        warn_on_cache_fault(
            self.cache
                .put_score(
                    &address,
                    &cached_score(&recomputed.result, recomputed.as_of),
                )
                .await,
            "risk_score",
            &address,
        );

        Ok(Response::new(to_pb_screening(&facts)))
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

    async fn get_similar_addresses(
        &self,
        request: Request<SimilarAddressesRequest>,
    ) -> Result<Response<SimilarAddressesReply>, Status> {
        let request = request.into_inner();
        let address = parse_address(&request.address)?;
        let chain = Chain(request.chain);
        let schema = self.similarity.schema;
        // One clock reading for the whole request: the baseline's staleness
        // and the cache's must be judged against the same instant.
        let now = Utc::now();

        // Bulkhead. `try_acquire` sheds instead of queueing: a caller waiting
        // behind a full queue for an expensive read gets a timeout either way,
        // and an unbounded wait queue is how one endpoint's burst becomes the
        // whole service's latency. RESOURCE_EXHAUSTED is the status a client
        // retry policy backs off on, and the edge maps it to 502.
        let _permit = match self.similarity.permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                metrics::counter!(SIMILARITY_REQUESTS, "outcome" => "shed").increment(1);
                return Err(Status::resource_exhausted(
                    "similarity search is at capacity; retry shortly",
                ));
            }
        };

        let found = similarity::similar_addresses(similarity::SearchRequest {
            store: self.similarity.embeddings.as_ref(),
            chain,
            address: &address,
            schema,
            baseline: self.similarity.baseline.get(now),
            limits: self.similarity.limits,
            requested_results: request.limit,
            now,
        })
        .await;

        let search = match found {
            Ok(Some(search)) => search,
            Ok(None) => {
                // Never embedded under this version — reported as
                // `found = false` so the edge answers a clean 404, the same
                // shape the entity reads use for an unknown id.
                metrics::counter!(SIMILARITY_REQUESTS, "outcome" => "not_found").increment(1);
                return Ok(Response::new(SimilarAddressesReply {
                    found: false,
                    embedding_version: schema.version().to_owned(),
                    schema_hash: schema.content_hash().to_owned(),
                    ..Default::default()
                }));
            }
            // The two data states: the address exists and the comparison does
            // not. An explained empty result, not a status a retry policy
            // would act on — see `similarity::Unavailable`.
            Err(err) => match err.unavailable() {
                Some(reason) => {
                    let label: &'static str = reason.into();
                    metrics::counter!(SIMILARITY_REQUESTS, "outcome" => label).increment(1);
                    tracing::debug!(
                        address = %model::address_key(&address),
                        chain = chain.id(),
                        reason = label,
                        "similarity search could not run",
                    );
                    return Ok(Response::new(SimilarAddressesReply {
                        found: true,
                        embedding_version: schema.version().to_owned(),
                        schema_hash: schema.content_hash().to_owned(),
                        unavailable_reason: label.to_owned(),
                        ..Default::default()
                    }));
                }
                None => return Err(status_for(err)),
            },
        };

        metrics::counter!(SIMILARITY_REQUESTS, "outcome" => "served").increment(1);
        metrics::histogram!(SIMILARITY_RESULTS).record(search.results.len() as f64);
        if search.approximate {
            metrics::counter!(SIMILARITY_APPROXIMATE).increment(1);
        }

        Ok(Response::new(SimilarAddressesReply {
            found: true,
            embedding_version: search.embedding_version,
            schema_hash: search.schema_hash,
            subject_computed_at_unix_millis: millis(search.subject_computed_at),
            results: search
                .results
                .into_iter()
                .map(|hit| PbSimilarAddress {
                    address: model::address_key(&hit.address),
                    entity_id: hit.entity_id.map(|id| id.to_string()).unwrap_or_default(),
                    // The wire is the one place the newtype unwraps.
                    similarity: hit.similarity.get(),
                    observations_truncated: hit.observations_truncated,
                    computed_at_unix_millis: millis(hit.computed_at),
                    factors: hit
                        .factors
                        .into_iter()
                        .map(|factor| PbSimilarityFactor {
                            feature: factor.feature.to_owned(),
                            subject_value: factor.subject_value,
                            candidate_value: factor.candidate_value,
                            subject_z: factor.subject_z,
                            candidate_z: factor.candidate_z,
                            contribution: factor.contribution,
                        })
                        .collect(),
                })
                .collect(),
            // Saturating rather than `as`: a count this large is impossible
            // (the shortlist is capped), and a silent wrap would understate it.
            candidates_considered: search.candidates_considered.try_into().unwrap_or(u32::MAX),
            candidates_skipped: search.candidates_skipped.try_into().unwrap_or(u32::MAX),
            approximate: search.approximate,
            unavailable_reason: String::new(),
        }))
    }

    async fn list_link_candidates(
        &self,
        request: Request<LinkCandidatesRequest>,
    ) -> Result<Response<LinkCandidatesReply>, Status> {
        let request = request.into_inner();
        let address = parse_address(&request.address)?;
        // The [`Limit`] stance: a caller asking for more than the ceiling is
        // served at the ceiling, not rejected.
        let limit = match request.limit {
            0 => LINK_CANDIDATES_DEFAULT,
            n => n.min(LINK_CANDIDATES_MAX),
        };

        let rows = self
            .links
            .links_for_address(&address, limit as usize)
            .await
            .map_err(status_for)?;

        metrics::counter!(LINK_CANDIDATE_REQUESTS).increment(1);
        metrics::histogram!(LINK_CANDIDATE_RESULTS).record(rows.len() as f64);

        Ok(Response::new(LinkCandidatesReply {
            candidates: rows.into_iter().map(link_candidate_to_wire).collect(),
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
                    address: m
                        .address
                        .as_ref()
                        .map(model::address_key)
                        .unwrap_or_default(),
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
        InMemoryIntelligenceStore, InMemoryLinkCandidateStore, RecordingEmbeddingStore,
    };

    /// Similarity seams wired to an empty double — what every test that isn't
    /// about similarity needs, so adding the subsystem didn't change what any
    /// other RPC test says.
    fn similarity_seams() -> SimilaritySeams {
        similarity_seams_over(Arc::new(RecordingEmbeddingStore::new()))
    }

    fn similarity_seams_over(embeddings: Arc<RecordingEmbeddingStore>) -> SimilaritySeams {
        seams_with_permits(embeddings, 32)
    }

    /// Seams with an explicit bulkhead width, so the shedding path is
    /// reachable from a test without saturating a real one.
    fn seams_with_permits(
        embeddings: Arc<RecordingEmbeddingStore>,
        permits: usize,
    ) -> SimilaritySeams {
        let schema = crate::embedding::default_embedder().schema();
        SimilaritySeams {
            embeddings,
            schema,
            limits: SimilarityLimits::default(),
            baseline: Arc::new(crate::baseline_cache::BaselineSnapshot::new(
                Chain::ETHEREUM,
                schema.version().to_owned(),
                crate::baseline_cache::BaselineCacheConfig::default(),
            )),
            permits: Arc::new(tokio::sync::Semaphore::new(permits)),
        }
    }

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
            similarity_seams(),
            Arc::new(InMemoryLinkCandidateStore::new()),
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
            similarity_seams(),
            Arc::new(InMemoryLinkCandidateStore::new()),
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
            similarity_seams(),
            Arc::new(InMemoryLinkCandidateStore::new()),
        );
        (service, store, graph)
    }

    // ── §20.3 behavioral similarity ─────────────────────────────────────────

    /// Seed a population of embeddings plus a baseline over it, and hand back
    /// a service reading them. `values` is applied to the first feature of an
    /// otherwise-default vector, so the population varies along one legible
    /// axis.
    async fn service_with_embeddings(
        population: &[(u8, f32)],
    ) -> (IntelligenceReadService, Arc<RecordingEmbeddingStore>) {
        use crate::embedding::{baseline, default_embedder, BehaviorInputs};
        use crate::embedding_store::EmbeddingStore;

        let embeddings = Arc::new(RecordingEmbeddingStore::new());
        let embedder = default_embedder();
        let schema = embedder.schema();

        let vectors: Vec<_> = population
            .iter()
            .map(|(byte, first)| {
                let mut vector = embedder.embed(
                    Address::repeat_byte(*byte),
                    None,
                    &BehaviorInputs::default(),
                    Utc::now(),
                );
                vector.values[0] = *first;
                vector
            })
            .collect();
        embeddings
            .append(Chain::ETHEREUM, &vectors)
            .await
            .expect("seed embeddings");

        let sample: Vec<Vec<f32>> = vectors.iter().map(|v| v.values.clone()).collect();
        // Computed *now*, not at the epoch: the snapshot refuses a baseline
        // past `max_age`, and an epoch-dated one is (correctly) ancient.
        if let Some(mut population_baseline) = baseline::compute(schema, &sample, Utc::now()) {
            // The real minimum is a population statistic; these tests are
            // about the ranking, not about how many addresses back it.
            population_baseline.sample_count = baseline::MIN_SAMPLES;
            embeddings
                .put_baseline(Chain::ETHEREUM, &population_baseline)
                .await
                .expect("seed baseline");
        }

        // The service reads the baseline from its snapshot, not from the
        // store, so seeding the store is only half the setup — the snapshot
        // has to be loaded, exactly as `main` does at boot.
        let seams = similarity_seams_over(embeddings.clone());
        seams
            .baseline
            .refresh(embeddings.as_ref(), Utc::now())
            .await
            .expect("load the baseline snapshot");

        let store = Arc::new(InMemoryIntelligenceStore::new());
        let service = IntelligenceReadService::new(
            store_seams(&store),
            Arc::new(InMemoryHotCache::new()),
            Arc::new(FixedLeaderboard::new(Leaderboard::default())),
            Arc::new(InMemoryAdjacency::new()),
            GraphLimits::default(),
            seams,
            Arc::new(InMemoryLinkCandidateStore::new()),
        );
        (service, embeddings)
    }

    async fn similar(
        service: &IntelligenceReadService,
        byte: u8,
        limit: u32,
    ) -> SimilarAddressesReply {
        service
            .get_similar_addresses(Request::new(SimilarAddressesRequest {
                address: model::address_key(&Address::repeat_byte(byte)),
                chain: Chain::ETHEREUM.id(),
                limit,
            }))
            .await
            .expect("the RPC succeeds")
            .into_inner()
    }

    /// The happy path end to end: the nearest behavior wins, the score is
    /// stamped with the schema it was computed under, and every hit carries
    /// the factors that produced it.
    #[tokio::test]
    async fn similar_addresses_ranks_neighbours_and_explains_each_one() {
        let (service, _) = service_with_embeddings(&[
            (0x11, 5.0),
            (0x22, 4.0),
            (0x33, -5.0),
            (0x44, 1.0),
            (0x55, 0.0),
        ])
        .await;

        let reply = similar(&service, 0x11, 0).await;

        assert!(reply.found);
        assert_eq!(reply.unavailable_reason, "");
        assert_eq!(
            reply.embedding_version,
            crate::embedding::v1::VERSION,
            "the reply names the feature space the scores live in"
        );
        assert_eq!(
            reply.schema_hash,
            crate::embedding::v1::SCHEMA.content_hash()
        );
        assert!(!reply.results.is_empty());

        let subject = model::address_key(&Address::repeat_byte(0x11));
        assert!(
            reply.results.iter().all(|hit| hit.address != subject),
            "an address is not its own behavioral neighbour"
        );
        // Descending, and the address that behaves most like the subject leads.
        let scores: Vec<f32> = reply.results.iter().map(|hit| hit.similarity).collect();
        assert!(scores.windows(2).all(|w| w[0] >= w[1]), "{scores:?}");
        assert_eq!(
            reply.results[0].address,
            model::address_key(&Address::repeat_byte(0x22))
        );

        let top = &reply.results[0];
        assert!(
            !top.factors.is_empty(),
            "a hit without an explanation is not an answer"
        );
        let summed: f32 = top.factors.iter().map(|f| f.contribution).sum();
        assert!(
            (summed - top.similarity).abs() < 1e-4,
            "the factors are the score's decomposition: {summed} vs {}",
            top.similarity
        );
        assert!(top.factors.iter().any(|f| !f.feature.is_empty()));
    }

    /// An address nobody has embedded is a clean miss the edge turns into a
    /// 404 — not an empty ranking, which would read as "no similar addresses".
    #[tokio::test]
    async fn an_unembedded_subject_is_found_false() {
        let (service, _) = service_with_embeddings(&[(0x11, 5.0), (0x22, 4.0)]).await;
        let reply = similar(&service, 0xEE, 0).await;
        assert!(!reply.found);
        assert!(reply.results.is_empty());
        // The version still comes back, so a caller can tell "no vector under
        // *this* version" from "no such address at all".
        assert_eq!(reply.embedding_version, crate::embedding::v1::VERSION);
    }

    /// The candidate-link listing: proposals come back strongest-first, in
    /// canonical pair order, with the anchor's evidence and the decision state
    /// — including *decided* ones, which are part of the address's story.
    #[tokio::test]
    async fn link_candidates_are_listed_strongest_first_with_their_decision_state() {
        use crate::link_candidate::{Decision, LinkFactor, LinkStatus, Proposal};
        use crate::similarity::Similarity;
        use events::primitives::{Confidence, LabelKind};

        let links = Arc::new(InMemoryLinkCandidateStore::new());
        let subject = Address::repeat_byte(0x11);
        let candidate = |anchor: u8, similarity: f64| Proposal {
            candidate_id: crate::link_candidate::link_candidate_id(
                &subject,
                &Address::repeat_byte(anchor),
                "behavior-v1",
            ),
            address_a: subject,
            address_b: Address::repeat_byte(anchor),
            anchor: Address::repeat_byte(anchor),
            anchor_labels: vec![LabelKind::KnownScammer],
            entity_a: None,
            entity_b: None,
            similarity: Similarity::new(similarity),
            confidence: Confidence::new(0.4),
            embedding_version: "behavior-v1".into(),
            schema_hash: "abc".into(),
            factors: vec![LinkFactor {
                feature: "edge_count_log".into(),
                subject_value: 1.0,
                candidate_value: 1.1,
                contribution: 0.3,
            }],
            proposed_at: Utc::now(),
            last_seen_at: Utc::now(),
        };
        links.propose_link(&candidate(0x22, 0.90)).await.unwrap();
        links.propose_link(&candidate(0x33, 0.95)).await.unwrap();
        links
            .decide_link(
                candidate(0x22, 0.90).candidate_id,
                LinkStatus::Rejected,
                &Decision {
                    by: "analyst-7".into(),
                    note: Some("same off-the-shelf arbitrage strategy".into()),
                    at: Utc::now(),
                },
            )
            .await
            .unwrap();

        let store = Arc::new(InMemoryIntelligenceStore::new());
        let service = IntelligenceReadService::new(
            store_seams(&store),
            Arc::new(InMemoryHotCache::new()),
            Arc::new(FixedLeaderboard::new(Leaderboard::default())),
            Arc::new(InMemoryAdjacency::new()),
            GraphLimits::default(),
            similarity_seams(),
            links,
        );

        let reply = service
            .list_link_candidates(Request::new(LinkCandidatesRequest {
                address: model::address_key(&subject),
                limit: 0,
            }))
            .await
            .expect("listing succeeds")
            .into_inner();

        assert_eq!(reply.candidates.len(), 2);
        assert_eq!(reply.candidates[0].similarity, 0.95, "strongest first");
        assert_eq!(reply.candidates[0].status, "proposed");
        assert_eq!(reply.candidates[0].anchor_labels, vec!["known_scammer"]);
        assert!(
            reply.candidates[0].entity_a.is_empty(),
            "an unclustered side is the empty-string flattening, not a blank uuid"
        );
        // The rejection is *kept and returned*: a pair that keeps being
        // re-proposed after a human dismissed it is how a bad threshold makes
        // itself visible.
        let rejected = &reply.candidates[1];
        assert_eq!(rejected.status, "rejected");
        assert_eq!(rejected.decided_by, "analyst-7");
        assert!(rejected.decided_at_unix_millis > 0);
    }

    /// No baseline yet is a state, not a failure: the address exists, the
    /// comparison does not, and the reply says which.
    #[tokio::test]
    async fn a_missing_baseline_is_an_explained_empty_result_not_an_error() {
        use crate::embedding::{default_embedder, BehaviorInputs};
        use crate::embedding_store::EmbeddingStore;

        let embeddings = Arc::new(RecordingEmbeddingStore::new());
        let mut vector = default_embedder().embed(
            Address::repeat_byte(0x11),
            None,
            &BehaviorInputs::default(),
            Utc::now(),
        );
        vector.values[0] = 3.0;
        embeddings
            .append(Chain::ETHEREUM, &[vector])
            .await
            .expect("seed");

        let store = Arc::new(InMemoryIntelligenceStore::new());
        let service = IntelligenceReadService::new(
            store_seams(&store),
            Arc::new(InMemoryHotCache::new()),
            Arc::new(FixedLeaderboard::new(Leaderboard::default())),
            Arc::new(InMemoryAdjacency::new()),
            GraphLimits::default(),
            similarity_seams_over(embeddings),
            Arc::new(InMemoryLinkCandidateStore::new()),
        );

        let reply = similar(&service, 0x11, 0).await;
        assert!(
            reply.found,
            "the address is embedded; only the comparison is unavailable"
        );
        assert_eq!(reply.unavailable_reason, "no_baseline");
        assert!(reply.results.is_empty());
    }

    /// An address with no recorded behavior at all has no direction to search
    /// along. Reported as such rather than as a NaN-ordered ranking of the
    /// whole population.
    #[tokio::test]
    async fn a_featureless_subject_reports_no_signal() {
        let (service, _) = service_with_embeddings(&[(0x11, 0.0), (0x22, 4.0), (0x33, 5.0)]).await;
        let reply = similar(&service, 0x11, 0).await;
        assert!(reply.found);
        assert_eq!(reply.unavailable_reason, "no_signal");
        assert!(reply.results.is_empty());
    }

    /// An over-eager `limit` is served at the ceiling, the same stance the
    /// leaderboard and the entity graph take — a reasonable request, answered.
    #[tokio::test]
    async fn a_requested_limit_is_clamped_rather_than_rejected() {
        let population: Vec<(u8, f32)> = (1..=12).map(|i| (i, i as f32)).collect();
        let (service, _) = service_with_embeddings(&population).await;

        let two = similar(&service, 0x06, 2).await;
        assert_eq!(two.results.len(), 2);

        let huge = similar(&service, 0x06, 10_000).await;
        assert!(huge.results.len() <= SimilarityLimits::default().max_results);
        assert!(huge.results.len() >= 2);
    }

    /// The bulkhead sheds rather than queues once its permits are gone.
    ///
    /// This is the property that keeps an expensive read from degrading the
    /// p50-critical screening path it shares a service with: an unbounded wait
    /// queue would convert this endpoint's burst into everyone's latency.
    /// `RESOURCE_EXHAUSTED` is what a client retry policy backs off on.
    #[tokio::test]
    async fn similarity_sheds_beyond_its_concurrency_limit() {
        let (service, embeddings) = service_with_embeddings(&[(0x11, 5.0), (0x22, 4.0)]).await;

        // Rebuild the service with a single permit, already held.
        let seams = seams_with_permits(embeddings.clone(), 1);
        seams
            .baseline
            .refresh(embeddings.as_ref(), Utc::now())
            .await
            .expect("load baseline");
        let held = seams
            .permits
            .clone()
            .try_acquire_owned()
            .expect("the only permit");

        let store = Arc::new(InMemoryIntelligenceStore::new());
        let saturated = IntelligenceReadService::new(
            store_seams(&store),
            Arc::new(InMemoryHotCache::new()),
            Arc::new(FixedLeaderboard::new(Leaderboard::default())),
            Arc::new(InMemoryAdjacency::new()),
            GraphLimits::default(),
            seams,
            Arc::new(InMemoryLinkCandidateStore::new()),
        );

        let status = saturated
            .get_similar_addresses(Request::new(SimilarAddressesRequest {
                address: model::address_key(&Address::repeat_byte(0x11)),
                chain: Chain::ETHEREUM.id(),
                limit: 0,
            }))
            .await
            .expect_err("a saturated bulkhead sheds");
        assert_eq!(status.code(), tonic::Code::ResourceExhausted);

        // Releasing the permit restores service — shedding is backpressure,
        // not a latch.
        drop(held);
        let reply = similar(&service, 0x11, 0).await;
        assert!(reply.found);
    }

    /// A stale population baseline is refused *as a state*, not served: a
    /// ranking against a population that has moved on is confident and wrong,
    /// which is worse than no ranking.
    #[tokio::test]
    async fn a_baseline_past_max_age_reports_no_baseline() {
        use crate::baseline_cache::{BaselineCacheConfig, BaselineSnapshot};

        let (_service, embeddings) = service_with_embeddings(&[(0x11, 5.0), (0x22, 4.0)]).await;
        use crate::embedding_store::EmbeddingStore;

        let schema = crate::embedding::default_embedder().schema();

        // A baseline computed ten days ago, read under a one-day ceiling —
        // the real shape of "the baseline job died last week".
        let stale_store = Arc::new(RecordingEmbeddingStore::new());
        let mut stale = crate::embedding::baseline::compute(
            schema,
            &vec![vec![0.0; schema.dimension()]; 3],
            Utc::now() - chrono::Duration::days(10),
        )
        .expect("a baseline");
        stale.sample_count = crate::embedding::baseline::MIN_SAMPLES;
        stale_store
            .put_baseline(Chain::ETHEREUM, &stale)
            .await
            .expect("seed the stale baseline");

        let expired = Arc::new(BaselineSnapshot::new(
            Chain::ETHEREUM,
            schema.version().to_owned(),
            BaselineCacheConfig {
                refresh_interval: std::time::Duration::from_secs(60),
                max_age: std::time::Duration::from_secs(24 * 60 * 60),
            },
        ));
        expired
            .refresh(stale_store.as_ref(), Utc::now())
            .await
            .expect("load");
        assert!(
            expired.get(Utc::now()).is_none(),
            "a ten-day-old baseline is past a one-day ceiling"
        );

        let store = Arc::new(InMemoryIntelligenceStore::new());
        let service = IntelligenceReadService::new(
            store_seams(&store),
            Arc::new(InMemoryHotCache::new()),
            Arc::new(FixedLeaderboard::new(Leaderboard::default())),
            Arc::new(InMemoryAdjacency::new()),
            GraphLimits::default(),
            SimilaritySeams {
                baseline: expired,
                ..seams_with_permits(embeddings.clone(), 4)
            },
            Arc::new(InMemoryLinkCandidateStore::new()),
        );

        let reply = similar(&service, 0x11, 0).await;
        assert!(
            reply.found,
            "the address exists; only the comparison does not"
        );
        assert_eq!(reply.unavailable_reason, "no_baseline");
    }

    /// End to end through the store seam: the first search materializes a
    /// ranking, the second serves it, and a baseline re-derivation
    /// invalidates it — the three states the cache exists to have.
    #[tokio::test]
    async fn a_search_materializes_then_replays_then_invalidates_on_a_new_baseline() {
        let (service, embeddings) =
            service_with_embeddings(&[(0x11, 5.0), (0x22, 4.0), (0x33, -5.0), (0x44, 1.0)]).await;

        assert_eq!(embeddings.materialized_count(), 0);

        let first = similar(&service, 0x11, 0).await;
        assert!(!first.results.is_empty());
        assert_eq!(
            embeddings.materialized_count(),
            1,
            "a live search materializes its ranking"
        );

        // Second call: same answer, served from the materialized entry.
        let second = similar(&service, 0x11, 0).await;
        assert_eq!(
            second.results.len(),
            first.results.len(),
            "a replayed ranking has the same shape"
        );
        assert_eq!(second.results[0].address, first.results[0].address);
        assert_eq!(
            second.candidates_considered, 0,
            "a cache hit reports the work this request did — none"
        );
        assert_eq!(
            embeddings.materialized_count(),
            1,
            "a hit must not rewrite the entry"
        );

        // A re-derived baseline changes the fingerprint, so the stored ranking
        // stops being usable and the next search recomputes — §20.3's
        // "re-derived baseline changes rankings" contract surviving the cache.
        let schema = crate::embedding::default_embedder().schema();
        // A *different* population, but one that still has spread: a baseline
        // of identical rows has zero spread everywhere, which standardizes the
        // subject to the zero vector and refuses the search for `no_signal` —
        // which would pass this assertion for entirely the wrong reason.
        let varied: Vec<Vec<f32>> = (0..6)
            .map(|i| {
                let mut row = vec![0.0f32; schema.dimension()];
                row[0] = i as f32 * 3.0;
                row
            })
            .collect();
        let mut moved =
            crate::embedding::baseline::compute(schema, &varied, Utc::now()).expect("a baseline");
        moved.sample_count = crate::embedding::baseline::MIN_SAMPLES;
        embeddings
            .put_baseline(Chain::ETHEREUM, &moved)
            .await
            .expect("re-derive");

        let seams = seams_with_permits(embeddings.clone(), 8);
        seams
            .baseline
            .refresh(embeddings.as_ref(), Utc::now())
            .await
            .expect("pick up the new baseline");

        let store = Arc::new(InMemoryIntelligenceStore::new());
        let rebased = IntelligenceReadService::new(
            store_seams(&store),
            Arc::new(InMemoryHotCache::new()),
            Arc::new(FixedLeaderboard::new(Leaderboard::default())),
            Arc::new(InMemoryAdjacency::new()),
            GraphLimits::default(),
            seams,
            Arc::new(InMemoryLinkCandidateStore::new()),
        );

        let after = similar(&rebased, 0x11, 0).await;
        assert!(
            after.candidates_considered > 0,
            "a superseded baseline must force a live recompute, not replay a \
             ranking produced under the old one"
        );
    }

    /// A malformed address is the caller's fault and says so — never the
    /// INTERNAL a store failure gets.
    #[tokio::test]
    async fn a_bad_address_is_invalid_argument() {
        let (service, _) = service_with_embeddings(&[(0x11, 1.0)]).await;
        let status = service
            .get_similar_addresses(Request::new(SimilarAddressesRequest {
                address: "not-an-address".into(),
                chain: Chain::ETHEREUM.id(),
                limit: 0,
            }))
            .await
            .expect_err("a malformed address is rejected");
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
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

    // ── GetScreeningFacts (§11, Sprint 14 t1) ────────────────────────

    /// A cached bundle answers without touching the stores, mapping every
    /// field onto the wire.
    #[tokio::test]
    async fn screening_facts_cache_hit_skips_the_store() {
        use crate::cache::CachedScreeningFacts;
        use crate::model::SanctionEntry;

        let (service, _store, cache) = service();
        let address = Address::repeat_byte(0xAB);
        let entity_id = EntityId::new();
        cache
            .put_screening_facts(
                &address,
                &CachedScreeningFacts {
                    score: 87,
                    confidence: events::primitives::Confidence::new(0.91),
                    model_version: MODEL_VERSION.to_owned(),
                    computed_at: Utc::now(),
                    sanctions: vec![SanctionEntry {
                        address,
                        list_name: "ofac_sdn".into(),
                        entry: "Evil Corp".into(),
                        listed_at: None,
                    }],
                    labels: vec![],
                    entity_id: Some(entity_id),
                    entity_size: 4,
                    factors: vec![RiskFactor {
                        name: "sanctions-match".into(),
                        delta: 45.0,
                        evidence_ref: "sanctions:ofac_sdn".into(),
                    }],
                },
            )
            .await
            .unwrap();

        let reply = service
            .get_screening_facts(Request::new(ScreeningFactsRequest {
                address: format!("{address:#x}"),
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(reply.score, 87);
        assert_eq!(reply.model_version, MODEL_VERSION);
        assert_eq!(reply.sanctions.len(), 1);
        assert_eq!(reply.sanctions[0].list, "ofac_sdn");
        assert_eq!(reply.sanctions[0].entry, "Evil Corp");
        assert_eq!(reply.entity_id, Some(entity_id.to_string()));
        assert_eq!(reply.entity_size, 4);
        assert_eq!(reply.factors.len(), 1);
        assert_eq!(reply.factors[0].name, "sanctions-match");
        assert_eq!(reply.factors[0].evidence_ref, "sanctions:ofac_sdn");
    }

    /// A miss computes live from the stores — sanctions, labels and entity
    /// all land in the reply — and repopulates both the bundle and the plain
    /// score cache from the one store pass.
    #[tokio::test]
    async fn screening_facts_cache_miss_computes_live_and_populates_both_caches() {
        use crate::model::SanctionEntry;
        use crate::store::SanctionsStore;

        let (service, store, cache) = service();
        let address = Address::repeat_byte(0xCD);

        store
            .seed_sanctions(&[SanctionEntry {
                address,
                list_name: "ofac_sdn".into(),
                entry: "Evil Corp".into(),
                listed_at: None,
            }])
            .await
            .unwrap();
        let label = LabelRecord::new(
            address,
            LabelKind::KnownScammer,
            "drainer",
            LabelSource::Manual,
            "operator:test",
            Utc::now(),
        );
        store.add_label(&label).await.unwrap();
        let entity_id = EntityId::new();
        store
            .create_entity(entity_id, &address, "seed", Utc::now())
            .await
            .unwrap();

        let reply = service
            .get_screening_facts(Request::new(ScreeningFactsRequest {
                address: format!("{address:#x}"),
            }))
            .await
            .unwrap()
            .into_inner();

        // sanction (45) + KnownScammer manual label (40); a singleton entity
        // adds no cluster factor but is still reported as membership.
        assert_eq!(reply.score, 85);
        assert_eq!(reply.sanctions.len(), 1);
        assert_eq!(reply.labels.len(), 1);
        assert_eq!(reply.labels[0].value, "drainer");
        assert_eq!(reply.entity_id, Some(entity_id.to_string()));
        assert_eq!(reply.entity_size, 1);
        // Two factors (sanction + label), each carrying the evidence_ref the
        // explainability contract requires (§11 Sprint 14 t3).
        assert_eq!(reply.factors.len(), 2);
        assert!(reply.factors.iter().all(|f| !f.evidence_ref.is_empty()));

        let bundle = cache.screening_facts(&address).await.unwrap();
        assert!(bundle.is_some(), "the miss should populate the bundle");
        assert_eq!(
            bundle.unwrap().factors.len(),
            2,
            "the cached bundle carries the same factor breakdown as the reply"
        );
        let score = cache.score(&address, MODEL_VERSION).await.unwrap();
        assert_eq!(
            score.map(|s| s.score),
            Some(85),
            "the same pass should populate the plain score cache"
        );
    }

    /// A clean address screens as 0/100 at confidence 0.0 with no sanctions —
    /// the kernel's documented "no evidence" answer, never an error.
    #[tokio::test]
    async fn screening_facts_for_an_unknown_address_are_clean() {
        let (service, _store, _cache) = service();
        let reply = service
            .get_screening_facts(Request::new(ScreeningFactsRequest {
                address: format!("{:#x}", Address::repeat_byte(0x77)),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reply.score, 0);
        assert_eq!(reply.confidence, 0.0);
        assert!(reply.sanctions.is_empty());
        assert!(reply.labels.is_empty());
        assert_eq!(reply.entity_id, None);
        assert!(reply.factors.is_empty());
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
