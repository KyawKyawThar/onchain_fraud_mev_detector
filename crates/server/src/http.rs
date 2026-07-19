//! The public §11 API service: `GET /v1/address/{addr}/risk` and `/labels`
//! (gRPC into `intelligence`), `GET /v1/audit/incident/{id}` (proxies
//! event-store), `GET /v1/incidents` (proxies simulation-projection), and
//! `WS /v1/stream` (the provisional/confirmed/retracted alert lifecycle,
//! fed by [`crate::stream`]) — all behind [`crate::auth::require_jwt`].
//! `/healthz` is the only open route.
//!
//! Follows event-store's `http.rs` shape: one [`OpenApiRouter`] assembled from
//! `#[utoipa::path]`-annotated handlers so the served routes and the Swagger
//! docs at `/swagger-ui` can't drift, a bearer security scheme registered for
//! the "Authorize" button, and production middleware (timeout, body limit,
//! trace) layered over the whole thing.

use std::sync::Arc;
use std::time::Duration;

use api_error::ApiError;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use chrono::Utc;
use event_bus::EventSink;
use event_bus::Transience;
use events::primitives::{AccountAddress, Chain, CustomerId, RuleId};
use events::rule_engine::RuleCreated;
use events::{DomainEvent, EventEnvelope};
use intelligence::model::address_key;
use rule_engine::model::{Action, Condition, LogicOp, Rule, TemporalConstraint};
use rule_engine::store::{CreateRuleOutcome, RuleStore};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use utoipa_swagger_ui::SwaggerUi;

use crate::auth::require_jwt;
use crate::config::JwtConfig;
use crate::intelligence_client::IntelligenceClient;
use crate::stream::{self, WsMessage};
use crate::upstream;
use crate::usage::{self, UsageRecorder};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(OpenApi)]
#[openapi(
    info(
        title = "api-service",
        version = env!("CARGO_PKG_VERSION"),
        description = "Public read API (§11): address risk/labels, incident audit trail and listing. \
            Also serves `WS /v1/stream` (not representable in OpenAPI): the live alert lifecycle — \
            `provisional_alert` → `alert_confirmed` → `alert_retracted` — bearer-gated the same as \
            every other `/v1` route.",
    ),
    components(schemas(RiskResponse, LabelResponse, LabelsResponse, CreateRuleRequest, CreateRuleResponse, BuildersResponse, BuilderEntry, RelayEntry, EntityGraphResponse, GraphNodeResponse, GraphEdgeResponse, EntityTimelineResponse, TimelineMilestoneResponse)),
    modifiers(&SecurityAddon),
    tags((name = "api-service", description = "Public read API (§11)")),
)]
pub struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_token",
                SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer).build()),
            );
        }
    }
}

/// Shared handler state.
#[derive(Clone)]
pub struct AppState {
    pub intelligence: IntelligenceClient,
    pub http_client: reqwest::Client,
    pub event_store_url: String,
    pub simulation_url: String,
    pub jwt: JwtConfig,
    /// Fan-out for `WS /v1/stream` (§11): [`crate::stream::run`] feeds this
    /// from Kafka; each WS connection holds its own `subscribe()`d receiver.
    pub alerts: broadcast::Sender<WsMessage>,
    /// §13 metering: every authenticated `/v1` call records an
    /// `api_call_made` here; [`crate::usage::run`] publishes the queue as
    /// `UsageRecorded` events.
    pub usage: UsageRecorder,
    /// The customer-isolated rule-definition store behind `POST /v1/rules`
    /// (§9, Sprint 9 t4) — `PgRuleStore` in production, keyed by the JWT's
    /// `CustomerId` so a body can never write another customer's rules.
    pub rules: Arc<dyn RuleStore>,
    /// The backbone producer `POST /v1/rules` announces `RuleCreated` on
    /// (§2) — shares the binary's one `KafkaEventSink` with usage metering.
    pub events: Arc<dyn EventSink>,
}

fn build_router(state: AppState) -> (Router<AppState>, utoipa::openapi::OpenApi) {
    // `from_fn_with_state` captures whatever value it's handed — it isn't tied to
    // the router's own state type — so `require_jwt` (which only needs
    // `JwtConfig`) can be layered with just that slice of `AppState`, no adapter
    // function required to bridge the two.
    //
    // `/v1/stream` is a plain `.route` (not `routes!`) because it's a WS
    // upgrade, not a `#[utoipa::path]`-describable JSON handler — utoipa has no
    // WebSocket support, so it's documented in prose (the module doc + the
    // OpenAPI `description` below) rather than in the generated spec.
    // Layer order: `route_layer` wraps what's already there, so the JWT gate
    // (added last, outermost) runs first and inserts the `CustomerId`
    // extension the usage layer reads — an unauthenticated request is
    // rejected before it can be metered (§13).
    let protected = OpenApiRouter::new()
        .routes(routes!(address_risk))
        .routes(routes!(address_labels))
        .routes(routes!(builders))
        .routes(routes!(entity_graph))
        .routes(routes!(entity_timeline))
        .routes(routes!(audit_incident))
        .routes(routes!(list_incidents))
        .routes(routes!(create_rule))
        .route("/v1/stream", get(stream::stream_ws))
        .route_layer(middleware::from_fn_with_state(
            state.usage.clone(),
            usage::record_usage,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.jwt.clone(),
            require_jwt,
        ));

    let open = OpenApiRouter::new().routes(routes!(healthz));

    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .merge(protected)
        .merge(open)
        .split_for_parts()
}

/// Build the full router: the OpenAPI-described `/v1` surface (JWT-gated) plus
/// `/healthz`, Swagger UI, and production middleware (timeout + trace).
pub fn router(state: AppState) -> Router {
    let (router, api) = build_router(state.clone());

    router
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", api))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// `GET /healthz` — trivial liveness probe (no upstream dependency check —
/// this service is a thin front door, not a store owner).
#[utoipa::path(get, path = "/healthz", tag = "api-service", responses((status = 200, description = "Alive", body = String)))]
async fn healthz() -> &'static str {
    "ok"
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct RiskResponse {
    address: String,
    /// 0-100, "how risky".
    score: u32,
    /// 0-1, "how sure".
    confidence: f64,
    model_version: String,
    computed_at_unix_millis: i64,
}

/// `GET /v1/address/{address}/risk` — the address's current risk score (§8.3),
/// via intelligence's `IntelligenceRead` gRPC service.
#[utoipa::path(
    get,
    path = "/v1/address/{address}/risk",
    tag = "api-service",
    params(("address" = String, Path, description = "On-chain address, 0x-prefixed hex (any case)")),
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "Current risk score", body = RiskResponse),
        (status = 400, description = "Address is not valid hex"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 502, description = "intelligence is unreachable"),
    ),
)]
async fn address_risk(
    State(state): State<AppState>,
    Path(address): Path<AccountAddress>,
) -> Result<Json<RiskResponse>, ApiError> {
    let reply = state
        .intelligence
        .risk_score(address)
        .await
        .map_err(ApiError::bad_gateway)?;

    Ok(Json(RiskResponse {
        address: address_key(&address),
        score: reply.score,
        confidence: reply.confidence,
        model_version: reply.model_version,
        computed_at_unix_millis: reply.computed_at_unix_millis,
    }))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct LabelResponse {
    label_id: String,
    kind: String,
    value: String,
    confidence: f64,
    source: String,
    source_detail: String,
    created_at_unix_millis: i64,
    valid_until_unix_millis: Option<i64>,
}

impl From<intelligence::pb::Label> for LabelResponse {
    fn from(label: intelligence::pb::Label) -> Self {
        Self {
            label_id: label.label_id,
            kind: label.kind,
            value: label.value,
            confidence: label.confidence,
            source: label.source,
            source_detail: label.source_detail,
            created_at_unix_millis: label.created_at_unix_millis,
            valid_until_unix_millis: label.valid_until_unix_millis,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct LabelsResponse {
    address: String,
    labels: Vec<LabelResponse>,
}

/// `GET /v1/address/{address}/labels` — the address's active labels (§8.1),
/// via intelligence's `IntelligenceRead` gRPC service.
#[utoipa::path(
    get,
    path = "/v1/address/{address}/labels",
    tag = "api-service",
    params(("address" = String, Path, description = "On-chain address, 0x-prefixed hex (any case)")),
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "Active labels", body = LabelsResponse),
        (status = 400, description = "Address is not valid hex"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 502, description = "intelligence is unreachable"),
    ),
)]
async fn address_labels(
    State(state): State<AppState>,
    Path(address): Path<AccountAddress>,
) -> Result<Json<LabelsResponse>, ApiError> {
    let labels = state
        .intelligence
        .labels(address)
        .await
        .map_err(ApiError::bad_gateway)?;

    Ok(Json(LabelsResponse {
        address: address_key(&address),
        labels: labels.into_iter().map(LabelResponse::from).collect(),
    }))
}

#[derive(Debug, Deserialize)]
struct BuildersQuery {
    /// Chain id to rank within. Defaults to Ethereum mainnet.
    #[serde(default = "default_chain")]
    chain: u64,
    /// Max builder rows; `0`/absent uses the intelligence default (relays are
    /// always returned in full).
    #[serde(default)]
    limit: u32,
    /// Optional recency floor (Unix milliseconds).
    #[serde(default)]
    since_unix_millis: Option<i64>,
}

fn default_chain() -> u64 {
    Chain::ETHEREUM.id()
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct BuilderEntry {
    /// Payout address (feeRecipient), lowercase 0x-hex.
    fee_recipient: String,
    /// Display name from intelligence labels; empty when unlabeled.
    builder_label: String,
    blocks_produced: u64,
    sandwich_count: u64,
    arb_count: u64,
    other_mev_count: u64,
    mev_extracted_usd: f64,
}

impl From<intelligence::pb::BuilderStats> for BuilderEntry {
    fn from(s: intelligence::pb::BuilderStats) -> Self {
        Self {
            fee_recipient: s.fee_recipient,
            builder_label: s.builder_label,
            blocks_produced: s.blocks_produced,
            sandwich_count: s.sandwich_count,
            arb_count: s.arb_count,
            other_mev_count: s.other_mev_count,
            mev_extracted_usd: s.mev_extracted_usd,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct RelayEntry {
    relay: String,
    blocks_delivered: u64,
    sandwich_count: u64,
    arb_count: u64,
    other_mev_count: u64,
    mev_extracted_usd: f64,
    /// Market share (0-1) of every relay-delivered block of each MEV type.
    sandwich_share: f64,
    arb_share: f64,
    other_mev_share: f64,
}

impl From<intelligence::pb::RelayStats> for RelayEntry {
    fn from(s: intelligence::pb::RelayStats) -> Self {
        Self {
            relay: s.relay,
            blocks_delivered: s.blocks_delivered,
            sandwich_count: s.sandwich_count,
            arb_count: s.arb_count,
            other_mev_count: s.other_mev_count,
            mev_extracted_usd: s.mev_extracted_usd,
            sandwich_share: s.sandwich_share,
            arb_share: s.arb_share,
            other_mev_share: s.other_mev_share,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct BuildersResponse {
    chain: u64,
    /// Builders ranked by confirmed sandwich volume, descending.
    builders: Vec<BuilderEntry>,
    /// Configured relays with their market share by MEV type.
    relays: Vec<RelayEntry>,
}

/// `GET /v1/builders` — the §10 builder/relay leaderboard: top builders by
/// confirmed sandwich volume and each relay's market share by MEV type, via
/// intelligence's `IntelligenceRead` gRPC service (which aggregates the
/// append-only block-production snapshots in ClickHouse).
#[utoipa::path(
    get,
    path = "/v1/builders",
    tag = "api-service",
    params(
        ("chain" = Option<u64>, Query, description = "Chain id (default 1 = Ethereum)"),
        ("limit" = Option<u32>, Query, description = "Max builder rows (0 = server default)"),
        ("since_unix_millis" = Option<i64>, Query, description = "Only blocks at/after this instant"),
    ),
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "Builder/relay leaderboard", body = BuildersResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 502, description = "intelligence is unreachable"),
    ),
)]
async fn builders(
    State(state): State<AppState>,
    Query(query): Query<BuildersQuery>,
) -> Result<Json<BuildersResponse>, ApiError> {
    let reply = state
        .intelligence
        .builder_leaderboard(query.chain, query.limit, query.since_unix_millis)
        .await
        .map_err(ApiError::bad_gateway)?;

    Ok(Json(BuildersResponse {
        chain: query.chain,
        builders: reply.builders.into_iter().map(BuilderEntry::from).collect(),
        relays: reply.relays.into_iter().map(RelayEntry::from).collect(),
    }))
}

#[derive(Debug, Deserialize)]
struct EntityGraphQuery {
    /// Chain id to walk within. Defaults to Ethereum mainnet.
    #[serde(default = "default_chain")]
    chain: u64,
    /// Hops out from the entity's members; `0`/absent uses the intelligence
    /// default, and the value is clamped to intelligence's hard ceiling.
    #[serde(default)]
    hops: u32,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct GraphNodeResponse {
    /// 0x-prefixed lowercase hex address.
    address: String,
    /// Distance from the nearest entity member (0 for a member).
    hop: u32,
    /// This address is one of the entity's own members (a walk seed).
    is_seed: bool,
    /// This address is a degree-capped hub — the walk stopped here (§8.2).
    is_hub: bool,
}

impl From<intelligence::pb::GraphNode> for GraphNodeResponse {
    fn from(n: intelligence::pb::GraphNode) -> Self {
        Self {
            address: n.address,
            hop: n.hop,
            is_seed: n.is_seed,
            is_hub: n.is_hub,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct GraphEdgeResponse {
    /// Lexicographically smaller endpoint, 0x-hex.
    from: String,
    to: String,
}

impl From<intelligence::pb::GraphEdge> for GraphEdgeResponse {
    fn from(e: intelligence::pb::GraphEdge) -> Self {
        Self {
            from: e.from,
            to: e.to,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct EntityGraphResponse {
    entity_id: String,
    /// The entity's member addresses — the walk's hop-0 seeds.
    seeds: Vec<String>,
    nodes: Vec<GraphNodeResponse>,
    edges: Vec<GraphEdgeResponse>,
    /// The walk stopped early — more of the graph may exist beyond these nodes.
    truncated: bool,
    /// Why it stopped short (`hub_boundary` | `hop_boundary` | `node_budget`);
    /// empty for a complete graph.
    truncation_reasons: Vec<String>,
}

/// `GET /v1/entity/{entity_id}/graph?hops=3` — the addresses connected to an
/// entity, out to `hops` levels, as a **degree-capped** subgraph (§8.2 —
/// critical, §11), via intelligence's `IntelligenceRead` gRPC service (which
/// walks the ClickHouse adjacency store, stopping at hub nodes).
#[utoipa::path(
    get,
    path = "/v1/entity/{entity_id}/graph",
    tag = "api-service",
    params(
        ("entity_id" = String, Path, format = Uuid, description = "Entity id"),
        ("chain" = Option<u64>, Query, description = "Chain id (default 1 = Ethereum)"),
        ("hops" = Option<u32>, Query, description = "Hops out from the entity's members (0 = server default)"),
    ),
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "The entity's degree-capped connected-address subgraph", body = EntityGraphResponse),
        (status = 400, description = "Entity id is not a valid UUID"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 404, description = "No such entity"),
        (status = 502, description = "intelligence is unreachable"),
    ),
)]
async fn entity_graph(
    State(state): State<AppState>,
    Extension(customer): Extension<CustomerId>,
    Path(entity_id): Path<uuid::Uuid>,
    Query(query): Query<EntityGraphQuery>,
) -> Result<Json<EntityGraphResponse>, ApiError> {
    let reply = state
        .intelligence
        .entity_graph(entity_id.to_string(), query.chain, query.hops)
        .await
        .map_err(ApiError::bad_gateway)?;

    if !reply.found {
        return Err(ApiError::not_found(format!("entity {entity_id} not found")));
    }

    state
        .usage
        .record(customer, events::system::UsageEventType::EntityQueried);

    Ok(Json(EntityGraphResponse {
        entity_id: entity_id.to_string(),
        seeds: reply.seeds,
        nodes: reply
            .nodes
            .into_iter()
            .map(GraphNodeResponse::from)
            .collect(),
        edges: reply
            .edges
            .into_iter()
            .map(GraphEdgeResponse::from)
            .collect(),
        truncated: reply.truncated,
        truncation_reasons: reply.truncation_reasons,
    }))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct TimelineMilestoneResponse {
    /// `first_seen` | `labeled` | `incident`.
    kind: String,
    occurred_at_unix_millis: i64,
    /// The member address this milestone concerns; absent when entity-level.
    address: Option<String>,
    /// A one-line narrative rendering of the milestone.
    summary: String,
    /// A stable reference for the audit-trail hop (incident_id / label_id).
    reference: Option<String>,
}

impl From<intelligence::pb::TimelineMilestone> for TimelineMilestoneResponse {
    fn from(m: intelligence::pb::TimelineMilestone) -> Self {
        // The wire uses empty strings for "absent" (proto3 has no bare optional
        // string); re-inflate them to `None` at the JSON boundary.
        let non_empty = |s: String| if s.is_empty() { None } else { Some(s) };
        Self {
            kind: m.kind,
            occurred_at_unix_millis: m.occurred_at_unix_millis,
            address: non_empty(m.address),
            summary: m.summary,
            reference: non_empty(m.reference),
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct EntityTimelineResponse {
    entity_id: String,
    /// Milestones oldest first.
    milestones: Vec<TimelineMilestoneResponse>,
}

/// `GET /v1/entity/{entity_id}/timeline` — the entity's curated milestone
/// history (§8.4, §11): first seen, label/classification changes, and notable
/// attributed incidents. Entity-level and narrative, distinct from the
/// incident-level forensic `GET /v1/audit/incident/{id}`. Projected by
/// intelligence over its own stores.
#[utoipa::path(
    get,
    path = "/v1/entity/{entity_id}/timeline",
    tag = "api-service",
    params(("entity_id" = String, Path, format = Uuid, description = "Entity id")),
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "The entity's milestone timeline", body = EntityTimelineResponse),
        (status = 400, description = "Entity id is not a valid UUID"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 404, description = "No such entity"),
        (status = 502, description = "intelligence is unreachable"),
    ),
)]
async fn entity_timeline(
    State(state): State<AppState>,
    Extension(customer): Extension<CustomerId>,
    Path(entity_id): Path<uuid::Uuid>,
) -> Result<Json<EntityTimelineResponse>, ApiError> {
    let reply = state
        .intelligence
        .entity_timeline(entity_id.to_string())
        .await
        .map_err(ApiError::bad_gateway)?;

    if !reply.found {
        return Err(ApiError::not_found(format!("entity {entity_id} not found")));
    }

    state
        .usage
        .record(customer, events::system::UsageEventType::EntityQueried);

    Ok(Json(EntityTimelineResponse {
        entity_id: entity_id.to_string(),
        milestones: reply
            .milestones
            .into_iter()
            .map(TimelineMilestoneResponse::from)
            .collect(),
    }))
}

/// Query parameters forwarded verbatim to the upstream (pagination/filter
/// params belong to event-store's/simulation-projection's own contracts, not
/// duplicated here).
type RawQuery = std::collections::BTreeMap<String, String>;

/// `GET /v1/audit/incident/{incident_id}` — proxies event-store's internal
/// `GET /v1/audit/incident/{incident_id}` verbatim (query string forwarded,
/// upstream status/body passed through).
#[utoipa::path(
    get,
    path = "/v1/audit/incident/{incident_id}",
    tag = "api-service",
    params(("incident_id" = String, Path, description = "Incident id")),
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "The incident's event sequence (proxied from event-store)"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 502, description = "event-store is unreachable"),
    ),
)]
async fn audit_incident(
    State(state): State<AppState>,
    Path(incident_id): Path<String>,
    Query(params): Query<RawQuery>,
) -> Result<Response, ApiError> {
    let proxied = upstream::get(
        &state.http_client,
        &state.event_store_url,
        &format!("/v1/audit/incident/{incident_id}"),
        &params,
    )
    .await
    .map_err(ApiError::bad_gateway)?;

    Ok((proxied.status, Json(proxied.body)).into_response())
}

/// `GET /v1/incidents` — proxies simulation-projection's internal
/// `GET /v1/incidents` verbatim.
#[utoipa::path(
    get,
    path = "/v1/incidents",
    tag = "api-service",
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "A page of confirmed incidents (proxied from simulation-projection)"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 502, description = "simulation-projection is unreachable"),
    ),
)]
async fn list_incidents(
    State(state): State<AppState>,
    Query(params): Query<RawQuery>,
) -> Result<Response, ApiError> {
    let proxied = upstream::get(
        &state.http_client,
        &state.simulation_url,
        "/v1/incidents",
        &params,
    )
    .await
    .map_err(ApiError::bad_gateway)?;

    Ok((proxied.status, Json(proxied.body)).into_response())
}

/// Rule-engine events are not chain-scoped facts, but every envelope must
/// name a chain — stamped [`Chain::ETHEREUM`], the same single-chain-MVP
/// posture as `usage.rs`'s `UsageRecorded` emission.
const RULE_EVENT_CHAIN: Chain = Chain::ETHEREUM;

/// `POST /v1/rules` body: the §9 rule document **exactly as stored** (the
/// wire form IS the stored JSONB form — no translation layer), minus the two
/// fields the server owns: `owner` always comes from the bearer token (the
/// write half of the isolation contract — a body cannot name another
/// customer), and `id` is server-minted unless the client supplies one as an
/// idempotency key for safe retries.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct CreateRuleRequest {
    /// Optional client-supplied idempotency key (UUID). Retrying a create
    /// with the same id is a no-op (`200 already_exists`), never a duplicate.
    #[serde(default)]
    #[schema(value_type = Option<String>, format = Uuid)]
    id: Option<RuleId>,
    name: String,
    /// Defaults to `true` — a created rule evaluates immediately.
    #[serde(default = "default_enabled")]
    enabled: bool,
    /// §9 conditions, externally tagged snake_case (e.g.
    /// `{"transfer_amount": {"chain": 1, "gt": "1000000"}}`).
    #[schema(value_type = Vec<Object>)]
    conditions: Vec<Condition>,
    /// `all` | `any` | `not`.
    #[schema(value_type = String, example = "all")]
    logic: LogicOp,
    /// Optional §9 temporal clause (`sequence` / `frequency`).
    #[serde(default)]
    #[schema(value_type = Object)]
    temporal: Option<TemporalConstraint>,
    /// §9 actions (e.g. `{"webhook_alert": {"url": "https://…"}}`).
    #[schema(value_type = Vec<Object>)]
    actions: Vec<Action>,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct CreateRuleResponse {
    rule_id: String,
    /// `created` on a fresh write, `already_exists` on an idempotent retry.
    status: &'static str,
}

/// `POST /v1/rules` — create a customer-defined alerting rule (§9, the
/// enterprise tier's entry point). Validated at this boundary
/// (`Rule::validate` — a 422 names the offending field in the customer's own
/// wire vocabulary); a successful create announces `RuleCreated` on the
/// backbone, which the rule-engine service uses as its refresh trigger.
///
/// The event publish is one-shot best-effort (logged loudly on failure, like
/// the intelligence CLI's `publish_once`): the store write is the durable
/// fact, and the rule engine's periodic backstop refresh picks the rule up
/// even if the announcement is lost — an indefinite publish retry has no
/// place on a customer-facing request path.
#[utoipa::path(
    post,
    path = "/v1/rules",
    tag = "api-service",
    request_body = CreateRuleRequest,
    security(("bearer_token" = [])),
    responses(
        (status = 201, description = "Rule created", body = CreateRuleResponse),
        (status = 200, description = "Idempotent retry: this rule id already exists", body = CreateRuleResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 409, description = "The customer already has a live rule with this name"),
        (status = 422, description = "The rule definition is invalid (reason in the body)"),
        (status = 502, description = "The rule store is unreachable"),
    ),
)]
async fn create_rule(
    State(state): State<AppState>,
    Extension(customer): Extension<CustomerId>,
    Json(body): Json<CreateRuleRequest>,
) -> Result<Response, ApiError> {
    let rule = Rule {
        id: body.id.unwrap_or_else(RuleId::new),
        owner: customer,
        name: body.name,
        enabled: body.enabled,
        conditions: body.conditions,
        logic: body.logic,
        temporal: body.temporal,
        actions: body.actions,
    };

    // Reject a bad definition here, with the §9 customer-language reason —
    // the store re-validates (defense in depth), but a 422 beats its 500.
    if let Err(invalid) = rule.validate() {
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": invalid.to_string() })),
        )
            .into_response());
    }

    // Compose the §2 `RuleCreated` announcement up front: the store writes it
    // to the transactional outbox in the same transaction as the rule row
    // (§20), and the rule-engine binary's outbox flusher publishes it — so a
    // crash anywhere after the commit can no longer lose the announcement
    // (the old direct-publish path could, leaving the engine blind until its
    // periodic backstop refresh).
    let announcement = rule_created_announcement(&rule).map_err(ApiError::internal)?;

    match state
        .rules
        .create_rule_announced(&rule, &announcement, Utc::now())
        .await
    {
        Ok(CreateRuleOutcome::Created) => Ok((
            StatusCode::CREATED,
            Json(CreateRuleResponse {
                rule_id: rule.id.to_string(),
                status: "created",
            }),
        )
            .into_response()),
        Ok(CreateRuleOutcome::AlreadyExists) => Ok((
            StatusCode::OK,
            Json(CreateRuleResponse {
                rule_id: rule.id.to_string(),
                status: "already_exists",
            }),
        )
            .into_response()),
        Ok(CreateRuleOutcome::NameTaken) => Ok((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": format!("a live rule named {:?} already exists", rule.name)
            })),
        )
            .into_response()),
        Err(err) if err.is_transient() => Err(ApiError::bad_gateway(err)),
        Err(err) => Err(ApiError::internal(err)),
    }
}

/// Encode the §2 `RuleCreated` announcement for a rule as a full wire-form
/// [`EventEnvelope`] value — what [`create_rule`] hands the store to write
/// into the transactional outbox (§20). Publishing happens later, off the
/// request path, in the rule-engine binary's outbox flusher.
fn rule_created_announcement(rule: &Rule) -> Result<serde_json::Value, serde_json::Error> {
    let definition = serde_json::to_value(rule)?;
    let event = DomainEvent::RuleCreated(RuleCreated {
        rule_id: rule.id,
        owner: rule.owner,
        definition,
    });
    serde_json::to_value(EventEnvelope::new(RULE_EVENT_CHAIN, event))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{build_router, AppState};
    use crate::config::JwtConfig;
    use crate::intelligence_client::IntelligenceClient;
    use crate::usage::UsageRecorder;
    use event_bus::test_util::RecordingSink;
    use events::system::UsageRecorded;
    use rule_engine::test_util::InMemoryRuleStore;
    use secrecy::SecretString;
    use tokio::sync::mpsc;

    /// Everything a handler test observes: the state to build the router
    /// from, plus the doubles behind it (what got metered, what got stored,
    /// what got published).
    struct TestState {
        state: AppState,
        usage_rx: mpsc::Receiver<UsageRecorded>,
        rules: Arc<InMemoryRuleStore>,
        events: Arc<RecordingSink>,
    }

    /// A throwaway state — `connect_lazy` does no I/O (the channel dials on
    /// first RPC), so the router/spec can be built with no live intelligence.
    fn test_state() -> TestState {
        let (usage, usage_rx) = UsageRecorder::channel(16);
        let rules = Arc::new(InMemoryRuleStore::new());
        let events = Arc::new(RecordingSink::default());
        let state = AppState {
            intelligence: IntelligenceClient::connect_lazy("http://127.0.0.1:50051".to_owned())
                .expect("lazy channel never fails to construct"),
            http_client: reqwest::Client::new(),
            event_store_url: "http://127.0.0.1:8081".to_owned(),
            simulation_url: "http://127.0.0.1:8082".to_owned(),
            jwt: JwtConfig {
                secret: SecretString::from("test-secret"),
                issuer: "mev".to_owned(),
            },
            alerts: tokio::sync::broadcast::channel(16).0,
            usage,
            rules: rules.clone(),
            events: events.clone(),
        };
        TestState {
            state,
            usage_rx,
            rules,
            events,
        }
    }

    #[tokio::test]
    async fn openapi_spec_collects_paths_schemas_and_security() {
        // The spec is built by the *router* from the handler annotations — the same
        // spec that ships at `/api-docs/openapi.json` — so this guards against
        // route/doc drift, not just against a missing derive.
        let ts = test_state();
        let (_router, api) = build_router(ts.state);
        let spec = serde_json::to_value(&api).expect("serialize spec");

        for name in [
            "RiskResponse",
            "LabelResponse",
            "LabelsResponse",
            "CreateRuleRequest",
            "CreateRuleResponse",
            "BuildersResponse",
            "BuilderEntry",
            "RelayEntry",
            "EntityGraphResponse",
            "GraphNodeResponse",
            "GraphEdgeResponse",
            "EntityTimelineResponse",
            "TimelineMilestoneResponse",
        ] {
            assert!(
                spec["components"]["schemas"].get(name).is_some(),
                "OpenAPI components missing schema `{name}`"
            );
        }

        assert!(spec["components"]["securitySchemes"]["bearer_token"].is_object());

        for (path, method) in [
            ("/healthz", "get"),
            ("/v1/address/{address}/risk", "get"),
            ("/v1/address/{address}/labels", "get"),
            ("/v1/builders", "get"),
            ("/v1/entity/{entity_id}/graph", "get"),
            ("/v1/entity/{entity_id}/timeline", "get"),
            ("/v1/audit/incident/{incident_id}", "get"),
            ("/v1/incidents", "get"),
            ("/v1/rules", "post"),
        ] {
            assert!(
                spec["paths"][path][method].is_object(),
                "OpenAPI paths missing `{method} {path}`"
            );
        }
    }

    #[tokio::test]
    async fn builders_requires_a_bearer_token_and_proxies_intelligence() {
        use axum::body::Body;
        use axum::http::{header, Request, StatusCode};
        use tower::ServiceExt;

        let ts = test_state();
        let bearer = mint_bearer(&ts.state, "00000000-0000-0000-0000-0000000000c0");
        let router = super::router(ts.state);

        // No token → rejected by the JWT gate before reaching the handler.
        let response = router
            .clone()
            .oneshot(Request::get("/v1/builders").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Authenticated, but the lazy intelligence channel has no server here,
        // so the gRPC call fails → 502 (the front door reached the handler and
        // tried to proxy). Query params parse (defaults applied).
        let response = router
            .oneshot(
                Request::get("/v1/builders?limit=5")
                    .header(header::AUTHORIZATION, &bearer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn entity_graph_and_timeline_are_bearer_gated_and_proxy_intelligence() {
        use axum::body::Body;
        use axum::http::{header, Request, StatusCode};
        use tower::ServiceExt;

        let ts = test_state();
        let bearer = mint_bearer(&ts.state, "00000000-0000-0000-0000-0000000000c0");
        let router = super::router(ts.state);
        let entity = uuid::Uuid::new_v4();

        for path in [
            format!("/v1/entity/{entity}/graph?hops=2"),
            format!("/v1/entity/{entity}/timeline"),
        ] {
            // No token → rejected by the JWT gate before the handler.
            let response = router
                .clone()
                .oneshot(Request::get(&path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");

            // Authenticated, but the lazy intelligence channel has no server
            // here, so the gRPC call fails → 502 (reached the handler, tried to
            // proxy). This also proves the UUID path + query params parse.
            let response = router
                .clone()
                .oneshot(
                    Request::get(&path)
                        .header(header::AUTHORIZATION, &bearer)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{path}");
        }

        // A non-UUID entity id is a 400 from axum's path parsing, before any
        // upstream call.
        let response = router
            .oneshot(
                Request::get("/v1/entity/not-a-uuid/timeline")
                    .header(header::AUTHORIZATION, &bearer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn authenticated_v1_calls_are_metered_and_everything_else_is_not() {
        use axum::body::Body;
        use axum::http::{header, Request, StatusCode};
        use tower::ServiceExt;

        let customer = "00000000-0000-0000-0000-0000000000c0";
        let ts = test_state();
        let mut usage_rx = ts.usage_rx;
        let bearer = mint_bearer(&ts.state, customer);
        let router = super::router(ts.state);

        // Open route: never metered.
        let response = router
            .clone()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(usage_rx.try_recv().is_err(), "/healthz must not be metered");

        // Unauthenticated /v1 call: rejected before the meter.
        let response = router
            .clone()
            .oneshot(Request::get("/v1/incidents").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            usage_rx.try_recv().is_err(),
            "a 401 must not be metered (§13 — no billable identity)"
        );

        // Authenticated /v1 call: metered against the token's customer even
        // though the upstream is unreachable here (502) — "ApiCallMade" is
        // the call, not its outcome.
        let response = router
            .oneshot(
                Request::get("/v1/incidents")
                    .header(header::AUTHORIZATION, &bearer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

        let usage = usage_rx.try_recv().expect("the call must be metered");
        assert_eq!(
            usage
                .customer_id
                .expect("ApiCallMade is customer-attributed"),
            events::primitives::CustomerId(customer.parse().unwrap())
        );
        assert_eq!(
            usage.event_type,
            events::system::UsageEventType::ApiCallMade.as_wire_str()
        );
        assert_eq!(usage.quantity, 1);
        assert!(usage_rx.try_recv().is_err(), "exactly one event per call");
    }

    // ── POST /v1/rules (§9, Sprint 9 t4) ─────────────────────────────

    /// Mint a bearer token for `customer` against the test state's JWT config.
    fn mint_bearer(state: &AppState, customer: &str) -> String {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use secrecy::ExposeSecret;

        let claims = crate::auth::Claims {
            sub: customer.to_owned(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
            iss: state.jwt.issuer.clone(),
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(state.jwt.secret.expose_secret().as_bytes()),
        )
        .expect("mint test token");
        format!("Bearer {token}")
    }

    /// POST a JSON body to `/v1/rules` and return `(status, body)`.
    async fn post_rules(
        router: axum::Router,
        bearer: Option<&str>,
        body: serde_json::Value,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        use axum::body::Body;
        use axum::http::{header, Request};
        use tower::ServiceExt;

        let mut request =
            Request::post("/v1/rules").header(header::CONTENT_TYPE, "application/json");
        if let Some(bearer) = bearer {
            request = request.header(header::AUTHORIZATION, bearer);
        }
        let response = router
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, body)
    }

    /// §9's trader-protection rule, as a customer would POST it — the wire
    /// form is the stored form.
    fn trader_rule_body(name: &str) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "conditions": [
                { "incident_kind": { "kind": "sandwich", "min_confidence": 0.8 } }
            ],
            "logic": "all",
            "actions": [ { "slack_alert": { "channel": "#trading-alerts" } } ]
        })
    }

    /// The §9 create path end to end: 201, the rule stored under the token's
    /// customer (never a body-supplied owner), and `RuleCreated` announced on
    /// the backbone with the full definition.
    #[tokio::test]
    async fn post_rules_creates_stores_under_the_token_owner_and_announces() {
        use events::primitives::CustomerId;
        use rule_engine::store::RuleStore;

        let customer = "00000000-0000-0000-0000-0000000000c0";
        let ts = test_state();
        let bearer = mint_bearer(&ts.state, customer);
        let router = super::router(ts.state);

        // A hostile body naming another owner: unknown fields are ignored —
        // the token is the only owner authority.
        let mut body = trader_rule_body("Sandwich bot targeting my wallet");
        body["owner"] = serde_json::json!("11111111-1111-1111-1111-111111111111");

        let (status, reply) = post_rules(router, Some(&bearer), body).await;
        assert_eq!(status, axum::http::StatusCode::CREATED);
        assert_eq!(reply["status"], "created");

        let owner = CustomerId(uuid::Uuid::parse_str(customer).unwrap());
        let stored = ts.rules.rules_for_owner(owner).await.unwrap();
        assert_eq!(stored.len(), 1, "stored under the token's customer");
        assert!(stored[0].enabled, "enabled defaults to true");
        assert_eq!(stored[0].id.to_string(), reply["rule_id"]);

        // The announcement rides the store's transactional outbox (§20) —
        // nothing publishes on the request path itself.
        assert!(ts.events.events().is_empty(), "no direct publish");
        let announced = ts.rules.announcements();
        assert_eq!(announced.len(), 1);
        let envelope: events::EventEnvelope =
            serde_json::from_value(announced[0].clone()).expect("outbox row is a wire envelope");
        match envelope.payload {
            events::DomainEvent::RuleCreated(created) => {
                assert_eq!(created.owner, owner);
                assert_eq!(created.rule_id, stored[0].id);
                assert_eq!(
                    created.definition["conditions"][0]["incident_kind"]["kind"],
                    "sandwich"
                );
            }
            other => panic!("expected RuleCreated, got {other:?}"),
        }
    }

    /// An invalid definition is a 422 naming the offending field in the §9
    /// wire vocabulary — nothing stored, nothing announced.
    #[tokio::test]
    async fn post_rules_rejects_an_invalid_definition_with_422() {
        let ts = test_state();
        let bearer = mint_bearer(&ts.state, "00000000-0000-0000-0000-0000000000c0");
        let rules = ts.rules.clone();
        let events = ts.events.clone();
        let router = super::router(ts.state);

        let body = serde_json::json!({
            "name": "unbounded",
            "conditions": [ { "risk_score": {} } ],
            "logic": "all",
            "actions": [ { "slack_alert": { "channel": "#x" } } ]
        });
        let (status, reply) = post_rules(router, Some(&bearer), body).await;
        assert_eq!(status, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            reply["error"]
                .as_str()
                .unwrap()
                .contains("at least one of gt/lt"),
            "the customer-language reason rides the body: {reply}"
        );
        assert!(events.events().is_empty(), "nothing announced");
        let owner = events::primitives::CustomerId(
            uuid::Uuid::parse_str("00000000-0000-0000-0000-0000000000c0").unwrap(),
        );
        use rule_engine::store::RuleStore;
        assert!(rules.rules_for_owner(owner).await.unwrap().is_empty());
    }

    /// Retrying a create with the same client-supplied id is an idempotent
    /// no-op (200), and a *different* rule under an already-taken live name
    /// is a 409 — the two non-201 outcomes speak the store's domain.
    #[tokio::test]
    async fn post_rules_is_idempotent_by_id_and_conflicts_by_name() {
        let ts = test_state();
        let bearer = mint_bearer(&ts.state, "00000000-0000-0000-0000-0000000000c0");
        let rules = ts.rules.clone();
        let router = super::router(ts.state);

        let rule_id = uuid::Uuid::new_v4().to_string();
        let mut body = trader_rule_body("my rule");
        body["id"] = serde_json::json!(rule_id);

        let (status, _) = post_rules(router.clone(), Some(&bearer), body.clone()).await;
        assert_eq!(status, axum::http::StatusCode::CREATED);

        let (status, reply) = post_rules(router.clone(), Some(&bearer), body).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(reply["status"], "already_exists");
        assert_eq!(
            rules.announcements().len(),
            1,
            "an idempotent retry enqueues nothing new on the outbox"
        );

        // Same name, fresh id → the per-owner live-name constraint.
        let (status, reply) = post_rules(router, Some(&bearer), trader_rule_body("my rule")).await;
        assert_eq!(status, axum::http::StatusCode::CONFLICT);
        assert!(reply["error"].as_str().unwrap().contains("my rule"));
    }

    /// The rules endpoint sits behind the same JWT gate as every /v1 route.
    #[tokio::test]
    async fn post_rules_requires_a_bearer_token() {
        let ts = test_state();
        let router = super::router(ts.state);

        let (status, _) = post_rules(router, None, trader_rule_body("x")).await;
        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    }
}
