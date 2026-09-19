//! The public §11 API service: `GET /v1/address/{addr}/risk` and `/labels`
//! plus the synchronous `POST /v1/address/{addr}/screen` decision (gRPC into
//! `intelligence`, decided through a named policy — `GET /v1/policies` lists
//! them, `PUT /v1/policies/{name}` authors a customer's own, §11 Sprint 14
//! t2), `GET /v1/audit/incident/{id}` (proxies event-store),
//! `GET /v1/incidents` (proxies simulation-projection), and
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
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use chrono::{DateTime, Utc};
use event_bus::EventSink;
use event_bus::Transience;
use events::feedback::{AlertFeedbackRecorded, FeedbackReason, FeedbackVerdict};
use events::primitives::IncidentId;
use events::primitives::{AccountAddress, Chain, CustomerId, RuleId};
use events::rule_engine::RuleCreated;
use events::system::{FactsStaleness, ScreeningDecisionRecorded, UsageEventType};
use events::{DomainEvent, EventEnvelope};
use intelligence::model::address_key;
use intelligence::pb::ScreeningFactsReply;
use rule_engine::model::{Action, Condition, LogicOp, Rule, RuleDefinition, TemporalConstraint};
use rule_engine::store::{CreateRuleOutcome, RuleStore};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use utoipa_swagger_ui::SwaggerUi;

use crate::audit::AuditRecorder;
use crate::auth::require_jwt;
use crate::config::JwtConfig;
use crate::degrade::{self, ScreeningFallback};
use crate::feedback;
use crate::intelligence_client::{self, IntelligenceClient};
use crate::policy_store::{self, PolicyStore};
use crate::rate_limit::{self, ScreeningRateLimiter};
use crate::stream::{self, WsMessage};
use crate::upstream;
use crate::usage::{self, UsageRecorder};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// `POST /v1/address/{addr}/screen`'s payload cap (§11, readiness Epic D). The
/// only body the endpoint accepts is `{"policy": "<name, at most 64 chars>"}`,
/// so a kilobyte is already generous; refusing a larger body before it is
/// buffered keeps a big-payload flood off the p50-critical path, which axum's
/// router-wide 2 MiB default would not.
const SCREEN_BODY_LIMIT_BYTES: usize = 1024;

/// `POST /v1/incidents/{incident_id}/feedback`'s payload cap (§19, readiness
/// Epic E): a verdict plus at most [`MAX_FEEDBACK_REASON_CHARS`] of prose.
const FEEDBACK_BODY_LIMIT_BYTES: usize = 4096;

/// Ceiling on the free-text `reason` a verdict may carry. It is read by a
/// human looking into why a detector's precision moved, and anything longer
/// than a short paragraph is a document that belongs somewhere else — but the
/// real reason for a limit is that this string is copied onto the event
/// backbone, into the ledger and into every replay of both.
const MAX_FEEDBACK_REASON_CHARS: usize = 1000;

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
    components(schemas(RiskResponse, LabelResponse, LabelsResponse, ScreenRequest, ScreenResponse, SanctionMatchResponse, FactorResponse, crate::screen::Decision, crate::screen::DecisionBasis, events::system::FactsStaleness, events::system::ScreeningStaleReason, crate::screen::StalePolicy, CreateRuleRequest, CreateRuleResponse, BuildersResponse, BuilderEntry, RelayEntry, SimilarAddressesResponse, SimilarAddressResponse, SimilarityFactorResponse, EntityGraphResponse, GraphNodeResponse, GraphEdgeResponse, EntityTimelineResponse, TimelineMilestoneResponse, UpsertPolicyRequest, PolicyResponse, PoliciesResponse, AddMonitoredWalletRequest, FeedbackRequest, FeedbackResponse, events::feedback::FeedbackVerdict)),
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
    /// §11 Sprint 14 t3: every `POST /v1/address/{addr}/screen` call records
    /// its outcome here; [`crate::audit::run`] publishes the queue as
    /// `ScreeningDecisionRecorded` — the access-audit trail, independent of
    /// the `usage` metering fact above.
    pub audit: AuditRecorder,
    /// §19 readiness Epic E: the pool `POST /v1/incidents/{id}/feedback`
    /// writes its verdict through, into the `feedback_outbox` a background
    /// flusher publishes from ([`crate::feedback`]). A durable write rather
    /// than an in-memory queue because a dropped verdict is a *sample*
    /// removed from an accuracy measurement, non-randomly, exactly when the
    /// platform is unhealthy.
    pub feedback: Arc<dyn feedback::FeedbackQueue>,
    /// The §19 feedback capability's **verifying** half (readiness Epic E).
    /// This service can check a grant and cannot mint one — the type is the
    /// enforcement (`feedback_grant::VerifyingKey`), not a convention.
    ///
    /// `None` when this deployment has no `FEEDBACK_GRANT_SECRET`: the
    /// feedback endpoint answers 503 and nothing else is affected.
    pub feedback_grant: Option<Arc<feedback_grant::VerifyingKey>>,
    /// The customer-isolated rule-definition store behind `POST /v1/rules`
    /// (§9, Sprint 9 t4) — `PgRuleStore` in production, keyed by the JWT's
    /// `CustomerId` so a body can never write another customer's rules.
    pub rules: Arc<dyn RuleStore>,
    /// The backbone producer `POST /v1/rules` announces `RuleCreated` on
    /// (§2) — shares the binary's one `KafkaEventSink` with usage metering.
    pub events: Arc<dyn EventSink>,
    /// The customer-authored decision-policy store `POST /v1/address/{addr}/screen`
    /// and `PUT /v1/policies/{name}` read/write (§11, Sprint 14 t2) —
    /// `PgPolicyStore` in production, keyed by the JWT's `CustomerId` the
    /// same way `rules` is.
    pub policies: Arc<dyn PolicyStore>,
    /// The dedicated rate-limit ceiling `POST /v1/address/{addr}/screen`
    /// checks before doing any work (§19, Sprint 14 t4) — `RedisScreeningRateLimiter`
    /// in production, keyed by the JWT's `CustomerId` the same way `policies`/
    /// `rules` are.
    pub screening_rate_limit: Arc<dyn ScreeningRateLimiter>,
    /// `POST /v1/address/{addr}/screen`'s graceful degradation (§11, readiness
    /// Epic D, [`crate::degrade`]): a last-known-good snapshot answers, flagged,
    /// when intelligence is slow or unavailable. `None` is disarmed — fresh or
    /// fail closed.
    pub screening_fallback: Option<ScreeningFallback>,
    /// The pod-local sanctions list (§8.5, [`crate::sanctions_view`]) every
    /// screening decision is checked against — fresh or stale — and whose
    /// currency decides whether a stale `allow` may stand.
    pub sanctions: Arc<crate::sanctions_view::SanctionsView>,
    /// The decorated screening read (`crate::facts_source`: bulkhead → breaker
    /// → latency tracking → hedging over `intelligence`). `None` reads through
    /// `intelligence` undecorated — the handler tests' setting.
    pub screening_source: Option<Arc<dyn degrade::FactsSource>>,
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
    // Its own sub-router so the rate-limit layer applies ONLY to this route
    // (§19) — every other `/v1` route stays unaffected by the screening
    // ceiling. Layered inside the JWT gate below (it reads the `CustomerId`
    // extension), and runs before the usage-metering layer reaches this
    // route's handler, so a rejected call never pays the intelligence/
    // policy-store round-trip.
    let screening = OpenApiRouter::new()
        .routes(routes!(screen_address))
        .route_layer(DefaultBodyLimit::max(SCREEN_BODY_LIMIT_BYTES))
        .route_layer(middleware::from_fn_with_state(
            state.screening_rate_limit.clone(),
            rate_limit::enforce_screening_rate_limit,
        ));

    // The §20.3 similarity read gets its own sub-router and its own ceiling,
    // for the same reason screening has one — and more urgently. It is the
    // most expensive read the platform serves (an ANN scan plus a bounded
    // re-rank), and it reaches the *same* intelligence service and ClickHouse
    // that `screen` does, so an unbounded burst here degrades a p50 < 100ms
    // SLO on an endpoint that has nothing to do with it. Bounded separately
    // rather than sharing screening's bucket: they have different costs and
    // different SLOs, and one budget would let either starve the other.
    let similarity = OpenApiRouter::new()
        .routes(routes!(address_similar))
        .route_layer(middleware::from_fn_with_state(
            state.screening_rate_limit.clone(),
            rate_limit::enforce_similarity_rate_limit,
        ));

    // Its own sub-router for the body cap alone: a verdict is a one-line
    // judgement plus a sentence of prose, so the router-wide 2 MiB default is
    // three orders of magnitude of slack on a write that reaches the Kafka
    // backbone. Capped at the source rather than validated after buffering.
    let feedback_route = OpenApiRouter::new()
        .routes(routes!(record_incident_feedback))
        .route_layer(DefaultBodyLimit::max(FEEDBACK_BODY_LIMIT_BYTES));

    let protected = OpenApiRouter::new()
        .routes(routes!(address_risk))
        .routes(routes!(address_labels))
        .merge(similarity)
        .merge(screening)
        .routes(routes!(list_policies))
        .routes(routes!(upsert_policy))
        .routes(routes!(builders))
        .routes(routes!(entity_graph))
        .routes(routes!(entity_timeline))
        .routes(routes!(address_link_candidates))
        .routes(routes!(audit_incident))
        .routes(routes!(list_incidents))
        .routes(routes!(wallet_mev_exposure))
        .routes(routes!(timing_recommendation))
        .routes(routes!(add_monitored_wallet))
        .routes(routes!(list_monitored_wallets))
        .routes(routes!(remove_monitored_wallet))
        .routes(routes!(create_rule))
        .merge(feedback_route)
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
        // §19 — the API p50/p99 panel. Added via `Router::layer` (not a
        // ServiceBuilder wrapping the whole app), so routing has already run
        // and `MatchedPath` is in the request's extensions, same as the
        // `TraceLayer` above.
        .layer(middleware::from_fn(crate::metrics::record_http_metrics))
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
        .map_err(intelligence_client::to_api_error)?;

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
        .map_err(intelligence_client::to_api_error)?;

    Ok(Json(LabelsResponse {
        address: address_key(&address),
        labels: labels.into_iter().map(LabelResponse::from).collect(),
    }))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct SanctionMatchResponse {
    /// Which list designated it (`ofac_sdn`, `eu_consolidated`, …).
    list: String,
    /// The list's own entry (SDN name / programme).
    entry: String,
}

/// One factor behind a screening decision's `score` (§8.3), with its
/// evidence pointer — the explainability contract §11 requires on a
/// `review`/`block` (Sprint 14 t3): mirrors `events::intelligence::RiskFactor`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
struct FactorResponse {
    name: String,
    /// Signed contribution to the score for this factor.
    delta: f64,
    /// Pointer to the evidence (incident id, label id, …) behind this factor.
    evidence_ref: String,
}

impl From<&events::intelligence::RiskFactor> for FactorResponse {
    fn from(factor: &events::intelligence::RiskFactor) -> Self {
        Self {
            name: factor.name.clone(),
            delta: factor.delta,
            evidence_ref: factor.evidence_ref.clone(),
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct ScreenRequest {
    /// Named policy to decide through: a built-in
    /// (`default`/`strict`/`monitor-only`) or one of the caller's own
    /// (`PUT /v1/policies/{name}`). Defaults to `default` when omitted —
    /// including when the request carries no body at all.
    #[serde(default)]
    policy: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct ScreenResponse {
    address: String,
    /// The outcome: `allow` | `review` | `block`.
    decision: crate::screen::Decision,
    /// Which rule produced it: `sanctions_hard_block` | `score_thresholds`.
    decision_basis: crate::screen::DecisionBasis,
    /// The named policy that decided this call (§11, Sprint 14 t2) — pinned
    /// alongside `decision_basis` so a past verdict is always reconstructible
    /// even after the customer retunes the policy's thresholds.
    policy_name: String,
    policy_version: i32,
    /// The address is on at least one sanctions list (§8.5) — always a
    /// `block`, regardless of policy.
    sanctioned: bool,
    /// The sanctions-list matches behind a `sanctions_hard_block`.
    sanctions: Vec<SanctionMatchResponse>,
    /// 0-100, "how risky" (§8.3).
    score: u32,
    /// 0-1, "how sure".
    confidence: f64,
    model_version: String,
    computed_at_unix_millis: i64,
    /// The address's active labels — context for the compliance record.
    labels: Vec<LabelResponse>,
    /// The address's resolved entity, if clustered.
    entity_id: Option<String>,
    /// Member count of that entity (0 when unclustered).
    entity_size: u32,
    /// The full per-factor breakdown behind `score`, each with its
    /// `evidence_ref` (§11 Sprint 14 t3) — present on a `review`/`block` so
    /// the decision is explainable and auditable; omitted on `allow` to keep
    /// the common-case response lean (the audit trail still records the
    /// factors for every decision regardless, see `crate::audit`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    factors: Vec<FactorResponse>,
    /// `true` when this decision was rendered over a last-known-good snapshot
    /// because intelligence was slow or unavailable (§11 graceful degradation).
    /// Always present, so a caller branches on one boolean: a customer that
    /// cannot accept stale facts on a withdrawal holds it on `stale: true`.
    stale: bool,
    /// Why the facts were stale and how old they were — omitted when fresh.
    #[serde(skip_serializing_if = "Option::is_none")]
    staleness: Option<FactsStaleness>,
}

/// `POST /v1/address/{address}/screen` — the **synchronous** counterparty
/// screening decision (§11): pre-transaction `allow`/`review`/`block` over
/// the intelligence service's cached risk score, confidence, labels, entity
/// and sanctions status (one `GetScreeningFacts` gRPC round-trip; Redis hot
/// path, §8.3), mapped through the named decision policy the body selects
/// (§11, Sprint 14 t2 — `crate::screen`, `crate::policy_store`). A sanctions
/// match hard-blocks regardless of score or policy (§8.5). The one
/// latency-critical blocking surface in the API.
///
/// POST, not GET: a screening decision is a billable, legally-weighty event
/// — every call is recorded onto the backbone as `ScreeningDecisionRecorded`
/// (§11, Sprint 14 t3, `crate::audit`) and will meter a `ScreeningCall` (t4)
/// — not a cacheable read. The body is optional — an absent or empty body,
/// or one naming no `policy`, uses `default`, and it is capped at 1 KiB.
///
/// **Graceful degradation** (readiness Epic D, [`crate::degrade`]): the call
/// sits inline on a customer's withdrawal, so when intelligence is slow past
/// its fresh budget, or transiently unavailable, the decision is rendered over
/// the address's last-known-good facts — through the caller's *current* policy,
/// sanctions hard-block intact — and flagged `stale: true` with its age and
/// reason, on the response and in the audit record. With no usable snapshot the
/// endpoint still fails closed with a 502; it never allows by default.
#[utoipa::path(
    post,
    path = "/v1/address/{address}/screen",
    tag = "api-service",
    params(("address" = String, Path, description = "On-chain address, 0x-prefixed hex (any case)")),
    request_body(content = ScreenRequest, description = "Optional. Selects the named policy; omit (or an empty body) uses `default`."),
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "The screening decision with its driving facts — `stale: true` when rendered over last-known-good facts because intelligence was slow or unavailable", body = ScreenResponse),
        (status = 400, description = "Address is not valid hex, the body isn't valid JSON, or `policy` names nothing this customer can see"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 413, description = "The request body exceeds the endpoint's 1 KiB cap"),
        (status = 429, description = "This endpoint's dedicated rate limit was exceeded (§19)"),
        (status = 502, description = "intelligence is unreachable with no usable last-known-good snapshot, or the policy store is unreachable"),
    ),
)]
async fn screen_address(
    State(state): State<AppState>,
    Extension(customer): Extension<CustomerId>,
    Path(address): Path<AccountAddress>,
    body: axum::body::Bytes,
) -> Result<Json<ScreenResponse>, ApiError> {
    // The body is optional (see the handler docs): an empty one is
    // indistinguishable from "no policy named" rather than a JSON parse
    // failure, so it's checked before ever calling `serde_json`.
    let policy_name = if body.is_empty() {
        None
    } else {
        serde_json::from_slice::<ScreenRequest>(&body)
            .map_err(|err| ApiError::bad_request(format!("invalid request body: {err}")))?
            .policy
    }
    .unwrap_or_else(|| crate::screen::DEFAULT_POLICY_NAME.to_owned());

    let policy = state
        .policies
        .resolve(customer, &policy_name)
        .await
        .map_err(policy_store::to_api_error)?
        .ok_or_else(|| ApiError::bad_request(format!("no such policy: {policy_name:?}")))?;

    // Fresh facts — or, when intelligence is slow or unavailable and degradation
    // is armed, a flagged last-known-good snapshot (`crate::degrade`). Either way
    // the decision below runs the caller's current policy.
    let degrade::ResolvedFacts {
        mut facts,
        staleness,
    } = degrade::resolve_facts(
        match &state.screening_source {
            Some(source) => source.as_ref(),
            None => &state.intelligence,
        },
        state.screening_fallback.as_ref(),
        address,
    )
    .await
    .map_err(intelligence_client::to_api_error)?;

    // §8.5 on every decision: the pod-local sanctions view can only *add*
    // designations to what intelligence reported — a snapshot taken before a
    // designation, or an intelligence cache racing an import, still blocks.
    if let Some(listed) = state.sanctions.lookup(&address) {
        merge_sanctions(&mut facts.sanctions, listed);
    }
    let freshness = match staleness {
        None => crate::screen::Freshness::Fresh,
        Some(staleness) => crate::screen::Freshness::Stale {
            staleness,
            sanctions_verified: state.sanctions.vouches(),
        },
    };

    // Wire → domain → policy: the prost reply is distilled once at the
    // transport edge's `From` impl; the decision layer only ever sees the
    // typed input.
    let input = crate::screen::ScreeningInput::from(&facts);
    let sanctioned = input.sanctioned;
    let verdict = crate::screen::decide(input, &policy, freshness);

    // §13 per-call metering: only on the success path — a call that 502'd
    // before a verdict was ever rendered isn't a billable screening call,
    // unlike `ApiCallMade` (which meters every authenticated request
    // regardless of outcome). Quantity is always 1; §13's Developer/Growth/
    // Scale/Enterprise volume tiers are computed downstream from these raw
    // events, never gated here (see `crate::rate_limit`'s module docs).
    state.usage.record(customer, UsageEventType::ScreeningCall);

    let outcome = ScreeningOutcome {
        customer,
        address,
        facts,
        verdict,
        sanctioned,
        freshness,
        decided_at: Utc::now(),
    };

    // The access-audit trail (§11 Sprint 14 t3): recorded for *every* decision,
    // not just a block/review — a borderline `allow` is just as much a fact a
    // compliance reviewer may need to reconstruct later. Non-blocking (see
    // `crate::audit`), so it can never add to the response's latency.
    state.audit.record(outcome.audit_record());
    Ok(Json(outcome.into_response()))
}

/// Add the view's designations to intelligence's, without duplicates.
fn merge_sanctions(
    reported: &mut Vec<intelligence::pb::SanctionMatch>,
    listed: Vec<intelligence::pb::SanctionMatch>,
) {
    for designation in listed {
        if !reported.contains(&designation) {
            reported.push(designation);
        }
    }
}

/// One rendered screening decision — the single value both the API response and
/// the access-audit record are derived from (§1 pure core).
///
/// One value rather than two mappers fed the same arguments, because the two
/// artifacts must agree on what the customer was told. Above all on
/// **freshness**: a decision rendered over a stale snapshot that disclosed
/// staleness to the customer but not to the audit trail (or the reverse) is
/// exactly the drift that threading the flag through two call sites invites.
struct ScreeningOutcome {
    customer: CustomerId,
    address: AccountAddress,
    facts: ScreeningFactsReply,
    verdict: crate::screen::Verdict,
    sanctioned: bool,
    freshness: crate::screen::Freshness,
    decided_at: DateTime<Utc>,
}

impl ScreeningOutcome {
    /// The §11 access-audit fact. Carries the full per-factor breakdown whatever
    /// the outcome, so a later review can reconstruct *why* even a borderline
    /// `allow` landed where it did.
    fn audit_record(&self) -> ScreeningDecisionRecorded {
        ScreeningDecisionRecorded {
            customer_id: self.customer,
            address: self.address,
            decision: self.verdict.decision,
            decision_basis: self.verdict.basis,
            policy_name: self.verdict.policy_name.clone(),
            policy_version: self.verdict.policy_version,
            score: self.facts.score,
            confidence: self.facts.confidence,
            sanctioned: self.sanctioned,
            model_version: self.facts.model_version.clone(),
            factors: self.verdict.factors.clone(),
            timestamp: self.decided_at,
            facts_staleness: self.freshness.staleness(),
        }
    }

    /// The `POST /v1/address/{addr}/screen` body. Consumes the outcome (no
    /// defensive clones on the SLO path); the factor breakdown is scoped to
    /// `review`/`block` — an `allow` stays lean on the wire while the audit
    /// record always carries it.
    fn into_response(self) -> ScreenResponse {
        let factors = if self.verdict.decision == crate::screen::Decision::Allow {
            Vec::new()
        } else {
            self.verdict
                .factors
                .iter()
                .map(FactorResponse::from)
                .collect()
        };
        let staleness = self.freshness.staleness();
        ScreenResponse {
            address: address_key(&self.address),
            decision: self.verdict.decision,
            decision_basis: self.verdict.basis,
            policy_name: self.verdict.policy_name,
            policy_version: self.verdict.policy_version,
            sanctioned: self.sanctioned,
            sanctions: self
                .facts
                .sanctions
                .into_iter()
                .map(|s| SanctionMatchResponse {
                    list: s.list,
                    entry: s.entry,
                })
                .collect(),
            score: self.facts.score,
            confidence: self.facts.confidence,
            model_version: self.facts.model_version,
            computed_at_unix_millis: self.facts.computed_at_unix_millis,
            labels: self
                .facts
                .labels
                .into_iter()
                .map(LabelResponse::from)
                .collect(),
            entity_id: self.facts.entity_id,
            entity_size: self.facts.entity_size,
            factors,
            stale: staleness.is_some(),
            staleness,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct PolicyResponse {
    name: String,
    version: i32,
    /// Score at/above which an otherwise-clean address holds for review.
    review_at: u8,
    /// Score at/above which an otherwise-clean address blocks outright.
    /// Absent means monitor-only: score can never block, only review.
    block_at: Option<u8>,
    /// `serve` | `review` — how a decision over stale facts is treated.
    on_stale: crate::screen::StalePolicy,
}

impl From<crate::screen::Policy> for PolicyResponse {
    fn from(policy: crate::screen::Policy) -> Self {
        Self {
            name: policy.name,
            version: policy.version,
            review_at: policy.thresholds.review_at(),
            block_at: policy.thresholds.block_at(),
            on_stale: policy.on_stale,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct PoliciesResponse {
    /// The free catalog every customer gets before authoring anything of
    /// their own — always exactly `default`/`strict`/`monitor-only`.
    builtin: Vec<PolicyResponse>,
    /// This customer's own named policies, each at its latest version.
    custom: Vec<PolicyResponse>,
}

/// `GET /v1/policies` — the full set of policy names this customer can pass
/// as `POST /v1/address/{addr}/screen`'s `policy` field: the built-in
/// catalog plus their own custom ones, each at its latest version (§11,
/// Sprint 14 t2).
#[utoipa::path(
    get,
    path = "/v1/policies",
    tag = "api-service",
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "The built-in catalog plus this customer's own policies", body = PoliciesResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 502, description = "The policy store is unreachable"),
    ),
)]
async fn list_policies(
    State(state): State<AppState>,
    Extension(customer): Extension<CustomerId>,
) -> Result<Json<PoliciesResponse>, ApiError> {
    let custom = state
        .policies
        .policies_for_owner(customer)
        .await
        .map_err(policy_store::to_api_error)?;

    Ok(Json(PoliciesResponse {
        builtin: crate::screen::builtin_catalog()
            .into_iter()
            .map(PolicyResponse::from)
            .collect(),
        custom: custom.into_iter().map(PolicyResponse::from).collect(),
    }))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct UpsertPolicyRequest {
    /// Score (0-100) at/above which an otherwise-clean address holds for
    /// review.
    review_at: u8,
    /// Score (0-100) at/above which an otherwise-clean address blocks
    /// outright. Omit (or `null`) for monitor-only: score can never block,
    /// only review — a sanctions match still hard-blocks regardless (§8.5).
    #[serde(default)]
    block_at: Option<u8>,
    /// What to do with a decision over stale facts: `serve` (default) or
    /// `review` — never auto-allow when intelligence could not confirm them.
    #[serde(default)]
    on_stale: crate::screen::StalePolicy,
}

/// `PUT /v1/policies/{name}` — create or retune one of this customer's named
/// decision policies (§11, Sprint 14 t2). Every call writes a **new**
/// version: thresholds are never edited in place, so a screening verdict
/// minted under an earlier version stays reconstructible after this customer
/// changes their mind. `name` may not be one of the built-in catalog
/// (`default`/`strict`/`monitor-only`) — those are read-only.
#[utoipa::path(
    put,
    path = "/v1/policies/{name}",
    tag = "api-service",
    params(("name" = String, Path, description = "Policy name (must not be a built-in name)")),
    request_body = UpsertPolicyRequest,
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "The policy version just written", body = PolicyResponse),
        (status = 400, description = "The name is reserved for a built-in policy, or block_at < review_at"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 502, description = "The policy store is unreachable"),
    ),
)]
async fn upsert_policy(
    State(state): State<AppState>,
    Extension(customer): Extension<CustomerId>,
    Path(name): Path<String>,
    Json(body): Json<UpsertPolicyRequest>,
) -> Result<Json<PolicyResponse>, ApiError> {
    let policy = state
        .policies
        .upsert_policy(
            customer,
            &name,
            body.review_at,
            body.block_at,
            body.on_stale,
            Utc::now(),
        )
        .await
        .map_err(policy_store::to_api_error)?;

    Ok(Json(policy.into()))
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
        .map_err(intelligence_client::to_api_error)?;

    Ok(Json(BuildersResponse {
        chain: query.chain,
        builders: reply.builders.into_iter().map(BuilderEntry::from).collect(),
        relays: reply.relays.into_iter().map(RelayEntry::from).collect(),
    }))
}

#[derive(Debug, Deserialize)]
struct SimilarAddressesQuery {
    /// Chain id whose embedding population to search. Defaults to Ethereum.
    #[serde(default = "default_chain")]
    chain: u64,
    /// How many neighbours to return; `0`/absent uses the intelligence
    /// default, and the value is clamped to its ceiling.
    #[serde(default)]
    limit: u32,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct SimilarityFactorResponse {
    /// The behavior feature's stable schema name (e.g. `busiest_day_share`).
    feature: String,
    /// The subject's value in the vector's own raw, interpretable units.
    subject_value: f32,
    /// The neighbour's raw value.
    candidate_value: f32,
    /// The subject's value in robust z-units against the population baseline.
    subject_z: f32,
    /// The neighbour's value in robust z-units.
    candidate_z: f32,
    /// Signed share of `similarity`. Positive: both sit on the same side of
    /// the population median, pulling them together. Negative: opposite sides.
    /// The factors of a result sum to its `similarity`.
    contribution: f32,
}

impl From<intelligence::pb::SimilarityFactor> for SimilarityFactorResponse {
    fn from(f: intelligence::pb::SimilarityFactor) -> Self {
        Self {
            feature: f.feature,
            subject_value: f.subject_value,
            candidate_value: f.candidate_value,
            subject_z: f.subject_z,
            candidate_z: f.candidate_z,
            contribution: f.contribution,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct SimilarAddressResponse {
    /// 0x-prefixed lowercase hex address.
    address: String,
    /// The neighbour's resolved entity at its compute time; absent when it
    /// belongs to none.
    entity_id: Option<String>,
    /// Cosine similarity between baseline-standardized behavior vectors,
    /// in `[-1, 1]`.
    similarity: f32,
    /// This neighbour's vector describes a recent activity window rather than
    /// its whole history (§8.2's hub rule) — a weaker claim, marked.
    observations_truncated: bool,
    /// When the neighbour's vector was computed — how stale this match is.
    computed_at_unix_millis: i64,
    /// The behavioral factors driving the match, largest effect first.
    factors: Vec<SimilarityFactorResponse>,
}

impl From<intelligence::pb::SimilarAddress> for SimilarAddressResponse {
    fn from(a: intelligence::pb::SimilarAddress) -> Self {
        Self {
            address: a.address,
            // `''` is the wire's absent-entity flattening; an empty string in
            // JSON would read as an entity whose id happens to be blank.
            entity_id: Some(a.entity_id).filter(|id| !id.is_empty()),
            similarity: a.similarity,
            observations_truncated: a.observations_truncated,
            computed_at_unix_millis: a.computed_at_unix_millis,
            factors: a
                .factors
                .into_iter()
                .map(SimilarityFactorResponse::from)
                .collect(),
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct SimilarAddressesResponse {
    address: String,
    /// The schema version and hash every score here was computed under. Two
    /// scores are only comparable when both match.
    embedding_version: String,
    schema_hash: String,
    /// When the subject's own behavior vector was computed.
    subject_computed_at_unix_millis: i64,
    /// Most similar first.
    results: Vec<SimilarAddressResponse>,
    /// The candidate shortlist filled its cap, so a better neighbour may exist
    /// outside it. `false` means the search saw the whole comparable
    /// population and this ranking is exact.
    approximate: bool,
    /// How many rows the shortlist stage returned.
    candidates_considered: u32,
    /// Shortlisted rows dropped during the exact re-rank: a superseded row for
    /// an address already seen, a vector from another schema version, or one
    /// with no signal to compare against.
    candidates_skipped: u32,
    /// Absent when the search ran. Otherwise why it could not, as a state
    /// rather than an error: `no_baseline` (the population baseline for this
    /// version has not been computed yet) or `no_signal` (this address is at
    /// the population median on essentially every feature, so there is no
    /// behavioral direction to search along). `results` is empty in both cases.
    unavailable_reason: Option<String>,
}

/// `GET /v1/address/{address}/similar?limit=20` — addresses that behave like
/// this one (§20.3, §8.3), each with the behavioral factors that drove the
/// match.
///
/// intelligence shortlists neighbours off the ClickHouse vector index over
/// `address_embeddings.vector`, then re-ranks them exactly against the
/// population baseline, so `similarity` is a cosine in **standardized** units
/// and `approximate` says whether the shortlist could have missed a better
/// neighbour.
///
/// A high score is an investigative lead and the §20.3 clustering signal's
/// input — a reduced-confidence heuristic. It is never evidence that two
/// addresses are the same entity: merges still require the §8.2 on-chain
/// evidence heuristics.
#[utoipa::path(
    get,
    path = "/v1/address/{address}/similar",
    tag = "api-service",
    params(
        ("address" = String, Path, description = "On-chain address, 0x-prefixed hex (any case)"),
        ("chain" = Option<u64>, Query, description = "Chain id (default 1 = Ethereum)"),
        ("limit" = Option<u32>, Query, description = "Neighbours to return (0 = server default)"),
    ),
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "Behaviorally similar addresses, most similar first", body = SimilarAddressesResponse),
        (status = 400, description = "Address is not valid hex"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 404, description = "This address has no behavior vector"),
        (status = 502, description = "intelligence is unreachable"),
    ),
)]
async fn address_similar(
    State(state): State<AppState>,
    Extension(customer): Extension<CustomerId>,
    Path(address): Path<AccountAddress>,
    Query(query): Query<SimilarAddressesQuery>,
) -> Result<Json<SimilarAddressesResponse>, ApiError> {
    let reply = state
        .intelligence
        .similar_addresses(address_key(&address), query.chain, query.limit)
        .await
        .map_err(intelligence_client::to_api_error)?;

    if !reply.found {
        return Err(ApiError::not_found(format!(
            "address {} has no behavior vector under {}",
            address_key(&address),
            reply.embedding_version
        )));
    }

    // Metered like the other investigation reads (§13). Deliberately the same
    // SKU as the entity graph/timeline rather than a new one: a divergent
    // event_type string is an unreconcilable billing line, and this is the
    // same kind of question about the same graph.
    state
        .usage
        .record(customer, events::system::UsageEventType::EntityQueried);

    Ok(Json(SimilarAddressesResponse {
        address: address_key(&address),
        embedding_version: reply.embedding_version,
        schema_hash: reply.schema_hash,
        subject_computed_at_unix_millis: reply.subject_computed_at_unix_millis,
        results: reply
            .results
            .into_iter()
            .map(SimilarAddressResponse::from)
            .collect(),
        approximate: reply.approximate,
        candidates_considered: reply.candidates_considered,
        candidates_skipped: reply.candidates_skipped,
        unavailable_reason: Some(reply.unavailable_reason).filter(|r| !r.is_empty()),
    }))
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
struct LinkCandidatesQuery {
    /// How many proposals to return; `0`/absent uses the intelligence default,
    /// and the value is clamped to its ceiling.
    #[serde(default)]
    limit: u32,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct LinkFactorResponse {
    /// The behavior feature's stable schema name.
    feature: String,
    /// The subject's value in the vector's own raw, interpretable units.
    subject_value: f32,
    /// The other address's raw value.
    candidate_value: f32,
    /// Signed share of `similarity`; the factors of a proposal sum to it.
    contribution: f32,
}

impl From<intelligence::pb::LinkFactor> for LinkFactorResponse {
    fn from(f: intelligence::pb::LinkFactor) -> Self {
        Self {
            feature: f.feature,
            subject_value: f.subject_value,
            candidate_value: f.candidate_value,
            contribution: f.contribution,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct LinkCandidateResponse {
    candidate_id: String,
    /// The pair, canonically ordered — a candidate link is symmetric, so
    /// neither address is "the subject". `anchor` carries the direction that
    /// matters.
    address_a: String,
    address_b: String,
    /// Whichever of the pair carried the directly-known actor label that made
    /// the proposal worth making.
    anchor: String,
    /// The anchor's label kinds at proposal time (`known_scammer`,
    /// `sanctioned_entity`, `mev_bot`), frozen — a later revocation does not
    /// rewrite why the proposal exists.
    anchor_labels: Vec<String>,
    /// Each side's entity at proposal time; absent when unclustered.
    entity_a: Option<String>,
    entity_b: Option<String>,
    /// Cosine similarity between baseline-standardized behavior vectors.
    similarity: f32,
    /// The §8.1 reduced-confidence band this signal is worth. Always below the
    /// entity-derived 0.5 band: a behavioral match is weaker evidence than a
    /// graph one.
    confidence: f64,
    /// The feature space the comparison was made in.
    embedding_version: String,
    schema_hash: String,
    /// The behavioral factors behind the score, largest effect first.
    factors: Vec<LinkFactorResponse>,
    /// `proposed` | `confirmed` | `rejected`. Only an operator moves it off
    /// `proposed` — nothing in the pipeline does.
    status: String,
    proposed_at_unix_millis: i64,
    /// Refreshed every time the proposal is rediscovered: "still true on the
    /// latest recomputation" is a materially stronger claim than "seen once".
    last_seen_at_unix_millis: i64,
    decided_at_unix_millis: Option<i64>,
    decided_by: Option<String>,
    decision_note: Option<String>,
}

impl From<intelligence::pb::LinkCandidate> for LinkCandidateResponse {
    fn from(c: intelligence::pb::LinkCandidate) -> Self {
        Self {
            candidate_id: c.candidate_id,
            address_a: c.address_a,
            address_b: c.address_b,
            anchor: c.anchor,
            anchor_labels: c.anchor_labels,
            // `''`/`0` are the wire's absent flattening; passing them through
            // as JSON would read as a blank entity id and a 1970 decision.
            entity_a: Some(c.entity_a).filter(|id| !id.is_empty()),
            entity_b: Some(c.entity_b).filter(|id| !id.is_empty()),
            similarity: c.similarity,
            confidence: c.confidence,
            embedding_version: c.embedding_version,
            schema_hash: c.schema_hash,
            factors: c
                .factors
                .into_iter()
                .map(LinkFactorResponse::from)
                .collect(),
            status: c.status,
            proposed_at_unix_millis: c.proposed_at_unix_millis,
            last_seen_at_unix_millis: c.last_seen_at_unix_millis,
            decided_at_unix_millis: Some(c.decided_at_unix_millis).filter(|at| *at != 0),
            decided_by: Some(c.decided_by).filter(|by| !by.is_empty()),
            decision_note: Some(c.decision_note).filter(|note| !note.is_empty()),
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct LinkCandidatesResponse {
    address: String,
    /// Strongest first. Includes decided proposals: that a link was proposed
    /// *and rejected* is as much a part of this address's story as an open one.
    candidates: Vec<LinkCandidateResponse>,
}

/// `GET /v1/address/{address}/link-candidates?limit=20` — the §20.3 clustering
/// signal's proposals touching this address.
///
/// Each is a behavioral link to a **directly-known** actor, entered into entity
/// clustering as a reduced-confidence heuristic exactly the way §8.1 treats
/// every heuristic label. A proposal is a lead, not a finding: entity merges
/// still require the §8.2 on-chain evidence heuristics, and nothing in the
/// pipeline moves a proposal past `proposed` — only an operator does.
///
/// Unlike `/similar`, this is a plain keyed read of already-computed rows, so
/// it carries no separate rate-limit bucket: the expensive work happened in the
/// `link-signal` consumer, which is why the proposals are materialized at all.
#[utoipa::path(
    get,
    path = "/v1/address/{address}/link-candidates",
    tag = "api-service",
    params(
        ("address" = String, Path, description = "On-chain address, 0x-prefixed hex (any case)"),
        ("limit" = Option<u32>, Query, description = "Proposals to return (0 = server default)"),
    ),
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "Candidate links touching this address, strongest first", body = LinkCandidatesResponse),
        (status = 400, description = "Address is not valid hex"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 502, description = "intelligence is unreachable"),
    ),
)]
async fn address_link_candidates(
    State(state): State<AppState>,
    Extension(customer): Extension<CustomerId>,
    Path(address): Path<AccountAddress>,
    Query(query): Query<LinkCandidatesQuery>,
) -> Result<Json<LinkCandidatesResponse>, ApiError> {
    let reply = state
        .intelligence
        .link_candidates(address_key(&address), query.limit)
        .await
        .map_err(intelligence_client::to_api_error)?;

    // No 404 arm, deliberately: an address with no proposals is a *complete*
    // answer ("nothing has been proposed about this address"), not a missing
    // resource. `/similar` 404s because a subject with no vector cannot be
    // compared at all; here there is nothing to be missing.
    state
        .usage
        .record(customer, events::system::UsageEventType::EntityQueried);

    Ok(Json(LinkCandidatesResponse {
        address: address_key(&address),
        candidates: reply
            .candidates
            .into_iter()
            .map(LinkCandidateResponse::from)
            .collect(),
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
        .map_err(intelligence_client::to_api_error)?;

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
        .map_err(intelligence_client::to_api_error)?;

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
        (status = 502, description = "event-store is unreachable or answered 5xx"),
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
    .map_err(ApiError::bad_gateway)?
    .client_visible("event-store")?;

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
        (status = 502, description = "simulation-projection is unreachable or answered 5xx"),
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
    .map_err(ApiError::bad_gateway)?
    .client_visible("simulation-projection")?;

    Ok((proxied.status, Json(proxied.body)).into_response())
}

/// `GET /v1/wallet/{addr}/mev-exposure?since=` — proxies simulation-projection's
/// internal `GET /v1/wallet/{addr}/mev-exposure` verbatim (§11): counts and USD
/// totals by kind for every confirmed incident that named `addr` as its victim,
/// each linked to its `/v1/audit/incident/{incident_id}` audit trail via
/// `incident_id`.
#[utoipa::path(
    get,
    path = "/v1/wallet/{addr}/mev-exposure",
    tag = "api-service",
    params(
        ("addr" = String, Path, description = "Wallet address"),
        ("since" = Option<String>, Query, description = "Only incidents at/after this RFC 3339 timestamp"),
    ),
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "The wallet's MEV-exposure summary (proxied from simulation-projection)"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 502, description = "simulation-projection is unreachable or answered 5xx"),
    ),
)]
async fn wallet_mev_exposure(
    State(state): State<AppState>,
    Extension(customer): Extension<CustomerId>,
    Path(addr): Path<String>,
    Query(params): Query<RawQuery>,
) -> Result<Response, ApiError> {
    let proxied = upstream::get(
        &state.http_client,
        &state.simulation_url,
        &format!("/v1/wallet/{addr}/mev-exposure"),
        &params,
    )
    .await
    .map_err(ApiError::bad_gateway)?
    .client_visible("simulation-projection")?;

    state.usage.record(
        customer,
        events::system::UsageEventType::WalletMevExposureQueried,
    );

    Ok((proxied.status, Json(proxied.body)).into_response())
}

/// `GET /v1/timing/recommendation?chain=&size=` — proxies simulation-projection's
/// internal `GET /v1/timing/recommendation` verbatim (safe-block-timing):
/// historical incident intensity ranked into the safest-first low-MEV
/// windows for the given chain and "size" (severity) band. A heuristic over
/// historical patterns — the response always carries a `caveat` field, never
/// a guarantee.
#[utoipa::path(
    get,
    path = "/v1/timing/recommendation",
    tag = "api-service",
    params(
        ("chain" = Option<u64>, Query, description = "Chain id (defaults to Ethereum mainnet)"),
        ("size" = Option<String>, Query, description = "low | medium | high | critical (defaults to medium)"),
    ),
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "Ranked low-MEV time windows for the chain/size, with sample size and caveat (proxied from simulation-projection)"),
        (status = 400, description = "Unrecognized `size` value"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 502, description = "simulation-projection is unreachable or answered 5xx"),
    ),
)]
async fn timing_recommendation(
    State(state): State<AppState>,
    Extension(customer): Extension<CustomerId>,
    Query(params): Query<RawQuery>,
) -> Result<Response, ApiError> {
    let proxied = upstream::get(
        &state.http_client,
        &state.simulation_url,
        "/v1/timing/recommendation",
        &params,
    )
    .await
    .map_err(ApiError::bad_gateway)?
    .client_visible("simulation-projection")?;

    state.usage.record(
        customer,
        events::system::UsageEventType::TimingRecommendationQueried,
    );

    Ok((proxied.status, Json(proxied.body)).into_response())
}

/// `POST /v1/monitored-wallets` request body: the wallet to opt in for the
/// caller's scheduled §25 exposure report push.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct AddMonitoredWalletRequest {
    /// Chain id. Defaults to Ethereum mainnet.
    #[serde(default = "default_chain")]
    chain_id: u64,
    #[schema(value_type = String)]
    address: AccountAddress,
}

/// What this service proxies to simulation-projection's internal
/// `POST /v1/monitored-wallets` — `owner` is composed here from the caller's
/// JWT, never taken from the request body (a body cannot opt in another
/// customer's wallet).
#[derive(Serialize)]
struct MonitoredWalletProxyRequest {
    owner: CustomerId,
    chain_id: u64,
    address: AccountAddress,
}

/// `POST /v1/monitored-wallets` — opt an address in for the caller's
/// scheduled MEV-exposure report push (§25), delivered via the notification
/// service (§12) on a recurring cadence. Idempotent: opting the same pair in
/// twice is a `200`, not a duplicate.
///
/// Meters `ApiCallMade` only (the router-wide middleware). The dedicated
/// `WalletMonitored` usage fact (§13, "per customer-configured address") is
/// metered **recurringly** by simulation-projection's scheduler — once per
/// wallet per report cycle, for as long as it stays opted in — not once here
/// at opt-in; see `simulation::exposure_report`'s module docs for why.
#[utoipa::path(
    post,
    path = "/v1/monitored-wallets",
    tag = "api-service",
    request_body = AddMonitoredWalletRequest,
    security(("bearer_token" = [])),
    responses(
        (status = 201, description = "Wallet opted in"),
        (status = 200, description = "Already monitored (idempotent retry)"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 502, description = "simulation-projection is unreachable or answered 5xx"),
    ),
)]
async fn add_monitored_wallet(
    State(state): State<AppState>,
    Extension(customer): Extension<CustomerId>,
    Json(body): Json<AddMonitoredWalletRequest>,
) -> Result<Response, ApiError> {
    let proxied = upstream::post_json(
        &state.http_client,
        &state.simulation_url,
        "/v1/monitored-wallets",
        &MonitoredWalletProxyRequest {
            owner: customer,
            chain_id: body.chain_id,
            address: body.address,
        },
    )
    .await
    .map_err(ApiError::bad_gateway)?
    .client_visible("simulation-projection")?;

    Ok((proxied.status, Json(proxied.body)).into_response())
}

/// `GET /v1/monitored-wallets` — the caller's own opted-in wallets, proxied
/// from simulation-projection's internal `GET /v1/monitored-wallets` (`owner`
/// composed from the caller's JWT, not a client-supplied query param).
#[utoipa::path(
    get,
    path = "/v1/monitored-wallets",
    tag = "api-service",
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "The caller's monitored wallets (proxied from simulation-projection)"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 502, description = "simulation-projection is unreachable or answered 5xx"),
    ),
)]
async fn list_monitored_wallets(
    State(state): State<AppState>,
    Extension(customer): Extension<CustomerId>,
) -> Result<Response, ApiError> {
    let mut query = RawQuery::new();
    query.insert("owner".to_owned(), customer.to_string());

    let proxied = upstream::get(
        &state.http_client,
        &state.simulation_url,
        "/v1/monitored-wallets",
        &query,
    )
    .await
    .map_err(ApiError::bad_gateway)?
    .client_visible("simulation-projection")?;

    Ok((proxied.status, Json(proxied.body)).into_response())
}

/// `DELETE /v1/monitored-wallets/{chain_id}/{address}` — opt out. Proxies
/// simulation-projection's internal `DELETE /v1/monitored-wallets/{chain_id}/{address}`
/// (`owner` composed from the caller's JWT, so a caller can only ever remove
/// their own opt-in).
#[utoipa::path(
    delete,
    path = "/v1/monitored-wallets/{chain_id}/{address}",
    tag = "api-service",
    params(
        ("chain_id" = u64, Path, description = "Chain id"),
        ("address" = String, Path, description = "Wallet address"),
    ),
    security(("bearer_token" = [])),
    responses(
        (status = 204, description = "Opted out"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 404, description = "This address was not monitored for this caller"),
        (status = 502, description = "simulation-projection is unreachable or answered 5xx"),
    ),
)]
async fn remove_monitored_wallet(
    State(state): State<AppState>,
    Extension(customer): Extension<CustomerId>,
    Path((chain_id, address)): Path<(u64, String)>,
) -> Result<Response, ApiError> {
    let mut query = RawQuery::new();
    query.insert("owner".to_owned(), customer.to_string());

    let proxied = upstream::delete(
        &state.http_client,
        &state.simulation_url,
        &format!("/v1/monitored-wallets/{chain_id}/{address}"),
        &query,
    )
    .await
    .map_err(ApiError::bad_gateway)?
    .client_visible("simulation-projection")?;

    // The upstream's 204/404 carry no body (`remove_monitored_wallet` on the
    // simulation-projection side answers with a bare `StatusCode`); attaching
    // an empty-string JSON body to a 204 would violate its "no body" contract,
    // unlike every other proxy here whose upstream always answers JSON.
    Ok(
        if proxied.body.is_string() && proxied.body.as_str() == Some("") {
            proxied.status.into_response()
        } else {
            (proxied.status, Json(proxied.body)).into_response()
        },
    )
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
    // The customer's half and the platform's half, assembled through the
    // shared `RuleDefinition` (§9) rather than by hand. That type is also what
    // §20.4's natural-language drafter emits and what its structured-output
    // schema is generated from, so "a drafted rule is exactly a `POST
    // /v1/rules` body" is a fact about the types rather than a claim in a doc
    // comment — and `owner`/`id` stay the two fields no body can name.
    let rule = RuleDefinition {
        name: body.name,
        enabled: body.enabled,
        conditions: body.conditions,
        logic: body.logic,
        temporal: body.temporal,
        actions: body.actions,
    }
    .into_rule(body.id.unwrap_or_else(RuleId::new), customer);

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

/// `POST /v1/incidents/{incident_id}/feedback` body: the customer's verdict on
/// one incident, plus optional prose. Nothing else — `customer_id` comes from
/// the bearer token (owner-from-JWT, the same rule `POST /v1/rules` follows: a
/// body can never attribute an opinion to somebody else) and `submitted_at`
/// comes from this service's clock, because a client-supplied timestamp is the
/// ledger's last-writer key and would let one caller pin a verdict at the end
/// of time.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct FeedbackRequest {
    /// The capability token from the alert that was delivered — proof that
    /// this incident was shown to this customer (`feedback-grant`). Without
    /// it there is nothing authorizing the write: "the incident exists" is
    /// true of every incident in the platform.
    grant: String,
    /// `true_positive` | `false_positive` | `unclear`.
    #[schema(value_type = String, example = "false_positive")]
    verdict: FeedbackVerdict,
    /// Why, as a closed set — `our_own_activity`, `known_counterparty`,
    /// `threshold_too_sensitive`, `duplicate_alert`, `confirmed_harm`,
    /// `unspecified`. This is the field the platform acts on.
    #[serde(default)]
    #[schema(value_type = String, example = "our_own_activity")]
    reason_code: FeedbackReason,
    /// Optional free text, at most [`MAX_FEEDBACK_REASON_CHARS`] characters.
    /// Never parsed and never routed on.
    ///
    /// **Do not include personal data.** It is written to an append-only
    /// event log held for the §18 statutory window, where individual fields
    /// cannot be edited or erased.
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct FeedbackResponse {
    incident_id: String,
    /// Always `recorded` — the verdict is on its way to the backbone. A
    /// verdict that could *not* be queued is a 503, never this.
    status: &'static str,
}

/// `POST /v1/incidents/{incident_id}/feedback` — tell the platform it was
/// right or wrong about one incident (§19, readiness Epic E).
///
/// This is the false-positive loop's only input. The verdict is published as
/// `AlertFeedbackRecorded`, folded into the simulation service's feedback
/// ledger, and read by the §19 false-positive panel and the SLO alert behind
/// it. It changes nothing about the incident itself: a `false_positive`
/// verdict is *not* a retraction (§7 retraction is the platform withdrawing
/// its own finding), the incident stays exactly as it was, and both statements
/// live on the record.
///
/// Authorized by a **capability**, not by a lookup: the caller presents the
/// signed grant that was delivered with the alert, which proves the incident
/// was shown to them. Every accepted verdict moves an accuracy number, so
/// "this incident exists" — true of every incident in the platform — is not a
/// sufficient reason to keep one.
#[utoipa::path(
    post,
    path = "/v1/incidents/{incident_id}/feedback",
    tag = "api-service",
    params(("incident_id" = String, Path, format = Uuid, description = "Incident id")),
    request_body = FeedbackRequest,
    security(("bearer_token" = [])),
    responses(
        (status = 202, description = "Verdict recorded", body = FeedbackResponse),
        (status = 200, description = "Idempotent retry: this verdict was already recorded", body = FeedbackResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "The grant is invalid, expired, or not for this incident/customer"),
        (status = 422, description = "The verdict is malformed (reason in the body)"),
        (status = 503, description = "The verdict could not be durably accepted — retry"),
    ),
)]
async fn record_incident_feedback(
    State(state): State<AppState>,
    Extension(customer): Extension<CustomerId>,
    Path(incident_id): Path<uuid::Uuid>,
    headers: axum::http::HeaderMap,
    Json(body): Json<FeedbackRequest>,
) -> Result<Response, ApiError> {
    // The standard retry-safety header. Optional: a caller who does not send
    // one still gets deduplicated on the verdict's own identity.
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty() && v.len() <= 128);
    if let Some(reason) = body.reason.as_deref() {
        // Counted in characters, not bytes: the body limit already bounds the
        // bytes, and a customer writing in a non-Latin script should get the
        // same allowance as one writing in English.
        if reason.chars().count() > MAX_FEEDBACK_REASON_CHARS {
            return Ok((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "error": format!(
                        "reason is longer than {MAX_FEEDBACK_REASON_CHARS} characters"
                    )
                })),
            )
                .into_response());
        }
    }

    // Authorization, and the only I/O-free part of it: the grant proves this
    // incident was *delivered* to this customer. It replaces the existence
    // check an earlier draft did against event-store, which authorized
    // nothing (every incident exists), leaked an existence oracle through its
    // 404, and coupled a scarce human signal to a second service being up.
    let Some(verifying_key) = state.feedback_grant.as_deref() else {
        // Not configured here. 503, not 404: the route exists and a retry
        // against a correctly configured deployment will work — and the
        // absent secret must never read as "no such incident".
        return Err(ApiError::unavailable(
            "feedback is not enabled on this deployment (FEEDBACK_GRANT_SECRET unset)",
        ));
    };
    let grant = feedback_grant::verify(verifying_key, &body.grant)
        .map_err(|_| ApiError::forbidden("the feedback grant is not valid"))?;

    // The grant names an incident and a recipient; the request names a path
    // and carries a bearer token. All four must agree. Checking the customer
    // here rather than inside `verify` is deliberate: the capability says who
    // it was issued to, and the *service* says who is calling — conflating
    // them turns a capability into a bearer token anyone who intercepts it
    // can spend.
    if grant.incident_id != incident_id || grant.customer_id != customer.0 {
        return Err(ApiError::forbidden(
            "the feedback grant is not for this incident",
        ));
    }

    let verdict = AlertFeedbackRecorded {
        incident_id: IncidentId(incident_id),
        customer_id: customer,
        verdict: body.verdict,
        reason_code: body.reason_code,
        // An empty string is not a reason; normalize it away here so the
        // ledger never has to distinguish `None` from `Some("")`.
        reason: body
            .reason
            .map(|r| r.trim().to_string())
            .filter(|r| !r.is_empty()),
        // From the signed grant, never from the body: the cohort decides which
        // sample this verdict joins, and a recipient who could choose it could
        // promote their own opinion into the number a README quotes.
        cohort: grant.cohort.parse().unwrap_or_default(),
        submitted_at: Utc::now(),
    };

    let labels = [
        ("verdict", verdict.verdict.as_str()),
        ("reason_code", verdict.reason_code.as_str()),
        ("cohort", verdict.cohort.as_str()),
    ];
    let key = feedback::idempotency_key(&verdict, idempotency_key.as_deref());
    let envelope =
        serde_json::to_value(feedback::envelope_for(verdict)).map_err(ApiError::internal)?;

    // One INSERT, then 202. No transaction: this outbox row *is* the write —
    // there is no second table for it to commit atomically with — so the
    // pool's implicit single-statement transaction is exactly the guarantee
    // needed, and holding an explicit one would only widen the window.
    let queued = state.feedback.enqueue(&envelope, &key).await;

    match queued {
        Ok(outbox::Enqueued::Queued) => {
            metrics::counter!(feedback::FEEDBACK_RECORDED_TOTAL, &labels).increment(1);
            Ok((
                StatusCode::ACCEPTED,
                Json(FeedbackResponse {
                    incident_id: incident_id.to_string(),
                    status: "recorded",
                }),
            )
                .into_response())
        }
        // A retry of something already accepted. `200` rather than `202`, and
        // a different `status`, so a client can tell the two apart — the same
        // shape `POST /v1/rules` uses for an idempotent create.
        Ok(outbox::Enqueued::AlreadyQueued) => {
            metrics::counter!(feedback::FEEDBACK_DUPLICATE_TOTAL).increment(1);
            Ok((
                StatusCode::OK,
                Json(FeedbackResponse {
                    incident_id: incident_id.to_string(),
                    status: "already_recorded",
                }),
            )
                .into_response())
        }
        Err(err) => {
            // Postgres is down. Say so rather than 202-ing a verdict we could
            // not keep: this sample is small, the caller is a human who will
            // happily retry, and a lie here biases the FP rate toward optimism
            // exactly when the platform is unhealthy.
            metrics::counter!(feedback::FEEDBACK_REFUSED_TOTAL).increment(1);
            tracing::warn!(error = %err, "could not durably accept a verdict");
            Err(ApiError::unavailable("could not record the verdict; retry"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{build_router, AppState};
    use crate::audit::AuditRecorder;
    use crate::config::JwtConfig;
    use crate::feedback::test_util::InMemoryFeedbackQueue;
    use crate::intelligence_client::IntelligenceClient;
    use crate::policy_store::test_util::InMemoryPolicyStore;
    use crate::policy_store::PolicyStore;
    use crate::rate_limit::test_util::InMemoryRateLimiter;
    use crate::usage::UsageRecorder;
    use event_bus::test_util::RecordingSink;
    use events::system::{
        ScreeningDecision, ScreeningDecisionBasis, ScreeningDecisionRecorded, ScreeningStaleReason,
        UsageEventType, UsageRecorded,
    };
    use rule_engine::test_util::InMemoryRuleStore;
    use secrecy::SecretString;
    use tokio::sync::mpsc;

    /// Everything a handler test observes: the state to build the router
    /// from, plus the doubles behind it (what got metered, what got stored,
    /// what got published).
    struct TestState {
        state: AppState,
        usage_rx: mpsc::Receiver<UsageRecorded>,
        audit_rx: mpsc::Receiver<ScreeningDecisionRecorded>,
        /// What the handler parked — the doubles' view of the outbox.
        feedback: Arc<InMemoryFeedbackQueue>,
        rules: Arc<InMemoryRuleStore>,
        events: Arc<RecordingSink>,
        policies: Arc<InMemoryPolicyStore>,
    }

    /// A throwaway state — `connect_lazy` does no I/O (the channel dials on
    /// first RPC), so the router/spec can be built with no live intelligence.
    fn test_state() -> TestState {
        let (usage, usage_rx) = UsageRecorder::channel(16);
        let (audit, audit_rx) = AuditRecorder::channel(16);
        let feedback = Arc::new(InMemoryFeedbackQueue::new());
        let rules = Arc::new(InMemoryRuleStore::new());
        let events = Arc::new(RecordingSink::default());
        let policies = Arc::new(InMemoryPolicyStore::new());
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
            audit,
            feedback: feedback.clone(),
            feedback_grant: Some(Arc::new(feedback_grant::VerifyingKey::from_secret(
                SecretString::from(TEST_GRANT_SECRET),
            ))),
            rules: rules.clone(),
            events: events.clone(),
            policies: policies.clone(),
            screening_rate_limit: Arc::new(InMemoryRateLimiter::unbounded()),
            screening_fallback: None,
            sanctions: Arc::new(crate::sanctions_view::SanctionsView::default()),
            screening_source: None,
        };
        TestState {
            state,
            usage_rx,
            audit_rx,
            feedback,
            rules,
            events,
            policies,
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
            "ScreenRequest",
            "ScreenResponse",
            "SanctionMatchResponse",
            "ScreeningDecision",
            "ScreeningDecisionBasis",
            "FactsStaleness",
            "ScreeningStaleReason",
            "StalePolicy",
            "CreateRuleRequest",
            "CreateRuleResponse",
            "BuildersResponse",
            "BuilderEntry",
            "RelayEntry",
            "SimilarAddressesResponse",
            "SimilarAddressResponse",
            "SimilarityFactorResponse",
            "LinkCandidatesResponse",
            "LinkCandidateResponse",
            "LinkFactorResponse",
            "EntityGraphResponse",
            "GraphNodeResponse",
            "GraphEdgeResponse",
            "EntityTimelineResponse",
            "TimelineMilestoneResponse",
            "UpsertPolicyRequest",
            "PolicyResponse",
            "PoliciesResponse",
            "AddMonitoredWalletRequest",
            "FeedbackRequest",
            "FeedbackResponse",
            "FeedbackVerdict",
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
            ("/v1/address/{address}/similar", "get"),
            ("/v1/address/{address}/link-candidates", "get"),
            ("/v1/address/{address}/screen", "post"),
            ("/v1/policies", "get"),
            ("/v1/policies/{name}", "put"),
            ("/v1/builders", "get"),
            ("/v1/entity/{entity_id}/graph", "get"),
            ("/v1/entity/{entity_id}/timeline", "get"),
            ("/v1/audit/incident/{incident_id}", "get"),
            ("/v1/incidents", "get"),
            ("/v1/wallet/{addr}/mev-exposure", "get"),
            ("/v1/monitored-wallets", "post"),
            ("/v1/monitored-wallets", "get"),
            ("/v1/monitored-wallets/{chain_id}/{address}", "delete"),
            ("/v1/rules", "post"),
            ("/v1/incidents/{incident_id}/feedback", "post"),
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
    async fn address_similar_is_bearer_gated_and_proxies_intelligence() {
        use axum::body::Body;
        use axum::http::{header, Request, StatusCode};
        use tower::ServiceExt;

        let ts = test_state();
        let bearer = mint_bearer(&ts.state, "00000000-0000-0000-0000-0000000000c0");
        let router = super::router(ts.state);
        let path = "/v1/address/0x1111111111111111111111111111111111111111/similar?limit=5";

        // No token → rejected by the JWT gate before the handler, so an
        // unauthenticated call can never be metered.
        let response = router
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Authenticated, but the lazy intelligence channel has no server here,
        // so the gRPC call fails → 502 (reached the handler, tried to proxy).
        // This also proves the address path and `limit` query param parse.
        let response = router
            .clone()
            .oneshot(
                Request::get(path)
                    .header(header::AUTHORIZATION, &bearer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

        // A malformed address is rejected by axum's path extractor, before any
        // upstream call — the same boundary the other address routes hold.
        let response = router
            .oneshot(
                Request::get("/v1/address/not-an-address/similar")
                    .header(header::AUTHORIZATION, &bearer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn address_link_candidates_is_bearer_gated_and_proxies_intelligence() {
        use axum::body::Body;
        use axum::http::{header, Request, StatusCode};
        use tower::ServiceExt;

        let ts = test_state();
        let bearer = mint_bearer(&ts.state, "00000000-0000-0000-0000-0000000000c0");
        let router = super::router(ts.state);
        let path = "/v1/address/0x1111111111111111111111111111111111111111/link-candidates?limit=5";

        let response = router
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Authenticated, but the lazy intelligence channel has no server here,
        // so the gRPC call fails → 502 (reached the handler, tried to proxy).
        let response = router
            .clone()
            .oneshot(
                Request::get(path)
                    .header(header::AUTHORIZATION, &bearer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

        let response = router
            .oneshot(
                Request::get("/v1/address/not-an-address/link-candidates")
                    .header(header::AUTHORIZATION, &bearer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
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

    /// The screen endpoint sits behind the same JWT gate as every /v1 route,
    /// parses its address, and proxies intelligence (502 when unreachable —
    /// the same posture as /risk and /labels).
    #[tokio::test]
    async fn screen_is_bearer_gated_validates_the_address_and_proxies_intelligence() {
        use axum::body::Body;
        use axum::http::{header, Request, StatusCode};
        use tower::ServiceExt;

        let ts = test_state();
        let bearer = mint_bearer(&ts.state, "00000000-0000-0000-0000-0000000000c0");
        let router = super::router(ts.state);
        let path = format!("/v1/address/{:#x}/screen", alloy_primitives::Address::ZERO);

        // No token → rejected by the JWT gate before the handler.
        let response = router
            .clone()
            .oneshot(Request::post(&path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Authenticated, but the lazy intelligence channel has no server
        // here, so the gRPC call fails → 502 (reached the handler, tried the
        // read). Screening degrades loudly, never silently "allows".
        let response = router
            .clone()
            .oneshot(
                Request::post(&path)
                    .header(header::AUTHORIZATION, &bearer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

        // A non-hex address is a 400 from path parsing, before any RPC.
        let response = router
            .oneshot(
                Request::post("/v1/address/not-an-address/screen")
                    .header(header::AUTHORIZATION, &bearer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// An unknown `policy` name is a 400, resolved (and rejected) before the
    /// endpoint ever calls the unreachable intelligence channel — a bad
    /// request never spends the screening deadline budget on a doomed RPC.
    #[tokio::test]
    async fn screen_rejects_an_unknown_policy_name_before_calling_intelligence() {
        use axum::body::Body;
        use axum::http::{header, Request, StatusCode};
        use tower::ServiceExt;

        let ts = test_state();
        let bearer = mint_bearer(&ts.state, "00000000-0000-0000-0000-0000000000c0");
        let router = super::router(ts.state);
        let path = format!("/v1/address/{:#x}/screen", alloy_primitives::Address::ZERO);

        let response = router
            .oneshot(
                Request::post(&path)
                    .header(header::AUTHORIZATION, &bearer)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"policy":"nonexistent"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// §13/Sprint 14 t4: `ScreeningCall` is billable metering, distinct from
    /// the always-fires `ApiCallMade` — a call that never produced a verdict
    /// (here, the lazy intelligence channel 502s before `decide` runs) must
    /// not bill one. Only the generic per-request meter fires.
    #[tokio::test]
    async fn a_failed_screening_call_meters_api_call_made_but_not_screening_call() {
        use axum::body::Body;
        use axum::http::{header, Request, StatusCode};
        use tower::ServiceExt;

        let customer = "00000000-0000-0000-0000-0000000000c0";
        let ts = test_state();
        let mut usage_rx = ts.usage_rx;
        let bearer = mint_bearer(&ts.state, customer);
        let router = super::router(ts.state);
        let path = format!("/v1/address/{:#x}/screen", alloy_primitives::Address::ZERO);

        let response = router
            .oneshot(
                Request::post(&path)
                    .header(header::AUTHORIZATION, &bearer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

        let usage = usage_rx.try_recv().expect("ApiCallMade always fires");
        assert_eq!(
            usage.event_type,
            events::system::UsageEventType::ApiCallMade.as_wire_str()
        );
        assert!(
            usage_rx.try_recv().is_err(),
            "no ScreeningCall — the call 502'd before a verdict was rendered"
        );
    }

    /// §19/Sprint 14 t4: the screening endpoint's rate limit is its own
    /// dedicated bucket — exhausting it 429s further `/screen` calls but
    /// leaves every other `/v1` route unaffected.
    #[tokio::test]
    async fn screening_endpoint_enforces_its_own_dedicated_rate_limit() {
        use axum::body::Body;
        use axum::http::{header, Request, StatusCode};
        use tower::ServiceExt;

        let customer = "00000000-0000-0000-0000-0000000000c0";
        let mut ts = test_state();
        ts.state.screening_rate_limit =
            std::sync::Arc::new(crate::rate_limit::test_util::InMemoryRateLimiter::new(1));
        let bearer = mint_bearer(&ts.state, customer);
        let router = super::router(ts.state);
        let path = format!("/v1/address/{:#x}/screen", alloy_primitives::Address::ZERO);

        // First call within budget: reaches the handler (502 — no live
        // intelligence here), proving the limiter didn't block it.
        let response = router
            .clone()
            .oneshot(
                Request::post(&path)
                    .header(header::AUTHORIZATION, &bearer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

        // Second call exceeds the limit of 1 — rejected before the handler.
        let response = router
            .clone()
            .oneshot(
                Request::post(&path)
                    .header(header::AUTHORIZATION, &bearer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        // A 429 must tell the client when to retry (production SDK contract).
        assert!(
            response.headers().contains_key(header::RETRY_AFTER),
            "429 must carry a Retry-After header"
        );

        // A different `/v1` route is untouched — the limit is dedicated to
        // `/screen`, not a router-wide ceiling.
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
    }

    /// End to end (§11, Sprint 14 t3): a real `IntelligenceReadService`
    /// (in-memory stores) behind the gRPC client, seeded with a sanctions
    /// match — the response carries the full factor breakdown with
    /// `evidence_ref`s (a `block` decision, so `factors` is populated, unlike
    /// the lean `allow` case), and the access-audit record published through
    /// `state.audit` mirrors the decision exactly.
    #[tokio::test]
    async fn screen_response_and_audit_record_carry_the_factor_breakdown_on_a_block() {
        use axum::body::Body;
        use axum::http::{header, Request, StatusCode};
        use intelligence::model::SanctionEntry;
        use intelligence::pb::intelligence_read_server::IntelligenceReadServer;
        use intelligence::store::SanctionsStore;
        use intelligence::test_util::{
            store_seams, FixedLeaderboard, InMemoryAdjacency, InMemoryHotCache,
            InMemoryIntelligenceStore, RecordingEmbeddingStore,
        };
        use tower::ServiceExt;

        let address = alloy_primitives::Address::repeat_byte(0xEE);

        // Boot a real intelligence gRPC service on an ephemeral port, seeded
        // with one sanctions match — the same in-memory doubles `grpc.rs`'s
        // own tests use.
        let store = std::sync::Arc::new(InMemoryIntelligenceStore::new());
        store
            .seed_sanctions(&[SanctionEntry {
                address,
                list_name: "ofac_sdn".into(),
                entry: "Evil Corp".into(),
                listed_at: None,
            }])
            .await
            .unwrap();
        let intelligence_service = intelligence::grpc::IntelligenceReadService::new(
            store_seams(&store),
            std::sync::Arc::new(InMemoryHotCache::new()),
            std::sync::Arc::new(FixedLeaderboard::new(Default::default())),
            std::sync::Arc::new(InMemoryAdjacency::new()),
            Default::default(),
            // This test is about screening; the similarity seam is wired to an
            // empty double so it exists without affecting anything asserted.
            intelligence::grpc::SimilaritySeams {
                embeddings: std::sync::Arc::new(RecordingEmbeddingStore::new()),
                schema: intelligence::embedding::default_embedder().schema(),
                limits: Default::default(),
                baseline: std::sync::Arc::new(intelligence::baseline_cache::BaselineSnapshot::new(
                    events::primitives::Chain::ETHEREUM,
                    intelligence::embedding::default_embedder()
                        .schema()
                        .version()
                        .to_owned(),
                    Default::default(),
                )),
                permits: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
            },
            std::sync::Arc::new(intelligence::test_util::InMemoryLinkCandidateStore::new()),
        );
        // Reserve an ephemeral port, then hand its address (not the listener
        // itself — `tonic::transport::Server::serve` binds its own) to the
        // gRPC server, the same "find a free port" trick used elsewhere in
        // this workspace's tests.
        let grpc_addr = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap()
        };
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(IntelligenceReadServer::new(intelligence_service))
                .serve(grpc_addr)
                .await
                .unwrap();
        });
        // Poll until the server is accepting connections rather than sleeping a
        // fixed guess (a fixed sleep flakes under CI load). Bounded to ~1s.
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(grpc_addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let mut ts = test_state();
        ts.state.intelligence =
            IntelligenceClient::connect_lazy(format!("http://{grpc_addr}")).unwrap();
        let bearer = mint_bearer(&ts.state, "00000000-0000-0000-0000-0000000000c0");
        let router = super::router(ts.state);
        let path = format!("/v1/address/{address:#x}/screen");

        let response = router
            .oneshot(
                Request::post(&path)
                    .header(header::AUTHORIZATION, &bearer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["decision"], "block");
        assert_eq!(json["decision_basis"], "sanctions_hard_block");
        assert_eq!(json["stale"], false, "a live intelligence read is fresh");
        assert!(
            json.get("staleness").is_none(),
            "no staleness on a fresh decision"
        );
        let factors = json["factors"]
            .as_array()
            .expect("factors present on a block");
        assert!(!factors.is_empty(), "a block must carry its evidence");
        assert!(factors[0]["evidence_ref"]
            .as_str()
            .unwrap()
            .starts_with("sanction:"));

        // The access-audit record mirrors the response exactly — typed, so a
        // compliance consumer matches the enum, never re-parses a string.
        let recorded = ts
            .audit_rx
            .try_recv()
            .expect("the screening decision was recorded for the access-audit trail");
        assert_eq!(recorded.decision, ScreeningDecision::Block);
        assert_eq!(
            recorded.decision_basis,
            ScreeningDecisionBasis::SanctionsHardBlock
        );
        assert!(recorded.sanctioned);
        assert!(!recorded.factors.is_empty());
        assert_eq!(recorded.facts_staleness, None);
    }

    /// An intelligence channel pointing at a port nothing listens on: every read
    /// fails fast with a transient `Unavailable` — the "intelligence is down"
    /// case, without depending on what happens to be bound to a fixed port.
    fn unreachable_intelligence() -> IntelligenceClient {
        let addr = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        IntelligenceClient::connect_lazy(format!("http://{addr}")).unwrap()
    }

    fn armed_fallback(
        store: Arc<crate::degrade::test_util::InMemorySnapshotStore>,
    ) -> crate::degrade::ScreeningFallback {
        let (recorder, _dropped) = crate::degrade::SnapshotRecorder::channel(16);
        crate::degrade::ScreeningFallback::new(
            crate::degrade::Degradation {
                fresh_budget: std::time::Duration::from_millis(150),
                max_stale_age: std::time::Duration::from_secs(900),
            },
            store,
            recorder,
        )
    }

    /// Readiness Epic D, end to end through the router: intelligence is down,
    /// a last-known-good snapshot exists, and the withdrawal gets a decision
    /// instead of a 502 — flagged on the response, recorded as stale in the
    /// audit trail, and still billed (a verdict was rendered). The snapshot is
    /// sanctioned and the policy is `monitor-only`: the §8.5 hard block
    /// survives both the staleness and the softest policy.
    #[tokio::test]
    async fn screen_serves_a_flagged_stale_decision_when_intelligence_is_unavailable() {
        use axum::body::Body;
        use axum::http::{header, Request, StatusCode};
        use tower::ServiceExt;

        let address = alloy_primitives::Address::repeat_byte(0xEF);
        let store = Arc::new(crate::degrade::test_util::InMemorySnapshotStore::new());
        store.insert(
            address,
            crate::degrade::FactsSnapshot {
                facts: intelligence::pb::ScreeningFactsReply {
                    score: 12,
                    model_version: "risk-v1".into(),
                    sanctions: vec![intelligence::pb::SanctionMatch {
                        list: "ofac_sdn".into(),
                        entry: "Evil Corp".into(),
                    }],
                    ..Default::default()
                },
                observed_at: chrono::Utc::now() - chrono::Duration::seconds(30),
            },
        );

        let mut ts = test_state();
        ts.state.intelligence = unreachable_intelligence();
        ts.state.screening_fallback = Some(armed_fallback(store));
        let bearer = mint_bearer(&ts.state, "00000000-0000-0000-0000-0000000000c0");
        let router = super::router(ts.state);

        let response = router
            .oneshot(
                Request::post(format!("/v1/address/{address:#x}/screen"))
                    .header(header::AUTHORIZATION, &bearer)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"policy":"monitor-only"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["decision"], "block");
        assert_eq!(json["decision_basis"], "sanctions_hard_block");
        assert_eq!(json["stale"], true);
        assert_eq!(json["staleness"]["reason"], "intelligence_unavailable");
        assert!(json["staleness"]["age_ms"].as_u64().unwrap() >= 30_000);

        let recorded = ts
            .audit_rx
            .try_recv()
            .expect("the stale decision is audited");
        let staleness = recorded
            .facts_staleness
            .expect("the audit trail records that the facts were stale");
        assert_eq!(
            staleness.reason,
            ScreeningStaleReason::IntelligenceUnavailable
        );

        let metered: Vec<String> = std::iter::from_fn(|| ts.usage_rx.try_recv().ok())
            .map(|usage| usage.event_type)
            .collect();
        assert!(
            metered.contains(&UsageEventType::ScreeningCall.as_wire_str().to_owned()),
            "a stale decision is still a rendered verdict, so it is billed: {metered:?}"
        );
    }

    /// Armed but with nothing to fall back on, the endpoint behaves exactly as
    /// before: fail closed, never a default allow.
    #[tokio::test]
    async fn screen_still_fails_closed_when_armed_with_no_snapshot() {
        use axum::body::Body;
        use axum::http::{header, Request, StatusCode};
        use tower::ServiceExt;

        let mut ts = test_state();
        ts.state.intelligence = unreachable_intelligence();
        ts.state.screening_fallback = Some(armed_fallback(Arc::new(
            crate::degrade::test_util::InMemorySnapshotStore::new(),
        )));
        let bearer = mint_bearer(&ts.state, "00000000-0000-0000-0000-0000000000c0");
        let router = super::router(ts.state);

        let response = router
            .oneshot(
                Request::post(format!(
                    "/v1/address/{:#x}/screen",
                    alloy_primitives::Address::ZERO
                ))
                .header(header::AUTHORIZATION, &bearer)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(
            ts.audit_rx.try_recv().is_err(),
            "no verdict, no audit record"
        );
    }

    fn clean_snapshot(score: u32) -> crate::degrade::FactsSnapshot {
        crate::degrade::FactsSnapshot {
            facts: intelligence::pb::ScreeningFactsReply {
                score,
                model_version: "risk-v1".into(),
                ..Default::default()
            },
            observed_at: chrono::Utc::now() - chrono::Duration::seconds(30),
        }
    }

    async fn screen_json(
        router: axum::Router,
        bearer: &str,
        address: alloy_primitives::Address,
        body: &'static str,
    ) -> serde_json::Value {
        use axum::body::Body;
        use axum::http::{header, Request, StatusCode};
        use tower::ServiceExt;

        let response = router
            .oneshot(
                Request::post(format!("/v1/address/{address:#x}/screen"))
                    .header(header::AUTHORIZATION, bearer)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// A stale answer cannot vouch for sanctions status on its own: with the
    /// sanctions view never synced, a clean low-score snapshot is held for
    /// review rather than allowed — under the default `serve` policy.
    #[tokio::test]
    async fn a_stale_allow_is_held_when_the_sanctions_view_cannot_vouch() {
        let address = alloy_primitives::Address::repeat_byte(0xA1);
        let store = Arc::new(crate::degrade::test_util::InMemorySnapshotStore::new());
        store.insert(address, clean_snapshot(5));

        let mut ts = test_state();
        ts.state.intelligence = unreachable_intelligence();
        ts.state.screening_fallback = Some(armed_fallback(store));
        let bearer = mint_bearer(&ts.state, "00000000-0000-0000-0000-0000000000c0");
        let json = screen_json(super::router(ts.state), &bearer, address, "").await;

        assert_eq!(json["decision"], "review");
        assert_eq!(json["decision_basis"], "stale_facts_review");
        assert_eq!(json["stale"], true);
    }

    /// With a current sanctions view, a stale clean address is allowed under
    /// `serve` — and an address the view lists is blocked even though its
    /// snapshot, taken before the designation, says nothing about sanctions.
    #[tokio::test]
    async fn the_sanctions_view_decides_what_a_stale_snapshot_cannot_know() {
        let clean = alloy_primitives::Address::repeat_byte(0xA2);
        let designated_since = alloy_primitives::Address::repeat_byte(0xA3);
        let store = Arc::new(crate::degrade::test_util::InMemorySnapshotStore::new());
        store.insert(clean, clean_snapshot(5));
        store.insert(designated_since, clean_snapshot(0));

        let mut ts = test_state();
        ts.state.intelligence = unreachable_intelligence();
        ts.state.screening_fallback = Some(armed_fallback(store));
        ts.state.sanctions = Arc::new(crate::sanctions_view::SanctionsView::seeded(
            vec![(
                designated_since,
                vec![intelligence::pb::SanctionMatch {
                    list: "ofac_sdn".into(),
                    entry: "Designated Later".into(),
                }],
            )],
            std::time::Duration::from_secs(180),
        ));
        let bearer = mint_bearer(&ts.state, "00000000-0000-0000-0000-0000000000c0");
        let router = super::router(ts.state);

        let json = screen_json(router.clone(), &bearer, clean, "").await;
        assert_eq!(json["decision"], "allow");
        assert_eq!(json["stale"], true, "still disclosed");

        let json = screen_json(router, &bearer, designated_since, "").await;
        assert_eq!(json["decision"], "block");
        assert_eq!(json["decision_basis"], "sanctions_hard_block");
        assert_eq!(json["sanctions"][0]["list"], "ofac_sdn");
    }

    /// `on_stale` is part of a policy's versioned identity: authoring it mints a
    /// version, it round-trips through the API, and a `review` policy holds a
    /// stale allow that `serve` would have let through.
    #[tokio::test]
    async fn a_customer_policy_can_hold_stale_allows_for_review() {
        use axum::body::Body;
        use axum::http::{header, Request, StatusCode};
        use tower::ServiceExt;

        let address = alloy_primitives::Address::repeat_byte(0xA4);
        let store = Arc::new(crate::degrade::test_util::InMemorySnapshotStore::new());
        store.insert(address, clean_snapshot(5));

        let mut ts = test_state();
        ts.state.intelligence = unreachable_intelligence();
        ts.state.screening_fallback = Some(armed_fallback(store));
        ts.state.sanctions = Arc::new(crate::sanctions_view::SanctionsView::seeded(
            vec![],
            std::time::Duration::from_secs(180),
        ));
        let bearer = mint_bearer(&ts.state, "00000000-0000-0000-0000-0000000000c0");
        let router = super::router(ts.state);

        let put = |body: &'static str| {
            Request::put("/v1/policies/careful")
                .header(header::AUTHORIZATION, &bearer)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap()
        };
        let response = router
            .clone()
            .oneshot(put(r#"{"review_at":40,"block_at":80}"#))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = router
            .clone()
            .oneshot(put(r#"{"review_at":40,"block_at":80,"on_stale":"review"}"#))
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body["version"], 2,
            "a stale-behaviour change is a new version"
        );
        assert_eq!(body["on_stale"], "review");

        let json = screen_json(router.clone(), &bearer, address, r#"{"policy":"default"}"#).await;
        assert_eq!(json["decision"], "allow");
        let json = screen_json(router, &bearer, address, r#"{"policy":"careful"}"#).await;
        assert_eq!(json["decision"], "review");
        assert_eq!(json["decision_basis"], "stale_facts_review");
    }

    /// The payload cap: the endpoint's only legitimate body is a policy name,
    /// so an oversized one is refused before it is buffered or reaches any
    /// dependency.
    #[tokio::test]
    async fn screen_rejects_a_body_over_its_cap() {
        use axum::body::Body;
        use axum::http::{header, Request, StatusCode};
        use tower::ServiceExt;

        let ts = test_state();
        let bearer = mint_bearer(&ts.state, "00000000-0000-0000-0000-0000000000c0");
        let router = super::router(ts.state);
        let oversized = format!(
            r#"{{"policy":"{}"}}"#,
            "x".repeat(super::SCREEN_BODY_LIMIT_BYTES)
        );

        let response = router
            .oneshot(
                Request::post(format!(
                    "/v1/address/{:#x}/screen",
                    alloy_primitives::Address::ZERO
                ))
                .header(header::AUTHORIZATION, &bearer)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(oversized))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// The §11/Sprint 14 t2 policy surface end to end: `PUT /v1/policies/{name}`
    /// writes a customer's own policy, `GET /v1/policies` lists the built-in
    /// catalog alongside it, and `POST /v1/address/{addr}/screen` resolves it
    /// by name from the request body (proved by the 502 the lazy intelligence
    /// channel produces once the *policy* half of the handler has accepted the
    /// name — an unknown-policy 400 never gets that far, per the test above).
    #[tokio::test]
    async fn policies_can_be_authored_listed_and_selected_for_screening() {
        use axum::body::Body;
        use axum::http::{header, Request, StatusCode};
        use tower::ServiceExt;

        let customer = "00000000-0000-0000-0000-0000000000c0";
        let ts = test_state();
        let policies = ts.policies.clone();
        let bearer = mint_bearer(&ts.state, customer);
        let router = super::router(ts.state);

        // A built-in name is reserved — 400, nothing written.
        let response = router
            .clone()
            .oneshot(
                Request::put("/v1/policies/strict")
                    .header(header::AUTHORIZATION, &bearer)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"review_at":10,"block_at":50}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // An invalid threshold pair (block below review) — 400, nothing written.
        let response = router
            .clone()
            .oneshot(
                Request::put("/v1/policies/acme")
                    .header(header::AUTHORIZATION, &bearer)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"review_at":80,"block_at":40}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // A valid custom policy — 200, version 1.
        let response = router
            .clone()
            .oneshot(
                Request::put("/v1/policies/acme")
                    .header(header::AUTHORIZATION, &bearer)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"review_at":10,"block_at":60}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["name"], "acme");
        assert_eq!(body["version"], 1);

        // Retuning writes version 2, never overwrites version 1.
        let response = router
            .clone()
            .oneshot(
                Request::put("/v1/policies/acme")
                    .header(header::AUTHORIZATION, &bearer)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"review_at":15,"block_at":65}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["version"], 2);

        // Straight against the double: version 1's thresholds are still
        // there (append-only, never overwritten) even though `resolve`/
        // `custom_policy` now read version 2.
        let owner = events::primitives::CustomerId(uuid::Uuid::parse_str(customer).unwrap());
        let latest = policies
            .custom_policy(owner, "acme")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.version, 2);
        assert_eq!(latest.thresholds.review_at(), 15);

        // GET /v1/policies: the built-in catalog plus this customer's own,
        // at its latest version only.
        let response = router
            .clone()
            .oneshot(
                Request::get("/v1/policies")
                    .header(header::AUTHORIZATION, &bearer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let builtin_names: Vec<&str> = body["builtin"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert_eq!(builtin_names, vec!["default", "strict", "monitor-only"]);
        assert_eq!(body["custom"].as_array().unwrap().len(), 1);
        assert_eq!(body["custom"][0]["name"], "acme");
        assert_eq!(body["custom"][0]["version"], 2);

        // POST /v1/address/{addr}/screen naming the custom policy: it
        // resolves (no 400), then fails on the unreachable intelligence
        // channel exactly like every other screen test here — proving the
        // *policy* half accepted the name before the RPC ever ran.
        let path = format!("/v1/address/{:#x}/screen", alloy_primitives::Address::ZERO);
        let response = router
            .oneshot(
                Request::post(&path)
                    .header(header::AUTHORIZATION, &bearer)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"policy":"acme"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    /// `PUT /v1/policies/{name}` is idempotent (HTTP `PUT` semantics): a
    /// re-submit with unchanged thresholds returns the same version and
    /// appends nothing to the audit history — only a real change climbs.
    #[tokio::test]
    async fn put_policy_is_idempotent_on_unchanged_thresholds() {
        use axum::body::Body;
        use axum::http::{header, Request, StatusCode};
        use tower::ServiceExt;

        let ts = test_state();
        let bearer = mint_bearer(&ts.state, "00000000-0000-0000-0000-0000000000c0");
        let router = super::router(ts.state);

        let put = |body: &'static str| {
            let router = router.clone();
            let bearer = bearer.clone();
            async move {
                let response = router
                    .oneshot(
                        Request::put("/v1/policies/acme")
                            .header(header::AUTHORIZATION, &bearer)
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(Body::from(body))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
            }
        };

        assert_eq!(put(r#"{"review_at":10,"block_at":60}"#).await["version"], 1);
        // Same thresholds again → still version 1 (idempotent, nothing appended).
        assert_eq!(put(r#"{"review_at":10,"block_at":60}"#).await["version"], 1);
        // A genuine change climbs to version 2.
        assert_eq!(put(r#"{"review_at":10,"block_at":55}"#).await["version"], 2);
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
    // ── §19 analyst feedback (readiness Epic E) ────────────────────────

    use super::{FeedbackReason, FeedbackVerdict, MAX_FEEDBACK_REASON_CHARS};
    use axum::http::StatusCode;

    /// The capability secret both halves of the test share — the same value a
    /// deployment gives notification (which mints) and the API service (which
    /// verifies).
    const TEST_GRANT_SECRET: &str = "test-grant-secret";

    /// Mint a grant the way notification would.
    fn mint_grant(incident: uuid::Uuid, customer: &str, cohort: &str) -> String {
        let key = feedback_grant::MintingKey::from_secret(SecretString::from(TEST_GRANT_SECRET));
        feedback_grant::mint(
            &key,
            &feedback_grant::Grant {
                incident_id: incident,
                customer_id: customer.parse().expect("a customer uuid"),
                cohort: cohort.to_owned(),
            },
            (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
        )
        .expect("mint")
    }

    async fn post_feedback(
        router: axum::Router,
        bearer: Option<&str>,
        incident_id: &str,
        body: serde_json::Value,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        use axum::body::Body;
        use axum::http::{header, Request};
        use tower::ServiceExt;

        let mut request = Request::post(format!("/v1/incidents/{incident_id}/feedback"))
            .header(header::CONTENT_TYPE, "application/json");
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
        let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, body)
    }

    #[tokio::test]
    async fn feedback_records_the_verdict_under_the_token_owner() {
        let incident = uuid::Uuid::from_u128(0x1c);
        let customer = "00000000-0000-0000-0000-0000000000c0";
        let ts = test_state();
        let bearer = mint_bearer(&ts.state, customer);
        let router = super::router(ts.state.clone());

        let (status, body) = post_feedback(
            router,
            Some(&bearer),
            &incident.to_string(),
            serde_json::json!({
                "grant": mint_grant(incident, customer, "solicited"),
                "verdict": "false_positive",
                "reason_code": "our_own_activity",
                "reason": "  our own rebalancer  ",
            }),
        )
        .await;

        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        assert_eq!(body["status"], "recorded");

        // The parked envelope, read back the way the flusher will.
        let queued = ts.feedback.queued();
        assert_eq!(queued.len(), 1);
        let envelope: events::EventEnvelope =
            serde_json::from_value(queued[0].clone()).expect("a wire-form envelope");
        let events::DomainEvent::AlertFeedbackRecorded(recorded) = envelope.payload else {
            panic!("expected an AlertFeedbackRecorded payload");
        };
        assert_eq!(recorded.incident_id.0, incident);
        assert_eq!(recorded.verdict, FeedbackVerdict::FalsePositive);
        assert_eq!(recorded.reason_code, FeedbackReason::OurOwnActivity);
        // Owner-from-JWT: the body has no say in who the verdict belongs to.
        assert_eq!(recorded.customer_id.0.to_string(), customer);
        assert_eq!(recorded.reason.as_deref(), Some("our own rebalancer"));
        // And the cohort comes from the signed grant, not the request.
        assert_eq!(recorded.cohort, events::feedback::FeedbackCohort::Solicited);
    }

    #[tokio::test]
    async fn a_verdict_without_a_grant_is_refused() {
        let incident = uuid::Uuid::from_u128(0x1c);
        let ts = test_state();
        let bearer = mint_bearer(&ts.state, "00000000-0000-0000-0000-0000000000c0");
        let router = super::router(ts.state.clone());

        let (status, _) = post_feedback(
            router,
            Some(&bearer),
            &incident.to_string(),
            serde_json::json!({ "grant": "not-a-token", "verdict": "false_positive" }),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            ts.feedback.queued().is_empty(),
            "an unauthorized verdict must never reach the SLI"
        );
    }

    #[tokio::test]
    async fn a_grant_for_another_customers_delivery_is_refused() {
        // The isolation property, adversarially: Mallory holds a *valid*
        // grant — it was minted for Alice, and Mallory intercepted it. Her own
        // bearer token does not match the grant's recipient, so the capability
        // is worthless to her. Without this check a grant would be a bearer
        // token anyone who read an email could spend.
        let incident = uuid::Uuid::from_u128(0x1c);
        let alice = "00000000-0000-0000-0000-0000000000a1";
        let mallory = "00000000-0000-0000-0000-0000000000b2";
        let ts = test_state();
        let bearer = mint_bearer(&ts.state, mallory);
        let router = super::router(ts.state.clone());

        let (status, _) = post_feedback(
            router,
            Some(&bearer),
            &incident.to_string(),
            serde_json::json!({
                "grant": mint_grant(incident, alice, "volunteered"),
                "verdict": "false_positive",
            }),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(ts.feedback.queued().is_empty());
    }

    #[tokio::test]
    async fn a_grant_for_a_different_incident_is_refused() {
        // Self-service poisoning: one legitimately delivered incident's grant
        // replayed against every other incident id in the platform.
        let delivered = uuid::Uuid::from_u128(0x1c);
        let target = uuid::Uuid::from_u128(0xdead);
        let customer = "00000000-0000-0000-0000-0000000000c0";
        let ts = test_state();
        let bearer = mint_bearer(&ts.state, customer);
        let router = super::router(ts.state.clone());

        let (status, _) = post_feedback(
            router,
            Some(&bearer),
            &target.to_string(),
            serde_json::json!({
                "grant": mint_grant(delivered, customer, "volunteered"),
                "verdict": "false_positive",
            }),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(ts.feedback.queued().is_empty());
    }

    #[tokio::test]
    async fn an_unconfigured_deployment_503s_feedback_and_serves_everything_else() {
        // The rollout hazard this guards: prod provisions `app-secrets`
        // outside the repo, and a missing key must degrade one endpoint —
        // never keep the pod from starting.
        let incident = uuid::Uuid::from_u128(0x1c);
        let customer = "00000000-0000-0000-0000-0000000000c0";
        let mut ts = test_state();
        ts.state.feedback_grant = None;
        let bearer = mint_bearer(&ts.state, customer);
        let router = super::router(ts.state.clone());

        let (status, _) = post_feedback(
            router,
            Some(&bearer),
            &incident.to_string(),
            serde_json::json!({
                "grant": mint_grant(incident, customer, "volunteered"),
                "verdict": "false_positive",
            }),
        )
        .await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(ts.feedback.queued().is_empty());
    }

    #[tokio::test]
    async fn feedback_requires_a_bearer_token() {
        let incident = uuid::Uuid::from_u128(0x1c);
        let ts = test_state();
        let router = super::router(ts.state);

        let (status, _) = post_feedback(
            router,
            None,
            &incident.to_string(),
            serde_json::json!({ "grant": "irrelevant", "verdict": "true_positive" }),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn feedback_rejects_an_over_long_reason_with_422() {
        let incident = uuid::Uuid::from_u128(0x1c);
        let customer = "00000000-0000-0000-0000-0000000000c0";
        let ts = test_state();
        let bearer = mint_bearer(&ts.state, customer);
        let router = super::router(ts.state.clone());

        let (status, body) = post_feedback(
            router,
            Some(&bearer),
            &incident.to_string(),
            serde_json::json!({
                "grant": mint_grant(incident, customer, "volunteered"),
                "verdict": "unclear",
                "reason": "x".repeat(MAX_FEEDBACK_REASON_CHARS + 1),
            }),
        )
        .await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].as_str().unwrap().contains("longer than"));
    }

    #[tokio::test]
    async fn feedback_503s_rather_than_pretending_a_verdict_was_recorded() {
        // Postgres is down, so the platform cannot promise to keep this
        // verdict. Saying so beats a comfortable 202: the caller is a human
        // who will retry, and the sample is small enough that quietly losing
        // one biases the rate toward flattering the platform.
        let incident = uuid::Uuid::from_u128(0x1c);
        let customer = "00000000-0000-0000-0000-0000000000c0";
        let mut ts = test_state();
        ts.state.feedback = Arc::new(InMemoryFeedbackQueue::failing());
        let bearer = mint_bearer(&ts.state, customer);
        let router = super::router(ts.state.clone());

        let (status, _) = post_feedback(
            router,
            Some(&bearer),
            &incident.to_string(),
            serde_json::json!({
                "grant": mint_grant(incident, customer, "volunteered"),
                "verdict": "false_positive",
            }),
        )
        .await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn a_retried_submission_is_recognised_rather_than_counted_twice() {
        // The whole point of the durable path: a client that times out and
        // retries must not add a second opinion to an accuracy measurement.
        let incident = uuid::Uuid::from_u128(0x1c);
        let customer = "00000000-0000-0000-0000-0000000000c0";
        let ts = test_state();
        let bearer = mint_bearer(&ts.state, customer);
        let queue = ts.feedback.clone();
        let router = super::router(ts.state.clone());

        let body = serde_json::json!({
            "grant": mint_grant(incident, customer, "volunteered"),
            "verdict": "false_positive",
        });
        let (first, _) = post_feedback(
            router.clone(),
            Some(&bearer),
            &incident.to_string(),
            body.clone(),
        )
        .await;
        let (second, second_body) =
            post_feedback(router, Some(&bearer), &incident.to_string(), body).await;

        assert_eq!(first, StatusCode::ACCEPTED);
        assert_eq!(second, StatusCode::OK, "a retry is not a second verdict");
        assert_eq!(second_body["status"], "already_recorded");
        assert_eq!(queue.queued().len(), 1);
    }
}
