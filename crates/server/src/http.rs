//! The public §11 API service: `GET /v1/address/{addr}/risk` and `/labels`
//! (gRPC into `intelligence`), `GET /v1/audit/incident/{id}` (proxies
//! event-store) and `GET /v1/incidents` (proxies simulation-projection),
//! behind [`crate::auth::require_jwt`]. `/healthz` is the only open route.
//!
//! Follows event-store's `http.rs` shape: one [`OpenApiRouter`] assembled from
//! `#[utoipa::path]`-annotated handlers so the served routes and the Swagger
//! docs at `/swagger-ui` can't drift, a bearer security scheme registered for
//! the "Authorize" button, and production middleware (timeout, body limit,
//! trace) layered over the whole thing.

use std::time::Duration;

use api_error::ApiError;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use events::primitives::AccountAddress;
use intelligence::model::address_key;
use serde::Serialize;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use utoipa_swagger_ui::SwaggerUi;

use crate::auth::require_jwt;
use crate::config::JwtConfig;
use crate::intelligence_client::IntelligenceClient;
use crate::upstream;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(OpenApi)]
#[openapi(
    info(
        title = "api-service",
        version = env!("CARGO_PKG_VERSION"),
        description = "Public read API (§11): address risk/labels, incident audit trail and listing",
    ),
    components(schemas(RiskResponse, LabelResponse, LabelsResponse)),
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
}

fn build_router(state: AppState) -> (Router<AppState>, utoipa::openapi::OpenApi) {
    // `from_fn_with_state` captures whatever value it's handed — it isn't tied to
    // the router's own state type — so `require_jwt` (which only needs
    // `JwtConfig`) can be layered with just that slice of `AppState`, no adapter
    // function required to bridge the two.
    let protected = OpenApiRouter::new()
        .routes(routes!(address_risk))
        .routes(routes!(address_labels))
        .routes(routes!(audit_incident))
        .routes(routes!(list_incidents))
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

#[cfg(test)]
mod tests {
    use super::{build_router, AppState};
    use crate::config::JwtConfig;
    use crate::intelligence_client::IntelligenceClient;
    use secrecy::SecretString;

    /// A throwaway state — `connect_lazy` does no I/O (the channel dials on
    /// first RPC), so the router/spec can be built with no live intelligence.
    fn test_state() -> AppState {
        AppState {
            intelligence: IntelligenceClient::connect_lazy("http://127.0.0.1:50051".to_owned())
                .expect("lazy channel never fails to construct"),
            http_client: reqwest::Client::new(),
            event_store_url: "http://127.0.0.1:8081".to_owned(),
            simulation_url: "http://127.0.0.1:8082".to_owned(),
            jwt: JwtConfig {
                secret: SecretString::from("test-secret"),
                issuer: "mev".to_owned(),
            },
        }
    }

    #[tokio::test]
    async fn openapi_spec_collects_paths_schemas_and_security() {
        // The spec is built by the *router* from the handler annotations — the same
        // spec that ships at `/api-docs/openapi.json` — so this guards against
        // route/doc drift, not just against a missing derive.
        let (_router, api) = build_router(test_state());
        let spec = serde_json::to_value(&api).expect("serialize spec");

        for name in ["RiskResponse", "LabelResponse", "LabelsResponse"] {
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
            ("/v1/audit/incident/{incident_id}", "get"),
            ("/v1/incidents", "get"),
        ] {
            assert!(
                spec["paths"][path][method].is_object(),
                "OpenAPI paths missing `{method} {path}`"
            );
        }
    }
}
