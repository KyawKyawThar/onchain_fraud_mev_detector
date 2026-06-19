//! The internal HTTP append API (§4): `POST /v1/events`, write-authenticated,
//! plus an unauthenticated `GET /healthz` readiness probe.
//!
//! "Internal, write-authenticated" is a static shared bearer token — service to
//! service auth, deliberately distinct from the public §11 JWT. The token is
//! compared in constant time so a wrong guess leaks nothing through timing.
//!
//! The whole surface is described with OpenAPI ([`ApiDoc`]) and served as an
//! interactive Swagger UI at `/swagger-ui`, so the append endpoint is easy to
//! exercise by hand (the spec's event schemas come from the `events` crate's
//! `openapi` feature).

use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use events::primitives::{AccountAddress, IncidentId};
use events::EventEnvelope;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::query::{Cursor, EventPage, Filters, QueryError};
use crate::store::EventStore;

/// Cap on a single append batch. A within-limit body of tiny events could still
/// be a huge single insert, so the count is bounded independently of byte size.
const MAX_BATCH_LEN: usize = 1024;
/// Maximum request body size — internal callers send small JSON batches.
const MAX_BODY_BYTES: usize = 1 << 20; // 1 MiB
/// Hard ceiling on how long any request may run before the server cancels it.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// OpenAPI spec for the event-store API. Nested event schemas
/// ([`EventEnvelope`] → `DomainEvent` → every variant) are pulled in
/// automatically from the `events` crate's `ToSchema` derives.
#[derive(OpenApi)]
#[openapi(
    paths(append, healthz, audit_incident, events_by_address, replay),
    components(schemas(EventEnvelope, AppendResponse, EventPageResponse)),
    modifiers(&SecurityAddon),
    tags((name = "event-store", description = "Immutable event store — append + query API (§4, §18)")),
)]
pub struct ApiDoc;

/// Registers the `bearer_token` security scheme so Swagger UI shows an
/// "Authorize" button that adds `Authorization: Bearer …` to `POST /v1/events`.
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
    pub store: EventStore,
    /// The bearer token an append caller must present. Redacted in `Debug`.
    pub write_token: SecretString,
}

/// Build the router: `/v1/events` behind the bearer-token gate, `/healthz` open,
/// and the Swagger UI + spec at `/swagger-ui` and `/api-docs/openapi.json`.
///
/// Production middleware wraps the whole surface: a request timeout, a body-size
/// limit, and an HTTP `TraceLayer` whose spans stitch into the existing OTel
/// trace context (§19).
pub fn router(state: AppState) -> Router {
    let protected = Router::new().route("/v1/events", post(append)).route_layer(
        middleware::from_fn_with_state(state.clone(), require_write_token),
    );

    // Internal read surface: the §4 query API and §18 replay source, plus the
    // `/healthz` probe. Unauthenticated by design — these are reached only over
    // the internal network and are fronted by the public §11 API service, which
    // owns end-user auth. They are strictly read-only; every write goes through
    // the bearer-gated append above.
    let read = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/audit/incident/{incident_id}", get(audit_incident))
        .route("/v1/address/{address}/events", get(events_by_address))
        .route("/v1/replay", get(replay));

    protected
        .merge(read)
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Response body of a successful append.
#[derive(Debug, Serialize, utoipa::ToSchema)]
struct AppendResponse {
    /// Number of events durably written.
    appended: usize,
}

/// `POST /v1/events` — append a batch of envelopes. Body is a JSON array.
/// Returns `202 Accepted` with the count once durably written.
#[utoipa::path(
    post,
    path = "/v1/events",
    tag = "event-store",
    request_body = Vec<EventEnvelope>,
    security(("bearer_token" = [])),
    responses(
        (status = 202, description = "Events appended", body = AppendResponse),
        (status = 400, description = "An envelope used an unsupported schema version"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 413, description = "Batch exceeds the maximum number of events"),
        (status = 500, description = "Storage failure"),
    ),
)]
async fn append(
    State(state): State<AppState>,
    Json(envelopes): Json<Vec<EventEnvelope>>,
) -> Result<Response, AppError> {
    if envelopes.len() > MAX_BATCH_LEN {
        return Err(AppError::payload_too_large(format!(
            "batch of {} exceeds the maximum of {MAX_BATCH_LEN} events",
            envelopes.len()
        )));
    }

    // Reject anything written under a schema version this build can't read,
    // before touching storage (§2 versioning).
    for envelope in &envelopes {
        envelope.ensure_supported().map_err(AppError::bad_request)?;
    }

    state
        .store
        .append_batch(&envelopes)
        .await
        .map_err(AppError::internal)?;

    Ok((
        StatusCode::ACCEPTED,
        Json(AppendResponse {
            appended: envelopes.len(),
        }),
    )
        .into_response())
}

/// `GET /healthz` — readiness: confirms ClickHouse is reachable.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "event-store",
    responses(
        (status = 200, description = "ClickHouse reachable", body = String),
        (status = 500, description = "ClickHouse unreachable"),
    ),
)]
async fn healthz(State(state): State<AppState>) -> Result<&'static str, AppError> {
    state.store.ping().await.map_err(AppError::internal)?;
    Ok("ok")
}

/// Shared query string for all three read endpoints: an optional chain /
/// event-type narrowing, a half-open `[from, to)` time window (RFC 3339, e.g.
/// `2024-01-01T00:00:00Z`), and keyset pagination (`limit` + `cursor`). Every
/// field is optional; an unset field is simply not constrained.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct FilterParams {
    /// Restrict to one chain id (e.g. `1` for Ethereum).
    chain: Option<u64>,
    /// Restrict to one event type (e.g. `BlockAssembled`).
    event_type: Option<String>,
    /// Inclusive lower bound on `occurred_at` (RFC 3339).
    from: Option<DateTime<Utc>>,
    /// Exclusive upper bound on `occurred_at` (RFC 3339).
    to: Option<DateTime<Utc>>,
    /// Max events per page (clamped server-side to a hard ceiling).
    limit: Option<u64>,
    /// Opaque cursor from a previous page's `next_cursor`; resumes after it.
    cursor: Option<String>,
}

impl FilterParams {
    /// Convert to domain [`Filters`], parsing the opaque cursor token. A
    /// malformed cursor is the caller's fault — surfaced as a 400.
    fn into_filters(self) -> Result<Filters, AppError> {
        let cursor = self
            .cursor
            .map(|token| {
                Cursor::parse(&token)
                    .ok_or_else(|| AppError::bad_request(format!("invalid cursor `{token}`")))
            })
            .transpose()?;
        Ok(Filters {
            chain: self.chain,
            event_type: self.event_type,
            from: self.from,
            to: self.to,
            cursor,
            limit: self.limit,
        })
    }
}

/// Response body for the read endpoints: a page of events plus the cursor to
/// fetch the next page (`null` when the stream is exhausted, so a caller can
/// always distinguish a complete result from a truncated one).
#[derive(Debug, Serialize, utoipa::ToSchema)]
struct EventPageResponse {
    events: Vec<EventEnvelope>,
    next_cursor: Option<String>,
}

impl From<EventPage> for EventPageResponse {
    fn from(page: EventPage) -> Self {
        Self {
            events: page.events,
            next_cursor: page.next_cursor.map(|cursor| cursor.token()),
        }
    }
}

/// `GET /v1/audit/incident/{incident_id}` — the event sequence for one incident,
/// oldest first (§4 audit use case): the events whose payload directly carries
/// this incident id, optionally narrowed and paginated.
#[utoipa::path(
    get,
    path = "/v1/audit/incident/{incident_id}",
    tag = "event-store",
    params(("incident_id" = String, Path, format = Uuid, description = "Incident id"), FilterParams),
    responses(
        (status = 200, description = "A page of the incident's event sequence", body = EventPageResponse),
        (status = 400, description = "Invalid cursor"),
        (status = 500, description = "Storage failure"),
    ),
)]
async fn audit_incident(
    State(state): State<AppState>,
    Path(incident_id): Path<uuid::Uuid>,
    Query(params): Query<FilterParams>,
) -> Result<Json<EventPageResponse>, AppError> {
    let page = state
        .store
        .audit_incident(IncidentId(incident_id), &params.into_filters()?)
        .await
        .map_err(AppError::from_query)?;
    Ok(Json(page.into()))
}

/// `GET /v1/address/{address}/events` — every event referencing an on-chain
/// address, oldest first, within the optional filters (§4 by-address query).
#[utoipa::path(
    get,
    path = "/v1/address/{address}/events",
    tag = "event-store",
    params(
        ("address" = String, Path, description = "On-chain address, 0x-prefixed hex (any case)"),
        FilterParams,
    ),
    responses(
        (status = 200, description = "A page of events referencing the address", body = EventPageResponse),
        (status = 400, description = "Address is not valid hex, or invalid cursor"),
        (status = 500, description = "Storage failure"),
    ),
)]
async fn events_by_address(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Query(params): Query<FilterParams>,
) -> Result<Json<EventPageResponse>, AppError> {
    let address: AccountAddress = address
        .parse()
        .map_err(|_| AppError::bad_request(format!("invalid address `{address}`")))?;
    let page = state
        .store
        .events_by_address(address, &params.into_filters()?)
        .await
        .map_err(AppError::from_query)?;
    Ok(Json(page.into()))
}

/// `GET /v1/replay` — a deterministic event stream over a time window, oldest
/// first (§18 replay source). With `event_type` set this is the §4
/// replay-by-event-type-and-window; without it, the general by-time-range query.
/// Requires at least one of `chain`/`event_type`/`from`/`to` — an unbounded
/// replay over the whole log is refused with 400.
#[utoipa::path(
    get,
    path = "/v1/replay",
    tag = "event-store",
    params(FilterParams),
    responses(
        (status = 200, description = "A page of the deterministic stream for the window", body = EventPageResponse),
        (status = 400, description = "No narrowing filter, or invalid cursor"),
        (status = 500, description = "Storage failure"),
    ),
)]
async fn replay(
    State(state): State<AppState>,
    Query(params): Query<FilterParams>,
) -> Result<Json<EventPageResponse>, AppError> {
    let page = state
        .store
        .replay(&params.into_filters()?)
        .await
        .map_err(AppError::from_query)?;
    Ok(Json(page.into()))
}

/// Middleware: require a valid `Authorization: Bearer <token>` or reject 401.
async fn require_write_token(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    let expected = state.write_token.expose_secret();
    match presented {
        Some(token) if constant_time_eq(token.as_bytes(), expected.as_bytes()) => {
            next.run(req).await
        }
        _ => StatusCode::UNAUTHORIZED.into_response(),
    }
}

/// Constant-time byte comparison via `subtle` (audited; not subject to the
/// compiler short-circuiting a hand-rolled loop). Unequal lengths compare
/// unequal without leaking which byte differed.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// A handler error carrying the HTTP status to return. The message is logged and
/// returned as a plain-text body (this is an internal API; no need for a
/// structured error envelope yet).
struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    /// 500 — an unexpected failure (storage down, serialization bug).
    fn internal(err: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: err.to_string(),
        }
    }

    /// 400 — the request itself is bad (e.g. an unsupported schema version).
    fn bad_request(err: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: err.to_string(),
        }
    }

    /// Map a read-path failure to a status: an unbounded replay is the caller's
    /// mistake (400); a storage failure is ours (500).
    fn from_query(err: QueryError) -> Self {
        match err {
            QueryError::UnboundedReplay => Self::bad_request(QueryError::UnboundedReplay),
            QueryError::Store(inner) => Self::internal(inner),
        }
    }

    /// 413 — the batch is larger than the service accepts.
    fn payload_too_large(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            message: message.into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            // Log the detail, but never return internal error text (which can
            // carry storage URLs / SQL) to the caller.
            tracing::error!(status = %self.status, error = %self.message, "append request failed");
            (self.status, "internal server error").into_response()
        } else {
            // 4xx is the caller's own fault — the detail helps them fix it.
            tracing::warn!(status = %self.status, error = %self.message, "append request rejected");
            (self.status, self.message).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{constant_time_eq, ApiDoc};
    use utoipa::OpenApi;

    #[test]
    fn openapi_spec_resolves_event_schemas_and_security() {
        let spec = serde_json::to_value(ApiDoc::openapi()).expect("serialize spec");
        let schemas = &spec["components"]["schemas"];

        // The request-body type and a few nested event schemas must be collected
        // automatically (proves the `events/openapi` derives are reachable).
        for name in [
            "EventEnvelope",
            "DomainEvent",
            "BlockAssembled",
            "AppendResponse",
        ] {
            assert!(
                schemas.get(name).is_some(),
                "OpenAPI components missing schema `{name}`"
            );
        }

        // The bearer scheme backs Swagger's Authorize button.
        assert!(spec["components"]["securitySchemes"]["bearer_token"].is_object());
        // The append, probe, and query/replay endpoints are all documented.
        assert!(spec["paths"]["/v1/events"]["post"].is_object());
        assert!(spec["paths"]["/healthz"]["get"].is_object());
        assert!(spec["paths"]["/v1/audit/incident/{incident_id}"]["get"].is_object());
        assert!(spec["paths"]["/v1/address/{address}/events"]["get"].is_object());
        assert!(spec["paths"]["/v1/replay"]["get"].is_object());
    }

    #[test]
    fn constant_time_eq_matches_only_identical_tokens() {
        assert!(constant_time_eq(b"s3cr3t-token", b"s3cr3t-token"));
        assert!(!constant_time_eq(b"s3cr3t-token", b"s3cr3t-toker"));
        assert!(!constant_time_eq(b"s3cr3t-token", b"short"));
        assert!(!constant_time_eq(b"", b"x"));
        // An empty configured token still only matches an empty presentation.
        assert!(constant_time_eq(b"", b""));
    }
}
