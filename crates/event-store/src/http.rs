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

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use events::EventEnvelope;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use subtle::ConstantTimeEq;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

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
    paths(append, healthz),
    components(schemas(EventEnvelope, AppendResponse)),
    modifiers(&SecurityAddon),
    tags((name = "event-store", description = "Immutable event store — append API (§4)")),
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

    let public = Router::new().route("/healthz", get(healthz));

    protected
        .merge(public)
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
        // Both endpoints are documented.
        assert!(spec["paths"]["/v1/events"]["post"].is_object());
        assert!(spec["paths"]["/healthz"]["get"].is_object());
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
