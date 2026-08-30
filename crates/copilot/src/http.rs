//! The draft review API (§20.4) — where a human reads a narrative and
//! approves it, and the only way a draft ever becomes usable.
//!
//! # Nothing auto-delivers
//!
//! This is the boundary the whole feature is built around. A narrative sits at
//! `ready` forever until a person calls [`approve`]; nothing in this service
//! sends it anywhere, and no other service may act on a draft that is not
//! `approved` (`Draft::is_approved` is the one question they are allowed to
//! ask). §20.4's "LLM output is a proposal, never a fact" is, for narratives,
//! exactly this endpoint.
//!
//! # Reads open, verdicts authenticated
//!
//! Reading the queue is an internal-network read, the posture every other
//! internal read API in this system takes. A verdict is not: it is the durable
//! record of **who released a machine-written SAR narrative**, so it requires a
//! JWT verified by the shared `auth` crate, and the reviewer's identity is the
//! token's `sub`.
//!
//! It deliberately does *not* come from the request body any more. A name a
//! caller types is not an audit trail — anyone holding the credential could
//! sign a decision as anyone else, which is precisely the property an approval
//! record exists to deny. `sub` is whatever the issuer put there (a person, an
//! SSO subject); this service does not require it to be a customer UUID the
//! way the metered API does, because an incident narrative has no customer.
//!
//! # Swagger, because a compliance reviewer is not a `curl` user
//!
//! The spec is generated from the handlers, so it cannot drift from the routes
//! actually served, and the UI at `/swagger-ui` is how this gets exercised by
//! hand — the sprint plan's own requirement for every new API surface.

use std::sync::Arc;

use api_error::ApiError;
use auth::{Claims, JwtConfig};
use axum::extract::{Extension, Path, Query, State};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use utoipa_swagger_ui::SwaggerUi;

use crate::grounding::GroundingSummary;
use crate::metrics;
use crate::model::{Draft, DraftId, DraftKind, DraftSource, DraftStatus, Review};
use crate::store::{DraftFilter, DraftReview, StoreError, MAX_LIST_LIMIT};

/// Default page size for the review queue.
const DEFAULT_LIMIT: i64 = 50;

/// The OpenAPI surface. Paths come from the handlers' `#[utoipa::path]`
/// annotations (collected in [`build_router`]), so the spec is the routes.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "copilot",
        version = env!("CARGO_PKG_VERSION"),
        description = "LLM investigation copilot — SAR-draft narratives grounded in the incident's \
                       audit trail, and the human approval that is the only way one leaves the \
                       platform (§20.4)",
    ),
    components(schemas(DraftSummary, DraftDetail, GroundingView, ReviewRequest, ReviewResponse)),
    tags((name = "copilot", description = "Incident narrative drafts and their review (§20.4)")),
)]
pub struct ApiDoc;

/// Shared handler state.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn DraftReview>,
    /// How a reviewer's token is verified (§11, shared with the API service).
    pub jwt: JwtConfig,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState").finish_non_exhaustive()
    }
}

/// Assemble the routed surface and its spec from one source of truth.
fn build_router(state: AppState) -> (Router<AppState>, utoipa::openapi::OpenApi) {
    let (reviews, review_api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(approve))
        .routes(routes!(reject))
        // Only the verdict routes: a reviewer needs a token to *decide*, not to
        // read the queue.
        .layer(axum::middleware::from_fn_with_state(
            state.jwt.clone(),
            auth::require_jwt,
        ))
        .split_for_parts();

    let (reads, api) = OpenApiRouter::with_openapi(review_api)
        .routes(routes!(healthz))
        .routes(routes!(list_drafts))
        .routes(routes!(get_draft))
        .split_for_parts();

    (reads.merge(reviews), api)
}

/// Build the router: reads open, verdicts behind the bearer token, plus the
/// Swagger UI and spec.
pub fn router(state: AppState) -> Router {
    let (router, api) = build_router(state.clone());
    router
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", api))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// `GET /healthz` — this API is up. The K8s probes are `telemetry::health`'s
/// separate `/livez`/`/readyz` listener; this one is the read API's own.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "copilot",
    responses((status = 200, description = "The review API is up", body = String)),
)]
async fn healthz() -> &'static str {
    "ok"
}

/// One draft as the queue lists it — everything a reviewer needs to *triage*,
/// and not the narrative itself (which is a page of prose per row).
#[derive(Debug, Serialize, utoipa::ToSchema)]
struct DraftSummary {
    #[schema(value_type = String, format = Uuid)]
    draft_id: uuid::Uuid,
    /// The incident the narrative is about.
    #[schema(value_type = String, format = Uuid)]
    subject_id: uuid::Uuid,
    kind: String,
    status: String,
    /// `live` or `backfill` (§20.4's half-price historical path).
    source: String,
    /// The model that actually answered, once one has.
    model: Option<String>,
    /// How many of the narrative's claims carry a citation, and how many it
    /// makes. The triage number: a draft claiming twenty things and citing
    /// three is a different read than one claiming three and citing three.
    claims: Option<u32>,
    cited_claims: Option<u32>,
    grounded_event_ids: usize,
    /// Why a `blocked`/`failed` draft is not reviewable — a refusal, a
    /// truncation, or a failed citation check.
    last_error: Option<String>,
    reviewed_by: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// One draft in full — the reviewer's read.
#[derive(Debug, Serialize, utoipa::ToSchema)]
struct DraftDetail {
    #[serde(flatten)]
    summary: DraftSummary,
    /// The drafted narrative. Present for any draft the model answered,
    /// including a blocked one — a reviewer investigating *why* a draft was
    /// blocked has to be able to read what it said.
    body: Option<String>,
    /// The prompt artifact that produced it (`incident_narrative@v2`) and the
    /// hash of the bytes that ran — §20.4's provenance, so a reviewer can tell
    /// which instructions this narrative was written under.
    prompt_id: Option<String>,
    prompt_digest: Option<String>,
    /// The event ids the narrative cites, resolvable in the event store. This
    /// is the list a reviewer checks the claims against.
    #[schema(value_type = Vec<String>)]
    grounded: Vec<uuid::Uuid>,
    grounding: Option<GroundingView>,
    /// The Batch API job that produced it, for a backfilled draft.
    batch_id: Option<String>,
    review_note: Option<String>,
}

/// The citation check's findings.
#[derive(Debug, Serialize, utoipa::ToSchema)]
struct GroundingView {
    claims: usize,
    cited_claims: usize,
    /// Share of claims carrying a citation, `0.0`–`1.0`.
    cited_ratio: f64,
    /// Ids the narrative cited that were **not** in the window it was shown.
    /// Non-empty means the model invented a reference, and the draft is
    /// blocked; the ids are here because "which one" is the first thing
    /// anyone asks.
    #[schema(value_type = Vec<String>)]
    unknown_event_ids: Vec<uuid::Uuid>,
}

impl From<&GroundingSummary> for GroundingView {
    fn from(summary: &GroundingSummary) -> Self {
        Self {
            claims: summary.claims,
            cited_claims: summary.cited_claims,
            cited_ratio: summary.cited_ratio(),
            unknown_event_ids: summary.unknown_event_ids.clone(),
        }
    }
}

impl From<&Draft> for DraftSummary {
    fn from(draft: &Draft) -> Self {
        Self {
            draft_id: draft.draft_id.0,
            subject_id: draft.subject_id,
            kind: draft.kind.as_wire_str().to_owned(),
            status: draft.status.as_wire_str().to_owned(),
            source: draft.source.as_wire_str().to_owned(),
            model: draft.model().map(str::to_owned),
            claims: draft.grounding.as_ref().map(|g| g.claims as u32),
            cited_claims: draft.grounding.as_ref().map(|g| g.cited_claims as u32),
            grounded_event_ids: draft.grounded_event_ids.len(),
            last_error: draft.last_error.clone(),
            reviewed_by: draft.review.as_ref().map(|review| review.by.clone()),
            created_at: draft.created_at,
            updated_at: draft.updated_at,
        }
    }
}

impl From<&Draft> for DraftDetail {
    fn from(draft: &Draft) -> Self {
        Self {
            summary: DraftSummary::from(draft),
            body: draft.body().map(str::to_owned),
            prompt_id: draft.provenance.as_ref().map(|p| p.prompt_id.clone()),
            prompt_digest: draft.provenance.as_ref().map(|p| p.prompt_digest.clone()),
            grounded: draft.grounded_event_ids.clone(),
            grounding: draft.grounding.as_ref().map(GroundingView::from),
            batch_id: draft.batch_id.clone(),
            review_note: draft.review.as_ref().and_then(|review| review.note.clone()),
        }
    }
}

/// Query narrowing for the review queue.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
struct ListParams {
    /// `queued`/`in_flight`/`ready`/`blocked`/`failed`/`approved`/`rejected`.
    status: Option<String>,
    /// `incident_narrative` or `rule_draft`.
    kind: Option<String>,
    /// `live` or `backfill`.
    source: Option<String>,
    /// One incident id — the "show me this incident's draft" lookup.
    subject_id: Option<uuid::Uuid>,
    /// Max drafts to return (clamped server-side).
    limit: Option<i64>,
}

impl ListParams {
    fn into_filter(self) -> Result<DraftFilter, ApiError> {
        Ok(DraftFilter {
            status: parse_opt::<DraftStatus>("status", self.status)?,
            kind: parse_opt::<DraftKind>("kind", self.kind)?,
            source: parse_opt::<DraftSource>("source", self.source)?,
            subject_id: self.subject_id,
            limit: self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIST_LIMIT),
        })
    }
}

/// Parse an optional enum-valued query parameter, naming the value in the 400.
fn parse_opt<T: std::str::FromStr>(
    field: &str,
    value: Option<String>,
) -> Result<Option<T>, ApiError> {
    value
        .map(|value| {
            value
                .parse::<T>()
                .map_err(|_| ApiError::bad_request(format!("invalid {field} `{value}`")))
        })
        .transpose()
}

/// `GET /v1/drafts` — the review queue, newest first.
#[utoipa::path(
    get,
    path = "/v1/drafts",
    tag = "copilot",
    params(ListParams),
    responses(
        (status = 200, description = "Matching drafts, newest first", body = Vec<DraftSummary>),
        (status = 400, description = "Unknown status/kind/source value"),
        (status = 500, description = "Store failure"),
    ),
)]
async fn list_drafts(
    State(state): State<AppState>,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<DraftSummary>>, ApiError> {
    let filter = params.into_filter()?;
    let drafts = state.store.list(&filter).await.map_err(map_store_error)?;
    Ok(Json(drafts.iter().map(DraftSummary::from).collect()))
}

/// `GET /v1/drafts/{draft_id}` — one draft, including the narrative and the
/// event ids to check it against.
#[utoipa::path(
    get,
    path = "/v1/drafts/{draft_id}",
    tag = "copilot",
    params(("draft_id" = String, Path, format = Uuid, description = "Draft id")),
    responses(
        (status = 200, description = "The draft", body = DraftDetail),
        (status = 404, description = "No such draft"),
        (status = 500, description = "Store failure"),
    ),
)]
async fn get_draft(
    State(state): State<AppState>,
    Path(draft_id): Path<uuid::Uuid>,
) -> Result<Json<DraftDetail>, ApiError> {
    let draft = state
        .store
        .get(DraftId(draft_id))
        .await
        .map_err(map_store_error)?
        .ok_or_else(|| ApiError::not_found(format!("no draft {draft_id}")))?;
    Ok(Json(DraftDetail::from(&draft)))
}

/// A human's verdict.
///
/// Note what is *not* here: the reviewer. "Who decided" is the token's `sub`,
/// never a field a caller fills in — an approval signed with a name the caller
/// chose is not an audit record (see the module docs).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct ReviewRequest {
    /// Optional free-text note — why it was approved, or what was wrong.
    note: Option<String>,
}

/// The draft's state after a verdict.
#[derive(Debug, Serialize, utoipa::ToSchema)]
struct ReviewResponse {
    #[schema(value_type = String, format = Uuid)]
    draft_id: uuid::Uuid,
    status: String,
    reviewed_by: String,
    reviewed_at: DateTime<Utc>,
}

/// `POST /v1/drafts/{draft_id}/approve` — the §20.4 boundary. Only a `ready`
/// draft can be approved: approving a blocked or failed one would approve an
/// answer nobody has.
#[utoipa::path(
    post,
    path = "/v1/drafts/{draft_id}/approve",
    tag = "copilot",
    params(("draft_id" = String, Path, format = Uuid, description = "Draft id")),
    request_body = ReviewRequest,
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "Approved", body = ReviewResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 404, description = "No such draft"),
        (status = 409, description = "The draft is not in a reviewable state"),
        (status = 500, description = "Store failure"),
    ),
)]
async fn approve(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(draft_id): Path<uuid::Uuid>,
    Json(request): Json<ReviewRequest>,
) -> Result<Json<ReviewResponse>, ApiError> {
    decide(state, &claims, draft_id, Review::Approve, request).await
}

/// `POST /v1/drafts/{draft_id}/reject` — the other half. The draft is kept,
/// not deleted: the record of a narrative that was produced and refused is
/// itself part of the audit trail.
#[utoipa::path(
    post,
    path = "/v1/drafts/{draft_id}/reject",
    tag = "copilot",
    params(("draft_id" = String, Path, format = Uuid, description = "Draft id")),
    request_body = ReviewRequest,
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "Rejected", body = ReviewResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 404, description = "No such draft"),
        (status = 409, description = "The draft is not in a reviewable state"),
        (status = 500, description = "Store failure"),
    ),
)]
async fn reject(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(draft_id): Path<uuid::Uuid>,
    Json(request): Json<ReviewRequest>,
) -> Result<Json<ReviewResponse>, ApiError> {
    decide(state, &claims, draft_id, Review::Reject, request).await
}

async fn decide(
    state: AppState,
    claims: &Claims,
    draft_id: uuid::Uuid,
    verdict: Review,
    request: ReviewRequest,
) -> Result<Json<ReviewResponse>, ApiError> {
    // The verified subject, not a request field: a token that reaches here has
    // already proved who it belongs to.
    let reviewer = claims.sub.trim();
    if reviewer.is_empty() {
        return Err(ApiError::bad_request(
            "the token's `sub` is empty — an approval with no subject is not an approval",
        ));
    }
    let at = Utc::now();
    let status = state
        .store
        .review(
            DraftId(draft_id),
            verdict,
            reviewer,
            request.note.as_deref(),
            at,
        )
        .await
        .map_err(map_store_error)?;

    metrics::record_review(match verdict {
        Review::Approve => "approve",
        Review::Reject => "reject",
    });
    tracing::info!(%draft_id, %reviewer, status = status.as_wire_str(), "draft reviewed");

    Ok(Json(ReviewResponse {
        draft_id,
        status: status.as_wire_str().to_owned(),
        reviewed_by: reviewer.to_owned(),
        reviewed_at: at,
    }))
}

/// Map a store failure onto the shared API error vocabulary.
///
/// The three that matter are distinguishable on purpose: "no such draft" and
/// "that draft has no answer to approve" send a reviewer to completely
/// different places, and neither is our fault (so neither is a 500).
fn map_store_error(err: StoreError) -> ApiError {
    match err {
        StoreError::NotFound { draft_id } => ApiError::not_found(format!("no draft {draft_id}")),
        StoreError::NotReviewable { draft_id, status } => ApiError::conflict(format!(
            "draft {draft_id} is {status} and cannot be reviewed — only a `ready` draft has an \
             answer to approve"
        )),
        other => ApiError::internal(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DraftJob, DraftStatus};
    use crate::store::{DraftAttempt, DraftOutcome, DraftQueue, DraftWorkQueue};
    use crate::test_util::{completion, InMemoryDraftStore};
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::response::Response;
    use events::primitives::{Chain, IncidentId};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use llm::cache::CacheKey;
    use secrecy::SecretString;
    use tower::ServiceExt;

    const ISSUER: &str = "mevwatch";
    const SECRET: &str = "test-secret";
    const REVIEWER: &str = "alice@compliance";

    fn jwt() -> JwtConfig {
        JwtConfig {
            secret: SecretString::from(SECRET),
            issuer: ISSUER.to_owned(),
        }
    }

    /// A token this service accepts, signed for `sub`.
    fn token_for(sub: &str, secret: &str) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            &Claims {
                sub: sub.to_owned(),
                exp: 10_000_000_000,
                iss: ISSUER.to_owned(),
            },
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("sign")
    }

    async fn ready_draft(store: &Arc<InMemoryDraftStore>) -> (DraftId, uuid::Uuid) {
        let job = DraftJob::narrative(IncidentId::new(), Chain::ETHEREUM);
        store.enqueue(&job, Utc::now()).await.unwrap();
        let claimed = store
            .claim_batch(
                DraftKind::ALL,
                1,
                std::time::Duration::from_secs(60),
                3,
                Utc::now(),
            )
            .await
            .unwrap();
        let draft_id = claimed[0].job.draft_id;
        let event_id = uuid::Uuid::from_u128(0x5A);
        store
            .begin_attempt(
                draft_id,
                &CacheKey::new("claude-opus-5", &crate::test_util::request()),
                Some(crate::prompts::incident_narrative()),
                &[event_id],
                Utc::now(),
            )
            .await
            .unwrap();
        store
            .finish(
                draft_id,
                DraftOutcome::Completed(Box::new(completion(&format!(
                    "The attacker's transaction preceded the victim's swap [{event_id}]."
                )))),
                Utc::now(),
            )
            .await
            .unwrap();
        (draft_id, event_id)
    }

    fn app(store: Arc<InMemoryDraftStore>) -> Router {
        router(AppState { store, jwt: jwt() })
    }

    fn post(path: &str, token: Option<&str>, body: &str) -> HttpRequest<Body> {
        let mut builder = HttpRequest::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder.body(Body::from(body.to_owned())).unwrap()
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    /// The §20.4 boundary end to end: a ready draft is readable, and approving
    /// it is what flips the store state.
    #[tokio::test]
    async fn a_reviewer_reads_a_draft_and_approving_it_flips_the_store() {
        let store = Arc::new(InMemoryDraftStore::default());
        let (draft_id, event_id) = ready_draft(&store).await;
        let app = app(store.clone());

        let response = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri(format!("/v1/drafts/{draft_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let detail = body_json(response).await;
        assert_eq!(detail["status"], "ready");
        assert_eq!(detail["grounded"][0], event_id.to_string());
        assert_eq!(detail["prompt_id"], "incident_narrative@v2");
        assert!(detail["body"].as_str().unwrap().contains("attacker"));

        let response = app
            .clone()
            .oneshot(post(
                &format!("/v1/drafts/{draft_id}/approve"),
                Some(&token_for(REVIEWER, SECRET)),
                r#"{"note":"checked against the stream"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["status"], "approved");

        let draft = store.get(draft_id).await.unwrap().unwrap();
        assert!(draft.is_approved());
        assert_eq!(
            draft.review.unwrap().by,
            REVIEWER,
            "the audit trail records the *verified* subject, not a body field"
        );
    }

    /// A verdict is a write: without the token nothing changes.
    #[tokio::test]
    async fn a_verdict_without_the_token_is_refused_and_changes_nothing() {
        let store = Arc::new(InMemoryDraftStore::default());
        let (draft_id, _) = ready_draft(&store).await;
        let app = app(store.clone());

        // No token, a garbage token, and — the one that matters — a
        // well-formed token signed by somebody else's key.
        let forged = token_for("mallory", "not-our-secret");
        for token in [None, Some("garbage"), Some(forged.as_str())] {
            let response = app
                .clone()
                .oneshot(post(
                    &format!("/v1/drafts/{draft_id}/approve"),
                    token,
                    r#"{}"#,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        assert_eq!(
            store.get(draft_id).await.unwrap().unwrap().status,
            DraftStatus::Ready,
            "an unauthorised call must not review anything"
        );
    }

    /// Approving a draft with no usable answer is a 409, not a 500: the
    /// caller's state is wrong, and the message says which state.
    #[tokio::test]
    async fn a_blocked_draft_cannot_be_approved() {
        let store = Arc::new(InMemoryDraftStore::default());
        let job = DraftJob::narrative(IncidentId::new(), Chain::ETHEREUM);
        store.enqueue(&job, Utc::now()).await.unwrap();
        let claimed = store
            .claim_batch(
                DraftKind::ALL,
                1,
                std::time::Duration::from_secs(60),
                3,
                Utc::now(),
            )
            .await
            .unwrap();
        let draft_id = claimed[0].job.draft_id;
        store
            .begin_attempt(
                draft_id,
                &CacheKey::new("claude-opus-5", &crate::test_util::request()),
                Some(crate::prompts::incident_narrative()),
                &[uuid::Uuid::from_u128(1)],
                Utc::now(),
            )
            .await
            .unwrap();
        // Uncited prose: blocked by the citation check.
        store
            .finish(
                draft_id,
                DraftOutcome::Completed(Box::new(completion(
                    "The attacker laundered the proceeds through a mixing service.",
                ))),
                Utc::now(),
            )
            .await
            .unwrap();

        let response = app(store.clone())
            .oneshot(post(
                &format!("/v1/drafts/{draft_id}/approve"),
                Some(&token_for(REVIEWER, SECRET)),
                r#"{}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    /// A token with an empty subject cannot sign a decision: the audit record
    /// would name nobody.
    #[tokio::test]
    async fn a_token_with_no_subject_cannot_decide() {
        let store = Arc::new(InMemoryDraftStore::default());
        let (draft_id, _) = ready_draft(&store).await;
        let response = app(store)
            .oneshot(post(
                &format!("/v1/drafts/{draft_id}/approve"),
                Some(&token_for("   ", SECRET)),
                r#"{}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn the_queue_filters_and_an_unknown_status_is_a_400() {
        let store = Arc::new(InMemoryDraftStore::default());
        ready_draft(&store).await;
        let app = app(store);

        let response = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/v1/drafts?status=ready&kind=incident_narrative")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await.as_array().unwrap().len(), 1);

        let response = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/v1/drafts?status=approve")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn an_unknown_draft_is_a_404() {
        let store = Arc::new(InMemoryDraftStore::default());
        let response = app(store)
            .oneshot(
                HttpRequest::builder()
                    .uri(format!("/v1/drafts/{}", uuid::Uuid::new_v4()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
