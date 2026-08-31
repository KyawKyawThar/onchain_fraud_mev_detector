//! The copilot's HTTP surface (§20.4) — where a human reads a draft and
//! decides on it, and where a customer asks for a rule in plain English.
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
//! # `POST /v1/rules/draft` — asking, not activating (t4)
//!
//! The one write that is not a verdict. A customer posts a sentence; the
//! service records a `rule_draft` job **owned by the token's subject** and
//! returns a draft id. It does not call the model (that is the worker pool's
//! job, minutes later — see the crate docs on why an LLM call never rides a
//! request that something is waiting on), and it emphatically does not create
//! a rule.
//!
//! Three properties hold by construction rather than by care:
//!
//! * the owner is the verified `sub` parsed as a customer UUID, so a body
//!   cannot name another customer and the model has no field to put one in;
//! * the subject id is derived from `(owner, request)`, so a double-clicked
//!   button resolves to the draft that already exists instead of buying a
//!   second, differently-worded answer to the same question;
//! * activation is somewhere else entirely — the rule engine's own
//!   `POST /v1/rules`, which re-validates the definition under an owner it
//!   takes from the token. Nothing this service serves can make a rule run.
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
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
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
use crate::model::{Draft, DraftId, DraftJob, DraftKind, DraftSource, DraftStatus, Review};
use crate::rule_draft::MAX_REQUEST_BYTES;
use crate::store::{DraftFilter, DraftQueue, DraftReview, Enqueued, StoreError, MAX_LIST_LIMIT};

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
    components(schemas(
        DraftSummary,
        DraftDetail,
        GroundingView,
        RuleView,
        ReviewRequest,
        ReviewResponse,
        DraftRuleRequest,
        DraftRuleResponse,
    )),
    tags((name = "copilot", description = "Incident narrative drafts and their review (§20.4)")),
)]
pub struct ApiDoc;

/// Shared handler state.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn DraftReview>,
    /// The enqueue half, for `POST /v1/rules/draft`. Narrow on purpose: this
    /// handler records a job and nothing else — it cannot claim, call a model,
    /// or approve anything (`crate::store`'s four views).
    pub queue: Arc<dyn DraftQueue>,
    /// Nudges the worker pool that there is new work, so a customer waits the
    /// length of a draft rather than the length of a draft plus a poll
    /// interval. A latency hint only: polling is what actually drains the
    /// queue, because other pods enqueue too.
    pub wake: Arc<tokio::sync::Notify>,
    /// The chain stamped on this deployment's events (`COPILOT_CHAIN`). The
    /// copilot is not per-chain; a rule draft is not a chain fact either, and
    /// every envelope needs one.
    pub chain: events::primitives::Chain,
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
        .routes(routes!(draft_rule))
        // Only the writes: a reviewer needs a token to *decide* and a customer
        // needs one to *ask*, but neither needs one to read the queue. The
        // drafting route is here for a second reason as well — its owner is
        // the verified subject, so it cannot be served without a token at all.
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
    /// The compiled rule, for a rule draft (§20.4 t4). Present only when the
    /// draft crossed §9's parse boundary — a `blocked` rule draft has the
    /// compiler's complaint in `last_error` and nothing here, which is the
    /// whole distinction.
    rule: Option<RuleView>,
    /// The Batch API job that produced it, for a backfilled draft.
    batch_id: Option<String>,
    review_note: Option<String>,
}

/// A drafted rule, as its customer reviews it before activating it.
#[derive(Debug, Serialize, utoipa::ToSchema)]
struct RuleView {
    /// The definition in §9's wire form — **post this verbatim to the rule
    /// engine's `POST /v1/rules` to activate it**. There is no "activate"
    /// button here on purpose: making a rule run is the rule engine's write,
    /// under an owner it takes from the customer's own token, and a copilot
    /// endpoint that could do it would be this service creating rules.
    #[schema(value_type = Object)]
    definition: serde_json::Value,
    /// The same rule in plain language, rendered from the **compiled**
    /// definition rather than from anything the model said about its own
    /// output. That is what makes it a check: a model-written summary would be
    /// wrong in exactly the case that matters.
    explanation: String,
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
            rule: draft.compiled_rule().and_then(|compiled| {
                Some(RuleView {
                    explanation: compiled.explain(),
                    definition: serde_json::to_value(compiled.definition()).ok()?,
                })
            }),
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
            // The review queue is a queue: a reviewer reads the newest page and
            // narrows it, so no cursor is exposed here. Paging the *whole*
            // table is the audit sweep's job, and it holds the store directly.
            before: None,
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

/// `POST /v1/rules/draft` body: the customer's own sentence, and nothing else.
///
/// Note what is absent, twice over: an `owner` (the token's `sub` is the only
/// answer this service accepts) and any part of the rule itself. A body that
/// could carry half a definition would be a second, unvalidated way into the
/// rule store.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct DraftRuleRequest {
    /// What to alert on, in plain English — e.g. "alert me when any wallet
    /// within 2 hops of a sanctioned address moves more than $10K into our
    /// pools".
    request: String,
}

/// Where the customer picks the draft up.
#[derive(Debug, Serialize, utoipa::ToSchema)]
struct DraftRuleResponse {
    #[schema(value_type = String, format = Uuid)]
    draft_id: uuid::Uuid,
    /// `queued` on a fresh ask, `already_queued` when this customer has
    /// already asked this exact question — the same idempotent-retry
    /// vocabulary `POST /v1/rules` uses, and for the same reason: a
    /// double-clicked button must not buy a second billed answer.
    status: &'static str,
    /// Poll here (`GET /v1/drafts/{draft_id}`) for the compiled rule and its
    /// plain-language echo.
    draft_ref: String,
}

/// `POST /v1/rules/draft` — ask for a rule in plain English (§20.4).
///
/// Returns `202`: the model is called by the worker pool out of band, because
/// a completion takes minutes and no request path in this system waits on one.
/// Poll `GET /v1/drafts/{draft_id}` until it is `ready` (the compiled rule and
/// its echo are on the response) or `blocked` (the compiler's own error is in
/// `last_error`, and the draft can never run).
///
/// **This never creates a rule.** Activation is the rule engine's
/// `POST /v1/rules`, with the definition from the draft.
#[utoipa::path(
    post,
    path = "/v1/rules/draft",
    tag = "copilot",
    request_body = DraftRuleRequest,
    security(("bearer_token" = [])),
    responses(
        (status = 202, description = "Draft queued (or already queued)", body = DraftRuleResponse),
        (status = 400, description = "Empty request, or a `sub` that is not a customer UUID"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 413, description = "The request text exceeds the ceiling"),
        (status = 500, description = "Store failure"),
    ),
)]
async fn draft_rule(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(body): Json<DraftRuleRequest>,
) -> Result<Response, ApiError> {
    let owner = customer_from(&claims)?;
    let request = body.request.trim();
    if request.is_empty() {
        return Err(ApiError::bad_request(
            "`request` must describe what to alert on",
        ));
    }
    if request.len() > MAX_REQUEST_BYTES {
        // Refused rather than truncated: this string *is* the prompt, and a
        // silently shortened one drafts a rule for a question nobody asked.
        return Err(ApiError::payload_too_large(format!(
            "`request` is {} bytes; the ceiling is {MAX_REQUEST_BYTES}",
            request.len()
        )));
    }

    let job = DraftJob::rule_draft(owner, state.chain, request);
    let enqueued = state
        .queue
        .enqueue(&job, Utc::now())
        .await
        .map_err(map_store_error)?;

    let (draft_id, status) = match enqueued {
        Enqueued::Queued(id) => {
            // Only a *new* job is worth waking the pool for; a duplicate is
            // already in flight or already answered.
            state.wake.notify_one();
            (id, "queued")
        }
        Enqueued::AlreadyQueued(id) => (id, "already_queued"),
    };
    metrics::record_enqueued(
        DraftKind::RuleDraft.as_wire_str(),
        if enqueued.is_new() {
            "queued"
        } else {
            "duplicate"
        },
    );
    tracing::info!(%draft_id, %owner, status, "rule draft requested");

    Ok((
        StatusCode::ACCEPTED,
        Json(DraftRuleResponse {
            draft_id: draft_id.0,
            status,
            draft_ref: crate::announce::narrative_ref(draft_id),
        }),
    )
        .into_response())
}

/// The customer behind a verified token.
///
/// The API service's rule (`server::auth`), applied here to the one route that
/// needs it and deliberately not to the rest: a rule has a billing owner, an
/// incident narrative has a reviewer who is a person. Duplicated rather than
/// shared because `auth` is pinned as a workspace-dependency-free leaf by
/// arch-conformance, so it cannot know what a `CustomerId` is — and promoting
/// this there would give the verifier a domain type and, eventually, a reason
/// to grow issuance.
fn customer_from(claims: &Claims) -> Result<events::primitives::CustomerId, ApiError> {
    let sub = claims.sub.trim();
    let customer = uuid::Uuid::parse_str(sub)
        .map_err(|_| ApiError::bad_request("the token's `sub` is not a customer UUID"))?;
    if customer.is_nil() {
        // Reserved for platform-internal usage with no customer in scope
        // (§13); a rule owned by it would be unattributable and unmeterable.
        return Err(ApiError::bad_request(
            "the token's `sub` is the nil UUID, which is reserved for system usage",
        ));
    }
    Ok(events::primitives::CustomerId(customer))
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
    use axum::http::Request as HttpRequest;
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
        router(AppState {
            store: store.clone(),
            queue: store,
            wake: Arc::new(tokio::sync::Notify::new()),
            chain: Chain::ETHEREUM,
            jwt: jwt(),
        })
    }

    /// A `sub` the drafting route accepts: a customer UUID (§13).
    const CUSTOMER: &str = "00000000-0000-0000-0000-0000000000c0";
    const RULE_REQUEST: &str = "Alert me when any wallet within 2 hops of a sanctioned \
                                address moves more than $10K into our pools";

    fn customer_token() -> String {
        token_for(CUSTOMER, SECRET)
    }

    /// A rule draft that landed `ready`, as the worker would leave it.
    async fn ready_rule_draft(store: &Arc<InMemoryDraftStore>, body: &str) -> DraftId {
        let job = DraftJob::rule_draft(
            events::primitives::CustomerId(uuid::Uuid::parse_str(CUSTOMER).unwrap()),
            Chain::ETHEREUM,
            RULE_REQUEST,
        );
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
                Some(crate::prompts::rule_draft()),
                &[],
                Utc::now(),
            )
            .await
            .unwrap();
        store
            .finish(
                draft_id,
                DraftOutcome::Completed(Box::new(completion(body))),
                Utc::now(),
            )
            .await
            .unwrap();
        draft_id
    }

    const GOOD_RULE: &str = r##"{"name":"Sanctioned proximity inflow",
        "conditions":[{"hop_distance":{"from":"0x1111111111111111111111111111111111111111",
        "max_hops":2}}],"logic":"all","actions":[{"slack_alert":{"channel":"#compliance"}}]}"##;

    /// The whole t4 round trip through the API: ask in English, and read back
    /// a compiled rule plus the plain-language echo of what will actually run.
    #[tokio::test]
    async fn a_customer_asks_in_english_and_reads_back_a_compiled_rule() {
        let store = Arc::new(InMemoryDraftStore::default());
        let app = app(store.clone());

        let response = app
            .clone()
            .oneshot(post(
                "/v1/rules/draft",
                Some(&customer_token()),
                &serde_json::json!({ "request": RULE_REQUEST }).to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = body_json(response).await;
        assert_eq!(body["status"], "queued");
        let draft_id = body["draft_id"].as_str().unwrap().to_owned();

        // The row exists, is owned by the token's subject, and carries the
        // customer's own words — the worker's whole input.
        let draft = store
            .get(DraftId(uuid::Uuid::parse_str(&draft_id).unwrap()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(draft.kind, DraftKind::RuleDraft);
        assert_eq!(draft.status, DraftStatus::Queued);
        assert_eq!(draft.customer_id.unwrap().0.to_string(), CUSTOMER);
        assert_eq!(draft.source_text.as_deref(), Some(RULE_REQUEST));

        // …and nothing has been drafted or activated yet: this route records
        // work, it does not call a model and it does not create a rule.
        assert!(draft.answer.is_none());

        // The worker lands it. Now the read surface carries the compiled rule.
        let landed = ready_rule_draft(&store, GOOD_RULE).await;
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri(format!("/v1/drafts/{landed}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let detail = body_json(response).await;
        assert_eq!(detail["status"], "ready");
        assert_eq!(
            detail["rule"]["definition"]["name"],
            "Sanctioned proximity inflow"
        );
        let echo = detail["rule"]["explanation"].as_str().unwrap();
        assert!(echo.contains("within 2 transfer hop(s)"), "{echo}");
        assert_eq!(detail["prompt_id"], "rule_draft@v1");
    }

    /// §20.4's headline claim, at the API: a hallucinated condition comes back
    /// as the compiler's error on a draft that can never run — and the
    /// response carries no rule to activate.
    #[tokio::test]
    async fn a_hallucinated_rule_is_blocked_with_the_compilers_error() {
        let store = Arc::new(InMemoryDraftStore::default());
        let draft_id = ready_rule_draft(
            &store,
            r#"{"name":"Wash trading","conditions":[{"unusual_volume":{"gt":"1000"}}],
                "logic":"all","actions":[{"tag_address":{"label":"x"}}]}"#,
        )
        .await;

        let response = app(store.clone())
            .oneshot(
                HttpRequest::builder()
                    .uri(format!("/v1/drafts/{draft_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let detail = body_json(response).await;
        assert_eq!(detail["status"], "blocked");
        assert!(detail["rule"].is_null(), "there is nothing to activate");
        assert!(
            detail["last_error"]
                .as_str()
                .unwrap()
                .contains("unusual_volume"),
            "the customer sees the parser's own complaint: {detail}"
        );
        assert!(
            !store
                .get(draft_id)
                .await
                .unwrap()
                .unwrap()
                .status
                .is_reviewable(),
            "a draft that does not compile never reaches a review queue"
        );
    }

    /// Asking twice is asking once. The subject id is derived from
    /// `(owner, request)`, so a double-clicked button cannot buy a second
    /// billed answer to the same question.
    #[tokio::test]
    async fn the_same_request_twice_resolves_to_the_same_draft() {
        let store = Arc::new(InMemoryDraftStore::default());
        let app = app(store.clone());
        let body = serde_json::json!({ "request": RULE_REQUEST }).to_string();

        let first = body_json(
            app.clone()
                .oneshot(post("/v1/rules/draft", Some(&customer_token()), &body))
                .await
                .unwrap(),
        )
        .await;
        // Same ask, differently wrapped.
        let second_body =
            serde_json::json!({ "request": format!("  {RULE_REQUEST}\n") }).to_string();
        let second = body_json(
            app.oneshot(post(
                "/v1/rules/draft",
                Some(&customer_token()),
                &second_body,
            ))
            .await
            .unwrap(),
        )
        .await;

        assert_eq!(first["draft_id"], second["draft_id"]);
        assert_eq!(second["status"], "already_queued");
        assert_eq!(store.drafts().len(), 1);
    }

    /// The owner is the token, never the body. Two independent guards: an
    /// unauthenticated call is a 401, and a token whose `sub` is not a
    /// customer cannot own a rule at all.
    #[tokio::test]
    async fn a_rule_draft_needs_a_customer_token_and_takes_its_owner_from_it() {
        let store = Arc::new(InMemoryDraftStore::default());
        let app = app(store.clone());
        let body = serde_json::json!({
            "request": RULE_REQUEST,
            // A body field that looks like an owner. There is no such field,
            // so it is parsed away — and asserted away below.
            "owner": "00000000-0000-0000-0000-0000000000ff",
        })
        .to_string();

        for token in [None, Some("garbage")] {
            let response = app
                .clone()
                .oneshot(post("/v1/rules/draft", token, &body))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        // Correctly signed, but the subject is a person rather than a customer.
        let response = app
            .clone()
            .oneshot(post(
                "/v1/rules/draft",
                Some(&token_for(REVIEWER, SECRET)),
                &body,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(store.drafts().is_empty());

        let response = app
            .oneshot(post("/v1/rules/draft", Some(&customer_token()), &body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(
            store.drafts()[0].customer_id.unwrap().0.to_string(),
            CUSTOMER,
            "the owner is the verified subject, not the body's suggestion"
        );
    }

    #[tokio::test]
    async fn an_empty_or_oversized_request_is_refused() {
        let store = Arc::new(InMemoryDraftStore::default());
        let app = app(store.clone());

        for (body, expected) in [
            (
                serde_json::json!({ "request": "   " }).to_string(),
                StatusCode::BAD_REQUEST,
            ),
            (
                serde_json::json!({ "request": "x".repeat(MAX_REQUEST_BYTES + 1) }).to_string(),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ] {
            let response = app
                .clone()
                .oneshot(post("/v1/rules/draft", Some(&customer_token()), &body))
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }
        assert!(store.drafts().is_empty());
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
