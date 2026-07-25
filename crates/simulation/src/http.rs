//! `simulation-projection`'s internal HTTP read surface (§11): `GET /v1/incidents`
//! plus an unauthenticated `GET /healthz` probe.
//!
//! Internal and unauthenticated by design, the same posture as
//! [`event-store`'s read routes](../../event-store/src/http.rs) — reached only
//! over the internal network and fronted by the public §11 API service, which
//! owns end-user auth. No OpenAPI/Swagger here (unlike event-store's public-
//! shaped append API): this is a single small internal listing, not a surface
//! meant to be browsed/exercised by hand.

use std::sync::Arc;

use api_error::ApiError;
use axum::extract::{Path, Query, State};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use events::primitives::{AccountAddress, Chain, Severity};
use serde::{Deserialize, Serialize};
use tower_http::trace::TraceLayer;

use crate::exposure::{self, MevExposureSummary};
use crate::projection::{IncidentRecord, IncidentStatus};
use crate::store::{
    IncidentCursor, IncidentFilters, IncidentStore, PgIncidentStore, TimingStore,
    WalletExposureStore,
};
use crate::timing::{self, SizeBand, TimingRecommendation};

/// Shared handler state.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn IncidentStore>,
    /// Kept only for `/healthz` (`list_incidents` alone proves Postgres is up, but a
    /// dedicated trivial probe mirrors the rest of the workspace's `/healthz`
    /// convention without depending on there being at least one row).
    pub pg: PgIncidentStore,
    /// Backs `GET /v1/wallet/{addr}/mev-exposure` (§11).
    pub exposure: Arc<dyn WalletExposureStore>,
    /// Backs `GET /v1/timing/recommendation` (safe-block-timing).
    pub timing: Arc<dyn TimingStore>,
}

/// Build the router: `/v1/incidents`, `/v1/wallet/{addr}/mev-exposure`,
/// `/v1/timing/recommendation`, and `/healthz`, all open (see module docs).
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", axum::routing::get(healthz))
        .route("/v1/incidents", axum::routing::get(list_incidents))
        .route(
            "/v1/wallet/{addr}/mev-exposure",
            axum::routing::get(wallet_mev_exposure),
        )
        .route(
            "/v1/timing/recommendation",
            axum::routing::get(timing_recommendation),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// `GET /healthz` — readiness: confirms Postgres is reachable.
async fn healthz(State(state): State<AppState>) -> Result<&'static str, ApiError> {
    state.pg.ping().await.map_err(ApiError::internal)?;
    Ok("ok")
}

/// Query string for `GET /v1/incidents`: an optional status filter and keyset
/// pagination (`limit` + `cursor`). Every field is optional.
#[derive(Debug, Deserialize)]
struct ListParams {
    /// `unconfirmed` | `confirmed` | `finalized` | `retracted`.
    status: Option<String>,
    /// Max rows per page (clamped server-side).
    limit: Option<u64>,
    /// Opaque cursor from a previous page's `next_cursor`; resumes after it.
    cursor: Option<String>,
}

impl ListParams {
    fn into_filters(self) -> Result<IncidentFilters, ApiError> {
        let status = self
            .status
            .map(|raw| {
                IncidentStatus::parse(&raw)
                    .ok_or_else(|| ApiError::bad_request(format!("invalid status `{raw}`")))
            })
            .transpose()?;
        let cursor = self
            .cursor
            .map(|token| {
                IncidentCursor::parse(&token)
                    .ok_or_else(|| ApiError::bad_request(format!("invalid cursor `{token}`")))
            })
            .transpose()?;
        Ok(IncidentFilters {
            status,
            cursor,
            limit: self.limit,
        })
    }
}

/// One row of the `GET /v1/incidents` response — a wire-shaped projection of
/// [`IncidentRecord`] that deliberately omits the internal event-time watermarks
/// (`figures_at`/`retracted_at`/`finalized_at`): those are fold bookkeeping, not
/// part of the public read model (see [`IncidentRecord`]'s own docs).
#[derive(Debug, Serialize)]
struct IncidentDto {
    alert_id: String,
    incident_id: Option<String>,
    status: &'static str,
    kind: Option<&'static str>,
    severity: Option<&'static str>,
    profit: f64,
    victim_loss: f64,
    txs: Vec<String>,
    retraction_reason: Option<String>,
    finalized_block: Option<String>,
}

impl From<&IncidentRecord> for IncidentDto {
    fn from(record: &IncidentRecord) -> Self {
        Self {
            alert_id: record.alert_id.to_string(),
            incident_id: record.incident_id.map(|id| id.to_string()),
            status: record.status.as_str(),
            kind: record.kind.map(<&'static str>::from),
            severity: record.severity.map(<&'static str>::from),
            profit: record.profit,
            victim_loss: record.victim_loss,
            txs: record.txs.iter().map(|tx| format!("{tx:#x}")).collect(),
            retraction_reason: record.retraction_reason.clone(),
            finalized_block: record.finalized_block.map(|b| format!("{b:#x}")),
        }
    }
}

/// Response body: a page of incidents plus the cursor to fetch the next page
/// (`null` when the listing is exhausted).
#[derive(Debug, Serialize)]
struct IncidentPageResponse {
    incidents: Vec<IncidentDto>,
    next_cursor: Option<String>,
}

/// `GET /v1/incidents` — confirmed-incident rows, newest-updated first, optionally
/// narrowed by `status` and paginated.
async fn list_incidents(
    State(state): State<AppState>,
    Query(params): Query<ListParams>,
) -> Result<Json<IncidentPageResponse>, ApiError> {
    let page = state
        .store
        .list_incidents(&params.into_filters()?)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(IncidentPageResponse {
        incidents: page.incidents.iter().map(IncidentDto::from).collect(),
        next_cursor: page.next_cursor.map(|cursor| cursor.token()),
    }))
}

/// Query string for `GET /v1/wallet/{addr}/mev-exposure`: an optional lower bound
/// on `occurred_at` (RFC 3339), mirroring event-store's `from`/`to` convention.
#[derive(Debug, Deserialize)]
struct MevExposureParams {
    since: Option<DateTime<Utc>>,
}

/// `GET /v1/wallet/{addr}/mev-exposure` — every confirmed incident that named
/// `addr` as its victim, optionally narrowed to `occurred_at >= since` (§11):
/// counts and USD totals by kind, overall total/worst, and the per-incident list
/// each entry links to its existing `GET /v1/audit/incident/{incident_id}` audit
/// trail via `incident_id`.
async fn wallet_mev_exposure(
    State(state): State<AppState>,
    Path(addr): Path<AccountAddress>,
    Query(params): Query<MevExposureParams>,
) -> Result<Json<MevExposureSummary>, ApiError> {
    let rows = state
        .exposure
        .mev_exposure(&addr, params.since)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(exposure::summarize(rows)))
}

/// Query string for `GET /v1/timing/recommendation`: which chain, and which
/// "size" band (severity) to rank windows for. Both optional — an unset
/// `chain` defaults to Ethereum mainnet (mirrors api-service's
/// `default_chain` convention), an unset `size` defaults to `medium`.
#[derive(Debug, Deserialize)]
struct TimingParams {
    #[serde(default = "default_chain")]
    chain: u64,
    size: Option<String>,
}

/// Ethereum mainnet — the same default every other unscoped `chain` query
/// param in this workspace falls back to.
fn default_chain() -> u64 {
    Chain::ETHEREUM.id()
}

/// Parse the `size` query param's wire string into a [`SizeBand`], via the
/// same `deserialize_wire_str` primitive `store.rs`'s `parse_wire_enum`
/// builds on (one shared "wrap as `Value::String`, then deserialize" trick,
/// each layer wrapping the failure into its own error type). An unset `size`
/// defaults to [`Severity::Medium`]; an unrecognized string is the caller's
/// mistake, not ours.
fn parse_size(raw: Option<String>) -> Result<SizeBand, ApiError> {
    let Some(raw) = raw else {
        return Ok(Severity::Medium);
    };
    crate::store::deserialize_wire_str(&raw)
        .map_err(|_| ApiError::bad_request(format!("invalid size `{raw}`")))
}

/// `GET /v1/timing/recommendation` — safe-block-timing: historical incident
/// intensity for `chain`/`size`, ranked into the safest-first low-MEV
/// windows. A heuristic over historical patterns (see
/// [`timing::TIMING_CAVEAT`]), never a guarantee.
async fn timing_recommendation(
    State(state): State<AppState>,
    Query(params): Query<TimingParams>,
) -> Result<Json<TimingRecommendation>, ApiError> {
    let chain = Chain(params.chain);
    let severity = parse_size(params.size)?;

    let rows = state
        .timing
        .timing_buckets(chain, severity)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(timing::rank_windows(chain, severity, rows)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{ExposureRow, IncidentPage, JobUpdate, PersistError, TimingBucketRow};
    use crate::test_util::{InMemoryTimingStore, InMemoryWalletExposure};
    use async_trait::async_trait;
    use uuid::Uuid;

    /// Unused by this handler, but `AppState` needs an [`IncidentStore`] to
    /// construct; every method is unreachable from the wallet-exposure path.
    struct UnusedIncidentStore;

    #[async_trait]
    impl IncidentStore for UnusedIncidentStore {
        async fn upsert_incident(&self, _record: &IncidentRecord) -> Result<(), PersistError> {
            unimplemented!("not exercised by the wallet-exposure handler tests")
        }

        async fn record_job(&self, _job: &JobUpdate) -> Result<(), PersistError> {
            unimplemented!("not exercised by the wallet-exposure handler tests")
        }

        async fn list_incidents(
            &self,
            _filters: &IncidentFilters,
        ) -> Result<IncidentPage, PersistError> {
            unimplemented!("not exercised by the wallet-exposure handler tests")
        }
    }

    fn state(rows: Vec<ExposureRow>) -> AppState {
        // `connect_lazy` does no I/O — nothing here ever dials Postgres, since
        // `pg` (only used by `/healthz`) is never touched by this handler.
        let pool = sqlx::PgPool::connect_lazy("postgres://unused/unused")
            .expect("lazy pool construction does no I/O");
        AppState {
            store: Arc::new(UnusedIncidentStore),
            pg: PgIncidentStore::new(pool),
            exposure: Arc::new(InMemoryWalletExposure::new(rows)),
            timing: Arc::new(InMemoryTimingStore::default()),
        }
    }

    fn row(kind: &str, usd_lost: f64) -> ExposureRow {
        InMemoryWalletExposure::row(Uuid::new_v4(), kind, usd_lost, Utc::now())
    }

    /// Like [`state`], but for the timing-recommendation handler tests: no
    /// wallet-exposure rows, canned `TimingBucketRow`s instead.
    fn timing_state(rows: Vec<TimingBucketRow>) -> AppState {
        let pool = sqlx::PgPool::connect_lazy("postgres://unused/unused")
            .expect("lazy pool construction does no I/O");
        AppState {
            store: Arc::new(UnusedIncidentStore),
            pg: PgIncidentStore::new(pool),
            exposure: Arc::new(InMemoryWalletExposure::default()),
            timing: Arc::new(InMemoryTimingStore::new(rows)),
        }
    }

    #[tokio::test]
    async fn wallet_mev_exposure_summarizes_the_store_rows() {
        let state = state(vec![row("sandwich", 100.0), row("sandwich", 50.0)]);
        let Json(summary) = wallet_mev_exposure(
            State(state),
            Path(AccountAddress::ZERO),
            Query(MevExposureParams { since: None }),
        )
        .await
        .expect("handler succeeds");

        assert_eq!(summary.incident_count, 2);
        assert_eq!(summary.total_usd_lost, 150.0);
        assert_eq!(summary.worst_usd_lost, 100.0);
        assert_eq!(summary.by_kind.len(), 1);
    }

    #[tokio::test]
    async fn wallet_mev_exposure_with_no_incidents_is_all_zeroes() {
        let state = state(vec![]);
        let Json(summary) = wallet_mev_exposure(
            State(state),
            Path(AccountAddress::ZERO),
            Query(MevExposureParams { since: None }),
        )
        .await
        .expect("handler succeeds");

        assert_eq!(summary.incident_count, 0);
        assert!(summary.incidents.is_empty());
    }

    #[tokio::test]
    async fn timing_recommendation_ranks_the_store_rows() {
        let state = timing_state(vec![TimingBucketRow {
            slot_of_day: 5,
            incident_count: 3,
            total_victim_loss_usd: 900.0,
        }]);
        let Json(rec) = timing_recommendation(
            State(state),
            Query(TimingParams {
                chain: default_chain(),
                size: Some("high".to_owned()),
            }),
        )
        .await
        .expect("handler succeeds");

        assert_eq!(rec.chain, default_chain());
        assert_eq!(rec.size, "high");
        assert_eq!(rec.sample_size, 3);
        assert_eq!(rec.caveat, timing::TIMING_CAVEAT);
        // Slot 5 is the only one with any incidents, so every returned
        // window (the safest ones) must be a zero-incident slot.
        assert!(rec.windows.iter().all(|w| w.incident_count == 0));
    }

    #[tokio::test]
    async fn timing_recommendation_defaults_size_to_medium() {
        let state = timing_state(vec![]);
        let Json(rec) = timing_recommendation(
            State(state),
            Query(TimingParams {
                chain: default_chain(),
                size: None,
            }),
        )
        .await
        .expect("handler succeeds");

        assert_eq!(rec.size, "medium");
        assert_eq!(rec.sample_size, 0);
    }

    #[tokio::test]
    async fn timing_recommendation_rejects_an_unrecognized_size() {
        let state = timing_state(vec![]);
        let err = timing_recommendation(
            State(state),
            Query(TimingParams {
                chain: default_chain(),
                size: Some("gigantic".to_owned()),
            }),
        )
        .await
        .expect_err("an unrecognized size band is a 400, not a panic");

        match err {
            ApiError::BadRequest(detail) => assert!(detail.contains("gigantic"), "{detail}"),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }
}
