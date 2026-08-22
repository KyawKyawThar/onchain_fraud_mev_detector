//! The predictive pipeline's internal read API (§16.4): live position/risk
//! reads over the shared position tracker + cascade engine, plus a cascade
//! what-if simulator — Swagger-documented the same way event-store's append
//! API is ("easy to exercise by hand", that module's own words).
//!
//! Internal and unauthenticated by design, the same posture as event-store's
//! and simulation-projection's read routes — reached only over the internal
//! network. A public-facing JWT-gated proxy (mirroring `server`'s
//! `/v1/builders`-style routes) is future work, not required to exercise
//! this by hand today.
//!
//! Every handler is a thin read/compute wrapper over already-tested pure
//! functions ([`assess`], [`valued_total`], [`reflexivity::detect_cascade`])
//! — no new business logic lives here, only wiring and JSON shaping.
//!
//! # The cascade simulator's price-overlay contract
//!
//! [`reflexivity::detect_cascade`] expects its `prices` argument to *already*
//! reflect the trigger tick (mirrors [`CascadeEngine::on_price_tick`], which
//! inserts the tick into its own cache before folding). [`simulate_cascade`]
//! honors that explicitly: it clones the engine's live price cache and
//! overlays the caller's hypothetical price for the queried asset before
//! calling the walk — getting this wrong would silently ask "what if nothing
//! changed" instead of the intended "what if this asset dropped to $X".

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use alloy_primitives::{Address, U256};
use api_error::ApiError;
use axum::extract::{Path, Query, State};
use axum::{Json, Router};
use detector_api::{TokenMeta, UsdPrice};
use events::primitives::{AccountAddress, LendingProtocol, Severity};
use serde::{Deserialize, Serialize};
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use utoipa_swagger_ui::SwaggerUi;

use crate::cascade::{assess, valued_total, CascadeEngine, RiskThresholds};
use crate::position::{Position, PositionKey, PositionTracker};
use crate::price_source::PriceTick;
use crate::reflexivity::{self, ReflexivityLimits, SteppedImpactModel};

/// The OpenAPI surface: metadata + component schemas. Paths are collected
/// from the handlers' `#[utoipa::path]` annotations by [`build_router`], so
/// the spec can't drift from the routes actually served.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "predictive",
        version = env!("CARGO_PKG_VERSION"),
        description = "Predictive pipeline internal read API — live position risk + reflexivity cascade what-if simulation (§16.4)",
    ),
    components(schemas(PositionRiskResponse, CascadeSimulationResponse)),
    tags((name = "predictive", description = "Live position risk + reflexivity cascade simulation (§16)")),
)]
pub struct ApiDoc;

/// Shared handler state — every field is either already `Arc`-shared
/// elsewhere in `main.rs` (the tracker/engine) or cheap to clone per request
/// (the boot-time config values, all `Copy`).
#[derive(Clone)]
pub struct AppState {
    pub tracker: Arc<Mutex<PositionTracker>>,
    /// Shared with `main.rs::run_cascade` so a read here sees the same
    /// price cache the live cascade/reflexivity pipeline just folded a tick
    /// into — never a second, potentially-stale copy.
    pub engine: Arc<Mutex<CascadeEngine>>,
    pub assets: Arc<HashMap<Address, TokenMeta>>,
    pub thresholds: RiskThresholds,
    pub reflexivity_limits: ReflexivityLimits,
    pub price_impact_model: SteppedImpactModel,
}

/// Assemble the routed surface **and** its OpenAPI spec from one source of
/// truth — mirrors `event_store::http::build_router`. Takes no `state`
/// (unlike event-store's, which needs it for the write-token middleware):
/// every route here is open (module docs), so `with_state` only happens once,
/// in [`router`].
fn build_router() -> (Router<AppState>, utoipa::openapi::OpenApi) {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(healthz))
        .routes(routes!(list_positions))
        .routes(routes!(get_position))
        .routes(routes!(simulate_cascade))
        .split_for_parts()
}

/// Build the router: every route open (module docs), plus the Swagger UI +
/// spec at `/swagger-ui` and `/api-docs/openapi.json`.
pub fn router(state: AppState) -> Router {
    let (router, api) = build_router();
    router
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", api))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// `GET /healthz` — liveness: this service holds no external DB, so there is
/// nothing to ping; a response at all proves the HTTP server and its shared
/// state are up. Distinct from `telemetry::health`'s K8s `/livez`/`/readyz`
/// probes (a separate listener) — this one is this read API's own.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "predictive",
    responses((status = 200, description = "The read API is up", body = String)),
)]
async fn healthz() -> &'static str {
    "ok"
}

/// One position's live risk, as of the latest applied block and price tick.
#[derive(Debug, Serialize, utoipa::ToSchema)]
struct PositionRiskResponse {
    protocol: LendingProtocol,
    #[schema(value_type = String)]
    account: AccountAddress,
    /// `None` when any nonzero-balance asset can't be valued (missing price
    /// or metadata) — the same conservative-skip convention [`valued_total`]
    /// uses, not a `0.0` that would understate the position.
    collateral_usd: Option<f64>,
    debt_usd: Option<f64>,
    /// Collateral (weighted by liquidation threshold) over debt — below
    /// `1.0` is liquidatable. `None` when [`assess`] can't forecast this
    /// position (zero debt, or any nonzero asset unpriceable).
    health_factor: Option<f64>,
    distance_pct: Option<f64>,
    severity: Option<Severity>,
}

/// Value and assess one position against `assets`/`prices` — shared by both
/// read handlers below so the two can't drift.
fn position_risk(
    key: PositionKey,
    position: &Position,
    assets: &HashMap<Address, TokenMeta>,
    prices: &HashMap<Address, UsdPrice>,
    thresholds: &RiskThresholds,
) -> PositionRiskResponse {
    let assessment = assess(position, assets, prices, thresholds);
    PositionRiskResponse {
        protocol: key.protocol,
        account: key.account,
        collateral_usd: valued_total(&position.collateral, assets, prices),
        debt_usd: valued_total(&position.debt, assets, prices),
        health_factor: assessment.map(|a| a.health_factor),
        distance_pct: assessment.map(|a| a.distance_pct),
        severity: assessment.map(|a| a.severity),
    }
}

/// `GET /v1/positions` — every open position's live risk. The at-risk board:
/// paste straight into Postman/Swagger to see what the pipeline currently
/// tracks, no waiting for the next real oracle tick.
#[utoipa::path(
    get,
    path = "/v1/positions",
    tag = "predictive",
    responses((status = 200, description = "Every open position's live risk", body = [PositionRiskResponse])),
)]
async fn list_positions(State(state): State<AppState>) -> Json<Vec<PositionRiskResponse>> {
    let snapshot = state.tracker.lock().unwrap().snapshot();
    let prices = state.engine.lock().unwrap().prices().clone();

    let rows = snapshot
        .iter()
        .flat_map(|positions| positions.iter())
        .map(|(&key, position)| {
            position_risk(key, position, &state.assets, &prices, &state.thresholds)
        })
        .collect();
    Json(rows)
}

/// `aave`/`compound`, case-insensitively — the wire form `LendingProtocol`
/// itself uses on every other JSON surface, accepted as a bare path segment
/// here rather than requiring a caller to quote it as JSON.
fn parse_protocol(raw: &str) -> Result<LendingProtocol, ApiError> {
    match raw.to_ascii_lowercase().as_str() {
        "aave" => Ok(LendingProtocol::Aave),
        "compound" => Ok(LendingProtocol::Compound),
        other => Err(ApiError::bad_request(format!(
            "unknown protocol `{other}`; expected `aave` or `compound`"
        ))),
    }
}

/// `GET /v1/positions/{protocol}/{account}` — one account's live risk.
#[utoipa::path(
    get,
    path = "/v1/positions/{protocol}/{account}",
    tag = "predictive",
    params(
        ("protocol" = String, Path, description = "aave or compound"),
        ("account" = String, Path, description = "On-chain account, 0x-prefixed hex"),
    ),
    responses(
        (status = 200, description = "The account's live risk", body = PositionRiskResponse),
        (status = 400, description = "Invalid protocol or address"),
        (status = 404, description = "No open position for this account/protocol"),
    ),
)]
async fn get_position(
    State(state): State<AppState>,
    Path((protocol, account)): Path<(String, String)>,
) -> Result<Json<PositionRiskResponse>, ApiError> {
    let protocol = parse_protocol(&protocol)?;
    let account: AccountAddress = account
        .parse()
        .map_err(|_| ApiError::bad_request(format!("invalid address `{account}`")))?;
    let key = PositionKey { protocol, account };

    let snapshot = state.tracker.lock().unwrap().snapshot();
    let position = snapshot
        .as_deref()
        .and_then(|positions| positions.get(&key))
        .cloned()
        .ok_or_else(|| {
            ApiError::not_found(format!("no open {protocol:?} position for {account}"))
        })?;
    let prices = state.engine.lock().unwrap().prices().clone();

    Ok(Json(position_risk(
        key,
        &position,
        &state.assets,
        &prices,
        &state.thresholds,
    )))
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct SimulateParams {
    /// The asset whose hypothetical USD price to shock, 0x-prefixed hex.
    asset: String,
    /// The hypothetical price, in USD, for `asset` (e.g. `2180.0`).
    price: f64,
}

/// The reflexivity walk's outcome at a hypothetical trigger price — the wire
/// shape of [`reflexivity::CascadeOutcome`], flattened (module docs).
#[derive(Debug, Serialize, utoipa::ToSchema)]
struct CascadeSimulationResponse {
    #[schema(value_type = String)]
    trigger_asset: Address,
    trigger_price: f64,
    /// Whether this hypothetical price finds a genuine reflexive cascade —
    /// growth beyond the plain at-risk set ([`reflexivity`] module docs'
    /// "only reflexivity, never a bare risk snapshot").
    cascade_found: bool,
    reflexive_depth: u32,
    #[schema(value_type = Vec<String>)]
    accounts: Vec<AccountAddress>,
    aggregate_at_risk_usd: f64,
    /// The walk reached a degree-capped hub asset (§8.2) — see
    /// [`reflexivity::CascadeOutcome::hub_capped`].
    hub_capped: bool,
}

/// `GET /v1/cascade/simulate?asset=&price=` — the what-if endpoint: runs the
/// same reflexivity walk `main.rs::run_cascade` runs on every real oracle
/// tick, but against a caller-supplied hypothetical price instead of waiting
/// for one — "what happens if `asset` drops to `price` right now" (module
/// docs), directly against the live tracked position book.
#[utoipa::path(
    get,
    path = "/v1/cascade/simulate",
    tag = "predictive",
    params(SimulateParams),
    responses(
        (status = 200, description = "The reflexivity walk's outcome at the hypothetical price", body = CascadeSimulationResponse),
        (status = 400, description = "Invalid asset address or a non-finite/negative price"),
    ),
)]
async fn simulate_cascade(
    State(state): State<AppState>,
    Query(params): Query<SimulateParams>,
) -> Result<Json<CascadeSimulationResponse>, ApiError> {
    let asset: Address = params
        .asset
        .parse()
        .map_err(|_| ApiError::bad_request(format!("invalid asset address `{}`", params.asset)))?;
    let price = UsdPrice::try_new(params.price).map_err(ApiError::bad_request)?;
    // `updated_at` is never read by `detect_cascade` — only `asset`/`price`
    // matter, both already carried explicitly above.
    let tick = PriceTick {
        asset,
        price,
        updated_at: U256::ZERO,
    };

    let Some(positions) = state.tracker.lock().unwrap().snapshot() else {
        return Ok(Json(no_cascade(asset, price, false)));
    };

    // See module docs: `detect_cascade` needs the trigger already folded
    // into `prices`, the same thing `CascadeEngine::on_price_tick` does
    // internally on a real tick.
    let mut prices = state.engine.lock().unwrap().prices().clone();
    prices.insert(asset, price);

    let outcome = reflexivity::detect_cascade(
        tick,
        &state.assets,
        &prices,
        &positions,
        &state.thresholds,
        &state.reflexivity_limits,
        &state.price_impact_model,
    );

    Ok(Json(match outcome.warning {
        Some(warning) => CascadeSimulationResponse {
            trigger_asset: warning.trigger_asset,
            trigger_price: warning.trigger_price,
            cascade_found: true,
            reflexive_depth: warning.reflexive_depth,
            accounts: warning.accounts,
            aggregate_at_risk_usd: warning.aggregate_at_risk_usd.get(),
            hub_capped: outcome.hub_capped,
        },
        None => no_cascade(asset, price, outcome.hub_capped),
    }))
}

fn no_cascade(asset: Address, price: UsdPrice, hub_capped: bool) -> CascadeSimulationResponse {
    CascadeSimulationResponse {
        trigger_asset: asset,
        trigger_price: price.get(),
        cascade_found: false,
        reflexive_depth: 0,
        accounts: Vec::new(),
        aggregate_at_risk_usd: 0.0,
        hub_capped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::position::{LiquidationThresholds, Protocol};
    use detector_api::Bps;

    fn addr(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }

    const WETH: u8 = 0xE0;
    const USDC: u8 = 0xC0;

    fn test_state() -> AppState {
        AppState {
            tracker: Arc::new(Mutex::new(PositionTracker::new(
                16,
                LiquidationThresholds::default(),
            ))),
            engine: Arc::new(Mutex::new(CascadeEngine::new(RiskThresholds::default()))),
            assets: Arc::new(HashMap::new()),
            thresholds: RiskThresholds::default(),
            reflexivity_limits: ReflexivityLimits::default(),
            price_impact_model: SteppedImpactModel::default(),
        }
    }

    #[test]
    fn openapi_spec_collects_every_route_and_schema() {
        // Mirrors `event_store::http`'s guard: the spec is built by the
        // router from the handler annotations, so this catches route/doc
        // drift, not just a missing derive.
        let (_router, api) = build_router();
        let spec = serde_json::to_value(&api).expect("serialize spec");

        for name in ["PositionRiskResponse", "CascadeSimulationResponse"] {
            assert!(
                spec["components"]["schemas"].get(name).is_some(),
                "OpenAPI components missing schema `{name}`"
            );
        }
        for (path, method) in [
            ("/healthz", "get"),
            ("/v1/positions", "get"),
            ("/v1/positions/{protocol}/{account}", "get"),
            ("/v1/cascade/simulate", "get"),
        ] {
            assert!(
                spec["paths"][path][method].is_object(),
                "OpenAPI paths missing `{method} {path}`"
            );
        }
    }

    #[test]
    fn router_assembles_without_panicking() {
        // Exercises the `router()` wrapper itself (SwaggerUi merge +
        // `with_state`), not just `build_router`'s spec — a smoke test that
        // the full app, as `main.rs` constructs it, is well-formed.
        let _ = router(test_state());
    }

    #[test]
    fn parse_protocol_accepts_known_names_case_insensitively() {
        assert_eq!(parse_protocol("aave").unwrap(), LendingProtocol::Aave);
        assert_eq!(parse_protocol("AAVE").unwrap(), LendingProtocol::Aave);
        assert_eq!(
            parse_protocol("Compound").unwrap(),
            LendingProtocol::Compound
        );
    }

    #[test]
    fn parse_protocol_rejects_an_unknown_name() {
        assert!(parse_protocol("makerdao").is_err());
    }

    fn assets() -> HashMap<Address, TokenMeta> {
        let mut map = HashMap::new();
        map.insert(addr(WETH), TokenMeta::new(addr(WETH), None, 18));
        map.insert(addr(USDC), TokenMeta::new(addr(USDC), None, 6));
        map
    }

    fn prices() -> HashMap<Address, UsdPrice> {
        let mut map = HashMap::new();
        map.insert(addr(WETH), UsdPrice::try_new(2_000.0).unwrap());
        map.insert(addr(USDC), UsdPrice::try_new(1.0).unwrap());
        map
    }

    fn key() -> PositionKey {
        PositionKey {
            protocol: Protocol::Aave,
            account: addr(0x11),
        }
    }

    #[test]
    fn position_risk_reports_assessed_figures_for_a_priced_position() {
        let position = Position {
            collateral: [(addr(WETH), U256::from(2_000_000_000_000_000_000u64))].into(),
            debt: [(addr(USDC), U256::from(1_000_000_000u64))].into(),
            liquidation_threshold: Bps::new(8_000),
        };

        let row = position_risk(
            key(),
            &position,
            &assets(),
            &prices(),
            &RiskThresholds::default(),
        );

        assert_eq!(row.protocol, LendingProtocol::Aave);
        assert_eq!(row.account, addr(0x11));
        assert_eq!(row.collateral_usd, Some(4_000.0)); // 2 WETH @ $2,000
        assert_eq!(row.debt_usd, Some(1_000.0)); // 1,000 USDC @ $1
        assert!(row.health_factor.is_some());
        assert!(row.distance_pct.is_some());
        assert!(row.severity.is_some());
    }

    #[test]
    fn position_risk_nulls_the_forecast_when_unpriceable_but_still_values_collateral() {
        let position = Position {
            collateral: [(addr(WETH), U256::from(1_000_000_000_000_000_000u64))].into(),
            debt: [(addr(USDC), U256::from(500_000_000u64))].into(),
            liquidation_threshold: Bps::new(8_000),
        };
        let mut missing_price = prices();
        missing_price.remove(&addr(USDC)); // debt side unpriceable

        let row = position_risk(
            key(),
            &position,
            &assets(),
            &missing_price,
            &RiskThresholds::default(),
        );

        assert_eq!(row.collateral_usd, Some(2_000.0), "WETH side still values");
        assert_eq!(row.debt_usd, None, "USDC side can't be valued");
        assert_eq!(row.health_factor, None, "assess() needs both sides priced");
        assert_eq!(row.distance_pct, None);
        assert_eq!(row.severity, None);
    }

    #[test]
    fn no_cascade_carries_the_queried_trigger_and_hub_capped_flag() {
        let response = no_cascade(addr(WETH), UsdPrice::try_new(1_500.0).unwrap(), true);
        assert_eq!(response.trigger_asset, addr(WETH));
        assert_eq!(response.trigger_price, 1_500.0);
        assert!(!response.cascade_found);
        assert_eq!(response.reflexive_depth, 0);
        assert!(response.accounts.is_empty());
        assert_eq!(response.aggregate_at_risk_usd, 0.0);
        assert!(response.hub_capped);
    }
}
