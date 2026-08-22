//! Predictive events — the mempool-prediction pipeline's own family (§16),
//! separate from detection's fast path and simulation's slow path.
//!
//! Predictive events are **forecasts, not facts**: they carry `provisional:
//! true` like a fast-path alert, but unlike `PreliminaryAlertCreated` they are
//! never sim-confirmed — the event they forecast may simply not happen. That
//! is the point of a warning, not a defect in it (§16).

use crate::primitives::{
    AccountAddress, AlertKind, Confidence, LendingProtocol, PredictionId, Severity, UsdAmount,
};
use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};

/// A forecast raised from a pending (unconfirmed) mempool transaction (§16):
/// the predictive pipeline's counterpart to `PreliminaryAlertCreated`, minted
/// under block time from the public mempool rather than a confirmed block.
///
/// `provisional` is always `true` on creation, and — unlike the fast path —
/// stays `true` forever: a prediction is never upgraded to a confirmed
/// incident, only superseded by events that actually land.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PredictedAlert {
    pub prediction_id: PredictionId,
    /// The pending transaction that triggered the forecast.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub tx_hash: B256,
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub addresses: Vec<AccountAddress>,
    pub kind: AlertKind,
    pub confidence: Confidence,
    /// Always `true` — a forecast is never sim-confirmed (§16).
    pub provisional: bool,
}

/// A forecast raised by the Sprint 16 task 2 cascade engine: an open lending
/// position's health factor, recomputed at the latest mark prices, has
/// worsened into a riskier band than it was last observed at (§16.1, §16.2).
///
/// Like [`PredictedAlert`], `provisional` is always `true` and stays `true`
/// forever — a liquidation *forecast* is never upgraded to a confirmed
/// incident, only superseded by a real, sim-confirmed liquidation if one
/// actually lands. Only emitted on a *worsening* band crossing (never on
/// recovery back to a safer band) — a risk warning's job is to warn, not to
/// announce an all-clear.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LiquidationRiskPredicted {
    pub prediction_id: PredictionId,
    pub protocol: LendingProtocol,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub account: AccountAddress,
    /// Collateral (weighted by the position's liquidation threshold) over
    /// debt, at current mark prices — below `1.0` is liquidatable.
    pub health_factor: f64,
    /// Signed percentage-point distance from the liquidation boundary
    /// (`(health_factor - 1.0) * 100.0`); negative means already
    /// liquidatable.
    pub distance_pct: f64,
    /// The risk band `distance_pct` crossed into — `Medium`/`High`/`Critical`
    /// only; a `Low`-banded position never emits this event.
    pub severity: Severity,
    /// This is a measured balance/price computation, not a heuristic guess
    /// (unlike [`PredictedAlert::confidence`]'s label-derived confidence) —
    /// always [`Confidence::CERTAIN`]. The genuine uncertainty is whether the
    /// market moves further, which `distance_pct`/`severity` already express.
    pub confidence: Confidence,
    /// Always `true` — a forecast is never sim-confirmed (§16).
    pub provisional: bool,
}

/// A forecast raised by the Sprint 16 task 3 reflexivity walk: liquidating the
/// currently at-risk positions would itself move `trigger_asset`'s mark price
/// far enough (forced collateral sales) to pull *more* positions underwater —
/// a degree-bounded walk over the position graph, the same hub-node discipline
/// §8.2 applies to the entity graph (`intelligence::graph`), applied here to an
/// asset shared by too many open positions to model its price impact rather
/// than an address with too many neighbors.
///
/// Only emitted when the walk actually finds reflexive growth — a plain
/// at-risk position with no knock-on effect is already covered by
/// [`LiquidationRiskPredicted`] and doesn't warrant a cascade warning. Like
/// that event, `provisional` is always `true` and stays `true` forever, and
/// `confidence` is always [`Confidence::CERTAIN`] — this is a measured walk
/// over tracked positions and current prices, not a heuristic guess.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LiquidationCascadeWarned {
    pub prediction_id: PredictionId,
    /// The asset whose oracle mark-price tick started the walk — the asset
    /// named in the warning ("cascade triggers at ETH < $2,180").
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub trigger_asset: Address,
    /// `trigger_asset`'s USD price at the tick that started the walk.
    pub trigger_price: f64,
    /// How many hops the reflexive walk reached before the frontier stopped
    /// growing — bounded by the engine's configured max depth (§8.2-style
    /// hop bound).
    pub reflexive_depth: u32,
    /// Every account swept into the at-risk set, seed positions and every
    /// position the walk reflexively pulled in, across every protocol and
    /// deduplicated.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub accounts: Vec<AccountAddress>,
    /// Total collateral-side USD across the whole at-risk set, at real
    /// (not hypothetically shocked) prices — the headline cascade size
    /// ("a $40M cascade").
    pub aggregate_at_risk_usd: UsdAmount,
    /// The walk reached a degree-capped hub asset (held as collateral by more
    /// open positions than the configured cap) and stopped propagating a
    /// price shock through it (§8.2) — `reflexive_depth`/
    /// `aggregate_at_risk_usd` are a bounded estimate, not necessarily the
    /// full cascade.
    pub hub_capped: bool,
    pub confidence: Confidence,
    /// Always `true` — a forecast is never sim-confirmed (§16).
    pub provisional: bool,
}
