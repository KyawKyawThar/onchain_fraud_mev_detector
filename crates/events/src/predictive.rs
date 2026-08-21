//! Predictive events — the mempool-prediction pipeline's own family (§16),
//! separate from detection's fast path and simulation's slow path.
//!
//! Predictive events are **forecasts, not facts**: they carry `provisional:
//! true` like a fast-path alert, but unlike `PreliminaryAlertCreated` they are
//! never sim-confirmed — the event they forecast may simply not happen. That
//! is the point of a warning, not a defect in it (§16).

use crate::primitives::{
    AccountAddress, AlertKind, Confidence, LendingProtocol, PredictionId, Severity,
};
use alloy_primitives::B256;
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
