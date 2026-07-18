//! Predictive events — the mempool-prediction pipeline's own family (§16),
//! separate from detection's fast path and simulation's slow path.
//!
//! Predictive events are **forecasts, not facts**: they carry `provisional:
//! true` like a fast-path alert, but unlike `PreliminaryAlertCreated` they are
//! never sim-confirmed — the event they forecast may simply not happen. That
//! is the point of a warning, not a defect in it (§16).

use crate::primitives::{AccountAddress, AlertKind, Confidence, PredictionId};
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
