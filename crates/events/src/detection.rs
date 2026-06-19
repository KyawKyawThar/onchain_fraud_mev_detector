//! Detection events — fast path (§6). Heuristic detectors emit provisional
//! alerts in < 1s. Attribution-blind: these name behaviour, never actors.

use crate::primitives::{AccountAddress, AlertId, AlertKind, BlockRef, Confidence, DetectorRef};
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

/// A detector fired on a block. Carries the exact `(id, version, config_hash)`
/// so the result is reproducible (§6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DetectorTriggered {
    pub detector: DetectorRef,
    pub block: BlockRef,
    /// Transactions implicated in the pattern.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub txs: Vec<B256>,
    pub raw_confidence: Confidence,
    /// Detector-specific evidence. Shape varies per detector, so this is an
    /// opaque JSON document here; each detector defines its own evidence type
    /// and (de)serializes through this field.
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub evidence: serde_json::Value,
}

/// A provisional alert was raised from one or more triggers (§6). `provisional`
/// stays `true` until simulation confirms or finality is reached (§7, §15).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PreliminaryAlertCreated {
    pub alert_id: AlertId,
    pub detector: DetectorRef,
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub addresses: Vec<AccountAddress>,
    pub kind: AlertKind,
    pub confidence: Confidence,
    /// Always `true` on creation — kept explicit because it is the contract the
    /// API/WebSocket lifecycle depends on (§11).
    pub provisional: bool,
}
