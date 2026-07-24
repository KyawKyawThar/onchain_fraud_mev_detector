//! Detection events — fast path (§6). Heuristic detectors emit provisional
//! alerts in < 1s. Attribution-blind: these name behaviour, never actors.

use crate::primitives::{
    AccountAddress, AlertId, AlertKind, BlockRef, Confidence, DetectorRef, Severity,
    SuggestedAction, UsdAmount,
};
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
    /// A coarse USD-scale proxy for the finding's blast radius: the gross value
    /// moved by the implicated txs' priced transfers
    /// (`detection::emit::impact_usd`, §6). **Not** the authoritative harm
    /// figure — it can over-count multi-hop flows, and the real profit /
    /// victim-loss is measured later by simulation (§7). `None` when nothing
    /// could be priced (unknown, *not* zero). `#[serde(default)]` so a
    /// pre-scoring event still reads back (additive-field policy, SCHEMA.md).
    #[serde(default)]
    pub impact_usd: Option<UsdAmount>,
    /// Coarse severity band from `impact_usd` discounted by `confidence`
    /// (`detection::emit::severity_band`, §6). Attribution-blind: a
    /// `Critical` band means "high-harm, well-evidenced," not "involves a
    /// known bad actor" — that reweighting happens later, off this path, in
    /// the intelligence service (§8). Defaulted on read for backwards
    /// compatibility (see [`default_severity`]).
    #[serde(default = "default_severity")]
    pub severity: Severity,
    /// The operator-facing next step `severity` recommends
    /// (`detection::emit::suggested_action`, §6) — a total, deterministic
    /// function of `severity` alone. Defaulted on read for backwards
    /// compatibility (see [`default_suggested_action`]).
    #[serde(default = "default_suggested_action")]
    pub suggested_action: SuggestedAction,
}

/// Serde fallbacks for the §6 scoring fields, applied when a
/// `PreliminaryAlertCreated` written **before** those fields existed is read
/// back. The additive-field contract (SCHEMA.md) keeps old on-disk events
/// replayable without a `SCHEMA_VERSION` bump: rather than fail with a
/// `missing field` error, a legacy event decodes to the exact conservative
/// triple `detection::emit::preliminary_alert` mints for an *unpriced* finding
/// — `impact_usd = None` (via `Option`'s own default) ⇒ [`Severity::Low`] ⇒
/// [`SuggestedAction::Monitor`]. So "we didn't score this" and "this scored
/// low" read identically, which is the honest reading of a pre-scoring event.
fn default_severity() -> Severity {
    Severity::Low
}

fn default_suggested_action() -> SuggestedAction {
    SuggestedAction::Monitor
}
