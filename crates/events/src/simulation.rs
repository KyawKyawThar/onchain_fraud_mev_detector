//! Simulation events — slow path (§7). A revm worker confirms or retracts an
//! alert; only the *result* re-enters the event model (the `SimulationJob`
//! command itself never does — it lives on RabbitMQ, §2/§7).

use crate::primitives::{AlertId, AlertKind, IncidentId, Severity, SuggestedAction, UsdAmount};
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

/// Simulation was requested for a provisional alert. Emitted alongside the
/// RabbitMQ `SimulationJob` command so the request is auditable even though the
/// command is not (§7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SimulationRequested {
    pub alert_id: AlertId,
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub evidence: serde_json::Value,
}

/// A revm run finished. `confirmed` decides whether an incident is created or
/// the alert is dropped (§7). Monetary figures are USD estimates from the
/// counterfactual simulation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SimulationCompleted {
    pub alert_id: AlertId,
    pub profit: f64,
    pub victim_loss: f64,
    pub confirmed: bool,
}

/// A confirmed incident (§7). Re-enters the backbone keyed by `alert_id` so the
/// projection can dedup replays idempotently.
///
/// The scoring triple — `impact_usd`, `severity`, `suggested_action` — is
/// *restamped from the confirmed figures* (`simulation::result`), superseding
/// the provisional estimate the fast path scored onto `PreliminaryAlertCreated`
/// (§6): same shared banding policy ([`crate::scoring`]), but over revm-measured
/// harm at full confidence rather than a coarse pre-trade estimate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IncidentCreated {
    pub incident_id: IncidentId,
    pub alert_id: AlertId,
    pub kind: AlertKind,
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub txs: Vec<B256>,
    pub profit: f64,
    pub victim_loss: f64,
    /// Confirmed USD-scale impact — the headline harm from the simulated
    /// figures (`crate::scoring::severity_band`'s input), superseding the
    /// provisional `PreliminaryAlertCreated::impact_usd`. `None` when the run
    /// couldn't price it (unknown, *not* zero). `#[serde(default)]` so a
    /// pre-restamp incident still reads back (additive-field policy, SCHEMA.md).
    #[serde(default)]
    pub impact_usd: Option<UsdAmount>,
    pub severity: Severity,
    /// The operator-facing next step `severity` recommends
    /// (`crate::scoring::suggested_action`) — a total, deterministic function of
    /// `severity` alone. Defaulted on read for backwards compatibility (see
    /// [`default_suggested_action`]).
    #[serde(default = "default_suggested_action")]
    pub suggested_action: SuggestedAction,
}

/// Serde fallback for [`IncidentCreated::suggested_action`], applied when an
/// incident written **before** the field existed is read back. Mirrors the
/// detection path (`events::detection`): a pre-restamp incident decodes to the
/// conservative [`SuggestedAction::Monitor`] rather than failing with a
/// `missing field` error, keeping old on-disk events replayable without a
/// `SCHEMA_VERSION` bump (SCHEMA.md's additive-field policy).
fn default_suggested_action() -> SuggestedAction {
    SuggestedAction::Monitor
}

/// An incident was withdrawn — e.g. the underlying block was reverted (§7,
/// §15), or a later run contradicted it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IncidentRetracted {
    pub incident_id: IncidentId,
    pub reason: String,
}

/// The incident's block reached finality and can no longer be reorged (§15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IncidentFinalized {
    pub incident_id: IncidentId,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub block_hash: B256,
}
