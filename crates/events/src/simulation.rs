//! Simulation events — slow path (§7). A revm worker confirms or retracts an
//! alert; only the *result* re-enters the event model (the `SimulationJob`
//! command itself never does — it lives on RabbitMQ, §2/§7).

use crate::primitives::{AlertId, AlertKind, IncidentId, Severity};
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

/// Simulation was requested for a provisional alert. Emitted alongside the
/// RabbitMQ `SimulationJob` command so the request is auditable even though the
/// command is not (§7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimulationRequested {
    pub alert_id: AlertId,
    pub evidence: serde_json::Value,
}

/// A revm run finished. `confirmed` decides whether an incident is created or
/// the alert is dropped (§7). Monetary figures are USD estimates from the
/// counterfactual simulation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimulationCompleted {
    pub alert_id: AlertId,
    pub profit: f64,
    pub victim_loss: f64,
    pub confirmed: bool,
}

/// A confirmed incident (§7). Re-enters the backbone keyed by `alert_id` so the
/// projection can dedup replays idempotently.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentCreated {
    pub incident_id: IncidentId,
    pub alert_id: AlertId,
    pub kind: AlertKind,
    pub txs: Vec<B256>,
    pub profit: f64,
    pub victim_loss: f64,
    pub severity: Severity,
}

/// An incident was withdrawn — e.g. the underlying block was reverted (§7,
/// §15), or a later run contradicted it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentRetracted {
    pub incident_id: IncidentId,
    pub reason: String,
}

/// The incident's block reached finality and can no longer be reorged (§15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentFinalized {
    pub incident_id: IncidentId,
    pub block_hash: B256,
}
