//! Intelligence events — the moat (§8). Labels, entity clustering, attribution,
//! risk scores and sanctions. Attribution is a *mutable overlay* on top of the
//! immutable incident facts: conflicting labels are stored, never overwritten
//! (§8.1).

use crate::primitives::{AccountAddress, Confidence, EntityId, IncidentId, LabelId};
use serde::{Deserialize, Serialize};

/// A label was attached to an address (§8.1). Carries provenance (`source`) and
/// `confidence`; conflicting labels coexist rather than overwrite.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LabelAdded {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub address: AccountAddress,
    pub kind: String,
    pub value: String,
    pub confidence: Confidence,
    pub source: String,
}

/// A label's value changed (e.g. re-scored from a refreshed source) (§8.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LabelUpdated {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub address: AccountAddress,
    pub label_id: LabelId,
    pub old_value: String,
    pub new_value: String,
    pub source: String,
}

/// A label was withdrawn (§8.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LabelRevoked {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub address: AccountAddress,
    pub label_id: LabelId,
    pub reason: String,
}

/// A new entity (wallet cluster) was seeded (§8.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EntityCreated {
    pub entity_id: EntityId,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub seed_address: AccountAddress,
}

/// Two entities were merged into one. `evidence_ref` points at the clustering
/// signal that justified the merge — auditable, reversible on reorg (§8.2, §15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EntityMerged {
    pub surviving_id: EntityId,
    pub absorbed_id: EntityId,
    pub evidence_ref: String,
}

/// An entity was split back apart (§8.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EntitySplit {
    pub original_id: EntityId,
    pub new_ids: Vec<EntityId>,
    pub reason: String,
}

/// An incident was attributed to one or more entities (§8). Runs on
/// `IncidentCreated`; this is the overlay, decoupled from the incident fact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AttributionUpdated {
    pub incident_id: IncidentId,
    pub entity_ids: Vec<EntityId>,
    pub labels: Vec<String>,
}

/// An incident's attribution to one or more entities was withdrawn — the
/// reverse of [`AttributionUpdated`], emitted when `IncidentRetracted` (§7,
/// §15) undoes entity linkage on reorg. `entity_ids` names every entity that
/// lost this incident's attribution, so downstream risk-score recompute
/// (§8.3) can react the same way it reacts to `AttributionUpdated` — the
/// factors this incident contributed are gone, not just added-to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AttributionRetracted {
    pub incident_id: IncidentId,
    pub entity_ids: Vec<EntityId>,
}

/// A single factor contributing to a risk score, with the evidence that backs
/// it. The aggregate score is only as auditable as its factors (§8.3, §23).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RiskFactor {
    pub name: String,
    /// Signed contribution to the score for this factor.
    pub delta: f64,
    /// Pointer to the evidence (incident id, label id, …) behind this factor.
    pub evidence_ref: String,
}

/// A recomputed risk score (§8.3). Score (0–100, "how risky") and `confidence`
/// (0–1, "how sure") are independent axes computed in the same pass (§23).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RiskScoreUpdated {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub address: AccountAddress,
    pub entity_id: Option<EntityId>,
    /// 0–100.
    pub score: u8,
    pub confidence: Confidence,
    pub factors: Vec<RiskFactor>,
    pub model_version: String,
}

/// An address matched a sanctions list — a hard alert that bypasses the slow
/// path (§8.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SanctionHit {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub address: AccountAddress,
    pub list: String,
    pub entry: String,
}
