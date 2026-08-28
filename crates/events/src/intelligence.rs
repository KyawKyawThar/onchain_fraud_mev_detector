//! Intelligence events — the moat (§8). Labels, entity clustering, attribution,
//! risk scores and sanctions. Attribution is a *mutable overlay* on top of the
//! immutable incident facts: conflicting labels are stored, never overwritten
//! (§8.1).

use crate::primitives::{
    AccountAddress, Confidence, EntityId, IncidentId, LabelId, LinkCandidateId,
};
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

/// One behavioral feature's contribution to an address's embedding (§20.3) —
/// the explainability view over [`AddressEmbeddingUpdated::vector`], the same
/// "an aggregate is only as auditable as its parts" stance as [`RiskFactor`].
///
/// `feature` is the intelligence crate's frozen schema name (its `snake_case`
/// wire string), carried as a plain `String` here for the same reason
/// [`LabelAdded::kind`] is: the closed enum lives in the service that owns the
/// vocabulary, not in the shared schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BehaviorFactor {
    pub feature: String,
    /// The feature's scaled value in the vector.
    pub value: f32,
    /// This feature's share (0–1) of the vector's total squared magnitude —
    /// "how much of this address's behavior is this feature".
    pub share: f32,
}

/// An address's behavior vector was recomputed (§20.3). The intelligence
/// service's embedding job publishes one per address it recomputes, whether
/// off its schedule or off an invalidating input change — the embedding
/// analogue of [`RiskScoreUpdated`], and versioned the same way
/// (`embedding_version` + `schema_hash` are part of the output, so a reweight
/// is a new value under a new key, never a silent change under an old one).
///
/// The full `vector` rides along rather than only a "recomputed" notification:
/// a consumer that only needs to react (the §20.3 clustering signal) then
/// needs no second read, and one that wants history has it in the event store.
/// Its length is fixed by the named schema version, so the payload is bounded
/// by construction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AddressEmbeddingUpdated {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub address: AccountAddress,
    /// The address's resolved entity at compute time, if any.
    pub entity_id: Option<EntityId>,
    /// The schema/model version that produced `vector` (e.g. `behavior-v1`).
    pub embedding_version: String,
    /// Hex SHA-256 of the frozen feature schema behind `embedding_version` —
    /// so an accidental edit under an unchanged version name is detectable
    /// downstream, not just in the producing build.
    pub schema_hash: String,
    /// The scaled feature values, in schema order.
    pub vector: Vec<f32>,
    /// The largest-magnitude features behind `vector`, bounded — the
    /// explainable view (§8.3), not a second copy of the vector.
    pub top_factors: Vec<BehaviorFactor>,
    /// The address's observation history hit the read cap: `vector` describes
    /// its most *recent* activity window rather than all of it (§8.2's
    /// hub-node rule). A fidelity flag, marked rather than assumed (§20.1).
    pub observations_truncated: bool,
}

/// One feature's signed share of the behavioral similarity behind a proposed
/// link (§20.3) — the pair-shaped sibling of [`BehaviorFactor`], which explains
/// *one* address's vector rather than what two of them have in common.
///
/// The contributions of all features sum to
/// [`EntityLinkProposed::similarity`]: cosine over baseline-standardized
/// vectors decomposes exactly, so this is the score's decomposition and not an
/// attribution heuristic beside it. A negative contribution means the two
/// addresses sit on *opposite* sides of the population median on that feature
/// — carried deliberately, because "alike except on X" is what tells an
/// investigator whether to believe the link.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LinkFactor {
    pub feature: String,
    /// The subject's value in the vector's own raw, interpretable units.
    pub subject_value: f32,
    /// The candidate's raw value.
    pub candidate_value: f32,
    /// This feature's signed share of the similarity score.
    pub contribution: f32,
}

/// A behavioral **candidate link** between two addresses (§20.3, §8.1): the
/// subject behaves like `candidate`, and `anchor` — one of the two — carries a
/// directly-known actor label. The §20.3 clustering signal, published as an
/// event so the flywheel (§8.5) has an auditable record of every link the
/// graph was *offered*, not only the ones it accepted.
///
/// **This is not a merge, and consuming it as one is a bug.** Entity merges
/// (`EntityMerged`) still require the §8.2 on-chain evidence heuristics —
/// common funder, common deployer, same code hash, shared profit receiver.
/// Behavioral similarity widens *recall* (it can see a freshly funded bot with
/// no graph edges at all) at a confidence no clustering decision may be taken
/// on alone, which is exactly how §8.1 treats every heuristic label. The
/// `confidence` here is therefore capped strictly below the entity-derived
/// band and scaled by the similarity that produced it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EntityLinkProposed {
    pub candidate_id: LinkCandidateId,
    /// The address whose recomputed vector triggered the search.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub subject: AccountAddress,
    /// The subject's entity at proposal time, if the graph already placed it.
    pub subject_entity: Option<EntityId>,
    /// The behaviourally similar address.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub candidate: AccountAddress,
    /// The candidate's entity at proposal time, if any. Both entities present
    /// and different is the *merge*-candidate shape; still never an automatic
    /// merge.
    pub candidate_entity: Option<EntityId>,
    /// Which of the two carried the directly-known actor label that made this
    /// pair worth proposing.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub anchor: AccountAddress,
    /// The anchor's label kinds (`known_scammer`, `sanctioned_entity`,
    /// `mev_bot`, …) — wire strings, the same closed vocabulary
    /// [`LabelAdded::kind`] carries.
    pub anchor_labels: Vec<String>,
    /// Cosine similarity between baseline-standardized vectors, in `[-1, 1]`.
    pub similarity: f32,
    /// The §8.1 reduced-confidence band this signal is worth — always below
    /// the entity-derived 0.5, because a behavioral match is weaker evidence
    /// than a graph one.
    pub confidence: Confidence,
    /// The feature space the comparison was made in. Two similarities are only
    /// comparable if both match.
    pub embedding_version: String,
    pub schema_hash: String,
    /// The largest-magnitude contributions behind `similarity`, bounded.
    pub factors: Vec<LinkFactor>,
}
