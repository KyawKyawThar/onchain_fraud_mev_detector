//! Cross-chain events (cross-chain correlator, §24) — the omnichain
//! differentiator's own family: findings that only exist in the correlation
//! between two or more chains' legs, never visible to a single-chain
//! detector.
//!
//! [`BridgeMevDetected`]/[`CrossChainMevDetected`] are minted by the
//! correlator's windowed join (Sprint 17 task 2) directly off fast-path facts
//! (`DetectorTriggered`, §6), the same "provisional, not simulation-confirmed"
//! honesty [`crate::predictive`]'s forecasts carry: `profit`/`victim_loss` are
//! coarse proxies derived from whatever `impact_usd` the matched legs'
//! detectors priced, not a revm-measured figure, and `provisional` stays
//! `true` forever rather than being flipped by a later confirm step.
//!
//! [`CrossChainFindingRetracted`] is the reorg-side counterpart (Sprint 17
//! task 3, §15): a `finding_id` names exactly which finding a `BlockReverted`
//! on any of its legs' chains withdraws — see its own docs.

use crate::primitives::{
    AccountAddress, AlertKind, BlockRef, Chain, Confidence, CrossChainFindingId, Severity,
};
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

/// `#[serde(default)]` helper for a field that reads `true` on any
/// pre-Sprint-17-task-3 event lacking it — see `provisional`'s docs on
/// [`BridgeMevDetected`]/[`CrossChainMevDetected`] for why `true`, not
/// `bool::default()`'s `false`, is the honest backfill.
fn default_true() -> bool {
    true
}

/// One chain's contribution to a correlated cross-chain finding: which chain,
/// which block, which transaction. Carried per leg (rather than flattening to
/// a single `chain`/`block`) so a `BlockReverted` on *any* leg's chain can
/// retract the whole finding via the existing §15 machinery — a cross-chain
/// finding is only as final as its least-final leg (§24, Sprint 17 task 3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CrossChainLegRef {
    pub chain: Chain,
    pub block: BlockRef,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub tx: B256,
}

/// Value extracted on the settlement of a cross-chain transfer: a bridge
/// deposit on the source chain and the front-run/back-run of its fill on the
/// destination chain, correlated by a shared on-chain funder/recipient
/// (§6, §24).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BridgeMevDetected {
    /// Minted by the windowed join that completed this finding (Sprint 17
    /// task 2) so a later `BlockReverted` on either leg's chain can name and
    /// retract exactly this finding via [`CrossChainFindingRetracted`] (§15,
    /// Sprint 17 task 3) — the finding is only as final as its least-final
    /// leg (§24).
    pub finding_id: CrossChainFindingId,
    /// The bridge/pair identity the two legs were correlated under
    /// (operator/config concern — see
    /// `cross_chain_correlator::leg::BridgeOrPair`'s docs — so this crate
    /// carries it as an opaque string rather than a wire enum).
    pub bridge: String,
    pub deposit_leg: CrossChainLegRef,
    pub fill_leg: CrossChainLegRef,
    /// The behaviour-derived join key (§6, §24): a shared funder /
    /// profit-receiver / bridge-recipient observed on-chain — a *fact*,
    /// never an intelligence label. Attribution stays in §8.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub entity_hint: AccountAddress,
    /// Coarse, fast-path proxy for value captured on the fill leg — the sum
    /// of whatever `impact_usd` the matched detectors priced, never a
    /// simulation-confirmed figure.
    pub profit: f64,
    /// Coarse, fast-path proxy for value that moved on the deposit leg.
    pub victim_loss: f64,
    /// The weaker of the two legs' detector confidences (§6).
    pub confidence: Confidence,
    /// Banded from `profit`/`victim_loss` discounted by `confidence` via the
    /// shared [`crate::scoring::severity_band`] policy — the same banding
    /// rule the fast/slow detection paths use.
    pub severity: Severity,
    /// Always `true` on creation (production-readiness Bucket 1: "customers
    /// must distinguish unconfirmed from confirmed from day one"). Unlike a
    /// fast-path alert there is no simulation step that later flips this to
    /// `false` — a cross-chain finding is never sim-confirmed — so `true`
    /// here means "not yet past every leg's finality depth," and it is
    /// retracted outright (via [`CrossChainFindingRetracted`]), not
    /// downgraded, if reorged before that (§15, §24). `#[serde(default)]`
    /// (reading `true`) so a pre-task-3 stored event still deserializes —
    /// see [`default_true`].
    #[serde(default = "default_true")]
    pub provisional: bool,
}

/// The same asset priced differently across chains, closed by a bridge
/// round-trip: two or more legs that each look like an ordinary swap on
/// their own chain, correlated by a shared on-chain key into one finding no
/// single-chain arbitrage detector would flag (§24).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CrossChainMevDetected {
    /// See [`BridgeMevDetected::finding_id`] — the retraction key (§15,
    /// Sprint 17 task 3).
    pub finding_id: CrossChainFindingId,
    /// Always [`AlertKind::Arbitrage`] today — the only §2 behaviour kind a
    /// multi-leg cross-chain cycle maps to. Kept as the shared enum (not a
    /// new one) so a consumer routing on `kind` already knows this vocabulary
    /// (§6).
    pub kind: AlertKind,
    pub bridge: String,
    /// Every correlated leg, in ascending `observed_at` order — two or more,
    /// spanning at least two distinct chains by construction of the join.
    pub legs: Vec<CrossChainLegRef>,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub entity_hint: AccountAddress,
    /// Coarse, fast-path proxy: the sum of whatever `impact_usd` the matched
    /// legs' detectors priced.
    pub profit: f64,
    /// Wall-clock milliseconds between the first and last matched leg's
    /// `observed_at` (§24: the join is windowed on observation time, not
    /// block numbers, since chains finalize at different rates) — a real,
    /// measured figure, not an estimate.
    pub latency_ms: u64,
    /// The weakest of the matched legs' detector confidences (§6).
    pub confidence: Confidence,
    /// Banded from `profit` discounted by `confidence` via the shared
    /// [`crate::scoring::severity_band`] policy.
    pub severity: Severity,
    /// See [`BridgeMevDetected::provisional`] — always `true` on creation,
    /// never flipped, retracted outright on a least-final-leg reorg instead.
    #[serde(default = "default_true")]
    pub provisional: bool,
}

/// A correlated cross-chain finding was withdrawn because a `BlockReverted`
/// orphaned one of its legs' blocks (§15, Sprint 17 task 3) — the
/// cross-chain analogue of [`crate::simulation::IncidentRetracted`], applied
/// to a [`BridgeMevDetected`]/[`CrossChainMevDetected`] instead of a
/// simulation-confirmed incident. A finding is only as final as its
/// least-final leg (§24): the correlator retracts it the moment *any* leg's
/// block reverts, without waiting to see whether the other legs also
/// survive — a partial finding (missing the leg that anchored it) is no
/// longer the fact that was reported.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CrossChainFindingRetracted {
    pub finding_id: CrossChainFindingId,
    /// Human-readable audit reason naming the reverted leg (chain/block/its
    /// replacement) — mirrors
    /// `simulation::reorg::retraction_reason`'s explainability.
    pub reason: String,
}
