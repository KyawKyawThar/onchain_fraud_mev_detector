//! The canonical value of every [`DomainEvent`](crate::DomainEvent) variant.
//!
//! One representative, fully-populated sample per variant, plus the fixed
//! envelope metadata they are wrapped in. Three things are computed from these
//! same values, which is why they live here rather than in any one of them: the
//! byte-level wire-format goldens (`tests/wire_format.rs`), the committed schema
//! registry ([`super::generate`]), and the archived corpus every later version
//! must still decode. Two descriptions of "a sample event" would be free to
//! drift; there is one.
//!
//! Available to other crates behind the `schema` feature — a service's own tests
//! should build events from here rather than hand-rolling a fourth version of
//! the same value.
//!
//! ## Two invariants the registry depends on (and asserts)
//!
//! - **Nothing is `None`, nothing is empty.** A field serialized as `null` or an
//!   empty array reveals no shape, so the compatibility gate could not tell a
//!   retype from a no-op. Every optional field is `Some` and every collection
//!   has at least one element.
//! - **Every value is fixed.** No `now()`, no randomness — the serialized bytes
//!   must be reproducible across runs and machines.

use crate::chain::{
    BlockAssembled, BlockCanonicalized, BlockFinalized, BlockReverted, RawBlockReceived,
};
use crate::copilot::{IncidentNarrativeDrafted, NarrativeSource, RuleDraftProposed};
use crate::cross_chain::{
    BridgeMevDetected, CrossChainFindingRetracted, CrossChainLegRef, CrossChainMevDetected,
};
use crate::detection::{DetectorTriggered, PreliminaryAlertCreated};
use crate::intelligence::{
    AddressEmbeddingUpdated, AttributionRetracted, AttributionUpdated, BehaviorFactor,
    EntityCreated, EntityLinkProposed, EntityMerged, EntitySplit, LabelAdded, LabelRevoked,
    LabelUpdated, LinkFactor, RiskFactor, RiskScoreUpdated, SanctionHit,
};
use crate::predictive::{LiquidationCascadeWarned, LiquidationRiskPredicted, PredictedAlert};
use crate::primitives::{
    AccountAddress, AlertId, AlertKind, BlockRef, Chain, Confidence, CrossChainFindingId,
    CustomerId, DetectorRef, EntityId, IncidentId, LabelId, LendingProtocol, LinkCandidateId,
    PredictionId, RuleId, Severity, SuggestedAction, UsdAmount,
};
use crate::rule_engine::{RuleAlertCreated, RuleCreated, RuleTriggered};
use crate::simulation::{
    IncidentCreated, IncidentFinalized, IncidentRetracted, SimulationCompleted,
    SimulationRequested, WalletExposureReportReady,
};
use crate::system::{
    DriftedFeature, ModelDriftDetected, RetentionPolicyChanged, RetentionPurgeCompleted,
    ScreeningDecision, ScreeningDecisionBasis, ScreeningDecisionRecorded, UsageRecorded,
};
use crate::{DomainEvent, EventEnvelope};
use alloy_primitives::{Address, B256};
use chrono::{DateTime, Utc};
use serde_json::json;
// ── Deterministic fixtures ───────────────────────────────────────
// Every value below is fixed so the serialized bytes are stable across runs.
// Don't reach for randomness or `now()` here — a golden test must be
// reproducible.

pub fn block() -> BlockRef {
    BlockRef::new(19_800_000, B256::repeat_byte(0x11))
}

pub fn tx() -> B256 {
    B256::repeat_byte(0x22)
}

pub fn addr() -> AccountAddress {
    Address::repeat_byte(0x33)
}

pub fn detector() -> DetectorRef {
    DetectorRef {
        id: "sandwich".into(),
        version: "1.2".into(),
        config_hash: "cfg-abc".into(),
    }
}

pub fn ts() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap()
}

pub fn alert_id() -> AlertId {
    AlertId(uuid::Uuid::from_u128(0xA1))
}

pub fn incident_id() -> IncidentId {
    IncidentId(uuid::Uuid::from_u128(0x1C))
}

pub fn entity_id() -> EntityId {
    EntityId(uuid::Uuid::from_u128(0xE1))
}

/// A *second*, distinct entity — the clustering proposal names two sides, so
/// reusing `entity_id()` for both would hide a swapped-field regression.
pub fn subject_entity_id() -> EntityId {
    EntityId(uuid::Uuid::from_u128(0xE2))
}

pub fn label_id() -> LabelId {
    LabelId(uuid::Uuid::from_u128(0x1B))
}

pub fn rule_id() -> RuleId {
    RuleId(uuid::Uuid::from_u128(0x4E))
}

pub fn customer_id() -> CustomerId {
    CustomerId(uuid::Uuid::from_u128(0xC0))
}

pub fn prediction_id() -> PredictionId {
    PredictionId(uuid::Uuid::from_u128(0xF1))
}

pub fn finding_id() -> CrossChainFindingId {
    CrossChainFindingId(uuid::Uuid::from_u128(0xFD))
}

pub fn link_candidate_id() -> LinkCandidateId {
    LinkCandidateId(uuid::Uuid::from_u128(0x11C))
}
/// One representative value for every [`DomainEvent`] variant. The exhaustiveness
/// test proves this covers all of them.
pub fn sample_events() -> Vec<DomainEvent> {
    vec![
        // Chain (§5)
        DomainEvent::RawBlockReceived(RawBlockReceived {
            block: block(),
            timestamp: 1_700_000_000,
        }),
        DomainEvent::BlockAssembled(BlockAssembled {
            block: block(),
            tx_count: 142,
            trace_available: true,
        }),
        DomainEvent::BlockCanonicalized(BlockCanonicalized { block: block() }),
        DomainEvent::BlockReverted(BlockReverted {
            block: block(),
            replaced_by: B256::repeat_byte(0x44),
        }),
        DomainEvent::BlockFinalized(BlockFinalized { block: block() }),
        // Detection (§6)
        DomainEvent::DetectorTriggered(DetectorTriggered {
            detector: detector(),
            block: block(),
            txs: vec![tx()],
            raw_confidence: Confidence::new(0.9),
            evidence: json!({ "pool": "0xpool", "profit_wei": "1000" }),
        }),
        DomainEvent::PreliminaryAlertCreated(PreliminaryAlertCreated {
            alert_id: alert_id(),
            detector: detector(),
            addresses: vec![addr()],
            kind: AlertKind::Sandwich,
            confidence: Confidence::new(0.8),
            provisional: true,
            impact_usd: Some(UsdAmount::new(150_000.0)),
            severity: Severity::High,
            suggested_action: SuggestedAction::Escalate,
        }),
        // Simulation (§7)
        DomainEvent::SimulationRequested(SimulationRequested {
            alert_id: alert_id(),
            evidence: json!({ "txs": ["0xaa"] }),
        }),
        DomainEvent::SimulationCompleted(SimulationCompleted {
            alert_id: alert_id(),
            profit: 1234.5,
            victim_loss: 678.9,
            confirmed: true,
        }),
        DomainEvent::IncidentCreated(IncidentCreated {
            incident_id: incident_id(),
            alert_id: alert_id(),
            kind: AlertKind::Sandwich,
            txs: vec![tx()],
            profit: 1234.5,
            victim_loss: 678.9,
            impact_usd: Some(UsdAmount::new(120_000.0)),
            severity: Severity::High,
            suggested_action: SuggestedAction::Escalate,
            victim_address: Some(addr()),
            victim_loss_usd: Some(UsdAmount::new(678.9)),
        }),
        DomainEvent::IncidentRetracted(IncidentRetracted {
            incident_id: incident_id(),
            reason: "block reverted".into(),
        }),
        DomainEvent::IncidentFinalized(IncidentFinalized {
            incident_id: incident_id(),
            block_hash: B256::repeat_byte(0x11),
        }),
        DomainEvent::WalletExposureReportReady(WalletExposureReportReady {
            customer_id: customer_id(),
            address: addr(),
            period_start: ts(),
            period_end: ts(),
            headline: "$250.00 lost across 1 incident this period (worst: $250.00)".into(),
            summary: json!({ "incident_count": 1 }),
        }),
        // Intelligence (§8)
        DomainEvent::LabelAdded(LabelAdded {
            address: addr(),
            kind: "exchange".into(),
            value: "binance".into(),
            confidence: Confidence::new(0.95),
            source: "etherscan".into(),
        }),
        DomainEvent::LabelUpdated(LabelUpdated {
            address: addr(),
            label_id: label_id(),
            old_value: "binance".into(),
            new_value: "binance-14".into(),
            source: "etherscan".into(),
        }),
        DomainEvent::LabelRevoked(LabelRevoked {
            address: addr(),
            label_id: label_id(),
            reason: "source retracted".into(),
        }),
        DomainEvent::EntityCreated(EntityCreated {
            entity_id: entity_id(),
            seed_address: addr(),
        }),
        DomainEvent::EntityMerged(EntityMerged {
            surviving_id: entity_id(),
            absorbed_id: EntityId(uuid::Uuid::from_u128(0xE2)),
            evidence_ref: "common-funder".into(),
        }),
        DomainEvent::EntitySplit(EntitySplit {
            original_id: entity_id(),
            new_ids: vec![
                EntityId(uuid::Uuid::from_u128(0xE3)),
                EntityId(uuid::Uuid::from_u128(0xE4)),
            ],
            reason: "false merge".into(),
        }),
        DomainEvent::AttributionUpdated(AttributionUpdated {
            incident_id: incident_id(),
            entity_ids: vec![entity_id()],
            labels: vec!["mev-bot".into()],
        }),
        DomainEvent::AttributionRetracted(AttributionRetracted {
            incident_id: incident_id(),
            entity_ids: vec![entity_id()],
        }),
        DomainEvent::RiskScoreUpdated(RiskScoreUpdated {
            address: addr(),
            entity_id: Some(entity_id()),
            score: 87,
            confidence: Confidence::new(0.7),
            factors: vec![RiskFactor {
                name: "sandwich-incidents".into(),
                delta: 30.0,
                evidence_ref: "incident:1c".into(),
            }],
            model_version: "risk-v1".into(),
        }),
        DomainEvent::SanctionHit(SanctionHit {
            address: addr(),
            list: "OFAC".into(),
            entry: "SDN-123".into(),
        }),
        DomainEvent::AddressEmbeddingUpdated(AddressEmbeddingUpdated {
            address: addr(),
            entity_id: Some(entity_id()),
            embedding_version: "behavior-v1".into(),
            schema_hash: "a1b2c3".into(),
            // Exactly-representable f32s — a golden must not depend on the
            // shortest-repr float printer's rounding.
            vector: vec![0.5, 0.25, 0.0],
            top_factors: vec![BehaviorFactor {
                feature: "edge_count_log".into(),
                value: 0.5,
                share: 0.75,
            }],
            observations_truncated: false,
        }),
        DomainEvent::EntityLinkProposed(EntityLinkProposed {
            candidate_id: link_candidate_id(),
            subject: addr(),
            subject_entity: Some(subject_entity_id()),
            candidate: Address::repeat_byte(0x55),
            candidate_entity: Some(entity_id()),
            anchor: Address::repeat_byte(0x55),
            anchor_labels: vec!["known_scammer".into()],
            // Exactly-representable f32s — a golden must not depend on the
            // shortest-repr float printer's rounding.
            similarity: 0.9375,
            confidence: Confidence::new(0.4),
            embedding_version: "behavior-v1".into(),
            schema_hash: "a1b2c3".into(),
            factors: vec![LinkFactor {
                feature: "edge_count_log".into(),
                subject_value: 0.5,
                candidate_value: 0.25,
                contribution: 0.125,
            }],
        }),
        // Rule engine (§9)
        DomainEvent::RuleCreated(RuleCreated {
            rule_id: rule_id(),
            owner: customer_id(),
            definition: json!({ "when": "receives > 1M then touches mixer" }),
        }),
        DomainEvent::RuleTriggered(RuleTriggered {
            rule_id: rule_id(),
            address: addr(),
            matched_events: vec!["IncidentCreated".into()],
            context: json!({ "window_s": 3600 }),
        }),
        DomainEvent::RuleAlertCreated(RuleAlertCreated {
            alert_id: alert_id(),
            rule_id: rule_id(),
            owner: customer_id(),
            address: addr(),
            explanation: "large inflow then mixer".into(),
        }),
        // System (§13)
        DomainEvent::UsageRecorded(UsageRecorded {
            customer_id: Some(customer_id()),
            event_type: "api_query".into(),
            quantity: 1,
            timestamp: ts(),
        }),
        DomainEvent::ModelDriftDetected(ModelDriftDetected {
            model_id: "anomaly-iforest".into(),
            detector: detector(),
            feature_version: 1,
            granularity: "block".into(),
            baseline_hash: "9f2c".into(),
            samples: 512,
            window_closed_by: "full".into(),
            threshold: 3.0,
            max_magnitude: 4.5,
            drifted: vec![DriftedFeature {
                feature: "tx_count_log".into(),
                magnitude: 4.5,
                shift: 4.5,
                spread: 1.0,
            }],
            observed_at: ts(),
        }),
        // §18 governance facts. `previous_days: Some(..)` on purpose: the probe
        // reads optionality off the real codec, and a `None` here would record
        // the field as absent rather than as nullable.
        DomainEvent::RetentionPolicyChanged(RetentionPolicyChanged {
            store: "event_store_events".into(),
            previous_days: Some(2192),
            current_days: 2557,
            destructive: false,
            applied_by: "boot".into(),
            applied_at: ts(),
        }),
        DomainEvent::RetentionPurgeCompleted(RetentionPurgeCompleted {
            store: "copilot_drafts".into(),
            cutoff: ts(),
            artifact_days: 1827,
            destroyed: 412,
            held_back: 3,
            truncated: false,
            completed_at: ts(),
        }),
        DomainEvent::ScreeningDecisionRecorded(ScreeningDecisionRecorded {
            customer_id: customer_id(),
            address: addr(),
            decision: ScreeningDecision::Block,
            decision_basis: ScreeningDecisionBasis::SanctionsHardBlock,
            policy_name: "default".into(),
            policy_version: 1,
            score: 87,
            confidence: 0.7,
            sanctioned: true,
            model_version: "risk-v1".into(),
            factors: vec![RiskFactor {
                name: "sanctions-match".into(),
                delta: 45.0,
                evidence_ref: "sanctions:ofac_sdn".into(),
            }],
            timestamp: ts(),
        }),
        // AI copilot (§20.4)
        DomainEvent::IncidentNarrativeDrafted(IncidentNarrativeDrafted {
            incident_id: incident_id(),
            draft_id: uuid::Uuid::from_u128(0xD1),
            narrative_ref: "copilot://drafts/00000000-0000-0000-0000-0000000000d1".into(),
            model_id: "claude-opus-5".into(),
            prompt_id: "incident_narrative".into(),
            prompt_version: "v2".into(),
            prompt_digest: "3f9c".into(),
            grounded_event_ids: vec![uuid::Uuid::from_u128(0xE7)],
            claims: 6,
            cited_claims: 5,
            source: NarrativeSource::Backfill,
            drafted_at: ts(),
        }),
        DomainEvent::RuleDraftProposed(RuleDraftProposed {
            draft_id: uuid::Uuid::from_u128(0xD2),
            owner: customer_id(),
            source_text_hash: "9a1f".into(),
            draft_ref: "copilot://drafts/00000000-0000-0000-0000-0000000000d2".into(),
            definition: json!({
                "name": "Sanctioned proximity inflow",
                "enabled": true,
                "conditions": [{"risk_score": {"gt": 80}}],
                "logic": "all",
                "actions": [{"slack_alert": {"channel": "#compliance"}}],
            }),
            model_id: "claude-opus-5".into(),
            prompt_id: "rule_draft".into(),
            prompt_version: "v1".into(),
            prompt_digest: "7c41".into(),
            proposed_at: ts(),
        }),
        // Predictive (§16)
        DomainEvent::PredictedAlert(PredictedAlert {
            prediction_id: prediction_id(),
            tx_hash: tx(),
            addresses: vec![addr()],
            kind: AlertKind::Sandwich,
            confidence: Confidence::new(0.65),
            provisional: true,
        }),
        DomainEvent::LiquidationRiskPredicted(LiquidationRiskPredicted {
            prediction_id: prediction_id(),
            protocol: LendingProtocol::Aave,
            account: addr(),
            health_factor: 0.97,
            distance_pct: -3.0,
            severity: Severity::High,
            confidence: Confidence::CERTAIN,
            provisional: true,
        }),
        DomainEvent::LiquidationCascadeWarned(LiquidationCascadeWarned {
            prediction_id: prediction_id(),
            trigger_asset: Address::repeat_byte(0x44),
            trigger_price: 1_500.0,
            reflexive_depth: 2,
            accounts: vec![addr()],
            aggregate_at_risk_usd: UsdAmount::new(40_000_000.0),
            hub_capped: false,
            confidence: Confidence::CERTAIN,
            provisional: true,
        }),
        // Cross-chain (§24)
        DomainEvent::BridgeMevDetected(BridgeMevDetected {
            finding_id: finding_id(),
            bridge: "usdc-eth-base".into(),
            deposit_leg: CrossChainLegRef {
                chain: Chain::ETHEREUM,
                block: block(),
                tx: tx(),
            },
            fill_leg: CrossChainLegRef {
                chain: Chain::BASE,
                block: BlockRef::new(8_453_000, B256::repeat_byte(0x66)),
                tx: B256::repeat_byte(0x77),
            },
            entity_hint: addr(),
            profit: 5_000.0,
            victim_loss: 4_800.0,
            confidence: Confidence::new(0.8),
            severity: Severity::High,
            provisional: true,
        }),
        DomainEvent::CrossChainMevDetected(CrossChainMevDetected {
            finding_id: finding_id(),
            kind: AlertKind::Arbitrage,
            bridge: "usdc-eth-base".into(),
            legs: vec![
                CrossChainLegRef {
                    chain: Chain::ETHEREUM,
                    block: block(),
                    tx: tx(),
                },
                CrossChainLegRef {
                    chain: Chain::BASE,
                    block: BlockRef::new(8_453_000, B256::repeat_byte(0x66)),
                    tx: B256::repeat_byte(0x77),
                },
            ],
            entity_hint: addr(),
            profit: 12_000.0,
            latency_ms: 4_500,
            confidence: Confidence::new(0.75),
            severity: Severity::Medium,
            provisional: true,
        }),
        DomainEvent::CrossChainFindingRetracted(CrossChainFindingRetracted {
            finding_id: finding_id(),
            reason: "block 19800000 (0x1111…) reverted by reorg, replaced by 0x4444…".into(),
        }),
    ]
}

/// Fixed-metadata envelope around a simple payload. Like the samples above, all
/// inputs are constant so the bytes are reproducible.
pub fn sample_envelope() -> EventEnvelope {
    envelope_for(DomainEvent::BlockFinalized(BlockFinalized {
        block: block(),
    }))
}

/// The fixed envelope metadata every sample is wrapped in. One definition, so an
/// archived sample's bytes differ from another's only where the payloads do.
pub fn envelope_for(payload: DomainEvent) -> EventEnvelope {
    EventEnvelope::with_metadata(uuid::Uuid::from_u128(0xE2E), ts(), Chain::ETHEREUM, payload)
}
