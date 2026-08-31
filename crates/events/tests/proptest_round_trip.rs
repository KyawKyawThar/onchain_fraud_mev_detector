//! Codec-totality round trip for the domain event schema (§2, §18).
//!
//! [`tests/wire_format.rs`] pins each variant to one *hand-picked* byte-exact
//! shape — it proves the contract is what we think it is. This file proves the
//! complementary thing: that the codec is **total** — `deserialize(serialize(x))
//! == x` over the *whole* `DomainEvent` value space, not just the goldens. A
//! `proptest` strategy generates arbitrary envelopes (every variant, arbitrary
//! ids/hashes/strings/amounts/opaque-JSON payloads) and asserts the JSON encode
//! → decode round trip is the identity, shrinking any failure to a minimal
//! counterexample.
//!
//! This is the schema follow-up carried from Sprint 1 (an `Arbitrary` round trip
//! for `DomainEvent`), deliberately deferred to Sprint 4 task 4 where `proptest`
//! enters the workspace for the detector property tests anyway.
//!
//! # Why these generators stay inside the finite, sub-second, non-NaN box
//!
//! Equality here is the derived `PartialEq`, which compares the `f64` payload
//! fields (profit, victim_loss, RiskFactor::delta, Confidence) for *exact*
//! equality. JSON round-trips a finite `f64` exactly, but `NaN`/`±inf` serialize
//! to `null` and would never compare equal — so every float strategy is filtered
//! to finite. Likewise `DateTime<Utc>` is generated on whole seconds so its
//! RFC3339 form round-trips without sub-nanosecond drift. These are codec
//! constraints, not schema claims: a real producer's values already live in this
//! box (`UsdPrice`/`Confidence` validate at the edge; timestamps are unix
//! seconds).
//!
//! [`tests/wire_format.rs`]: ./wire_format.rs

use alloy_primitives::{Address, B256};
use chrono::{DateTime, Utc};
use proptest::prelude::*;
use uuid::Uuid;

use events::chain::{
    BlockAssembled, BlockCanonicalized, BlockFinalized, BlockReverted, RawBlockReceived,
};
use events::cross_chain::{
    BridgeMevDetected, CrossChainFindingRetracted, CrossChainLegRef, CrossChainMevDetected,
};
use events::detection::{DetectorTriggered, PreliminaryAlertCreated};
use events::intelligence::{
    AddressEmbeddingUpdated, AttributionUpdated, BehaviorFactor, EntityCreated, EntityLinkProposed,
    EntityMerged, EntitySplit, LabelAdded, LabelRevoked, LabelUpdated, LinkFactor, RiskFactor,
    RiskScoreUpdated, SanctionHit,
};
use events::predictive::{LiquidationCascadeWarned, LiquidationRiskPredicted, PredictedAlert};
use events::primitives::{
    AlertId, AlertKind, BlockRef, Chain, Confidence, CrossChainFindingId, CustomerId, DetectorRef,
    EntityId, IncidentId, LabelId, LendingProtocol, LinkCandidateId, PredictionId, RuleId,
    Severity, SuggestedAction, UsdAmount,
};
use events::rule_engine::{RuleAlertCreated, RuleCreated, RuleTriggered};
use events::simulation::{
    IncidentCreated, IncidentFinalized, IncidentRetracted, SimulationCompleted, SimulationRequested,
};
use events::system::UsageRecorded;
use events::{DomainEvent, EventEnvelope};

// ── Leaf strategies ──────────────────────────────────────────────
// One generator per primitive/value type the payloads are built from.

fn b256() -> impl Strategy<Value = B256> {
    any::<[u8; 32]>().prop_map(B256::from)
}

fn address() -> impl Strategy<Value = Address> {
    any::<[u8; 20]>().prop_map(Address::from)
}

fn uuid() -> impl Strategy<Value = Uuid> {
    any::<u128>().prop_map(Uuid::from_u128)
}

/// One JSON encode→decode of an `f64`. `serde_json`'s shortest-`f64` repr is *not
/// injective*: a handful of values serialize to a string that re-parses to an
/// adjacent `f64` (e.g. `0.44810579735494444` → `0.4481057973549445`), and that
/// quirk isn't even idempotent — one round trip can land on a value that *still*
/// doesn't round-trip. That's a known `serde_json` wart, not a schema defect.
fn round_trip(f: f64) -> f64 {
    let s = serde_json::to_string(&f).expect("a finite f64 serializes");
    serde_json::from_str(&s).expect("serde_json's own f64 output parses")
}

/// A finite `f64` that survives the JSON codec *exactly* — a true round-trip
/// fixed point. This is precisely the value space a JSON producer can emit and a
/// consumer read back identically, which is what the exact-`PartialEq` round trip
/// below asserts the schema preserves. Each candidate is mapped through one round
/// trip (landing most arbitrary floats on a fixed point) and kept only if that
/// result is itself stable — `NaN`/`inf` and the rare unstable residual are
/// rejected, so the reject rate stays negligible. Same spirit as `wire_format.rs`
/// hand-picking exactly-representable sample floats.
fn finite_f64() -> impl Strategy<Value = f64> {
    any::<f64>().prop_filter_map(
        "finite and a JSON round-trip fixed point",
        stable_fixed_point,
    )
}

/// `Some(round_trip(f))` when that value is a stable codec fixed point, else
/// `None`. Shared by [`finite_f64`] and [`confidence`].
fn stable_fixed_point(f: f64) -> Option<f64> {
    if !f.is_finite() {
        return None;
    }
    let r = round_trip(f);
    (round_trip(r) == r).then_some(r)
}

/// `Some(f)` when `f` is a stable JSON codec fixed point at `f32` width — the
/// [`stable_fixed_point`] argument, one precision down. `AddressEmbeddingUpdated`
/// carries `f32`s (an embedding is stored as `Array(Float32)`), and
/// `serde_json`'s shortest-repr printer has the same non-injectivity there.
fn stable_fixed_point_f32(f: f32) -> Option<f32> {
    if !f.is_finite() {
        return None;
    }
    let round_trip = |f: f32| -> f32 {
        let s = serde_json::to_string(&f).expect("a finite f32 serializes");
        serde_json::from_str(&s).expect("serde_json's own f32 output parses")
    };
    let r = round_trip(f);
    (round_trip(r) == r).then_some(r)
}

/// A finite `f32` that survives the JSON codec exactly — see [`finite_f64`].
fn finite_f32() -> impl Strategy<Value = f32> {
    any::<f32>().prop_filter_map(
        "finite and a JSON round-trip fixed point",
        stable_fixed_point_f32,
    )
}

/// A non-negative `UsdAmount`, restricted to codec-stable floats for the same
/// reason as [`finite_f64`]; `new` is a no-op sanitize here since the input is
/// already finite and `>= 0.0`.
fn usd_amount() -> impl Strategy<Value = UsdAmount> {
    (0.0f64..1e12).prop_filter_map("JSON round-trip fixed point", |f| {
        stable_fixed_point(f).map(UsdAmount::new)
    })
}

/// A `Confidence` over its whole valid range, restricted to codec-stable floats
/// for the same reason as [`finite_f64`]; `new` is a no-op clamp here since the
/// input is already in `[0.0, 1.0]`.
fn confidence() -> impl Strategy<Value = Confidence> {
    (0.0f64..=1.0).prop_filter_map("JSON round-trip fixed point", |f| {
        stable_fixed_point(f).map(Confidence::new)
    })
}

/// Whole-second timestamps in a wide but valid range (epoch‥≈2096); chrono's
/// RFC3339 form round-trips these exactly.
fn timestamp() -> impl Strategy<Value = DateTime<Utc>> {
    (0i64..=4_000_000_000i64)
        .prop_map(|secs| DateTime::<Utc>::from_timestamp(secs, 0).expect("in-range unix seconds"))
}

fn block_ref() -> impl Strategy<Value = BlockRef> {
    (any::<u64>(), b256()).prop_map(|(number, hash)| BlockRef::new(number, hash))
}

fn detector_ref() -> impl Strategy<Value = DetectorRef> {
    (any::<String>(), any::<String>(), any::<String>()).prop_map(|(id, version, config_hash)| {
        DetectorRef {
            id,
            version,
            config_hash,
        }
    })
}

fn alert_kind() -> impl Strategy<Value = AlertKind> {
    prop_oneof![
        Just(AlertKind::Sandwich),
        Just(AlertKind::Arbitrage),
        Just(AlertKind::Liquidation),
        Just(AlertKind::Flashloan),
        Just(AlertKind::Rugpull),
        Just(AlertKind::WashTrading),
        Just(AlertKind::AddressPoisoning),
    ]
}

fn severity() -> impl Strategy<Value = Severity> {
    prop_oneof![
        Just(Severity::Low),
        Just(Severity::Medium),
        Just(Severity::High),
        Just(Severity::Critical),
    ]
}

fn suggested_action() -> impl Strategy<Value = SuggestedAction> {
    prop_oneof![
        Just(SuggestedAction::Monitor),
        Just(SuggestedAction::Investigate),
        Just(SuggestedAction::Escalate),
        Just(SuggestedAction::EscalateImmediately),
    ]
}

fn alert_id() -> impl Strategy<Value = AlertId> {
    uuid().prop_map(AlertId)
}
fn incident_id() -> impl Strategy<Value = IncidentId> {
    uuid().prop_map(IncidentId)
}
fn entity_id() -> impl Strategy<Value = EntityId> {
    uuid().prop_map(EntityId)
}
fn label_id() -> impl Strategy<Value = LabelId> {
    uuid().prop_map(LabelId)
}
fn link_candidate_id() -> impl Strategy<Value = LinkCandidateId> {
    uuid().prop_map(LinkCandidateId)
}
fn rule_id() -> impl Strategy<Value = RuleId> {
    uuid().prop_map(RuleId)
}
fn customer_id() -> impl Strategy<Value = CustomerId> {
    uuid().prop_map(CustomerId)
}
fn prediction_id() -> impl Strategy<Value = PredictionId> {
    uuid().prop_map(PredictionId)
}
fn finding_id() -> impl Strategy<Value = CrossChainFindingId> {
    uuid().prop_map(CrossChainFindingId)
}

fn lending_protocol() -> impl Strategy<Value = LendingProtocol> {
    prop_oneof![Just(LendingProtocol::Aave), Just(LendingProtocol::Compound),]
}

/// The opaque `serde_json::Value` payloads (`evidence`, rule `definition`,
/// `context`): a bounded recursive document of nulls/bools/ints/finite-floats/
/// strings, plus small arrays and objects. The detector- and rule-specific shapes
/// the schema carries verbatim, so the round trip must hold for arbitrary JSON.
fn json_value() -> impl Strategy<Value = serde_json::Value> {
    use serde_json::Value;
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| Value::Number(n.into())),
        finite_f64().prop_map(|f| Value::Number(
            serde_json::Number::from_f64(f).expect("finite by construction")
        )),
        any::<String>().prop_map(Value::String),
    ];
    leaf.prop_recursive(3, 16, 5, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..5).prop_map(Value::Array),
            prop::collection::hash_map(any::<String>(), inner, 0..5)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

fn risk_factor() -> impl Strategy<Value = RiskFactor> {
    (any::<String>(), finite_f64(), any::<String>()).prop_map(|(name, delta, evidence_ref)| {
        RiskFactor {
            name,
            delta,
            evidence_ref,
        }
    })
}

// ── Per-family event strategies ──────────────────────────────────
// Grouped by domain so each `prop_oneof!` stays a readable size; the top-level
// `domain_event` unions the families.

fn chain_event() -> impl Strategy<Value = DomainEvent> {
    prop_oneof![
        (block_ref(), any::<u64>()).prop_map(|(block, timestamp)| DomainEvent::RawBlockReceived(
            RawBlockReceived { block, timestamp }
        )),
        (block_ref(), any::<u32>(), any::<bool>()).prop_map(
            |(block, tx_count, trace_available)| {
                DomainEvent::BlockAssembled(BlockAssembled {
                    block,
                    tx_count,
                    trace_available,
                })
            }
        ),
        block_ref().prop_map(|block| DomainEvent::BlockCanonicalized(BlockCanonicalized { block })),
        (block_ref(), b256()).prop_map(|(block, replaced_by)| DomainEvent::BlockReverted(
            BlockReverted { block, replaced_by }
        )),
        block_ref().prop_map(|block| DomainEvent::BlockFinalized(BlockFinalized { block })),
    ]
}

fn detection_event() -> impl Strategy<Value = DomainEvent> {
    prop_oneof![
        (
            detector_ref(),
            block_ref(),
            prop::collection::vec(b256(), 0..4),
            confidence(),
            json_value(),
        )
            .prop_map(|(detector, block, txs, raw_confidence, evidence)| {
                DomainEvent::DetectorTriggered(DetectorTriggered {
                    detector,
                    block,
                    txs,
                    raw_confidence,
                    evidence,
                })
            }),
        (
            alert_id(),
            detector_ref(),
            prop::collection::vec(address(), 0..4),
            alert_kind(),
            confidence(),
            any::<bool>(),
            proptest::option::of(usd_amount()),
            severity(),
            suggested_action(),
        )
            .prop_map(
                |(
                    alert_id,
                    detector,
                    addresses,
                    kind,
                    confidence,
                    provisional,
                    impact_usd,
                    severity,
                    suggested_action,
                )| {
                    DomainEvent::PreliminaryAlertCreated(PreliminaryAlertCreated {
                        alert_id,
                        detector,
                        addresses,
                        kind,
                        confidence,
                        provisional,
                        impact_usd,
                        severity,
                        suggested_action,
                    })
                }
            ),
    ]
}

fn simulation_event() -> impl Strategy<Value = DomainEvent> {
    prop_oneof![
        (alert_id(), json_value()).prop_map(|(alert_id, evidence)| {
            DomainEvent::SimulationRequested(SimulationRequested { alert_id, evidence })
        }),
        (alert_id(), finite_f64(), finite_f64(), any::<bool>()).prop_map(
            |(alert_id, profit, victim_loss, confirmed)| {
                DomainEvent::SimulationCompleted(SimulationCompleted {
                    alert_id,
                    profit,
                    victim_loss,
                    confirmed,
                })
            }
        ),
        (
            incident_id(),
            alert_id(),
            alert_kind(),
            prop::collection::vec(b256(), 0..4),
            finite_f64(),
            finite_f64(),
            prop::option::of(usd_amount()),
            severity(),
            suggested_action(),
            prop::option::of(address()),
            prop::option::of(usd_amount()),
        )
            .prop_map(
                |(
                    incident_id,
                    alert_id,
                    kind,
                    txs,
                    profit,
                    victim_loss,
                    impact_usd,
                    severity,
                    suggested_action,
                    victim_address,
                    victim_loss_usd,
                )| {
                    DomainEvent::IncidentCreated(IncidentCreated {
                        incident_id,
                        alert_id,
                        kind,
                        txs,
                        profit,
                        victim_loss,
                        impact_usd,
                        severity,
                        suggested_action,
                        victim_address,
                        victim_loss_usd,
                    })
                }
            ),
        (incident_id(), any::<String>()).prop_map(|(incident_id, reason)| {
            DomainEvent::IncidentRetracted(IncidentRetracted {
                incident_id,
                reason,
            })
        }),
        (incident_id(), b256()).prop_map(|(incident_id, block_hash)| {
            DomainEvent::IncidentFinalized(IncidentFinalized {
                incident_id,
                block_hash,
            })
        }),
    ]
}

fn intelligence_event() -> impl Strategy<Value = DomainEvent> {
    prop_oneof![
        (
            address(),
            any::<String>(),
            any::<String>(),
            confidence(),
            any::<String>(),
        )
            .prop_map(|(address, kind, value, confidence, source)| {
                DomainEvent::LabelAdded(LabelAdded {
                    address,
                    kind,
                    value,
                    confidence,
                    source,
                })
            }),
        (
            address(),
            label_id(),
            any::<String>(),
            any::<String>(),
            any::<String>(),
        )
            .prop_map(|(address, label_id, old_value, new_value, source)| {
                DomainEvent::LabelUpdated(LabelUpdated {
                    address,
                    label_id,
                    old_value,
                    new_value,
                    source,
                })
            }),
        (address(), label_id(), any::<String>()).prop_map(|(address, label_id, reason)| {
            DomainEvent::LabelRevoked(LabelRevoked {
                address,
                label_id,
                reason,
            })
        }),
        (entity_id(), address()).prop_map(|(entity_id, seed_address)| {
            DomainEvent::EntityCreated(EntityCreated {
                entity_id,
                seed_address,
            })
        }),
        (entity_id(), entity_id(), any::<String>()).prop_map(
            |(surviving_id, absorbed_id, evidence_ref)| {
                DomainEvent::EntityMerged(EntityMerged {
                    surviving_id,
                    absorbed_id,
                    evidence_ref,
                })
            }
        ),
        (
            entity_id(),
            prop::collection::vec(entity_id(), 0..4),
            any::<String>(),
        )
            .prop_map(|(original_id, new_ids, reason)| {
                DomainEvent::EntitySplit(EntitySplit {
                    original_id,
                    new_ids,
                    reason,
                })
            }),
        (
            incident_id(),
            prop::collection::vec(entity_id(), 0..4),
            prop::collection::vec(any::<String>(), 0..4),
        )
            .prop_map(|(incident_id, entity_ids, labels)| {
                DomainEvent::AttributionUpdated(AttributionUpdated {
                    incident_id,
                    entity_ids,
                    labels,
                })
            }),
        (
            address(),
            prop::option::of(entity_id()),
            any::<u8>(),
            confidence(),
            prop::collection::vec(risk_factor(), 0..4),
            any::<String>(),
        )
            .prop_map(
                |(address, entity_id, score, confidence, factors, model_version)| {
                    DomainEvent::RiskScoreUpdated(RiskScoreUpdated {
                        address,
                        entity_id,
                        score,
                        confidence,
                        factors,
                        model_version,
                    })
                }
            ),
        (address(), any::<String>(), any::<String>()).prop_map(|(address, list, entry)| {
            DomainEvent::SanctionHit(SanctionHit {
                address,
                list,
                entry,
            })
        }),
        (
            address(),
            prop::option::of(entity_id()),
            any::<String>(),
            any::<String>(),
            prop::collection::vec(finite_f32(), 0..8),
            prop::collection::vec(behavior_factor(), 0..4),
            any::<bool>(),
        )
            .prop_map(
                |(
                    address,
                    entity_id,
                    embedding_version,
                    schema_hash,
                    vector,
                    top_factors,
                    observations_truncated,
                )| {
                    DomainEvent::AddressEmbeddingUpdated(AddressEmbeddingUpdated {
                        address,
                        entity_id,
                        embedding_version,
                        schema_hash,
                        vector,
                        top_factors,
                        observations_truncated,
                    })
                },
            ),
        (
            link_candidate_id(),
            address(),
            prop::option::of(entity_id()),
            address(),
            prop::option::of(entity_id()),
            prop::collection::vec(any::<String>(), 0..3),
            finite_f32(),
            confidence(),
            any::<String>(),
            any::<String>(),
            prop::collection::vec(link_factor(), 0..4),
        )
            .prop_map(
                |(
                    candidate_id,
                    subject,
                    subject_entity,
                    candidate,
                    candidate_entity,
                    anchor_labels,
                    similarity,
                    confidence,
                    embedding_version,
                    schema_hash,
                    factors,
                )| {
                    DomainEvent::EntityLinkProposed(EntityLinkProposed {
                        candidate_id,
                        subject,
                        subject_entity,
                        // The anchor is always one of the pair — the invariant
                        // the store's CHECK constraint enforces, honoured here
                        // so a generated case is a *possible* event.
                        anchor: candidate,
                        candidate,
                        candidate_entity,
                        anchor_labels,
                        similarity,
                        confidence,
                        embedding_version,
                        schema_hash,
                        factors,
                    })
                },
            ),
    ]
}

fn link_factor() -> impl Strategy<Value = LinkFactor> {
    (any::<String>(), finite_f32(), finite_f32(), finite_f32()).prop_map(
        |(feature, subject_value, candidate_value, contribution)| LinkFactor {
            feature,
            subject_value,
            candidate_value,
            contribution,
        },
    )
}

fn behavior_factor() -> impl Strategy<Value = BehaviorFactor> {
    (any::<String>(), finite_f32(), finite_f32()).prop_map(|(feature, value, share)| {
        BehaviorFactor {
            feature,
            value,
            share,
        }
    })
}

fn rule_engine_event() -> impl Strategy<Value = DomainEvent> {
    prop_oneof![
        (rule_id(), customer_id(), json_value()).prop_map(|(rule_id, owner, definition)| {
            DomainEvent::RuleCreated(RuleCreated {
                rule_id,
                owner,
                definition,
            })
        }),
        (
            rule_id(),
            address(),
            prop::collection::vec(any::<String>(), 0..4),
            json_value(),
        )
            .prop_map(|(rule_id, address, matched_events, context)| {
                DomainEvent::RuleTriggered(RuleTriggered {
                    rule_id,
                    address,
                    matched_events,
                    context,
                })
            }),
        (
            rule_id(),
            alert_id(),
            customer_id(),
            address(),
            any::<String>(),
        )
            .prop_map(|(rule_id, alert_id, owner, address, explanation)| {
                DomainEvent::RuleAlertCreated(RuleAlertCreated {
                    alert_id,
                    rule_id,
                    owner,
                    address,
                    explanation,
                })
            }),
    ]
}

fn system_event() -> impl Strategy<Value = DomainEvent> {
    (
        proptest::option::of(customer_id()),
        any::<String>(),
        any::<u64>(),
        timestamp(),
    )
        .prop_map(|(customer_id, event_type, quantity, timestamp)| {
            DomainEvent::UsageRecorded(UsageRecorded {
                customer_id,
                event_type,
                quantity,
                timestamp,
            })
        })
}

/// Predictive (§16): `PredictedAlert`, `LiquidationRiskPredicted`, and
/// `LiquidationCascadeWarned`.
fn predictive_event() -> impl Strategy<Value = DomainEvent> {
    prop_oneof![
        (
            prediction_id(),
            b256(),
            prop::collection::vec(address(), 0..4),
            alert_kind(),
            confidence(),
        )
            .prop_map(|(prediction_id, tx_hash, addresses, kind, confidence)| {
                DomainEvent::PredictedAlert(PredictedAlert {
                    prediction_id,
                    tx_hash,
                    addresses,
                    kind,
                    confidence,
                    provisional: true,
                })
            }),
        (
            prediction_id(),
            lending_protocol(),
            address(),
            finite_f64(),
            finite_f64(),
            severity(),
        )
            .prop_map(
                |(prediction_id, protocol, account, health_factor, distance_pct, severity)| {
                    DomainEvent::LiquidationRiskPredicted(LiquidationRiskPredicted {
                        prediction_id,
                        protocol,
                        account,
                        health_factor,
                        distance_pct,
                        severity,
                        confidence: Confidence::CERTAIN,
                        provisional: true,
                    })
                }
            ),
        (
            prediction_id(),
            address(),
            finite_f64(),
            any::<u32>(),
            prop::collection::vec(address(), 0..4),
            usd_amount(),
            any::<bool>(),
        )
            .prop_map(
                |(
                    prediction_id,
                    trigger_asset,
                    trigger_price,
                    reflexive_depth,
                    accounts,
                    aggregate_at_risk_usd,
                    hub_capped,
                )| {
                    DomainEvent::LiquidationCascadeWarned(LiquidationCascadeWarned {
                        prediction_id,
                        trigger_asset,
                        trigger_price,
                        reflexive_depth,
                        accounts,
                        aggregate_at_risk_usd,
                        hub_capped,
                        confidence: Confidence::CERTAIN,
                        provisional: true,
                    })
                }
            ),
    ]
}

fn cross_chain_leg_ref() -> impl Strategy<Value = CrossChainLegRef> {
    (any::<u64>(), block_ref(), b256()).prop_map(|(chain_id, block, tx)| CrossChainLegRef {
        chain: Chain(chain_id),
        block,
        tx,
    })
}

/// Cross-chain (§24): `BridgeMevDetected`, `CrossChainMevDetected`,
/// `CrossChainFindingRetracted`.
fn cross_chain_event() -> impl Strategy<Value = DomainEvent> {
    prop_oneof![
        (
            finding_id(),
            any::<String>(),
            cross_chain_leg_ref(),
            cross_chain_leg_ref(),
            address(),
            finite_f64(),
            finite_f64(),
            confidence(),
            severity(),
            any::<bool>(),
        )
            .prop_map(
                |(
                    finding_id,
                    bridge,
                    deposit_leg,
                    fill_leg,
                    entity_hint,
                    profit,
                    victim_loss,
                    confidence,
                    severity,
                    provisional,
                )| {
                    DomainEvent::BridgeMevDetected(BridgeMevDetected {
                        finding_id,
                        bridge,
                        deposit_leg,
                        fill_leg,
                        entity_hint,
                        profit,
                        victim_loss,
                        confidence,
                        severity,
                        provisional,
                    })
                }
            ),
        (
            finding_id(),
            alert_kind(),
            any::<String>(),
            prop::collection::vec(cross_chain_leg_ref(), 2..4),
            address(),
            finite_f64(),
            any::<u64>(),
            confidence(),
            severity(),
            any::<bool>(),
        )
            .prop_map(
                |(
                    finding_id,
                    kind,
                    bridge,
                    legs,
                    entity_hint,
                    profit,
                    latency_ms,
                    confidence,
                    severity,
                    provisional,
                )| {
                    DomainEvent::CrossChainMevDetected(CrossChainMevDetected {
                        finding_id,
                        kind,
                        bridge,
                        legs,
                        entity_hint,
                        profit,
                        latency_ms,
                        confidence,
                        severity,
                        provisional,
                    })
                }
            ),
        (finding_id(), any::<String>()).prop_map(|(finding_id, reason)| {
            DomainEvent::CrossChainFindingRetracted(CrossChainFindingRetracted {
                finding_id,
                reason,
            })
        }),
    ]
}

/// AI copilot (§20.4): `IncidentNarrativeDrafted`.
fn copilot_event() -> impl Strategy<Value = DomainEvent> {
    (
        incident_id(),
        uuid(),
        any::<String>(),
        any::<String>(),
        any::<String>(),
        any::<u32>(),
        prop::collection::vec(uuid(), 0..4),
        prop_oneof![
            Just(events::copilot::NarrativeSource::Live),
            Just(events::copilot::NarrativeSource::Backfill),
        ],
        timestamp(),
    )
        .prop_map(
            |(
                incident_id,
                draft_id,
                narrative_ref,
                model_id,
                prompt_id,
                claims,
                grounded_event_ids,
                source,
                drafted_at,
            )| {
                DomainEvent::IncidentNarrativeDrafted(events::copilot::IncidentNarrativeDrafted {
                    incident_id,
                    draft_id,
                    narrative_ref,
                    model_id,
                    prompt_id,
                    prompt_version: "v2".into(),
                    prompt_digest: "3f9c".into(),
                    // Cited claims can never exceed the claims made: the
                    // generator asserts the invariant the parser produces.
                    cited_claims: claims,
                    claims,
                    grounded_event_ids,
                    source,
                    drafted_at,
                })
            },
        )
}

/// AI copilot (§20.4): `RuleDraftProposed`.
///
/// The `definition` is generated as a *shaped* JSON document rather than an
/// arbitrary `Value`: the field is untyped on the wire only because the event
/// crate must stay a leaf, and a round-trip over shapes the rule engine can
/// never emit would be testing `serde_json`, not this schema.
fn rule_draft_event() -> impl Strategy<Value = DomainEvent> {
    (
        uuid(),
        customer_id(),
        any::<String>(),
        any::<String>(),
        any::<u8>(),
        any::<String>(),
        timestamp(),
    )
        .prop_map(
            |(draft_id, owner, source_text_hash, name, threshold, model_id, proposed_at)| {
                DomainEvent::RuleDraftProposed(events::copilot::RuleDraftProposed {
                    draft_id,
                    owner,
                    source_text_hash,
                    draft_ref: format!("copilot://drafts/{draft_id}"),
                    definition: serde_json::json!({
                        "name": name,
                        "enabled": true,
                        "conditions": [{"risk_score": {"gt": threshold}}],
                        "logic": "all",
                        "actions": [{"slack_alert": {"channel": "#alerts"}}],
                    }),
                    model_id,
                    prompt_id: "rule_draft".into(),
                    prompt_version: "v1".into(),
                    prompt_digest: "7c41".into(),
                    proposed_at,
                })
            },
        )
}

/// Every `DomainEvent` variant, uniformly across the nine families.
fn domain_event() -> impl Strategy<Value = DomainEvent> {
    prop_oneof![
        chain_event(),
        detection_event(),
        simulation_event(),
        intelligence_event(),
        rule_engine_event(),
        system_event(),
        predictive_event(),
        copilot_event(),
        rule_draft_event(),
        cross_chain_event(),
    ]
}

/// A full envelope around an arbitrary payload. `with_metadata` stamps the
/// current `SCHEMA_VERSION`, so the decode path's version gate always admits it.
fn envelope() -> impl Strategy<Value = EventEnvelope> {
    (uuid(), timestamp(), any::<u64>(), domain_event()).prop_map(
        |(event_id, occurred_at, chain, payload)| {
            EventEnvelope::with_metadata(event_id, occurred_at, Chain(chain), payload)
        },
    )
}

proptest! {
    /// The codec is total: encoding an arbitrary envelope to JSON bytes and
    /// decoding through the crate's own `from_json_slice` reproduces it exactly.
    #[test]
    fn envelope_round_trips_through_json(env in envelope()) {
        let bytes = env.to_json_vec().expect("serialize");
        let back = EventEnvelope::from_json_slice(&bytes).expect("deserialize");
        prop_assert_eq!(env, back);
    }

    /// The bare payload round-trips too, and its adjacently-tagged `type` always
    /// equals `event_type()` — so a consumer routing on `type` can never disagree
    /// with the strum-derived name for any variant.
    #[test]
    fn payload_round_trips_and_type_tag_matches(ev in domain_event()) {
        let json = serde_json::to_string(&ev).expect("serialize");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse");
        prop_assert_eq!(
            value["type"].as_str().expect("type tag is a string"),
            ev.event_type(),
        );
        let back: DomainEvent = serde_json::from_str(&json).expect("deserialize");
        prop_assert_eq!(ev, back);
    }
}
