//! Risk scoring engine (§8.3, Sprint 8 t1): a pure, replay-deterministic
//! function from an address's labels/attributions/sanctions/entity
//! membership to an explainable risk score. `score` (0–100, "how risky") and
//! `confidence` (0–1, "how sure") are independent axes computed in one pass
//! (§8.3's two-axes rule) — every [`RiskFactor`] carries a signed `delta` and
//! an `evidence_ref` back to the row that produced it, and every score is
//! stamped with [`MODEL_VERSION`] so a later reweight can't silently change
//! an already-computed number under the same cache key. `factors` is bounded
//! to [`MAX_VISIBLE_FACTORS`] regardless of how much evidence an address
//! accumulates — an entity with thousands of attributed incidents surfaces
//! its largest-magnitude factors plus one aggregated "N more" row, never an
//! unbounded event payload (the same discipline as the §8.2 hub-node degree
//! cap).
//!
//! Deliberately has **no store dependency**: the caller assembles
//! [`RiskInputs`] from the Sprint 7 t1 seams
//! ([`LabelStore::labels_for`](crate::store::LabelStore::labels_for),
//! [`AttributionStore::attributions_for_entity`](crate::store::AttributionStore::attributions_for_entity),
//! [`SanctionsStore::sanction_matches`](crate::store::SanctionsStore::sanction_matches),
//! [`EntityStore::entity`](crate::store::EntityStore::entity)) and [`score`]
//! turns them into a [`RiskScoreUpdated`]. Sprint 8 t2 wires that call behind
//! the `(address, model_version)` cache + invalidate-on-input-change and
//! publishes the result; this module is the pure kernel underneath it, so the
//! scoring logic itself is unit-testable with plain structs and no database.

use chrono::{DateTime, Utc};
use events::intelligence::{RiskFactor, RiskScoreUpdated};
use events::primitives::{AccountAddress, Confidence, EntityId};

use crate::model::{
    AttributionRecord, EntityRecord, LabelKind, LabelRecord, LabelSource, SanctionEntry,
};

/// The current model version, stamped onto every score this module computes
/// (§8.3: "versioned — model version is part of output"). Bump on any change
/// to the weight table or half-lives below: a reweight is, by design, a
/// *different* `(address, model_version)` cache key (t2), never a value that
/// silently changes under an old one.
pub const MODEL_VERSION: &str = "risk-v1";

/// Score contribution, in points, per evidence source — the weight table the
/// architecture doc's worked example (§8.3) otherwise leaves as prose. Named
/// consts so a reweight is a one-line, reviewable diff instead of a buried
/// literal.
mod weights {
    /// A hit on any sanctions list (§8.5) — the single largest identity
    /// signal short of the 100 ceiling, so a sanctioned address with a heavy
    /// incident history can still separate from a sanctions-only address with
    /// none.
    pub const SANCTIONED: f64 = 45.0;
    pub const KNOWN_SCAMMER: f64 = 40.0;
    /// A `SanctionedEntity` *label* (distinct provenance from an actual
    /// [`super::SanctionEntry`] row — an operator or feed asserted it without
    /// a matching list entry existing yet).
    pub const SANCTIONED_ENTITY_LABEL: f64 = 45.0;
    pub const SCAMMER_ASSOCIATE: f64 = 15.0;
    pub const MIXER_USER: f64 = 12.0;
    pub const MEV_BOT: f64 = 10.0;
    pub const BUILDER_ADDRESS: f64 = 3.0;
    /// Widely-used legitimate infrastructure — a mild *negative* delta: seeing
    /// it is a (weak) signal the address is a venue, not itself the risky
    /// party. `delta` is signed for exactly this kind of nuance (§8.3).
    pub const CEX_WALLET: f64 = -5.0;
    pub const BRIDGE: f64 = 0.0;
    pub const PROTOCOL: f64 = 0.0;
    pub const DEPLOYER: f64 = 0.0;

    /// Per attributed incident (cf. §8.3's "+35 2 confirmed sandwich
    /// attacks"). This module has no per-incident profit figures to weight
    /// by, so each attributed incident contributes a flat base amount and
    /// volume + time-decay do the rest.
    pub const PER_ATTRIBUTED_INCIDENT: f64 = 8.0;

    /// Entity cluster size, capped: `min(members * PER_MEMBER, CLUSTER_CAP)`.
    pub const PER_CLUSTER_MEMBER: f64 = 2.0;
    pub const CLUSTER_CAP: f64 = 20.0;
}

/// Base point weight for one active label, by [`LabelKind`]. Zero-weight
/// kinds (`Bridge`/`Protocol`/`Deployer`) are purely descriptive and produce
/// no factor at all — see [`label_factors`].
fn label_weight(kind: LabelKind) -> f64 {
    match kind {
        LabelKind::KnownScammer => weights::KNOWN_SCAMMER,
        LabelKind::SanctionedEntity => weights::SANCTIONED_ENTITY_LABEL,
        LabelKind::ScammerAssociate => weights::SCAMMER_ASSOCIATE,
        LabelKind::MixerUser => weights::MIXER_USER,
        LabelKind::MevBot => weights::MEV_BOT,
        LabelKind::BuilderAddress => weights::BUILDER_ADDRESS,
        LabelKind::CexWallet => weights::CEX_WALLET,
        LabelKind::Bridge => weights::BRIDGE,
        LabelKind::Protocol => weights::PROTOCOL,
        LabelKind::Deployer => weights::DEPLOYER,
    }
}

/// Time-decay half-life in days, by evidentiary class (§8.3: "old incidents
/// contribute less"). `None` means no decay: an identity claim (manual
/// curation) doesn't get less true with time the way a stale incident's
/// relevance does.
fn label_half_life_days(source: LabelSource) -> Option<f64> {
    match source {
        LabelSource::Manual => None,
        LabelSource::Heuristic => Some(180.0),
        LabelSource::ExternalFeed => Some(90.0),
        LabelSource::EntityDerived => Some(120.0),
    }
}

/// Half-life for an attributed-incident factor — incidents are the clearest
/// case of "old incidents contribute less" (§8.3), so every attribution
/// decays on the same clock regardless of the entity's attribution
/// confidence (that confidence still feeds the aggregate separately).
const ATTRIBUTION_HALF_LIFE_DAYS: f64 = 180.0;

/// Hard cap on how many individual rows [`score`] surfaces in
/// `RiskScoreUpdated.factors`. Without this, an entity with thousands of
/// attributed incidents (a long-running scam wallet) or thousands of feed
/// labels turns into a thousand-row event — a large Kafka payload, and not
/// actually "explainable" (§8.3) past a screenful. `score`/`confidence` are
/// always computed over the *full*, uncapped factor set first (see [`score`]);
/// capping only trims what gets *surfaced*, on the same "bounded, not
/// unbounded" discipline as the §8.2 hub-node degree cap and this crate's
/// `BoundedFifoMap`.
const MAX_VISIBLE_FACTORS: usize = 10;

/// Exponential decay factor in `(0.0, 1.0]` for an evidence row of `age_days`
/// against `half_life_days`. `None` (no decay) or a non-positive age (a
/// clock skew or "just happened" row) both return full weight `1.0`.
fn decay_factor(
    created_at: DateTime<Utc>,
    as_of: DateTime<Utc>,
    half_life_days: Option<f64>,
) -> f64 {
    let Some(half_life) = half_life_days else {
        return 1.0;
    };
    let age_days = (as_of - created_at).num_seconds() as f64 / 86_400.0;
    if age_days <= 0.0 {
        return 1.0;
    }
    0.5_f64.powf(age_days / half_life)
}

/// Every input the engine needs for one address — already fetched by the
/// caller from the Sprint 7 t1 stores. Bundled so [`score`] takes one
/// argument instead of four, and a caller can't accidentally mix inputs for
/// two different addresses.
#[derive(Debug, Clone, Default)]
pub struct RiskInputs {
    /// Active labels for the address (already `as_of`-filtered by
    /// [`LabelStore::labels_for`](crate::store::LabelStore::labels_for)).
    pub labels: Vec<LabelRecord>,
    /// Incidents attributed to the address's resolved entity.
    pub attributions: Vec<AttributionRecord>,
    /// Sanctions-list matches for the address.
    pub sanctions: Vec<SanctionEntry>,
    /// The address's resolved entity, if any (drives the cluster-size
    /// factor).
    pub entity: Option<EntityRecord>,
}

/// One factor plus the evidentiary weight it contributes to the aggregate
/// `confidence` (§8.3's weighting table) — kept separate from `delta` so a
/// low-confidence factor still shows its full point contribution to `score`
/// while pulling `confidence` down, exactly the nuance the architecture doc
/// calls out.
struct ScoredFactor {
    factor: RiskFactor,
    evidence_confidence: f64,
}

fn sanction_factors(sanctions: &[SanctionEntry]) -> Vec<ScoredFactor> {
    sanctions
        .iter()
        .map(|entry| ScoredFactor {
            factor: RiskFactor {
                name: format!("Sanctions match: {} ({})", entry.entry, entry.list_name),
                delta: weights::SANCTIONED,
                evidence_ref: format!("sanction:{}:{}", entry.list_name, entry.entry),
            },
            // A verified list match is the strongest evidence class there is.
            evidence_confidence: 1.0,
        })
        .collect()
}

fn label_factors(labels: &[LabelRecord], as_of: DateTime<Utc>) -> Vec<ScoredFactor> {
    labels
        .iter()
        .filter_map(|label| {
            let base = label_weight(label.kind);
            if base == 0.0 {
                return None;
            }
            let decay = decay_factor(label.created_at, as_of, label_half_life_days(label.source));
            let kind_str: &'static str = label.kind.into();
            let source_str: &'static str = label.source.into();
            Some(ScoredFactor {
                factor: RiskFactor {
                    name: format!("{kind_str} label ({source_str}: {})", label.value),
                    delta: base * decay,
                    evidence_ref: format!("label:{}", label.label_id),
                },
                evidence_confidence: label.confidence.get(),
            })
        })
        .collect()
}

fn attribution_factors(
    attributions: &[AttributionRecord],
    as_of: DateTime<Utc>,
) -> Vec<ScoredFactor> {
    attributions
        .iter()
        .map(|attribution| {
            let decay = decay_factor(
                attribution.attributed_at,
                as_of,
                Some(ATTRIBUTION_HALF_LIFE_DAYS),
            );
            ScoredFactor {
                factor: RiskFactor {
                    name: format!("Attributed incident {}", attribution.incident_id),
                    delta: weights::PER_ATTRIBUTED_INCIDENT * decay,
                    evidence_ref: format!("incident:{}", attribution.incident_id),
                },
                evidence_confidence: attribution.confidence.get(),
            }
        })
        .collect()
}

fn entity_factor(entity: Option<&EntityRecord>) -> Option<ScoredFactor> {
    let entity = entity?;
    let members = entity.addresses.len();
    if members <= 1 {
        return None;
    }
    let delta = (members as f64 * weights::PER_CLUSTER_MEMBER).min(weights::CLUSTER_CAP);
    Some(ScoredFactor {
        factor: RiskFactor {
            name: format!("Entity cluster: {members} linked wallets"),
            delta,
            evidence_ref: format!("entity:{}", entity.entity_id),
        },
        // Cluster membership is an on-chain-verified structural fact, not a
        // heuristic guess — high weight (§8.3's confidence-weighting table).
        evidence_confidence: 1.0,
    })
}

/// Trim a descending-`|delta|`-sorted factor list to at most
/// [`MAX_VISIBLE_FACTORS`] rows. The largest individual factors pass through
/// unchanged; anything past the cap folds into one aggregate row summing
/// their deltas, so the *visible* breakdown still reconciles to the same
/// total `score` was computed from — a caller summing the returned factors
/// never sees a number that doesn't add up, it just sees the tail
/// compressed into one line instead of hundreds. A no-op below the cap.
fn cap_factors(mut factors: Vec<RiskFactor>) -> Vec<RiskFactor> {
    if factors.len() <= MAX_VISIBLE_FACTORS {
        return factors;
    }
    let overflow = factors.split_off(MAX_VISIBLE_FACTORS - 1);
    let overflow_count = overflow.len();
    let overflow_delta: f64 = overflow.iter().map(|f| f.delta).sum();
    factors.push(RiskFactor {
        name: format!("{overflow_count} more factors"),
        delta: overflow_delta,
        evidence_ref: format!("aggregated:{overflow_count}_factors"),
    });
    factors
}

/// Compute an address's risk score from already-fetched [`RiskInputs`],
/// `as_of` a given instant (an explicit input, not an ambient clock, so the
/// same call is deterministic in replay — the same discipline
/// [`LabelStore::labels_for`](crate::store::LabelStore::labels_for) already
/// follows, §18).
///
/// `score` is the sum of every factor's time-decayed `delta`, clamped into
/// `0..=100`. `confidence` is a *separate* aggregate: each factor's
/// evidentiary weight (§8.3's table — sanctions/entity structure highest,
/// then each label's/attribution's own stored confidence), weighted by how
/// much that factor's `delta` contributed to `score` — so a large delta
/// backed by weak evidence still drags the aggregate down, and an address
/// with no evidence at all is `0/100` at `confidence 0.0`, not a false
/// "clean". Both are computed over the full, uncapped factor set;
/// `factors` itself is then trimmed to [`MAX_VISIBLE_FACTORS`] rows
/// ([`cap_factors`]) so the *output* stays bounded even when the inputs
/// aren't.
pub fn score(
    address: AccountAddress,
    entity_id: Option<EntityId>,
    inputs: &RiskInputs,
    as_of: DateTime<Utc>,
) -> RiskScoreUpdated {
    let mut scored = Vec::new();
    scored.extend(sanction_factors(&inputs.sanctions));
    scored.extend(label_factors(&inputs.labels, as_of));
    scored.extend(attribution_factors(&inputs.attributions, as_of));
    scored.extend(entity_factor(inputs.entity.as_ref()));

    // Deterministic, explainable ordering: largest-magnitude contribution
    // first (the §8.3 worked example's ordering), ties broken by name so
    // output never depends on the stores' return order.
    scored.sort_by(|a, b| {
        b.factor
            .delta
            .abs()
            .partial_cmp(&a.factor.delta.abs())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.factor.name.cmp(&b.factor.name))
    });

    let raw_score: f64 = scored.iter().map(|s| s.factor.delta).sum();
    let score = raw_score.round().clamp(0.0, 100.0) as u8;

    let weight_sum: f64 = scored.iter().map(|s| s.factor.delta.abs()).sum();
    let confidence = if weight_sum > 0.0 {
        scored
            .iter()
            .map(|s| s.factor.delta.abs() * s.evidence_confidence)
            .sum::<f64>()
            / weight_sum
    } else {
        0.0
    };

    RiskScoreUpdated {
        address,
        entity_id,
        score,
        confidence: Confidence::new(confidence),
        factors: cap_factors(scored.into_iter().map(|s| s.factor).collect()),
        model_version: MODEL_VERSION.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EntityStatus, LabelSource};
    use alloy_primitives::Address;
    use events::primitives::{IncidentId, LabelId};
    use proptest::prelude::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    fn addr(byte: u8) -> AccountAddress {
        Address::repeat_byte(byte)
    }

    fn label(kind: LabelKind, source: LabelSource, created_at: DateTime<Utc>) -> LabelRecord {
        LabelRecord {
            label_id: LabelId::new(),
            address: addr(0x01),
            kind,
            value: "test".into(),
            confidence: source.default_confidence(),
            source,
            source_detail: "unit-test".into(),
            created_at,
            valid_until: None,
        }
    }

    fn sanction() -> SanctionEntry {
        SanctionEntry {
            address: addr(0x01),
            list_name: "ofac_sdn".into(),
            entry: "Evil Corp".into(),
            listed_at: None,
        }
    }

    fn attribution(confidence: f64, attributed_at: DateTime<Utc>) -> AttributionRecord {
        AttributionRecord {
            incident_id: IncidentId::new(),
            entity_id: EntityId::new(),
            confidence: Confidence::new(confidence),
            evidence: "unit-test".into(),
            attributed_at,
        }
    }

    fn entity(members: usize) -> EntityRecord {
        EntityRecord {
            entity_id: EntityId::new(),
            version: 1,
            status: EntityStatus::Active,
            absorbed_into: None,
            addresses: (0..members as u8).map(addr).collect(),
            created_at: at(0),
        }
    }

    #[test]
    fn no_evidence_is_zero_score_zero_confidence() {
        let result = score(addr(0x01), None, &RiskInputs::default(), at(1_000));
        assert_eq!(result.score, 0);
        assert_eq!(result.confidence.get(), 0.0);
        assert!(result.factors.is_empty());
        assert_eq!(result.model_version, MODEL_VERSION);
    }

    #[test]
    fn sanction_hit_drives_score_at_full_confidence() {
        let inputs = RiskInputs {
            sanctions: vec![sanction()],
            ..Default::default()
        };
        let result = score(addr(0x01), None, &inputs, at(1_000));
        assert_eq!(result.score, weights::SANCTIONED.round() as u8);
        assert_eq!(result.confidence.get(), 1.0);
        assert_eq!(result.factors.len(), 1);
        assert_eq!(
            result.factors[0].evidence_ref,
            "sanction:ofac_sdn:Evil Corp"
        );
    }

    #[test]
    fn manual_label_never_decays() {
        let created = at(0);
        let as_of = at(3600 * 24 * 3650); // ten years later
        let inputs = RiskInputs {
            labels: vec![label(LabelKind::KnownScammer, LabelSource::Manual, created)],
            ..Default::default()
        };
        let result = score(addr(0x01), None, &inputs, as_of);
        assert_eq!(result.factors[0].delta, weights::KNOWN_SCAMMER);
    }

    #[test]
    fn heuristic_label_decays_toward_zero_with_age() {
        let created = at(0);
        let fresh = score(
            addr(0x01),
            None,
            &RiskInputs {
                labels: vec![label(LabelKind::MevBot, LabelSource::Heuristic, created)],
                ..Default::default()
            },
            created,
        );
        let stale = score(
            addr(0x01),
            None,
            &RiskInputs {
                labels: vec![label(LabelKind::MevBot, LabelSource::Heuristic, created)],
                ..Default::default()
            },
            at(3600 * 24 * 360), // two half-lives out
        );
        assert_eq!(fresh.factors[0].delta, weights::MEV_BOT);
        assert!(stale.factors[0].delta < fresh.factors[0].delta / 3.0);
        assert!(stale.factors[0].delta > 0.0);
    }

    #[test]
    fn zero_weight_kinds_produce_no_factor() {
        let inputs = RiskInputs {
            labels: vec![label(LabelKind::Bridge, LabelSource::Manual, at(0))],
            ..Default::default()
        };
        let result = score(addr(0x01), None, &inputs, at(0));
        assert!(result.factors.is_empty());
        assert_eq!(result.score, 0);
    }

    #[test]
    fn negative_delta_labels_are_clamped_at_the_zero_floor() {
        let inputs = RiskInputs {
            labels: vec![label(LabelKind::CexWallet, LabelSource::Manual, at(0))],
            ..Default::default()
        };
        let result = score(addr(0x01), None, &inputs, at(0));
        assert_eq!(result.score, 0);
        assert_eq!(result.factors[0].delta, weights::CEX_WALLET);
    }

    #[test]
    fn low_confidence_factor_pulls_aggregate_confidence_down_but_not_delta() {
        let low_confidence_label = LabelRecord {
            confidence: Confidence::new(0.1),
            ..label(LabelKind::MixerUser, LabelSource::ExternalFeed, at(0))
        };
        let inputs = RiskInputs {
            labels: vec![low_confidence_label],
            ..Default::default()
        };
        let result = score(addr(0x01), None, &inputs, at(0));
        assert_eq!(result.factors[0].delta, weights::MIXER_USER);
        assert!(result.confidence.get() < 0.2);
    }

    #[test]
    fn attributed_incidents_accumulate_and_decay() {
        let inputs = RiskInputs {
            attributions: vec![attribution(1.0, at(0)), attribution(0.75, at(0))],
            ..Default::default()
        };
        let result = score(addr(0x01), None, &inputs, at(0));
        assert_eq!(
            result.score,
            (weights::PER_ATTRIBUTED_INCIDENT * 2.0).round() as u8
        );
    }

    #[test]
    fn entity_cluster_factor_is_capped() {
        let inputs = RiskInputs {
            entity: Some(entity(50)),
            ..Default::default()
        };
        let result = score(addr(0x01), None, &inputs, at(0));
        assert_eq!(result.factors[0].delta, weights::CLUSTER_CAP);
    }

    #[test]
    fn singleton_entity_produces_no_cluster_factor() {
        let inputs = RiskInputs {
            entity: Some(entity(1)),
            ..Default::default()
        };
        let result = score(addr(0x01), None, &inputs, at(0));
        assert!(result.factors.is_empty());
    }

    #[test]
    fn score_saturates_at_the_100_ceiling() {
        let inputs = RiskInputs {
            sanctions: vec![sanction()],
            labels: vec![label(LabelKind::KnownScammer, LabelSource::Manual, at(0))],
            attributions: vec![attribution(1.0, at(0)); 10],
            entity: Some(entity(50)),
        };
        let result = score(addr(0x01), None, &inputs, at(0));
        assert_eq!(result.score, 100);
    }

    #[test]
    fn factors_are_sorted_by_descending_magnitude() {
        let inputs = RiskInputs {
            sanctions: vec![sanction()],
            labels: vec![label(LabelKind::MevBot, LabelSource::Manual, at(0))],
            ..Default::default()
        };
        let result = score(addr(0x01), None, &inputs, at(0));
        assert!(result.factors[0].delta.abs() >= result.factors[1].delta.abs());
    }

    #[test]
    fn factor_count_at_or_below_the_cap_is_untouched() {
        let attributions: Vec<AttributionRecord> =
            (0..5).map(|_| attribution(1.0, at(0))).collect();
        let inputs = RiskInputs {
            attributions,
            ..Default::default()
        };
        let result = score(addr(0x01), None, &inputs, at(0));
        assert_eq!(result.factors.len(), 5);
        assert!(!result
            .factors
            .iter()
            .any(|f| f.evidence_ref.starts_with("aggregated:")));
    }

    #[test]
    fn factor_count_beyond_the_cap_folds_into_one_aggregate_row() {
        // 12 distinct attributed-incident factors: more than MAX_VISIBLE_FACTORS,
        // so the largest-scale-app failure mode (an entity with thousands of
        // attributed incidents) doesn't turn into a thousand-row event.
        let attributions: Vec<AttributionRecord> =
            (0..12).map(|_| attribution(1.0, at(0))).collect();
        let inputs = RiskInputs {
            attributions,
            ..Default::default()
        };
        let result = score(addr(0x01), None, &inputs, at(0));

        assert_eq!(result.factors.len(), MAX_VISIBLE_FACTORS);
        let overflow_row = result.factors.last().unwrap();
        assert_eq!(overflow_row.name, "3 more factors");
        assert!(overflow_row.evidence_ref.starts_with("aggregated:"));

        // Capping trims what's *surfaced*, not what's counted: the visible
        // rows (9 individual + 1 aggregate) still sum to the same total the
        // (uncapped, unclamped) score was computed from.
        let visible_sum: f64 = result.factors.iter().map(|f| f.delta).sum();
        assert_eq!(visible_sum, 12.0 * weights::PER_ATTRIBUTED_INCIDENT);
        assert_eq!(result.score, visible_sum.round() as u8);
    }

    proptest! {
        /// The decay factor is always in `(0.0, 1.0]` and strictly decreasing
        /// as age grows, for any positive half-life — the "old incidents
        /// contribute less" invariant, over the whole input space rather than
        /// a couple of hand-picked timestamps.
        #[test]
        fn decay_factor_is_bounded_and_monotonic(
            half_life in 1.0f64..1000.0,
            younger_days in 0.0f64..500.0,
            extra_days in 0.0f64..500.0,
        ) {
            let created = at(0);
            let younger = created + chrono::Duration::seconds((younger_days * 86_400.0) as i64);
            let older = younger + chrono::Duration::seconds((extra_days * 86_400.0) as i64);

            let d_younger = decay_factor(created, younger, Some(half_life));
            let d_older = decay_factor(created, older, Some(half_life));

            prop_assert!(d_younger > 0.0 && d_younger <= 1.0);
            prop_assert!(d_older > 0.0 && d_older <= 1.0);
            if extra_days > 0.0 {
                prop_assert!(d_older <= d_younger);
            }
        }
    }
}
