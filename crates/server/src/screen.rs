//! The counterparty-screening decision layer (§11, Sprint 14): the pure
//! mapping from an address's intelligence facts (score + sanctions status,
//! read via [`crate::intelligence_client::IntelligenceClient::screening_facts`])
//! to the synchronous `allow`/`review`/`block` outcome
//! `POST /v1/address/{addr}/screen` answers with.
//!
//! Deliberately store- and transport-free (the same discipline as
//! `intelligence::risk`): [`decide`] is a pure function from a
//! [`ScreeningInput`] to a [`Verdict`], so the legally-weighty threshold
//! logic is unit-testable with plain values. The generated gRPC reply never
//! reaches this layer — `crate::intelligence_client` owns the one wire→domain
//! conversion (the anti-corruption seam), the same way it owns
//! `Status`→`ApiError`. Sprint 14 t2 grows this into customer-configurable
//! **versioned named policies** (`default`/`strict`/`monitor-only`); what can
//! never change is the sanctions override — a sanctions-list match
//! hard-blocks regardless of any score threshold (§8.5: `SanctionHit` is
//! already a hard alert).

use serde::Serialize;

/// Review threshold of the §11 default policy: a score below this allows,
/// at/above it holds for manual compliance review.
pub const REVIEW_AT: u8 = 40;

/// Block threshold of the §11 default policy: a score at/above this rejects
/// the counterparty outright.
pub const BLOCK_AT: u8 = 80;

/// The three screening outcomes (§11). Serialized lowercase — the wire
/// vocabulary the spec names (`allow` / `review` / `block`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// No blocking signals (score < [`REVIEW_AT`]).
    Allow,
    /// Hold for manual compliance ([`REVIEW_AT`] ≤ score < [`BLOCK_AT`]).
    Review,
    /// Reject the counterparty (score ≥ [`BLOCK_AT`], or sanctions match).
    Block,
}

/// Which rule produced the decision — the first line of the explainability
/// contract (§11: a block/review must be auditable). Snake_case on the wire;
/// t3 adds the full per-factor breakdown alongside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DecisionBasis {
    /// A sanctions-list match hard-blocked, bypassing the score thresholds
    /// entirely (§8.5).
    SanctionsHardBlock,
    /// The score fell through the default policy's thresholds.
    ScoreThresholds,
}

/// The two decision-driving facts, distilled from the intelligence reply at
/// the transport edge (`crate::intelligence_client`'s `From` impl — the only
/// place the wire type is read for a decision). `score` is already clamped
/// into `0..=100` there, so this layer never sees an out-of-range value and
/// needs no defensive checks of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScreeningInput {
    /// 0–100, "how risky" (§8.3).
    pub score: u8,
    /// The address matched at least one sanctions list (§8.5).
    pub sanctioned: bool,
}

/// The outcome of one screening decision. A named struct rather than a
/// tuple so it can grow without touching every call site: t2 adds the
/// policy name/version that produced it, t3 the factor breakdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    pub decision: Decision,
    pub basis: DecisionBasis,
}

/// Map the decision-driving facts to the §11 outcome. Sanctions first:
/// the hard block bypasses the thresholds no matter how low the score is
/// (a freshly-listed address may not have accumulated score yet — the list
/// membership alone is the legal signal).
pub fn decide(input: ScreeningInput) -> Verdict {
    if input.sanctioned {
        return Verdict {
            decision: Decision::Block,
            basis: DecisionBasis::SanctionsHardBlock,
        };
    }
    let decision = match input.score {
        s if s >= BLOCK_AT => Decision::Block,
        s if s >= REVIEW_AT => Decision::Review,
        _ => Decision::Allow,
    };
    Verdict {
        decision,
        basis: DecisionBasis::ScoreThresholds,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(score: u8, sanctioned: bool) -> ScreeningInput {
        ScreeningInput { score, sanctioned }
    }

    /// The §11 threshold boundaries, pinned exactly: 39 allows, 40 reviews,
    /// 79 reviews, 80 blocks.
    #[test]
    fn score_thresholds_map_to_the_spec_boundaries() {
        assert_eq!(decide(input(0, false)).decision, Decision::Allow);
        assert_eq!(
            decide(input(REVIEW_AT - 1, false)).decision,
            Decision::Allow
        );
        assert_eq!(decide(input(REVIEW_AT, false)).decision, Decision::Review);
        assert_eq!(
            decide(input(BLOCK_AT - 1, false)).decision,
            Decision::Review
        );
        assert_eq!(decide(input(BLOCK_AT, false)).decision, Decision::Block);
        assert_eq!(decide(input(100, false)).decision, Decision::Block);
    }

    /// A sanctions match hard-blocks even a zero score — the §8.5 override
    /// bypasses the thresholds entirely, and says so in the basis.
    #[test]
    fn sanctions_hard_block_bypasses_the_thresholds() {
        let verdict = decide(input(0, true));
        assert_eq!(verdict.decision, Decision::Block);
        assert_eq!(verdict.basis, DecisionBasis::SanctionsHardBlock);

        // High score + sanctions still reports the sanctions basis — the
        // stronger, legally-weighted reason wins the explanation.
        let verdict = decide(input(100, true));
        assert_eq!(verdict.decision, Decision::Block);
        assert_eq!(verdict.basis, DecisionBasis::SanctionsHardBlock);
    }

    /// An unsanctioned decision reports the score-threshold basis.
    #[test]
    fn unsanctioned_decisions_carry_the_threshold_basis() {
        for score in [0, 50, 90] {
            assert_eq!(
                decide(input(score, false)).basis,
                DecisionBasis::ScoreThresholds
            );
        }
    }

    /// The wire vocabulary is the spec's: lowercase decisions, snake_case
    /// basis.
    #[test]
    fn wire_forms_match_the_spec_vocabulary() {
        assert_eq!(serde_json::to_value(Decision::Allow).unwrap(), "allow");
        assert_eq!(serde_json::to_value(Decision::Review).unwrap(), "review");
        assert_eq!(serde_json::to_value(Decision::Block).unwrap(), "block");
        assert_eq!(
            serde_json::to_value(DecisionBasis::SanctionsHardBlock).unwrap(),
            "sanctions_hard_block"
        );
        assert_eq!(
            serde_json::to_value(DecisionBasis::ScoreThresholds).unwrap(),
            "score_thresholds"
        );
    }
}
