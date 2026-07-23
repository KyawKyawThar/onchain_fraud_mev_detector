//! The counterparty-screening decision layer (§11, Sprint 14): the pure
//! mapping from an address's intelligence facts (score + sanctions status,
//! read via [`crate::intelligence_client::IntelligenceClient::screening_facts`])
//! to the synchronous `allow`/`review`/`block` outcome
//! `POST /v1/address/{addr}/screen` answers with.
//!
//! Deliberately store- and transport-free (the same discipline as
//! `intelligence::risk`): [`decide`] is a pure function from a
//! [`ScreeningInput`] and a [`Policy`] to a [`Verdict`], so the
//! legally-weighty threshold logic is unit-testable with plain values. The
//! generated gRPC reply never reaches this layer — `crate::intelligence_client`
//! owns the one wire→domain conversion (the anti-corruption seam), the same
//! way it owns `Status`→`ApiError`.
//!
//! Sprint 14 t2: **customer-configurable, versioned named policies**. Three
//! built-in policies ([`builtin_policy`]) ship for free — `default`, `strict`,
//! `monitor-only` — and a customer can additionally author their own named
//! policies (`crate::policy_store::PolicyStore`), each edit landing as a new
//! immutable version so a past verdict's `(policy_name, policy_version)`
//! always resolves back to the exact thresholds that produced it. What can
//! never change, on *any* policy, built-in or customer-authored: a
//! sanctions-list match hard-blocks regardless of score (§8.5: `SanctionHit`
//! is already a hard alert) — [`decide`] checks it before ever looking at the
//! policy's thresholds.

use serde::Serialize;

/// Policy names reserved for the built-in catalog — a customer cannot create
/// or overwrite a policy under one of these (`crate::policy_store::PolicyStore`
/// enforces this at the store boundary; listed here because the catalog is
/// this module's to define).
pub const BUILTIN_POLICY_NAMES: [&str; 3] = ["default", "strict", "monitor-only"];

/// Every built-in policy is version 1 forever — the catalog itself never
/// changes at runtime (a threshold retune would ship as a code change, which
/// is its own deploy/audit trail); only customer-authored policies grow
/// versions over time.
const BUILTIN_VERSION: i32 = 1;

/// The top of the risk-score domain (§8.3). A threshold above this is dead —
/// the intelligence edge clamps every score into `0..=100`
/// (`crate::intelligence_client`), so a `review_at`/`block_at` of, say, 200
/// would never fire. [`Policy::new`] rejects it rather than let a customer
/// store a silently-inert compliance policy.
pub const MAX_SCORE: u8 = 100;

/// Why a [`Thresholds`] pair or a [`Policy`] was rejected — at construction
/// or at the `crate::policy_store::PolicyStore` write boundary.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidPolicy {
    #[error("policy name must be non-empty and at most 64 characters")]
    NameLength,
    /// A threshold above [`MAX_SCORE`] — dead by construction (score never
    /// reaches it), so rejected rather than silently stored as inert.
    #[error("thresholds must be within 0..={MAX_SCORE}, got review_at={review_at}, block_at={block_at:?}")]
    ThresholdOutOfRange {
        review_at: u8,
        block_at: Option<u8>,
    },
    /// `block_at`, when present, must be at/above `review_at` — a policy
    /// where the block threshold is *more* lenient than the review threshold
    /// would let a block-worthy score sail through as merely "review".
    #[error("block_at ({block_at}) must be >= review_at ({review_at})")]
    BlockBelowReview { review_at: u8, block_at: u8 },
}

/// The score-threshold pair a policy decides by — a **value object** holding
/// the decision math, kept separate from a policy's *identity*
/// ([`Policy`]'s `name`/`version`). Fields are private and the only
/// constructor validates, so an out-of-range or inverted pair is
/// unrepresentable: once you hold a `Thresholds`, `review_at <= block_at`
/// (when present) and both sit in `0..=`[`MAX_SCORE`] — no call site has to
/// re-check. `Copy`, so the decision kernel passes it by value with no
/// allocation on the `/screen` hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Thresholds {
    review_at: u8,
    block_at: Option<u8>,
}

impl Thresholds {
    /// Validate and construct a threshold pair. Two invariants: every
    /// threshold sits within the score domain `0..=`[`MAX_SCORE`] (a higher
    /// one is inert — score never reaches it), and `block_at`, when present,
    /// is at/above `review_at` (otherwise a block-worthy score reads as
    /// merely "review").
    pub fn new(review_at: u8, block_at: Option<u8>) -> Result<Self, InvalidPolicy> {
        if review_at > MAX_SCORE || block_at.is_some_and(|b| b > MAX_SCORE) {
            return Err(InvalidPolicy::ThresholdOutOfRange {
                review_at,
                block_at,
            });
        }
        if let Some(block_at) = block_at {
            if block_at < review_at {
                return Err(InvalidPolicy::BlockBelowReview {
                    review_at,
                    block_at,
                });
            }
        }
        Ok(Self {
            review_at,
            block_at,
        })
    }

    /// Score at/above which an otherwise-clean address is held for review.
    pub fn review_at(&self) -> u8 {
        self.review_at
    }

    /// Score at/above which an otherwise-clean address is blocked outright.
    /// `None` is `monitor-only` mode: the score can never block — the worst
    /// a score alone can do is hold for `review`. A sanctions hard-block
    /// still applies regardless (see module docs).
    pub fn block_at(&self) -> Option<u8> {
        self.block_at
    }

    /// The score-only outcome — pure arithmetic on the pair, no sanctions
    /// (the caller applies that override first). Allocation-free.
    fn classify(&self, score: u8) -> Decision {
        match self.block_at {
            Some(block_at) if score >= block_at => Decision::Block,
            _ if score >= self.review_at => Decision::Review,
            _ => Decision::Allow,
        }
    }
}

/// A named, versioned decision policy: an identity (`name` + `version`) over
/// a [`Thresholds`] value object. `name` + `version` are carried on every
/// [`Verdict`] this policy produces — the audit trail's anchor back to "what
/// were the exact thresholds that decided this?", which matters because a
/// customer can retune a policy after the fact (each retune is a new
/// `version`, the old thresholds preserved).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub name: String,
    pub version: i32,
    pub thresholds: Thresholds,
}

impl Policy {
    /// Construct and validate a policy from raw thresholds — a convenience
    /// over [`Thresholds::new`] + [`Policy::with_thresholds`] for the
    /// built-in catalog and tests.
    pub fn new(
        name: impl Into<String>,
        version: i32,
        review_at: u8,
        block_at: Option<u8>,
    ) -> Result<Self, InvalidPolicy> {
        Self::with_thresholds(name, version, Thresholds::new(review_at, block_at)?)
    }

    /// Construct a policy over an already-validated [`Thresholds`]. Only the
    /// name is validated here — the thresholds carry their own invariant, so
    /// the store's write path builds the pair once ([`Thresholds::new`]) and
    /// never re-derives it.
    pub fn with_thresholds(
        name: impl Into<String>,
        version: i32,
        thresholds: Thresholds,
    ) -> Result<Self, InvalidPolicy> {
        let name = name.into();
        if name.is_empty() || name.len() > 64 {
            return Err(InvalidPolicy::NameLength);
        }
        Ok(Self {
            name,
            version,
            thresholds,
        })
    }

    /// This policy's name is one of the reserved built-ins
    /// ([`BUILTIN_POLICY_NAMES`]) — a customer-authored policy can never take
    /// this name.
    pub fn is_builtin_name(name: &str) -> bool {
        BUILTIN_POLICY_NAMES.contains(&name)
    }
}

/// Resolve a built-in policy by name — the free, no-storage catalog every
/// customer gets before authoring anything of their own:
///
/// * `default` — the §11 baseline: review at 40, block at 80.
/// * `strict` — a lower bar on both thresholds, for a customer that wants to
///   hold or block more aggressively than the baseline.
/// * `monitor-only` — score never blocks (`block_at: None`); a customer
///   dry-running a new threshold or a jurisdiction that requires visibility
///   without automated blocking still gets `review` flags, and sanctions
///   hard-blocks are unaffected.
///
/// `None` when `name` isn't a built-in — the caller then falls through to
/// `crate::policy_store::PolicyStore::resolve` for a customer-authored one.
pub fn builtin_policy(name: &str) -> Option<Policy> {
    match name {
        "default" => Some(
            Policy::new("default", BUILTIN_VERSION, 40, Some(80))
                .expect("built-in default policy is valid"),
        ),
        "strict" => Some(
            Policy::new("strict", BUILTIN_VERSION, 20, Some(50))
                .expect("built-in strict policy is valid"),
        ),
        "monitor-only" => Some(
            Policy::new("monitor-only", BUILTIN_VERSION, 40, None)
                .expect("built-in monitor-only policy is valid"),
        ),
        _ => None,
    }
}

/// The whole built-in catalog, in [`BUILTIN_POLICY_NAMES`] order — what
/// `GET /v1/policies` lists as the free presets. Keeps catalog enumeration in
/// this module (the catalog's owner) rather than re-derived at the HTTP edge.
pub fn builtin_catalog() -> Vec<Policy> {
    BUILTIN_POLICY_NAMES
        .into_iter()
        .map(|name| builtin_policy(name).expect("BUILTIN_POLICY_NAMES entries always resolve"))
        .collect()
}

/// The policy name a screening call uses when its request body names none —
/// `POST /v1/address/{addr}/screen`'s implicit default.
pub const DEFAULT_POLICY_NAME: &str = "default";

/// The three screening outcomes (§11). Serialized lowercase — the wire
/// vocabulary the spec names (`allow` / `review` / `block`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// No blocking signals (score below the policy's `review_at`).
    Allow,
    /// Hold for manual compliance (`review_at` <= score, and either the
    /// policy is `monitor-only` or score < `block_at`).
    Review,
    /// Reject the counterparty (score >= the policy's `block_at`, or a
    /// sanctions match — regardless of policy).
    Block,
}

/// Which rule produced the decision — the first line of the explainability
/// contract (§11: a block/review must be auditable). Snake_case on the wire;
/// t3 adds the full per-factor breakdown alongside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DecisionBasis {
    /// A sanctions-list match hard-blocked, bypassing the policy's
    /// thresholds entirely (§8.5).
    SanctionsHardBlock,
    /// The score fell through the policy's thresholds.
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

/// The outcome of one screening decision, plus the exact policy that
/// produced it — `name`/`version` are what makes a `block`/`review` from six
/// months ago reconstructible even after the customer has since retuned the
/// policy's thresholds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub decision: Decision,
    pub basis: DecisionBasis,
    pub policy_name: String,
    pub policy_version: i32,
}

/// Map the decision-driving facts through `policy` to the §11 outcome.
/// Sanctions first: the hard block bypasses the thresholds no matter how low
/// the score is (a freshly-listed address may not have accumulated score yet
/// — the list membership alone is the legal signal) and no matter which
/// policy — `monitor-only` softens score-driven blocking, never the
/// sanctions override.
pub fn decide(input: ScreeningInput, policy: &Policy) -> Verdict {
    if input.sanctioned {
        return Verdict {
            decision: Decision::Block,
            basis: DecisionBasis::SanctionsHardBlock,
            policy_name: policy.name.clone(),
            policy_version: policy.version,
        };
    }
    Verdict {
        decision: policy.thresholds.classify(input.score),
        basis: DecisionBasis::ScoreThresholds,
        policy_name: policy.name.clone(),
        policy_version: policy.version,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(score: u8, sanctioned: bool) -> ScreeningInput {
        ScreeningInput { score, sanctioned }
    }

    /// The `default` built-in policy's boundaries, pinned exactly: 39 allows,
    /// 40 reviews, 79 reviews, 80 blocks — the same numbers the pre-t2
    /// hardcoded consts carried.
    #[test]
    fn default_policy_maps_to_the_spec_boundaries() {
        let policy = builtin_policy("default").unwrap();
        assert_eq!(decide(input(0, false), &policy).decision, Decision::Allow);
        assert_eq!(decide(input(39, false), &policy).decision, Decision::Allow);
        assert_eq!(
            decide(input(40, false), &policy).decision,
            Decision::Review
        );
        assert_eq!(
            decide(input(79, false), &policy).decision,
            Decision::Review
        );
        assert_eq!(decide(input(80, false), &policy).decision, Decision::Block);
        assert_eq!(
            decide(input(100, false), &policy).decision,
            Decision::Block
        );
    }

    /// `strict` holds and blocks at lower scores than `default`.
    #[test]
    fn strict_policy_is_stricter_than_default() {
        let policy = builtin_policy("strict").unwrap();
        assert_eq!(decide(input(19, false), &policy).decision, Decision::Allow);
        assert_eq!(
            decide(input(20, false), &policy).decision,
            Decision::Review
        );
        assert_eq!(decide(input(50, false), &policy).decision, Decision::Block);
    }

    /// `monitor-only` never blocks on score alone — the worst a clean-of-
    /// sanctions high score can do is `review`.
    #[test]
    fn monitor_only_never_blocks_on_score() {
        let policy = builtin_policy("monitor-only").unwrap();
        assert_eq!(decide(input(39, false), &policy).decision, Decision::Allow);
        assert_eq!(
            decide(input(40, false), &policy).decision,
            Decision::Review
        );
        assert_eq!(
            decide(input(100, false), &policy).decision,
            Decision::Review,
            "monitor-only caps at review even for a maximal score"
        );
    }

    /// A sanctions match hard-blocks even a zero score, and survives every
    /// policy — including `monitor-only`, whose entire point is to soften
    /// score-driven blocking, not the sanctions override (§8.5 is a spec
    /// invariant, not a policy knob).
    #[test]
    fn sanctions_hard_block_survives_every_policy() {
        for name in BUILTIN_POLICY_NAMES {
            let policy = builtin_policy(name).unwrap();
            let verdict = decide(input(0, true), &policy);
            assert_eq!(verdict.decision, Decision::Block, "policy {name}");
            assert_eq!(
                verdict.basis,
                DecisionBasis::SanctionsHardBlock,
                "policy {name}"
            );

            // High score + sanctions still reports the sanctions basis — the
            // stronger, legally-weighted reason wins the explanation.
            let verdict = decide(input(100, true), &policy);
            assert_eq!(verdict.decision, Decision::Block, "policy {name}");
            assert_eq!(
                verdict.basis,
                DecisionBasis::SanctionsHardBlock,
                "policy {name}"
            );
        }
    }

    /// The verdict carries the exact policy identity that produced it.
    #[test]
    fn verdict_carries_the_policy_name_and_version() {
        let policy = Policy::new("acme-strict", 3, 10, Some(60)).unwrap();
        let verdict = decide(input(70, false), &policy);
        assert_eq!(verdict.policy_name, "acme-strict");
        assert_eq!(verdict.policy_version, 3);
    }

    /// An unsanctioned decision reports the score-threshold basis.
    #[test]
    fn unsanctioned_decisions_carry_the_threshold_basis() {
        let policy = builtin_policy("default").unwrap();
        for score in [0, 50, 90] {
            assert_eq!(
                decide(input(score, false), &policy).basis,
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

    #[test]
    fn builtin_policy_rejects_unknown_names() {
        assert!(builtin_policy("nonexistent").is_none());
    }

    #[test]
    fn policy_construction_rejects_a_block_threshold_below_review() {
        let err = Policy::new("bad", 1, 80, Some(40)).unwrap_err();
        assert_eq!(
            err,
            InvalidPolicy::BlockBelowReview {
                review_at: 80,
                block_at: 40
            }
        );
    }

    #[test]
    fn policy_construction_rejects_a_threshold_above_the_score_domain() {
        // A review threshold no score can reach — inert, so rejected.
        assert_eq!(
            Policy::new("dead", 1, 200, None).unwrap_err(),
            InvalidPolicy::ThresholdOutOfRange {
                review_at: 200,
                block_at: None
            }
        );
        // Same for a block threshold above the ceiling.
        assert_eq!(
            Policy::new("dead", 1, 10, Some(150)).unwrap_err(),
            InvalidPolicy::ThresholdOutOfRange {
                review_at: 10,
                block_at: Some(150)
            }
        );
        // The ceiling itself is valid: "block only at a maximal score".
        assert!(Policy::new("edge", 1, MAX_SCORE, Some(MAX_SCORE)).is_ok());
    }

    #[test]
    fn builtin_catalog_lists_every_builtin_in_order() {
        let names: Vec<String> = builtin_catalog().into_iter().map(|p| p.name).collect();
        assert_eq!(names, vec!["default", "strict", "monitor-only"]);
    }

    #[test]
    fn policy_construction_rejects_bad_names() {
        assert_eq!(
            Policy::new("", 1, 10, None).unwrap_err(),
            InvalidPolicy::NameLength
        );
        assert_eq!(
            Policy::new("x".repeat(65), 1, 10, None).unwrap_err(),
            InvalidPolicy::NameLength
        );
    }

    #[test]
    fn is_builtin_name_recognises_exactly_the_catalog() {
        for name in BUILTIN_POLICY_NAMES {
            assert!(Policy::is_builtin_name(name));
        }
        assert!(!Policy::is_builtin_name("acme-strict"));
    }
}
