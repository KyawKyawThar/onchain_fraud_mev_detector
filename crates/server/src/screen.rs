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

use events::intelligence::RiskFactor;
use events::system::FactsStaleness;

/// The screening outcome and its basis are the shared §11 domain vocabulary,
/// so their canonical types live on the schema crate (they ride the
/// `ScreeningDecisionRecorded` audit event, §2). The decision kernel here
/// produces those exact types rather than a server-local copy + a 1:1
/// conversion — so the API response, the audit event, and this kernel can
/// never disagree on the wire form (`allow`/`review`/`block`,
/// `sanctions_hard_block`/`score_thresholds`). This is also why there is no
/// hand-written `as_wire_str`: one type, one serde form, no drift.
pub use events::system::{ScreeningDecision as Decision, ScreeningDecisionBasis as DecisionBasis};

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
    ThresholdOutOfRange { review_at: u8, block_at: Option<u8> },
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
    /// What this policy does with a decision over stale facts.
    pub on_stale: StalePolicy,
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
            on_stale: StalePolicy::default(),
        })
    }

    /// This policy with a different stale-facts behaviour.
    #[must_use]
    pub fn with_on_stale(mut self, on_stale: StalePolicy) -> Self {
        self.on_stale = on_stale;
        self
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
                .expect("built-in strict policy is valid")
                // A customer who picks `strict` has asked to hold more, and a
                // decision on unconfirmed facts is exactly such a case.
                .with_on_stale(StalePolicy::Review),
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

/// What a policy does with a decision that must be rendered over **stale** facts
/// — a last-known-good snapshot, because intelligence was slow or unavailable
/// (`crate::degrade`). Part of a policy's versioned identity, like its
/// thresholds: changing it mints a new version.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    serde::Serialize,
    serde::Deserialize,
    utoipa::ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum StalePolicy {
    /// Decide on stale facts as on fresh ones. The decision still discloses
    /// `stale: true` and the facts' age. How every policy behaved before this
    /// existed, hence the default.
    #[default]
    Serve,
    /// Never auto-allow on facts intelligence could not confirm: a stale `allow`
    /// is held as `review`. A stale `block` stays a block.
    Review,
}

impl StalePolicy {
    /// The stored form — identical to the serde form, pinned by a test.
    pub fn as_wire(self) -> &'static str {
        match self {
            StalePolicy::Serve => "serve",
            StalePolicy::Review => "review",
        }
    }

    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "serve" => Some(StalePolicy::Serve),
            "review" => Some(StalePolicy::Review),
            _ => None,
        }
    }
}

/// The two decision-driving facts, distilled from the intelligence reply at
/// the transport edge (`crate::intelligence_client`'s `From` impl — the only
/// place the wire type is read for a decision). `score` is already clamped
/// into `0..=100` there, so this layer never sees an out-of-range value and
/// needs no defensive checks of its own.
#[derive(Debug, Clone, PartialEq)]
pub struct ScreeningInput {
    /// 0–100, "how risky" (§8.3).
    pub score: u8,
    /// The address matched at least one sanctions list (§8.5).
    pub sanctioned: bool,
    /// The full per-factor breakdown behind `score`, each with its
    /// `evidence_ref` — carried through to [`Verdict::factors`] untouched;
    /// this layer decides through the score, never re-derives it from the
    /// factors (§8.3's score/confidence pass already did that).
    pub factors: Vec<RiskFactor>,
}

/// The outcome of one screening decision, plus the exact policy that
/// produced it — `name`/`version` are what makes a `block`/`review` from six
/// months ago reconstructible even after the customer has since retuned the
/// policy's thresholds.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub decision: Decision,
    pub basis: DecisionBasis,
    pub policy_name: String,
    pub policy_version: i32,
    /// The full per-factor breakdown behind the score that produced
    /// `decision` (§11 Sprint 14 t3) — carried on every verdict regardless of
    /// outcome (the access-audit record wants it even for a borderline
    /// `allow`), though `POST /v1/address/{addr}/screen`'s response only
    /// serializes it on a `review`/`block` (see `crate::http::screen_address`).
    pub factors: Vec<RiskFactor>,
}

/// Whether the facts a decision was rendered over were confirmed by
/// intelligence on this request, or served from a last-known-good snapshot
/// (`crate::degrade`). A named enum rather than a bare `Option`, so a call site
/// states which case it is in instead of passing a `None` that could mean
/// "fresh" or "forgot".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Fresh,
    Stale {
        staleness: FactsStaleness,
        /// The pod-local sanctions view (`crate::sanctions_view`) is current
        /// enough to vouch that an address it does not list is not sanctioned.
        /// When it is not, nothing on this request confirms sanctions status,
        /// so a stale `allow` is held whatever the policy says.
        sanctions_verified: bool,
    },
}

impl Freshness {
    /// The disclosure a stale decision carries; `None` when fresh.
    pub fn staleness(self) -> Option<FactsStaleness> {
        match self {
            Freshness::Fresh => None,
            Freshness::Stale { staleness, .. } => Some(staleness),
        }
    }
}

/// Map the decision-driving facts through `policy` to the §11 outcome.
/// Sanctions first: the hard block bypasses the thresholds no matter how low
/// the score is (a freshly-listed address may not have accumulated score yet
/// — the list membership alone is the legal signal) and no matter which
/// policy — `monitor-only` softens score-driven blocking, never the
/// sanctions override.
///
/// Stale facts, third: a stale `allow` is held as `review`
/// ([`DecisionBasis::StaleFactsReview`]) when the policy says `on_stale: review`
/// or the sanctions view cannot vouch for the address. The hold is the
/// platform's for the second reason — an unverifiable sanctions status is not a
/// customer's trade to make — and never applies to a `block` or a `review`.
pub fn decide(input: ScreeningInput, policy: &Policy, freshness: Freshness) -> Verdict {
    // Taken by value so the factor breakdown *moves* into the verdict (and on
    // into the audit event) with no clone on the p50 < 100ms path; the caller
    // captures the Copy `sanctioned` flag before deciding if it still needs it.
    let (decision, basis) = if input.sanctioned {
        (Decision::Block, DecisionBasis::SanctionsHardBlock)
    } else {
        match (policy.thresholds.classify(input.score), freshness) {
            (
                Decision::Allow,
                Freshness::Stale {
                    sanctions_verified, ..
                },
            ) if policy.on_stale == StalePolicy::Review || !sanctions_verified => {
                (Decision::Review, DecisionBasis::StaleFactsReview)
            }
            (decision, _) => (decision, DecisionBasis::ScoreThresholds),
        }
    };
    Verdict {
        decision,
        basis,
        policy_name: policy.name.clone(),
        policy_version: policy.version,
        factors: input.factors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(score: u8, sanctioned: bool) -> ScreeningInput {
        ScreeningInput {
            score,
            sanctioned,
            factors: vec![],
        }
    }

    /// The `default` built-in policy's boundaries, pinned exactly: 39 allows,
    /// 40 reviews, 79 reviews, 80 blocks — the same numbers the pre-t2
    /// hardcoded consts carried.
    #[test]
    fn default_policy_maps_to_the_spec_boundaries() {
        let policy = builtin_policy("default").unwrap();
        assert_eq!(
            decide(input(0, false), &policy, Freshness::Fresh).decision,
            Decision::Allow
        );
        assert_eq!(
            decide(input(39, false), &policy, Freshness::Fresh).decision,
            Decision::Allow
        );
        assert_eq!(
            decide(input(40, false), &policy, Freshness::Fresh).decision,
            Decision::Review
        );
        assert_eq!(
            decide(input(79, false), &policy, Freshness::Fresh).decision,
            Decision::Review
        );
        assert_eq!(
            decide(input(80, false), &policy, Freshness::Fresh).decision,
            Decision::Block
        );
        assert_eq!(
            decide(input(100, false), &policy, Freshness::Fresh).decision,
            Decision::Block
        );
    }

    /// `strict` holds and blocks at lower scores than `default`.
    #[test]
    fn strict_policy_is_stricter_than_default() {
        let policy = builtin_policy("strict").unwrap();
        assert_eq!(
            decide(input(19, false), &policy, Freshness::Fresh).decision,
            Decision::Allow
        );
        assert_eq!(
            decide(input(20, false), &policy, Freshness::Fresh).decision,
            Decision::Review
        );
        assert_eq!(
            decide(input(50, false), &policy, Freshness::Fresh).decision,
            Decision::Block
        );
    }

    /// `monitor-only` never blocks on score alone — the worst a clean-of-
    /// sanctions high score can do is `review`.
    #[test]
    fn monitor_only_never_blocks_on_score() {
        let policy = builtin_policy("monitor-only").unwrap();
        assert_eq!(
            decide(input(39, false), &policy, Freshness::Fresh).decision,
            Decision::Allow
        );
        assert_eq!(
            decide(input(40, false), &policy, Freshness::Fresh).decision,
            Decision::Review
        );
        assert_eq!(
            decide(input(100, false), &policy, Freshness::Fresh).decision,
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
            let verdict = decide(input(0, true), &policy, Freshness::Fresh);
            assert_eq!(verdict.decision, Decision::Block, "policy {name}");
            assert_eq!(
                verdict.basis,
                DecisionBasis::SanctionsHardBlock,
                "policy {name}"
            );

            // High score + sanctions still reports the sanctions basis — the
            // stronger, legally-weighted reason wins the explanation.
            let verdict = decide(input(100, true), &policy, Freshness::Fresh);
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
        let verdict = decide(input(70, false), &policy, Freshness::Fresh);
        assert_eq!(verdict.policy_name, "acme-strict");
        assert_eq!(verdict.policy_version, 3);
    }

    /// An unsanctioned decision reports the score-threshold basis.
    #[test]
    fn unsanctioned_decisions_carry_the_threshold_basis() {
        let policy = builtin_policy("default").unwrap();
        for score in [0, 50, 90] {
            assert_eq!(
                decide(input(score, false), &policy, Freshness::Fresh).basis,
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

    fn stale(verified: bool) -> Freshness {
        Freshness::Stale {
            staleness: events::system::FactsStaleness {
                reason: events::system::ScreeningStaleReason::IntelligenceSlow,
                observed_at: chrono::Utc::now(),
                age_ms: 30_000,
            },
            sanctions_verified: verified,
        }
    }

    #[test]
    fn a_serve_policy_decides_stale_facts_like_fresh_ones_when_sanctions_are_verified() {
        let policy = builtin_policy("default").unwrap();
        let verdict = decide(input(10, false), &policy, stale(true));
        assert_eq!(verdict.decision, Decision::Allow);
        assert_eq!(verdict.basis, DecisionBasis::ScoreThresholds);
    }

    #[test]
    fn a_review_policy_holds_a_stale_allow() {
        let policy = builtin_policy("default")
            .unwrap()
            .with_on_stale(StalePolicy::Review);
        let verdict = decide(input(10, false), &policy, stale(true));
        assert_eq!(verdict.decision, Decision::Review);
        assert_eq!(verdict.basis, DecisionBasis::StaleFactsReview);

        // Fresh facts are unaffected by the stale setting.
        assert_eq!(
            decide(input(10, false), &policy, Freshness::Fresh).decision,
            Decision::Allow
        );
    }

    /// An unverifiable sanctions status is the platform's hold, not a policy
    /// choice: even `serve` and `monitor-only` hold a stale allow.
    #[test]
    fn unverifiable_sanctions_hold_a_stale_allow_under_every_policy() {
        for name in BUILTIN_POLICY_NAMES {
            let policy = builtin_policy(name).unwrap();
            let verdict = decide(input(0, false), &policy, stale(false));
            assert_eq!(verdict.decision, Decision::Review, "policy {name}");
            assert_eq!(
                verdict.basis,
                DecisionBasis::StaleFactsReview,
                "policy {name}"
            );
        }
    }

    #[test]
    fn staleness_never_softens_a_block_or_a_sanctions_hit() {
        let policy = builtin_policy("default").unwrap();
        assert_eq!(
            decide(input(90, false), &policy, stale(false)).decision,
            Decision::Block
        );
        let sanctioned = decide(input(0, true), &policy, stale(false));
        assert_eq!(sanctioned.decision, Decision::Block);
        assert_eq!(sanctioned.basis, DecisionBasis::SanctionsHardBlock);
        assert_eq!(
            decide(input(50, false), &policy, stale(false)).basis,
            DecisionBasis::ScoreThresholds,
            "an existing review is not relabelled"
        );
    }

    #[test]
    fn strict_holds_stale_allows_and_the_others_serve() {
        assert_eq!(
            builtin_policy("strict").unwrap().on_stale,
            StalePolicy::Review
        );
        assert_eq!(
            builtin_policy("default").unwrap().on_stale,
            StalePolicy::Serve
        );
        assert_eq!(
            builtin_policy("monitor-only").unwrap().on_stale,
            StalePolicy::Serve
        );
    }

    #[test]
    fn stale_policy_wire_forms_agree_across_serde_and_storage() {
        for policy in [StalePolicy::Serve, StalePolicy::Review] {
            assert_eq!(serde_json::to_value(policy).unwrap(), policy.as_wire());
            assert_eq!(StalePolicy::from_wire(policy.as_wire()), Some(policy));
        }
        assert_eq!(StalePolicy::from_wire("sometimes"), None);
        assert_eq!(
            serde_json::to_value(DecisionBasis::StaleFactsReview).unwrap(),
            "stale_facts_review"
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
