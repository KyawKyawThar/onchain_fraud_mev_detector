//! What a draft *kind* is, as one object (§20.4).
//!
//! # The problem this solves
//!
//! A draft kind is a vertical: it knows what to fetch, what to ask, whether the
//! answer is usable, and what the audit trail should say about it. Before this
//! module those four lived in four places — the generator built the request,
//! a free `land()` function in the store decided the status with a `match` on
//! kind, `announce::drafted_envelope` decided the event with a second `match`,
//! and the pool decided what to fetch by assuming.
//!
//! Splitting a contract across `match` arms in three modules has one specific
//! failure mode, and it is the worst one available here: **adding a kind and
//! forgetting its answer-check is silent.** The new kind falls through to the
//! default arm, lands `ready`, and reaches a customer with no boundary applied
//! at all — which is the single thing §20.4 exists to prevent. The compiler
//! cannot help, because a `match` with a catch-all is exhaustive.
//!
//! [`DraftCapability`] makes the vertical one trait, so a kind that cannot
//! answer all four questions does not compile, and [`CheckRegistry`] is
//! **exhaustive over [`DraftKind`]** at boot, so a kind nobody implemented is a
//! refused rollout rather than an unguarded draft. Same link-or-fail discipline
//! as `detection::DetectionPlan` and `llm::PromptRegistry`, applied to the
//! place where it buys the most.
//!
//! # Two registries, on purpose
//!
//! They answer different questions and they are deliberately not the same set:
//!
//! * [`CheckRegistry`] — *what a completion becomes*. Universal: every pod must
//!   be able to land every kind, because the cross-pod cache lands rows other
//!   pods enqueued. Pure, and it is what the **store** holds.
//! * [`crate::worker::GeneratorRegistry`] — *what this pod may run*. A subset:
//!   its kinds are the claim filter, so a pod cannot take a durable lease on
//!   work it has no generator for. It is what the **pool** holds.
//!
//! One trait, two registries built from it. A single registry would force one
//! of the two invariants to give: either a pod could claim work it cannot
//! finish, or it could not land an answer it already paid for.

use std::collections::BTreeMap;
use std::sync::Arc;

use events::EventEnvelope;
use llm::{Completion, CompletionRequest};
use uuid::Uuid;

use crate::announce::DraftedFacts;
use crate::audit::AuditStream;
use crate::draft::{DraftError, NarrativeDrafter};
use crate::grounding::{GroundingPolicy, GroundingSummary};
use crate::model::{ClaimedJob, DraftKind, DraftStatus};
use crate::rule_draft::RuleDrafter;

/// What a capability needs fetched before it can render a prompt.
///
/// Declared by the capability so the worker's fetch is *driven* by the roster
/// rather than assumed from it. Without this the pool read an incident audit
/// stream before every job of every kind — which for a rule draft means an
/// HTTP round trip for an id that is not an incident, answered empty, and then
/// a permanently failed job whose grounding was in the row all along.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grounding {
    /// The subject's audit stream, read from event-store (§4).
    IncidentAuditStream,
    /// Nothing external — the job row carries the whole input
    /// ([`crate::model::DraftJob::source_text`]).
    SourceText,
}

/// What a completion becomes once its kind has checked it — the single value
/// that turns a provider response into stored state.
///
/// Every path that lands an answer produces one of these through
/// [`CheckRegistry::apply`]: the worker's own `finish`, the cross-pod cache's
/// digest-keyed write, and the backfill's batch results. That is not tidiness —
/// it is the only way the three can agree on when a draft is `ready`. A cache
/// write that skipped the check would let a rebalance promote a draft the
/// worker would have blocked, which is the sort of divergence nobody notices
/// until a reviewer approves an ungrounded document.
#[derive(Debug, Clone, PartialEq)]
pub struct Landing {
    pub status: DraftStatus,
    /// The citation check's findings — `None` for kinds that make no citable
    /// claims (a rule draft has a compiler, not citations).
    pub grounding: Option<GroundingSummary>,
    /// What `grounded_event_ids` becomes: the cited subset for a checked
    /// narrative, and the window untouched otherwise.
    pub grounded_event_ids: Vec<Uuid>,
    pub last_error: Option<String>,
    /// Why this kind's boundary refused the draft, as a closed metrics label
    /// (`no_claims`/`uncited`/`fabricated` for a narrative;
    /// `malformed`/`invalid`/`uncompilable` for a rule), or `None` when it
    /// passed.
    ///
    /// Carried out of the check rather than counted inside it: a check is a
    /// pure function, and a pure function that also increments a counter cannot
    /// be used to *ask* what would happen — which is exactly what a dry run, a
    /// threshold sweep and t5's grounding audit all need to do. The one write
    /// path records it (see `PgDraftStore::write_landing`).
    pub rejected: Option<&'static str>,
}

impl Landing {
    /// The answer is usable. `grounded` is what the draft now stands on.
    pub fn ready(grounded: Vec<Uuid>) -> Self {
        Self {
            status: DraftStatus::Ready,
            grounding: None,
            grounded_event_ids: grounded,
            last_error: None,
            rejected: None,
        }
    }

    /// The call succeeded, was billed, and produced something unusable.
    ///
    /// `blocked`, never `failed`: re-running buys another answer with the same
    /// fault at full price. A human looks at `last_error` — which is exactly
    /// the split `blocked` exists for.
    pub fn blocked(reason: &'static str, message: impl Into<String>, grounded: Vec<Uuid>) -> Self {
        Self {
            status: DraftStatus::Blocked,
            grounding: None,
            grounded_event_ids: grounded,
            last_error: Some(message.into()),
            rejected: Some(reason),
        }
    }

    /// Attach the citation summary a narrative's check produced.
    pub fn with_grounding(mut self, summary: GroundingSummary) -> Self {
        self.grounding = Some(summary);
        self
    }
}

/// Everything one draft kind knows about itself.
///
/// Object-safe, and every method is pure or near-pure: a capability holds no
/// store, no client and no clock, so the whole vertical is testable with none
/// of them. The four questions are deliberately on **one** trait — a kind that
/// can be asked but not checked is the failure mode this replaces, and the way
/// to make it impossible is to make it not compile.
pub trait DraftCapability: Send + Sync + std::fmt::Debug {
    /// Which kind this capability serves.
    fn kind(&self) -> DraftKind;

    /// What the worker must fetch before [`Self::build_request`].
    ///
    /// No default: a new capability that forgot to answer would inherit
    /// somebody else's grounding, which is the bug this exists to prevent.
    fn grounding(&self) -> Grounding;

    /// Render the model request. `audit` is the grounding the worker fetched —
    /// empty for a [`Grounding::SourceText`] kind.
    fn build_request(
        &self,
        job: &ClaimedJob,
        audit: &AuditStream,
    ) -> Result<CompletionRequest, DraftError>;

    /// **The boundary.** Decide what this completion becomes.
    ///
    /// Called only for a completion that already stopped cleanly — the
    /// truncation/refusal guard is universal and lives in
    /// [`CheckRegistry::apply`], so an implementation never re-derives it.
    /// `window` is the event ids the attempt recorded showing the model.
    ///
    /// Pure: no I/O, no metrics, no clock.
    fn check(&self, window: &[Uuid], completion: &Completion) -> Landing;

    /// The audit record this kind files when a draft lands `ready`, or `None`
    /// if these facts do not describe an announceable draft.
    ///
    /// Pure, for the same reason: the mapping is where §20.4's provenance
    /// requirements actually land, so it must be testable without a store, a
    /// broker or a model.
    fn announce(&self, facts: DraftedFacts<'_>) -> Option<EventEnvelope>;
}

/// Why a roster could not be linked.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("two capabilities registered for draft kind {kind}: {first} and {second}")]
    Duplicate {
        kind: &'static str,
        first: String,
        second: String,
    },
    #[error("no draft capabilities linked — this pod could never claim any work")]
    Empty,
    #[error(
        "draft kind {kind} has no capability — every kind must be checkable on every pod, or an \
         answer for it would land with no boundary applied"
    )]
    Missing { kind: &'static str },
}

/// Every kind's boundary, resolved once at boot — what the **store** holds.
///
/// Exhaustive over [`DraftKind`] by construction ([`CheckRegistry::link`]).
/// That is the property worth the type: a kind added to the enum without a
/// capability fails the rollout, instead of landing `ready` with nothing having
/// looked at it.
#[derive(Debug)]
pub struct CheckRegistry {
    by_kind: BTreeMap<DraftKind, Arc<dyn DraftCapability>>,
}

impl Default for CheckRegistry {
    /// The shipped roster under the default grounding policy.
    fn default() -> Self {
        Self::with_grounding(GroundingPolicy::default())
    }
}

impl CheckRegistry {
    /// The shipped roster, with the deployment's citation policy applied to the
    /// one kind that has citations.
    ///
    /// Infallible: the roster is a literal in this function, and its
    /// exhaustiveness is asserted by a test rather than deferred to a runtime a
    /// deployment would discover.
    pub fn with_grounding(policy: GroundingPolicy) -> Self {
        Self::link(vec![
            Arc::new(NarrativeDrafter::new().with_grounding(policy)),
            Arc::new(RuleDrafter::new()),
        ])
        .expect("the shipped roster covers every draft kind exactly once")
    }

    /// Link a roster, requiring **every** [`DraftKind`] exactly once.
    pub fn link(capabilities: Vec<Arc<dyn DraftCapability>>) -> Result<Self, RegistryError> {
        let by_kind = index(capabilities)?;
        for kind in DraftKind::ALL {
            if !by_kind.contains_key(kind) {
                return Err(RegistryError::Missing {
                    kind: kind.as_wire_str(),
                });
            }
        }
        Ok(Self { by_kind })
    }

    pub fn get(&self, kind: DraftKind) -> Option<&Arc<dyn DraftCapability>> {
        self.by_kind.get(&kind)
    }

    /// Apply the §20.4 boundary to one completion.
    ///
    /// The universal half is here and the kind-specific half is delegated. A
    /// truncated or declined answer is never handed to a kind's check: there is
    /// nothing to check, and reporting "0 of 0 claims cited" over the top of a
    /// refusal would bury the actual reason in a derived one.
    pub fn apply(&self, kind: DraftKind, window: &[Uuid], completion: &Completion) -> Landing {
        if !completion.stop_reason.is_complete() {
            return Landing {
                rejected: None,
                ..Landing::blocked(
                    "unusable",
                    format!("unusable answer: {}", completion.stop_reason.as_str()),
                    window.to_vec(),
                )
            };
        }
        match self.get(kind) {
            Some(capability) => capability.check(window, completion),
            // Unreachable while `link` is exhaustive, and it fails *closed*: an
            // answer nobody can check is not an answer anybody may act on.
            None => Landing::blocked(
                "unservable",
                format!("no capability for draft kind {}", kind.as_wire_str()),
                window.to_vec(),
            ),
        }
    }

    /// The audit record for a landed draft of this kind.
    pub fn announce(&self, kind: DraftKind, facts: DraftedFacts<'_>) -> Option<EventEnvelope> {
        self.get(kind)?.announce(facts)
    }
}

/// Index a roster by kind, refusing duplicates and an empty set.
///
/// Shared by both registries so "two capabilities for one kind" has one
/// answer — a wiring bug that fails the rollout, never a last-one-wins that
/// shows up as drafts written by whichever `Arc` was second in a `Vec`.
pub(crate) fn index(
    capabilities: Vec<Arc<dyn DraftCapability>>,
) -> Result<BTreeMap<DraftKind, Arc<dyn DraftCapability>>, RegistryError> {
    let mut by_kind: BTreeMap<DraftKind, Arc<dyn DraftCapability>> = BTreeMap::new();
    for capability in capabilities {
        if let Some(existing) = by_kind.get(&capability.kind()) {
            return Err(RegistryError::Duplicate {
                kind: capability.kind().as_wire_str(),
                first: format!("{existing:?}"),
                second: format!("{capability:?}"),
            });
        }
        by_kind.insert(capability.kind(), capability);
    }
    if by_kind.is_empty() {
        return Err(RegistryError::Empty);
    }
    Ok(by_kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::completion;
    use llm::{StopReason, TokenUsage};
    use strum::IntoEnumIterator;

    /// The guarantee the whole module exists for: a kind with no capability
    /// cannot reach production, because the roster refuses to link.
    #[test]
    fn the_shipped_roster_covers_every_draft_kind() {
        let registry = CheckRegistry::default();
        for kind in DraftKind::iter() {
            assert!(
                registry.get(kind).is_some(),
                "{kind:?} has no capability — an answer for it would land unchecked"
            );
        }
    }

    #[test]
    fn a_roster_missing_a_kind_is_a_refused_boot() {
        let err = CheckRegistry::link(vec![Arc::new(RuleDrafter::new())])
            .expect_err("the narrative kind is unchecked");
        assert!(matches!(err, RegistryError::Missing { .. }));

        let err = CheckRegistry::link(vec![
            Arc::new(RuleDrafter::new()),
            Arc::new(RuleDrafter::new()),
        ])
        .expect_err("two capabilities for one kind");
        assert!(matches!(err, RegistryError::Duplicate { .. }));

        assert!(matches!(
            CheckRegistry::link(Vec::new()).expect_err("empty"),
            RegistryError::Empty
        ));
    }

    /// The universal guard: a truncation or a refusal never reaches a kind's
    /// own check, so the stored reason is the provider's and not a derived one.
    #[test]
    fn an_incomplete_answer_is_blocked_before_any_kind_sees_it() {
        let registry = CheckRegistry::default();
        for stop_reason in [
            StopReason::MaxTokens,
            StopReason::Refusal { category: None },
        ] {
            for kind in DraftKind::iter() {
                let landing = registry.apply(
                    kind,
                    &[Uuid::from_u128(1)],
                    &Completion {
                        text: "half a".into(),
                        stop_reason: stop_reason.clone(),
                        model: "claude-opus-5".into(),
                        usage: TokenUsage::default(),
                    },
                );
                assert_eq!(landing.status, DraftStatus::Blocked);
                let reason: String = stop_reason.as_str().to_string();
                assert!(landing.last_error.unwrap().contains(&reason));
                assert!(
                    landing.grounding.is_none(),
                    "a refusal has no citations to report"
                );
            }
        }
    }

    /// Fail-closed: if a kind's capability were ever missing at runtime, the
    /// answer is blocked rather than promoted.
    #[test]
    fn a_kind_with_no_capability_blocks_rather_than_readies() {
        // Built past `link`'s exhaustiveness check on purpose — this is the
        // state `link` makes unreachable, and the assertion is what the code
        // does if it is ever reached anyway.
        let partial = CheckRegistry {
            by_kind: index(vec![Arc::new(RuleDrafter::new())]).unwrap(),
        };
        let landing = partial.apply(
            DraftKind::IncidentNarrative,
            &[],
            &completion("a narrative [00000000-0000-0000-0000-000000000001]."),
        );
        assert_eq!(landing.status, DraftStatus::Blocked);
        assert_eq!(landing.rejected, Some("unservable"));
    }
}
