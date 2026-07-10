//! The rule compiler (§9, Sprint 9 t2): parse the stored definition →
//! evaluation *functions*, taken literally. Each [`Condition`] compiles to a
//! [`Matcher`] closure over [`EventCtx`]; a rule's conditions fold through its
//! [`LogicOp`]; the whole enabled set compiles **once** at load into a
//! [`CompiledRuleSet`] — never per event.
//!
//! Design decisions, and why:
//!
//! * **Closures, not a per-condition trait object.** The condition vocabulary
//!   is a closed enum (a product decision, see [`Condition`]); `match` in one
//!   compile function is exhaustive — adding a variant is a compile error
//!   here, exactly where the new matcher belongs. A `dyn ConditionMatcher`
//!   per variant would be an open abstraction over a deliberately closed set.
//! * **Link-or-fail at load** (the `DetectionPlan` discipline): compiling the
//!   set re-validates every rule and fails fast on the first bad one, so a
//!   malformed definition is a boot/refresh error with a rule id in it —
//!   never a per-event surprise. The store already guarantees validity, so
//!   this firing means a bug; it is cheap insurance, not a control path.
//! * **The compiler also emits the prefetch plan.** [`EnrichmentNeeds`] is
//!   folded from every condition in the set, so the consumer (t4) fetches
//!   exactly the intelligence the enabled rules test — one plan per rule-set
//!   swap, not N lookups per event per rule.
//! * **Snapshot swap for refresh.** Evaluation reads an immutable
//!   `Arc<CompiledRuleSet>` from [`RuleSetHandle`]; a refresh compiles a new
//!   set and swaps the pointer. Readers never lock across evaluation and
//!   never observe a half-updated set.

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};

use events::primitives::{AccountAddress, CustomerId, RuleId};

use crate::ctx::{EventCtx, EventFacts};
use crate::model::{Action, Condition, InvalidRule, LogicOp, Rule, TemporalConstraint};

/// One compiled predicate: pure, `Send + Sync`, built once at load. Boxed
/// because a rule set is a heterogeneous collection of these.
pub type Matcher = Box<dyn Fn(&EventCtx) -> bool + Send + Sync>;

/// A rule the set failed to compile — surfaced at load with the offending
/// rule's identity so the operator can find it, per the link-or-fail stance.
#[derive(Debug, thiserror::Error)]
#[error("rule {rule_id} ({name:?}) failed to compile: {source}")]
pub struct CompileError {
    pub rule_id: RuleId,
    pub name: String,
    #[source]
    pub source: InvalidRule,
}

/// A [`Rule`] compiled to its evaluable form. The definition's identity and
/// routing fields stay readable (the consumer needs `owner`/`actions` to
/// raise and deliver the alert); the matcher itself is private — evaluation
/// goes through [`instant_matches`](Self::instant_matches) or the temporal
/// engine, never by poking closures.
pub struct CompiledRule {
    pub id: RuleId,
    pub owner: CustomerId,
    pub name: String,
    pub actions: Vec<Action>,
    matcher: CompiledMatch,
}

/// Instant rules answer on the spot; temporal rules hand their compiled steps
/// to the per-`(rule_id, address)` state machine ([`crate::temporal`]).
enum CompiledMatch {
    Instant(Matcher),
    Temporal(CompiledTemporal),
}

/// A compiled §9 temporal clause. When `temporal` is present it *is* the
/// match — its steps carry the conditions to satisfy over time; the t4 API
/// layer keeps `Rule::conditions` consistent with the clause (see
/// `TemporalConstraint`'s docs).
pub enum CompiledTemporal {
    /// Steps must match in order, all within `within_blocks` of the first.
    Sequence {
        steps: Vec<Matcher>,
        within_blocks: u64,
    },
    /// One matcher must fire `count` times within a sliding window.
    Frequency {
        matcher: Matcher,
        count: u32,
        within_blocks: u64,
    },
}

impl CompiledTemporal {
    /// The clause's window length in blocks — what the t3 shell sizes each
    /// Redis key's TTL from ([`crate::state_store::TtlPolicy`]).
    pub fn within_blocks(&self) -> u64 {
        match self {
            CompiledTemporal::Sequence { within_blocks, .. }
            | CompiledTemporal::Frequency { within_blocks, .. } => *within_blocks,
        }
    }
}

impl CompiledRule {
    /// Evaluate an instant (non-temporal) rule against one event. Temporal
    /// rules return `false` here — their matching is stateful and lives in
    /// [`crate::temporal::step`].
    pub fn instant_matches(&self, ctx: &EventCtx) -> bool {
        match &self.matcher {
            CompiledMatch::Instant(matcher) => matcher(ctx),
            CompiledMatch::Temporal(_) => false,
        }
    }

    /// The compiled temporal clause, if this is a temporal rule — what the
    /// state machine steps through.
    pub fn temporal(&self) -> Option<&CompiledTemporal> {
        match &self.matcher {
            CompiledMatch::Instant(_) => None,
            CompiledMatch::Temporal(temporal) => Some(temporal),
        }
    }
}

/// Everything the consumer must prefetch into [`crate::ctx::Enrichment`] for
/// the *current* rule set — folded from every condition (top-level and
/// temporal) of every rule at compile time, so enrichment cost scales with
/// what rules actually test, not with what intelligence could answer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnrichmentNeeds {
    /// Every `HopDistance { from }` anchor named by any rule: the consumer
    /// resolves the subject address's distance to each (§8.2 adjacency).
    pub hop_anchors: BTreeSet<AccountAddress>,
    pub risk_score: bool,
    pub entity_labels: bool,
    pub sanctions: bool,
    pub counterparty_labels: bool,
    pub first_active_block: bool,
}

impl EnrichmentNeeds {
    fn absorb(&mut self, condition: &Condition) {
        match condition {
            // Event predicates: answered by the event itself, nothing to fetch.
            Condition::TransferAmount { .. } | Condition::IncidentKind { .. } => {}
            Condition::InteractedWith { label_kind, .. } => {
                self.counterparty_labels |= label_kind.is_some();
            }
            Condition::EntityLabel { .. } => self.entity_labels = true,
            Condition::RiskScore { .. } => self.risk_score = true,
            Condition::SanctionMatch { .. } => self.sanctions = true,
            Condition::HopDistance { from, .. } => {
                self.hop_anchors.insert(*from);
            }
            Condition::NewAddress { .. } => self.first_active_block = true,
        }
    }
}

/// The compiled, immutable evaluation set — one per load/refresh, shared via
/// [`RuleSetHandle`].
pub struct CompiledRuleSet {
    rules: Vec<CompiledRule>,
    needs: EnrichmentNeeds,
}

// Manual: matchers are closures, so `derive(Debug)` can't; identity + plan is
// what an operator log wants anyway.
impl std::fmt::Debug for CompiledRuleSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledRuleSet")
            .field("rules", &self.rules.len())
            .field("needs", &self.needs)
            .finish()
    }
}

impl CompiledRuleSet {
    /// Compile every rule or fail with the first offender (link-or-fail; see
    /// the module docs). The input is what [`crate::store::RuleStore::enabled_rules`]
    /// returns — this function doesn't filter `enabled` itself, so a test can
    /// compile exactly the set it means to.
    pub fn compile(rules: &[Rule]) -> Result<Self, CompileError> {
        let mut needs = EnrichmentNeeds::default();
        let compiled = rules
            .iter()
            .map(|rule| {
                rule.for_each_condition(|condition| needs.absorb(condition));
                compile_rule(rule)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            rules: compiled,
            needs,
        })
    }

    /// Every instant rule that matches this event — the fast, stateless half
    /// of evaluation. Temporal rules are driven separately (see
    /// [`temporal_rules`](Self::temporal_rules) and [`crate::temporal::step`]).
    pub fn evaluate<'a>(&'a self, ctx: &EventCtx) -> Vec<&'a CompiledRule> {
        self.rules
            .iter()
            .filter(|rule| rule.instant_matches(ctx))
            .collect()
    }

    /// The temporal rules the state-machine shell steps for each event.
    pub fn temporal_rules(&self) -> impl Iterator<Item = &CompiledRule> {
        self.rules.iter().filter(|rule| rule.temporal().is_some())
    }

    /// The prefetch plan for this set (see [`EnrichmentNeeds`]).
    pub fn needs(&self) -> &EnrichmentNeeds {
        &self.needs
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// The live rule set the evaluation path reads and a refresh swaps — snapshot
/// semantics: [`load`](Self::load) hands back an `Arc` the caller evaluates
/// against for as long as it likes (a concurrent swap can't tear it), and
/// [`swap`](Self::swap) publishes a freshly compiled set atomically. The lock
/// is held only for the pointer clone/replace, never across evaluation.
pub struct RuleSetHandle {
    inner: RwLock<Arc<CompiledRuleSet>>,
}

impl RuleSetHandle {
    pub fn new(set: CompiledRuleSet) -> Self {
        Self {
            inner: RwLock::new(Arc::new(set)),
        }
    }

    /// The current snapshot. Cheap (one `Arc` clone) — call per event or per
    /// batch, whichever consistency the caller wants.
    pub fn load(&self) -> Arc<CompiledRuleSet> {
        self.inner.read().expect("rule-set lock").clone()
    }

    /// Publish a new snapshot. In-flight evaluations against the old `Arc`
    /// finish undisturbed; the next [`load`](Self::load) sees the new set.
    pub fn swap(&self, set: CompiledRuleSet) {
        *self.inner.write().expect("rule-set lock") = Arc::new(set);
    }
}

/// Test-only: a rule's compiled temporal clause, for driving the state
/// machine directly ([`crate::temporal`]'s tests) without going through a set.
#[cfg(test)]
pub(crate) fn temporal_clause(rule: &Rule) -> CompiledTemporal {
    match compile_rule(rule).expect("valid rule").matcher {
        CompiledMatch::Temporal(temporal) => temporal,
        CompiledMatch::Instant(_) => panic!("rule has no temporal clause"),
    }
}

/// Compile one rule (validated first — see the module's link-or-fail note).
fn compile_rule(rule: &Rule) -> Result<CompiledRule, CompileError> {
    rule.validate().map_err(|source| CompileError {
        rule_id: rule.id,
        name: rule.name.clone(),
        source,
    })?;
    let matcher = match &rule.temporal {
        None => CompiledMatch::Instant(compile_logic(&rule.conditions, rule.logic)),
        Some(TemporalConstraint::Sequence {
            events,
            within_blocks,
        }) => CompiledMatch::Temporal(CompiledTemporal::Sequence {
            steps: events.iter().map(compile_condition).collect(),
            within_blocks: *within_blocks,
        }),
        Some(TemporalConstraint::Frequency {
            condition,
            count,
            within_blocks,
        }) => CompiledMatch::Temporal(CompiledTemporal::Frequency {
            matcher: compile_condition(condition),
            count: *count,
            within_blocks: *within_blocks,
        }),
    };
    Ok(CompiledRule {
        id: rule.id,
        owner: rule.owner,
        name: rule.name.clone(),
        actions: rule.actions.clone(),
        matcher,
    })
}

/// Fold a condition list through its [`LogicOp`] into one matcher.
fn compile_logic(conditions: &[Condition], logic: LogicOp) -> Matcher {
    let matchers: Vec<Matcher> = conditions.iter().map(compile_condition).collect();
    match logic {
        LogicOp::All => Box::new(move |ctx| matchers.iter().all(|matcher| matcher(ctx))),
        LogicOp::Any => Box::new(move |ctx| matchers.iter().any(|matcher| matcher(ctx))),
        LogicOp::Not => Box::new(move |ctx| !matchers.iter().any(|matcher| matcher(ctx))),
    }
}

/// Compile one condition to its closure. Each arm copies the data it tests
/// out of the definition (everything here is `Copy` or small), so the closure
/// owns its parameters and the `Rule` can be dropped after compile.
fn compile_condition(condition: &Condition) -> Matcher {
    match condition {
        Condition::TransferAmount {
            chain,
            token,
            gt,
            lt,
        } => {
            let (chain, token, gt, lt) = (*chain, *token, *gt, *lt);
            Box::new(move |ctx| match &ctx.facts {
                EventFacts::Transfer {
                    chain: ev_chain,
                    token: ev_token,
                    amount,
                    ..
                } => {
                    *ev_chain == chain
                        && *ev_token == token
                        && gt.is_none_or(|bound| *amount > bound)
                        && lt.is_none_or(|bound| *amount < bound)
                }
                _ => false,
            })
        }
        Condition::InteractedWith {
            address,
            label_kind,
        } => {
            let (address, label_kind) = (*address, *label_kind);
            Box::new(move |ctx| match &ctx.facts {
                // Both selectors, when present, describe the *same*
                // counterparty — so they AND.
                EventFacts::Transfer { counterparty, .. } => {
                    address.is_none_or(|wanted| *counterparty == wanted)
                        && label_kind
                            .is_none_or(|kind| ctx.enrichment.counterparty_labels.contains(&kind))
                }
                _ => false,
            })
        }
        Condition::IncidentKind {
            kind,
            min_confidence,
        } => {
            let (kind, min) = (*kind, *min_confidence);
            Box::new(move |ctx| match &ctx.facts {
                EventFacts::Incident {
                    kind: ev_kind,
                    confidence,
                } => *ev_kind == kind && confidence.get() >= min.get(),
                _ => false,
            })
        }
        Condition::EntityLabel {
            kind,
            min_confidence,
        } => {
            let (kind, min) = (*kind, *min_confidence);
            Box::new(move |ctx| {
                ctx.enrichment
                    .entity_labels
                    .iter()
                    .any(|(label, confidence)| *label == kind && confidence.get() >= min.get())
            })
        }
        Condition::RiskScore { gt, lt } => {
            let (gt, lt) = (*gt, *lt);
            Box::new(move |ctx| {
                ctx.enrichment.risk_score.is_some_and(|score| {
                    gt.is_none_or(|bound| score > bound) && lt.is_none_or(|bound| score < bound)
                })
            })
        }
        Condition::SanctionMatch { list } => {
            let list = list.clone();
            Box::new(move |ctx| match &list {
                Some(list) => ctx.enrichment.sanction_lists.contains(list),
                None => !ctx.enrichment.sanction_lists.is_empty(),
            })
        }
        Condition::HopDistance { from, max_hops } => {
            let (from, max_hops) = (*from, *max_hops);
            Box::new(move |ctx| {
                ctx.enrichment
                    .hop_distance
                    .get(&from)
                    .is_some_and(|hops| *hops <= max_hops)
            })
        }
        Condition::NewAddress {
            active_within_blocks,
        } => {
            let window = *active_within_blocks;
            Box::new(move |ctx| {
                ctx.enrichment
                    .first_active_block
                    .is_some_and(|first| ctx.block.saturating_sub(first) < window)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctx::Enrichment;
    use events::primitives::{AlertKind, Chain, Confidence, LabelKind};
    use rust_decimal::Decimal;

    fn addr(byte: u8) -> AccountAddress {
        AccountAddress::repeat_byte(byte)
    }

    /// A transfer event ctx with empty enrichment.
    fn transfer(
        amount: i64,
        token: Option<AccountAddress>,
        counterparty: AccountAddress,
    ) -> EventCtx {
        EventCtx {
            address: addr(0x01),
            block: 1_000,
            facts: EventFacts::Transfer {
                chain: Chain::ETHEREUM,
                token,
                amount: Decimal::new(amount, 0),
                counterparty,
            },
            enrichment: Enrichment::default(),
        }
    }

    /// A state-changed ctx (state predicates read only the enrichment).
    fn state(enrichment: Enrichment) -> EventCtx {
        EventCtx {
            address: addr(0x01),
            block: 1_000,
            facts: EventFacts::StateChanged,
            enrichment,
        }
    }

    fn matches(condition: &Condition, ctx: &EventCtx) -> bool {
        compile_condition(condition)(ctx)
    }

    #[test]
    fn transfer_amount_matcher() {
        let usdc = addr(0xAA);
        let cond = Condition::TransferAmount {
            chain: Chain::ETHEREUM,
            token: Some(usdc),
            gt: Some(Decimal::new(1_000_000, 0)),
            lt: None,
        };
        assert!(matches(&cond, &transfer(2_000_000, Some(usdc), addr(0x02))));
        // At the bound is not strictly greater.
        assert!(!matches(
            &cond,
            &transfer(1_000_000, Some(usdc), addr(0x02))
        ));
        // Wrong token / native asset don't match a token-scoped condition.
        assert!(!matches(
            &cond,
            &transfer(2_000_000, Some(addr(0xBB)), addr(0x02))
        ));
        assert!(!matches(&cond, &transfer(2_000_000, None, addr(0x02))));
        // Non-transfer events never match an event predicate.
        assert!(!matches(&cond, &state(Enrichment::default())));
    }

    #[test]
    fn interacted_with_selectors_and() {
        let mixer = addr(0x99);
        let both = Condition::InteractedWith {
            address: Some(mixer),
            label_kind: Some(LabelKind::MixerUser),
        };
        let mut ctx = transfer(10, None, mixer);
        // Right counterparty but unlabeled: the label selector fails.
        assert!(!matches(&both, &ctx));
        ctx.enrichment
            .counterparty_labels
            .insert(LabelKind::MixerUser);
        assert!(matches(&both, &ctx));
        // Wrong counterparty, right label: the address selector fails.
        let mut other = transfer(10, None, addr(0x42));
        other
            .enrichment
            .counterparty_labels
            .insert(LabelKind::MixerUser);
        assert!(!matches(&both, &other));
    }

    #[test]
    fn incident_kind_confidence_gate() {
        let cond = Condition::IncidentKind {
            kind: AlertKind::Sandwich,
            min_confidence: Confidence::new(0.8),
        };
        let incident = |kind, conf: f64| EventCtx {
            address: addr(0x01),
            block: 1_000,
            facts: EventFacts::Incident {
                kind,
                confidence: Confidence::new(conf),
            },
            enrichment: Enrichment::default(),
        };
        assert!(matches(&cond, &incident(AlertKind::Sandwich, 0.9)));
        // min_confidence is inclusive.
        assert!(matches(&cond, &incident(AlertKind::Sandwich, 0.8)));
        assert!(!matches(&cond, &incident(AlertKind::Sandwich, 0.7)));
        assert!(!matches(&cond, &incident(AlertKind::Arbitrage, 0.9)));
    }

    #[test]
    fn state_predicates_read_enrichment() {
        // RiskScore: absent score never matches (no score ≠ score 0).
        let risky = Condition::RiskScore {
            gt: Some(80),
            lt: None,
        };
        assert!(!matches(&risky, &state(Enrichment::default())));
        let mut enrichment = Enrichment {
            risk_score: Some(91),
            ..Enrichment::default()
        };
        assert!(matches(&risky, &state(enrichment.clone())));

        // EntityLabel with the confidence gate.
        let labeled = Condition::EntityLabel {
            kind: LabelKind::MevBot,
            min_confidence: Confidence::new(0.7),
        };
        enrichment
            .entity_labels
            .push((LabelKind::MevBot, Confidence::new(0.4)));
        assert!(!matches(&labeled, &state(enrichment.clone())));
        enrichment
            .entity_labels
            .push((LabelKind::MevBot, Confidence::new(0.9)));
        assert!(matches(&labeled, &state(enrichment.clone())));

        // SanctionMatch: named list vs any list.
        let any_list = Condition::SanctionMatch { list: None };
        let ofac = Condition::SanctionMatch {
            list: Some("ofac_sdn".into()),
        };
        assert!(!matches(&any_list, &state(enrichment.clone())));
        enrichment.sanction_lists.insert("eu_consolidated".into());
        assert!(matches(&any_list, &state(enrichment.clone())));
        assert!(!matches(&ofac, &state(enrichment.clone())));
        enrichment.sanction_lists.insert("ofac_sdn".into());
        assert!(matches(&ofac, &state(enrichment.clone())));

        // HopDistance: within bound; missing anchor = no match.
        let near = Condition::HopDistance {
            from: addr(0xEE),
            max_hops: 3,
        };
        assert!(!matches(&near, &state(enrichment.clone())));
        enrichment.hop_distance.insert(addr(0xEE), 3);
        assert!(matches(&near, &state(enrichment.clone())));
        enrichment.hop_distance.insert(addr(0xEE), 4);
        assert!(!matches(&near, &state(enrichment.clone())));

        // NewAddress: first activity within the window of ctx.block.
        let fresh = Condition::NewAddress {
            active_within_blocks: 100,
        };
        enrichment.first_active_block = Some(950);
        assert!(matches(&fresh, &state(enrichment.clone())));
        enrichment.first_active_block = Some(900);
        assert!(!matches(&fresh, &state(enrichment))); // exactly 100 blocks old
    }

    #[test]
    fn logic_ops_fold() {
        let usdc = addr(0xAA);
        let big = Condition::TransferAmount {
            chain: Chain::ETHEREUM,
            token: Some(usdc),
            gt: Some(Decimal::new(100, 0)),
            lt: None,
        };
        let risky = Condition::RiskScore {
            gt: Some(80),
            lt: None,
        };
        let conditions = vec![big, risky];

        let mut ctx = transfer(200, Some(usdc), addr(0x02));
        // Big transfer, low risk: All fails, Any passes, Not fails.
        assert!(!compile_logic(&conditions, LogicOp::All)(&ctx));
        assert!(compile_logic(&conditions, LogicOp::Any)(&ctx));
        assert!(!compile_logic(&conditions, LogicOp::Not)(&ctx));

        ctx.enrichment.risk_score = Some(95);
        assert!(compile_logic(&conditions, LogicOp::All)(&ctx));

        // Not: fires only when *no* condition matches.
        let quiet = state(Enrichment::default());
        assert!(compile_logic(&conditions, LogicOp::Not)(&quiet));
    }

    #[test]
    fn set_compiles_needs_and_splits_instant_from_temporal() {
        use crate::test_support::rules_for_compile_tests;
        let rules = rules_for_compile_tests();
        let set = CompiledRuleSet::compile(&rules).expect("compile");
        assert_eq!(set.len(), 2);
        assert_eq!(set.temporal_rules().count(), 1);

        // The prefetch plan covers exactly what the two rules test.
        let needs = set.needs();
        assert!(needs.counterparty_labels);
        assert!(needs.risk_score);
        assert!(!needs.sanctions);
        assert!(!needs.entity_labels);
        assert_eq!(needs.hop_anchors.len(), 0);
    }

    #[test]
    fn compile_is_link_or_fail() {
        use crate::test_support::rules_for_compile_tests;
        let mut rules = rules_for_compile_tests();
        rules[1].conditions = vec![Condition::RiskScore { gt: None, lt: None }];
        let err = CompiledRuleSet::compile(&rules).expect_err("must fail");
        assert_eq!(err.rule_id, rules[1].id);
        assert_eq!(
            err.source,
            InvalidRule::UnboundedRange { what: "risk_score" }
        );
    }

    #[test]
    fn handle_swaps_snapshots_atomically() {
        let rules = crate::test_support::rules_for_compile_tests();
        let handle = RuleSetHandle::new(CompiledRuleSet::compile(&rules).expect("compile"));
        let before = handle.load();
        assert_eq!(before.len(), 2);

        handle.swap(CompiledRuleSet::compile(&[]).expect("compile empty"));
        // The old snapshot is undisturbed; new loads see the new set.
        assert_eq!(before.len(), 2);
        assert!(handle.load().is_empty());
    }
}
