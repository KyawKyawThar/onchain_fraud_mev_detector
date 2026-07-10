//! Test doubles and builders for the crate's seams — the zero-infrastructure
//! implementations the t2–t5 consumers (and this crate's own tests) run
//! against, mirroring `intelligence::test_util`:
//!
//! * [`InMemoryRuleStore`] — the [`RuleStore`] double, honouring the *semantics*
//!   the Postgres implementation promises (idempotent keyed creates, per-owner
//!   name uniqueness among live rules, owner-scoped reads/writes — the
//!   isolation contract — soft delete, validation before insert). A test that
//!   passes here means the consumer logic is right; the `#[ignore]` integration
//!   tests prove the real store honours the same contract.
//! * [`RecordingActionSink`] — the [`ActionSink`] double: records every
//!   delivery instead of speaking HTTP, so evaluation tests assert on *what
//!   would have been sent*.
//! * [`RuleBuilder`] — the one place tests construct [`Rule`]s, so fixture
//!   noise doesn't spread and a model-field addition is a one-file change.

use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::primitives::{CustomerId, RuleId};

use crate::action::{ActionSink, DeliveryError, RuleAlert};
use crate::model::{Action, Condition, LogicOp, Rule, TemporalConstraint};
use crate::store::{CreateRuleOutcome, RuleStore, StoreError};

/// In-memory implementation of the [`RuleStore`] seam.
#[derive(Default)]
pub struct InMemoryRuleStore {
    inner: Mutex<Vec<StoredRule>>,
}

/// One stored rule + the row metadata the queries filter on.
struct StoredRule {
    rule: Rule,
    created_at: DateTime<Utc>,
    deleted_at: Option<DateTime<Utc>>,
}

impl InMemoryRuleStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RuleStore for InMemoryRuleStore {
    async fn create_rule(
        &self,
        rule: &Rule,
        at: DateTime<Utc>,
    ) -> Result<CreateRuleOutcome, StoreError> {
        rule.validate()?;
        let mut state = self.inner.lock().expect("store lock");
        // rule_id is the idempotency key — live or deleted, ids never reuse.
        if state.iter().any(|stored| stored.rule.id == rule.id) {
            return Ok(CreateRuleOutcome::AlreadyExists);
        }
        // Per-owner name uniqueness among *live* rules (the partial index).
        if state.iter().any(|stored| {
            stored.deleted_at.is_none()
                && stored.rule.owner == rule.owner
                && stored.rule.name == rule.name
        }) {
            return Ok(CreateRuleOutcome::NameTaken);
        }
        state.push(StoredRule {
            rule: rule.clone(),
            created_at: at,
            deleted_at: None,
        });
        Ok(CreateRuleOutcome::Created)
    }

    async fn rule(&self, owner: CustomerId, rule_id: RuleId) -> Result<Option<Rule>, StoreError> {
        let state = self.inner.lock().expect("store lock");
        Ok(state
            .iter()
            .find(|stored| {
                stored.deleted_at.is_none()
                    && stored.rule.id == rule_id
                    && stored.rule.owner == owner
            })
            .map(|stored| stored.rule.clone()))
    }

    async fn rules_for_owner(&self, owner: CustomerId) -> Result<Vec<Rule>, StoreError> {
        let state = self.inner.lock().expect("store lock");
        let mut live: Vec<&StoredRule> = state
            .iter()
            .filter(|stored| stored.deleted_at.is_none() && stored.rule.owner == owner)
            .collect();
        live.sort_by_key(|stored| (stored.created_at, stored.rule.id.0));
        Ok(live.into_iter().map(|stored| stored.rule.clone()).collect())
    }

    async fn set_enabled(
        &self,
        owner: CustomerId,
        rule_id: RuleId,
        enabled: bool,
        _at: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        let mut state = self.inner.lock().expect("store lock");
        let Some(stored) = state.iter_mut().find(|stored| {
            stored.deleted_at.is_none() && stored.rule.id == rule_id && stored.rule.owner == owner
        }) else {
            return Ok(false);
        };
        if stored.rule.enabled == enabled {
            return Ok(false);
        }
        stored.rule.enabled = enabled;
        Ok(true)
    }

    async fn delete_rule(
        &self,
        owner: CustomerId,
        rule_id: RuleId,
        at: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        let mut state = self.inner.lock().expect("store lock");
        let Some(stored) = state.iter_mut().find(|stored| {
            stored.deleted_at.is_none() && stored.rule.id == rule_id && stored.rule.owner == owner
        }) else {
            return Ok(false);
        };
        stored.deleted_at = Some(at);
        Ok(true)
    }

    async fn enabled_rules(&self) -> Result<Vec<Rule>, StoreError> {
        let state = self.inner.lock().expect("store lock");
        let mut live: Vec<&StoredRule> = state
            .iter()
            .filter(|stored| stored.deleted_at.is_none() && stored.rule.enabled)
            .collect();
        live.sort_by_key(|stored| (stored.created_at, stored.rule.id.0));
        Ok(live.into_iter().map(|stored| stored.rule.clone()).collect())
    }
}

// ── Rule builder ─────────────────────────────────────────────────

/// Fluent test-data builder for [`Rule`]. Starts from a minimal *valid* rule
/// (a `RiskScore > 80` condition and a webhook action are filled in by
/// [`build`](Self::build) if none are set), so a test states only what it is
/// about — the §9 equivalent of `LabelRecord::new`'s defaulting.
pub struct RuleBuilder {
    rule: Rule,
}

impl RuleBuilder {
    pub fn new(owner: CustomerId) -> Self {
        Self {
            rule: Rule {
                id: RuleId::new(),
                owner,
                name: "test-rule".into(),
                enabled: true,
                conditions: Vec::new(),
                logic: LogicOp::All,
                temporal: None,
                actions: Vec::new(),
            },
        }
    }

    pub fn id(mut self, id: RuleId) -> Self {
        self.rule.id = id;
        self
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.rule.name = name.into();
        self
    }

    pub fn disabled(mut self) -> Self {
        self.rule.enabled = false;
        self
    }

    /// Add a condition (repeatable).
    pub fn condition(mut self, condition: Condition) -> Self {
        self.rule.conditions.push(condition);
        self
    }

    pub fn logic(mut self, logic: LogicOp) -> Self {
        self.rule.logic = logic;
        self
    }

    pub fn temporal(mut self, temporal: TemporalConstraint) -> Self {
        self.rule.temporal = Some(temporal);
        self
    }

    /// Add an action (repeatable).
    pub fn action(mut self, action: Action) -> Self {
        self.rule.actions.push(action);
        self
    }

    /// Finish the rule, defaulting the condition/action if the test set none
    /// (see the type docs). The result is valid by construction — `build`
    /// asserts it, so a fixture drifting invalid fails loudly at the source.
    pub fn build(mut self) -> Rule {
        if self.rule.conditions.is_empty() {
            self.rule.conditions.push(Condition::RiskScore {
                gt: Some(80),
                lt: None,
            });
        }
        if self.rule.actions.is_empty() {
            self.rule.actions.push(Action::WebhookAlert {
                url: "https://alerts.example.com/hook".into(),
            });
        }
        self.rule
            .validate()
            .expect("RuleBuilder produced an invalid rule");
        self.rule
    }
}

// ── Recording action sink ────────────────────────────────────────

/// [`ActionSink`] double: records `(alert, action)` pairs instead of
/// delivering. Mirrors `event-bus`'s recording `EventSink`.
#[derive(Default)]
pub struct RecordingActionSink {
    deliveries: Mutex<Vec<(RuleAlert, Action)>>,
}

impl RecordingActionSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything delivered so far, in order.
    pub fn deliveries(&self) -> Vec<(RuleAlert, Action)> {
        self.deliveries.lock().expect("sink lock").clone()
    }
}

#[async_trait]
impl ActionSink for RecordingActionSink {
    async fn deliver(&self, alert: &RuleAlert, action: &Action) -> Result<(), DeliveryError> {
        self.deliveries
            .lock()
            .expect("sink lock")
            .push((alert.clone(), action.clone()));
        Ok(())
    }
}
