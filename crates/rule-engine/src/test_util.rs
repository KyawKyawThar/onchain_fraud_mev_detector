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
//! * [`InMemoryTemporalStore`] — the [`TemporalStateStore`] double for the t3
//!   shell: a map plus recorded TTLs (asserted on, never enforced — tests own
//!   the clock) and injectable transient faults for the retry path.
//! * [`RecordingActionSink`] — the [`ActionSink`] double: records every
//!   delivery instead of speaking HTTP, so evaluation tests assert on *what
//!   would have been sent*.
//! * [`RuleBuilder`] — the one place tests construct [`Rule`]s, so fixture
//!   noise doesn't spread and a model-field addition is a one-file change.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::primitives::{AccountAddress, Confidence, CustomerId, EntityId, LabelKind, RuleId};

use crate::action::{ActionSink, DeliveryError, RuleAlert};
use crate::compile::EnrichmentNeeds;
use crate::ctx::Enrichment;
use crate::enrich::{EnrichError, EnrichmentSource};
use crate::model::{Action, Condition, LogicOp, Rule, TemporalConstraint};
use crate::state_store::{StateKey, StateStoreError, TemporalStateStore};
use crate::store::{CreateRuleOutcome, RuleStore, StoreError};
use crate::temporal::TemporalState;

/// In-memory implementation of the [`RuleStore`] seam.
#[derive(Default)]
pub struct InMemoryRuleStore {
    inner: Mutex<Vec<StoredRule>>,
    /// Announcements enqueued by [`RuleStore::create_rule_announced`] — what a
    /// Pg store would have written to the `rule_outbox` table.
    announcements: Mutex<Vec<serde_json::Value>>,
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

    /// The announcements `create_rule_announced` enqueued — a test's view of
    /// what would sit in the Pg `rule_outbox` table.
    pub fn announcements(&self) -> Vec<serde_json::Value> {
        self.announcements
            .lock()
            .expect("announcements lock")
            .clone()
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

    async fn create_rule_announced(
        &self,
        rule: &Rule,
        announcement: &serde_json::Value,
        at: DateTime<Utc>,
    ) -> Result<CreateRuleOutcome, StoreError> {
        let outcome = self.create_rule(rule, at).await?;
        // Mirror the Pg transaction: the announcement lands iff the rule did.
        if outcome == CreateRuleOutcome::Created {
            self.announcements
                .lock()
                .expect("announcements lock")
                .push(announcement.clone());
        }
        Ok(outcome)
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

// ── In-memory temporal-state store ───────────────────────────────

/// In-memory implementation of the [`TemporalStateStore`] seam. TTLs are
/// *recorded* (so tests assert the shell computed the right bound) but never
/// enforced — expiry-as-window-close is the pure core's block arithmetic,
/// not something a test should race a clock for.
#[derive(Default)]
pub struct InMemoryTemporalStore {
    inner: Mutex<HashMap<StateKey, (TemporalState, Duration)>>,
    /// Remaining injected transient faults: while non-zero, every operation
    /// consumes one and fails transiently — exercising the worker's
    /// retry-not-drop policy.
    transient_faults: AtomicUsize,
    /// How many times `load` was called (including faulted attempts) — what
    /// the worker-cache tests observe to prove hot keys stop hitting the
    /// store.
    loads: AtomicUsize,
}

impl InMemoryTemporalStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Make the next `n` operations (any kind) fail with a transient error.
    pub fn inject_transient_faults(&self, n: usize) {
        self.transient_faults.store(n, Ordering::SeqCst);
    }

    /// The persisted machine for `key`, bypassing fault injection — for
    /// assertions.
    pub fn state(&self, key: &StateKey) -> Option<TemporalState> {
        let inner = self.inner.lock().expect("state lock");
        inner.get(key).map(|(state, _)| state.clone())
    }

    /// The TTL recorded with the last save of `key` — for assertions.
    pub fn ttl(&self, key: &StateKey) -> Option<Duration> {
        let inner = self.inner.lock().expect("state lock");
        inner.get(key).map(|(_, ttl)| *ttl)
    }

    /// How many machines are in flight.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("state lock").len()
    }

    /// Total `load` calls so far (faulted attempts included).
    pub fn loads(&self) -> usize {
        self.loads.load(Ordering::SeqCst)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Consume one injected fault, if any are pending.
    fn maybe_fault(&self) -> Result<(), StateStoreError> {
        let taken = self
            .transient_faults
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok();
        if taken {
            return Err(StateStoreError::Redis(redis::RedisError::from(
                std::io::Error::new(std::io::ErrorKind::ConnectionReset, "injected fault"),
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl TemporalStateStore for InMemoryTemporalStore {
    async fn load(&self, key: &StateKey) -> Result<Option<TemporalState>, StateStoreError> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        self.maybe_fault()?;
        Ok(self.state(key))
    }

    async fn save(
        &self,
        key: &StateKey,
        state: &TemporalState,
        ttl: Duration,
    ) -> Result<(), StateStoreError> {
        self.maybe_fault()?;
        let mut inner = self.inner.lock().expect("state lock");
        inner.insert(*key, (state.clone(), ttl));
        Ok(())
    }

    async fn clear(&self, key: &StateKey) -> Result<(), StateStoreError> {
        self.maybe_fault()?;
        let mut inner = self.inner.lock().expect("state lock");
        inner.remove(key);
        Ok(())
    }

    async fn in_flight_keys(&self) -> Result<Vec<StateKey>, StateStoreError> {
        self.maybe_fault()?;
        let inner = self.inner.lock().expect("state lock");
        Ok(inner.keys().copied().collect())
    }
}

// ── In-memory enrichment source ──────────────────────────────────

/// In-memory implementation of the [`EnrichmentSource`] seam (t4): tests seed
/// per-address [`Enrichment`] snapshots and per-entity member lists, and can
/// inject transient faults to exercise the consumer's retry-not-drop path.
/// Deliberately ignores [`EnrichmentNeeds`] and returns the full seeded
/// snapshot — the *production* adapter owns need-scoping; matchers only read
/// the fields their condition tests either way.
#[derive(Default)]
pub struct InMemoryEnrichment {
    snapshots: Mutex<HashMap<AccountAddress, Enrichment>>,
    members: Mutex<HashMap<EntityId, Vec<AccountAddress>>>,
    transient_faults: AtomicUsize,
}

impl InMemoryEnrichment {
    pub fn new() -> Self {
        Self::default()
    }

    /// Make the next `n` calls (either method) fail transiently.
    pub fn inject_transient_faults(&self, n: usize) {
        self.transient_faults.store(n, Ordering::SeqCst);
    }

    /// Replace the whole snapshot for an address.
    pub fn set_enrichment(&self, address: AccountAddress, enrichment: Enrichment) {
        self.snapshots
            .lock()
            .expect("enrichment lock")
            .insert(address, enrichment);
    }

    /// Seed the address's sanctions-list memberships.
    pub fn set_sanctions(&self, address: AccountAddress, lists: &[&str]) {
        let mut snapshots = self.snapshots.lock().expect("enrichment lock");
        snapshots.entry(address).or_default().sanction_lists =
            lists.iter().map(|list| (*list).to_owned()).collect();
    }

    /// Seed the address's current risk score.
    pub fn set_risk_score(&self, address: AccountAddress, score: u8) {
        let mut snapshots = self.snapshots.lock().expect("enrichment lock");
        snapshots.entry(address).or_default().risk_score = Some(score);
    }

    /// Seed the address's entity labels (kind + read-time confidence).
    pub fn set_entity_labels(&self, address: AccountAddress, labels: &[(LabelKind, f64)]) {
        let mut snapshots = self.snapshots.lock().expect("enrichment lock");
        snapshots.entry(address).or_default().entity_labels = labels
            .iter()
            .map(|(kind, confidence)| (*kind, Confidence::new(*confidence)))
            .collect();
    }

    /// Seed an entity's member list (the `EntityMerged` fan-out).
    pub fn set_members(&self, entity_id: EntityId, members: Vec<AccountAddress>) {
        self.members
            .lock()
            .expect("members lock")
            .insert(entity_id, members);
    }

    fn maybe_fault(&self) -> Result<(), EnrichError> {
        let taken = self
            .transient_faults
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok();
        if taken {
            return Err(EnrichError::transient("injected fault"));
        }
        Ok(())
    }
}

#[async_trait]
impl EnrichmentSource for InMemoryEnrichment {
    async fn enrichment(
        &self,
        address: &AccountAddress,
        _counterparty: Option<&AccountAddress>,
        _needs: &EnrichmentNeeds,
        _as_of: DateTime<Utc>,
    ) -> Result<Enrichment, EnrichError> {
        self.maybe_fault()?;
        Ok(self
            .snapshots
            .lock()
            .expect("enrichment lock")
            .get(address)
            .cloned()
            .unwrap_or_default())
    }

    async fn entity_members(
        &self,
        entity_id: EntityId,
    ) -> Result<Vec<AccountAddress>, EnrichError> {
        self.maybe_fault()?;
        Ok(self
            .members
            .lock()
            .expect("members lock")
            .get(&entity_id)
            .cloned()
            .unwrap_or_default())
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
