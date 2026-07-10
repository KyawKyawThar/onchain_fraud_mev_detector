//! The §9 Kafka consumer (Sprint 9 t4) — the imperative shell that ties every
//! seam in this crate together: consume `IncidentCreated` / `RiskScoreUpdated`
//! / `EntityMerged` / `LabelAdded` / `SanctionHit`, build one
//! [`EventCtx`] per subject address (enrichment prefetched per the compiled
//! set's [`EnrichmentNeeds`](crate::compile::EnrichmentNeeds)), evaluate
//! instant rules and step temporal ones, and emit `RuleTriggered` /
//! `RuleAlertCreated` (§2) back onto the backbone while handing each fired
//! rule's actions to the [`ActionSink`].
//!
//! ## What it subscribes to beyond the five §9 topics, and why
//!
//! * **`PreliminaryAlertCreated`** — `IncidentCreated` (§7) deliberately
//!   carries no addresses (and no confidence); both live on the provisional
//!   alert, correlated by `alert_id`. Same two-topic address-book +
//!   buffered-incident tolerance as intelligence's attribution consumer —
//!   cross-topic order is not guaranteed, so an incident that outruns its
//!   alert is buffered (FIFO-bounded), never dropped.
//! * **`BlockCanonicalized`** — none of the intelligence-side events carry a
//!   block height, but every temporal window and `NewAddress` check measures
//!   in blocks. The consumer keeps a per-chain **block watermark** from the
//!   canonical chain stream and stamps it onto each [`EventCtx`].
//! * **`RuleCreated`** — the refresh trigger: a rule created through
//!   `POST /v1/rules` re-loads and recompiles the enabled set (snapshot swap,
//!   [`refresh_rules`]) the moment its event lands, instead of waiting for the
//!   periodic backstop refresh the binary also runs (disable/delete have no
//!   events of their own yet).
//!
//! ## Offset discipline (§4/§17)
//!
//! Per record: build **all** ctxs first (enrichment reads — no side effects,
//! so a transient store fault retries cleanly via redelivery), then evaluate
//! instant rules (emission is `publish_resilient`, at-least-once), then
//! `pool.step` each ctx and **commit only after `pool.flush()`** — the t3
//! checkpoint barrier, so a crash can never lose an acknowledged window.
//! Redelivery may therefore re-emit a fire or re-step a machine: the same
//! at-least-once stance the rest of the backbone takes (consumers tolerate a
//! redelivered fact; the producer doesn't suppress it).
//!
//! Temporal fires are drained by a **separate task** ([`drain_fires`]) — a
//! full fires channel plus a flush from the same task deadlocks (see
//! `worker.rs`'s deadlock note).
//!
//! ## Scaling note (§20)
//!
//! One consumer instance today: the backbone topics are chain-keyed, so two
//! instances in one group would split an address's events across instances
//! and break the one-worker-owns-an-address invariant (§17). Scaling out
//! requires re-keying the rule-engine's feed by address first — documented in
//! `worker.rs`; until then, scale is the in-process partition count.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use event_bus::{handled_for, publish_resilient, run_consumer, EventHandler, EventSink, Handled};
use events::primitives::{AccountAddress, AlertId, Chain, Confidence};
use events::rule_engine::{RuleAlertCreated, RuleTriggered};
use events::simulation::IncidentCreated;
use events::{DomainEvent, EventEnvelope};
use rdkafka::consumer::StreamConsumer;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::action::{ActionSink, RuleAlert};
use crate::compile::{CompiledRule, CompiledRuleSet, RuleSetHandle};
use crate::ctx::{EventCtx, EventFacts};
use crate::enrich::EnrichmentSource;
use crate::store::RuleStore;
use crate::worker::{TemporalFire, TemporalPool};

/// Log/span label for this consumer.
const CONSUMER: &str = "rule-engine";

/// The event types this consumer subscribes to — the five §9 inputs plus the
/// three supporting streams the module docs justify. An explicit, closed list
/// (not a topic regex) so a renamed event fails loudly, the same discipline as
/// every consumer on the backbone.
const CONSUMED_EVENT_TYPES: &[&str] = &[
    "IncidentCreated",
    "RiskScoreUpdated",
    "EntityMerged",
    "LabelAdded",
    "SanctionHit",
    "PreliminaryAlertCreated",
    "BlockCanonicalized",
    "RuleCreated",
];

/// Bound on the learned alert→addresses book and the incidents-awaiting-
/// addresses buffer (mirrors `intelligence::attribution::DEFAULT_PENDING_CAPACITY`):
/// a flood of alerts/incidents that never correlate must not grow memory
/// without bound.
pub const DEFAULT_PENDING_CAPACITY: usize = 100_000;

/// Rule-engine events are not chain-scoped facts (a rule's temporal window can
/// legitimately span chains — state is keyed `(rule_id, address)`), but every
/// [`EventEnvelope`] must name a chain. Temporal fires are stamped
/// [`Chain::ETHEREUM`] — the same single-chain-MVP posture as the API
/// service's `UsageRecorded` emission; instant fires carry the triggering
/// event's actual chain.
const TEMPORAL_FIRE_CHAIN: Chain = Chain::ETHEREUM;

/// Counter (labeled by `outcome`: `swapped` | `kept_stale`): rule-set
/// refreshes. Any `kept_stale` rate means the engine is serving an outdated
/// snapshot because a reload compiled dirty — a bug (the store validates on
/// insert), so ops should alert on it, not discover it in the logs.
pub const RULE_SET_REFRESH_TOTAL: &str = "rule_set_refresh_total";

/// Counter (labeled by `kind`: `instant` | `temporal`): fires emitted — the
/// §9 throughput signal (a customer's rule storm shows up here first).
pub const RULE_FIRES_TOTAL: &str = "rule_fires_total";

/// The topics the consumer subscribes to (one per [`CONSUMED_EVENT_TYPES`] entry).
pub fn consumed_topics() -> Vec<String> {
    CONSUMED_EVENT_TYPES
        .iter()
        .map(|ty| events::topic_for(ty))
        .collect()
}

/// Build the consumer. Manual offset commit ties the commit to a fully
/// processed (and temporal-flushed) record; `earliest` means a fresh group
/// evaluates from the start of retained history.
pub fn build_consumer(brokers: &str, group_id: &str) -> Result<StreamConsumer> {
    rdkafka::ClientConfig::new()
        .set("bootstrap.servers", brokers)
        .set("group.id", group_id)
        .set("enable.auto.commit", "false")
        .set("auto.offset.reset", "earliest")
        .create()
        .context("creating Kafka consumer")
}

/// What a [`refresh_rules`] pass did — distinguishable outcomes rather than a
/// success that silently means "kept a stale set", so callers can meter and
/// branch on degradation instead of discovering it in the logs.
#[derive(Debug)]
pub enum RefreshOutcome {
    /// A freshly compiled set of this many rules is live.
    Swapped(usize),
    /// The reload compiled dirty; the *previous* snapshot stays live
    /// (degraded-but-alive beats a wedged stream — the store validates on
    /// insert, so this firing means a bug, not customer input). Carries the
    /// compile error naming the offending rule.
    KeptStale(crate::compile::CompileError),
}

/// Reload the enabled set from the store and publish it as the live snapshot
/// (link-or-fail compile; snapshot swap). Shared by the `RuleCreated` handler
/// and the binary's periodic backstop refresh; both outcomes are logged and
/// counted here ([`RULE_SET_REFRESH_TOTAL`]) so the two callers can't drift.
pub async fn refresh_rules(
    store: &dyn RuleStore,
    handle: &RuleSetHandle,
) -> Result<RefreshOutcome, crate::store::StoreError> {
    let rules = store.enabled_rules().await?;
    match CompiledRuleSet::compile(&rules) {
        Ok(set) => {
            let len = set.len();
            handle.swap(set);
            metrics::counter!(RULE_SET_REFRESH_TOTAL, "outcome" => "swapped").increment(1);
            tracing::info!(rules = len, "rule set refreshed");
            Ok(RefreshOutcome::Swapped(len))
        }
        Err(err) => {
            metrics::counter!(RULE_SET_REFRESH_TOTAL, "outcome" => "kept_stale").increment(1);
            tracing::error!(error = %err, "refreshed rules failed to compile; keeping the current set");
            Ok(RefreshOutcome::KeptStale(err))
        }
    }
}

// ── Fire emission (shared by the instant path and the temporal drain) ───────

/// Which path produced a fire. A closed sum rather than a `trigger: String` +
/// "empty `matched_blocks` means instant" convention, so the two shapes are
/// unmixable by construction (an instant fire *cannot* carry an evidence
/// window) and a future third source is a compile error in every `match`
/// below, not a silently wrong branch — the same move as `SimError`/`Handled`.
enum FireKind {
    /// An instant rule matched one event on the spot.
    Instant {
        /// The triggering event type (`"SanctionHit"`, …).
        trigger: &'static str,
    },
    /// A temporal window completed ([`TemporalFire`]).
    Temporal {
        /// The evidence window's blocks ([`crate::temporal::Fired`]).
        matched_blocks: Vec<u64>,
    },
}

impl FireKind {
    /// The `trigger` label carried in `RuleTriggered.context` and logs.
    fn label(&self) -> &'static str {
        match self {
            FireKind::Instant { trigger } => trigger,
            FireKind::Temporal { .. } => "temporal_window",
        }
    }

    /// The `kind` label on [`RULE_FIRES_TOTAL`].
    fn metric_label(&self) -> &'static str {
        match self {
            FireKind::Instant { .. } => "instant",
            FireKind::Temporal { .. } => "temporal",
        }
    }

    /// The evidence window (empty for instant fires, by type).
    fn matched_blocks(&self) -> &[u64] {
        match self {
            FireKind::Instant { .. } => &[],
            FireKind::Temporal { matched_blocks } => matched_blocks,
        }
    }
}

/// One rule match, normalized from either path — everything
/// [`FireEmitter::emit`] needs to publish the §2 events and hand the actions
/// to the sink.
struct Fire {
    rule_id: events::primitives::RuleId,
    owner: events::primitives::CustomerId,
    rule_name: String,
    actions: Vec<crate::model::Action>,
    address: AccountAddress,
    block: u64,
    kind: FireKind,
}

impl Fire {
    fn instant(rule: &CompiledRule, ctx: &EventCtx, trigger: &'static str) -> Self {
        Self {
            rule_id: rule.id,
            owner: rule.owner,
            rule_name: rule.name.clone(),
            actions: rule.actions.clone(),
            address: ctx.address,
            block: ctx.block,
            kind: FireKind::Instant { trigger },
        }
    }

    fn temporal(fire: TemporalFire) -> Self {
        Self {
            rule_id: fire.rule_id,
            owner: fire.owner,
            rule_name: fire.rule_name,
            actions: fire.actions,
            address: fire.address,
            block: fire.block,
            kind: FireKind::Temporal {
                matched_blocks: fire.matched_blocks,
            },
        }
    }

    /// The customer-readable account `RuleAlertCreated` carries.
    fn explanation(&self) -> String {
        match &self.kind {
            FireKind::Instant { trigger } => format!(
                "rule {:?} matched on {trigger} for {:#x} at block {}",
                self.rule_name, self.address, self.block
            ),
            FireKind::Temporal { matched_blocks } => format!(
                "rule {:?} completed its temporal window for {:#x} over blocks {:?}",
                self.rule_name, self.address, matched_blocks
            ),
        }
    }

    /// `RuleTriggered.matched_events` (§2): the temporal evidence window as
    /// one entry per matched block, or the single triggering event type.
    fn matched_events(&self) -> Vec<String> {
        match &self.kind {
            FireKind::Instant { trigger } => vec![(*trigger).to_owned()],
            FireKind::Temporal { matched_blocks } => matched_blocks
                .iter()
                .map(|block| format!("block:{block}"))
                .collect(),
        }
    }
}

/// Publishes the §2 events for one fire and hands the rule's actions to the
/// [`ActionSink`] — shared by the handler's instant path and the
/// [`drain_fires`] task so the two can't drift on what a fire means.
pub struct FireEmitter {
    sink: Arc<dyn EventSink>,
    actions: Arc<dyn ActionSink>,
    shutdown: CancellationToken,
    publish_backoff: Duration,
}

impl FireEmitter {
    pub fn new(
        sink: Arc<dyn EventSink>,
        actions: Arc<dyn ActionSink>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            sink,
            actions,
            shutdown,
            publish_backoff: event_bus::PUBLISH_BACKOFF,
        }
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn with_publish_backoff(mut self, backoff: Duration) -> Self {
        self.publish_backoff = backoff;
        self
    }

    /// RuleTriggered → RuleAlertCreated → one delivery per action. A fresh
    /// `alert_id` is minted per fire (a redelivered record re-fires under a
    /// new id — the documented at-least-once stance). Delivery failures are
    /// logged, not retried here: retry/receipts are the t5 adapter's policy,
    /// behind the [`ActionSink`] seam.
    async fn emit(&self, chain: Chain, fire: Fire) {
        let alert_id = AlertId::new();
        let explanation = fire.explanation();
        metrics::counter!(RULE_FIRES_TOTAL, "kind" => fire.kind.metric_label()).increment(1);

        self.publish(
            chain,
            DomainEvent::RuleTriggered(RuleTriggered {
                rule_id: fire.rule_id,
                address: fire.address,
                matched_events: fire.matched_events(),
                context: serde_json::json!({
                    "rule_name": fire.rule_name,
                    "block": fire.block,
                    "trigger": fire.kind.label(),
                }),
            }),
        )
        .await;

        self.publish(
            chain,
            DomainEvent::RuleAlertCreated(RuleAlertCreated {
                alert_id,
                rule_id: fire.rule_id,
                address: fire.address,
                explanation: explanation.clone(),
            }),
        )
        .await;

        let alert = RuleAlert {
            alert_id,
            rule_id: fire.rule_id,
            owner: fire.owner,
            address: fire.address,
            rule_name: fire.rule_name.clone(),
            explanation,
            matched_blocks: fire.kind.matched_blocks().to_vec(),
        };
        for action in &fire.actions {
            if let Err(err) = self.actions.deliver(&alert, action).await {
                tracing::warn!(
                    rule_id = %fire.rule_id,
                    error = %err,
                    transient = err.is_transient(),
                    "action delivery failed"
                );
            }
        }
    }

    async fn publish(&self, chain: Chain, payload: DomainEvent) {
        publish_resilient(
            self.sink.as_ref(),
            EventEnvelope::new(chain, payload),
            self.publish_backoff,
            &self.shutdown,
        )
        .await;
    }
}

/// Drain completed temporal windows into fires — run this from its **own
/// task** (never the task that calls `flush`/`step`; see the deadlock note in
/// `worker.rs`). Returns when the pool (all fire senders) is gone.
pub async fn drain_fires(emitter: Arc<FireEmitter>, mut fires: mpsc::Receiver<TemporalFire>) {
    while let Some(fire) = fires.recv().await {
        emitter
            .emit(TEMPORAL_FIRE_CHAIN, Fire::temporal(fire))
            .await;
    }
}

// ── Bounded FIFO map (the attribution consumer's tolerance, locally) ───────

/// A `HashMap` bounded to `capacity` distinct keys, FIFO-evicting the oldest
/// on overflow — same shape as `intelligence::attribution`'s (private) map,
/// for the same reason: unbounded correlation buffers are a memory-exhaustion
/// vector.
struct BoundedFifoMap<K, V> {
    capacity: usize,
    what: &'static str,
    entries: HashMap<K, V>,
    order: VecDeque<K>,
}

impl<K: Eq + std::hash::Hash + Copy + std::fmt::Display, V> BoundedFifoMap<K, V> {
    fn new(capacity: usize, what: &'static str) -> Self {
        Self {
            capacity,
            what,
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn put(&mut self, key: K, value: V) {
        if !self.entries.contains_key(&key) {
            self.evict_to_fit();
            self.order.push_back(key);
        }
        self.entries.insert(key, value);
    }

    fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key)
    }

    fn take(&mut self, key: &K) -> Option<V> {
        self.entries.remove(key)
    }

    fn evict_to_fit(&mut self) {
        if self.capacity == 0 {
            return;
        }
        while self.entries.len() >= self.capacity {
            match self.order.pop_front() {
                Some(oldest) => {
                    if self.entries.remove(&oldest).is_some() {
                        tracing::warn!(
                            key = %oldest,
                            capacity = self.capacity,
                            what = self.what,
                            "rule-engine consumer's bounded buffer is full; evicting the \
                             oldest entry — check for a stalled upstream partition"
                        );
                        break;
                    }
                }
                None => break,
            }
        }
    }
}

/// What `PreliminaryAlertCreated` teaches us about an alert: the subject
/// addresses and the detector confidence `IncidentCreated` doesn't carry.
#[derive(Clone)]
struct AlertFacts {
    addresses: Vec<AccountAddress>,
    confidence: Confidence,
}

/// An incident buffered until its alert's facts arrive, with the envelope
/// metadata its eventual evaluation needs.
struct PendingIncident {
    incident: IncidentCreated,
    chain: Chain,
    at: DateTime<Utc>,
}

/// The cross-topic state one consumer instance buffers, behind one lock. The
/// two correlation moves are methods *here* (tell, don't ask) so locking and
/// cloning live in one place and the handler arms read as policy.
struct PendingState {
    /// `alert_id → (addresses, confidence)`, learned from `PreliminaryAlertCreated`.
    alerts: BoundedFifoMap<AlertId, AlertFacts>,
    /// Incidents that outran their alert, keyed by `alert_id`.
    incidents: BoundedFifoMap<AlertId, PendingIncident>,
}

impl PendingState {
    fn new(capacity: usize) -> Self {
        Self {
            alerts: BoundedFifoMap::new(capacity, "alert address book"),
            incidents: BoundedFifoMap::new(capacity, "pending incidents"),
        }
    }

    /// Record what a provisional alert teaches and hand back any incident
    /// that was buffered waiting for exactly these facts.
    fn learn_alert(&mut self, alert_id: AlertId, facts: AlertFacts) -> Option<PendingIncident> {
        self.alerts.put(alert_id, facts);
        self.incidents.take(&alert_id)
    }

    /// The learned facts for an incident's alert — or buffer the incident
    /// until they arrive (cross-topic reorder; see the module docs), in which
    /// case `None` says there is nothing to evaluate yet.
    fn facts_or_buffer(
        &mut self,
        incident: IncidentCreated,
        chain: Chain,
        at: DateTime<Utc>,
    ) -> Option<(IncidentCreated, AlertFacts)> {
        match self.alerts.get(&incident.alert_id) {
            Some(facts) => Some((incident, facts.clone())),
            None => {
                self.incidents.put(
                    incident.alert_id,
                    PendingIncident {
                        incident,
                        chain,
                        at,
                    },
                );
                None
            }
        }
    }
}

/// A failure evaluating one record. Every fallible seam funnels into this so
/// the offset verdict is mapped in exactly one place
/// ([`EngineConsumer::verdict`]) instead of each call site re-deciding
/// retry-vs-skip — the same shape as `intelligence::attribution`'s
/// `AttributionError`.
#[derive(Debug, thiserror::Error)]
enum EngineError {
    #[error(transparent)]
    Enrich(#[from] crate::enrich::EnrichError),
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
    /// The temporal pool's workers are gone — shutdown is in motion. Not a
    /// retry/skip case: the record is left uncommitted for redelivery on the
    /// next boot.
    #[error("the temporal pool is shutting down")]
    Stopped,
}

impl EngineError {
    /// Whether retrying the same record could plausibly succeed (§4).
    /// `Stopped` never reaches this — [`EngineConsumer::verdict`] maps it to
    /// [`Handled::Stop`] first.
    fn is_transient(&self) -> bool {
        match self {
            EngineError::Enrich(err) => err.is_transient(),
            EngineError::Store(err) => err.is_transient(),
            EngineError::Stopped => false,
        }
    }
}

// ── The consumer ─────────────────────────────────────────────────

/// The t4 consumer: holds every seam evaluation needs. See the module docs
/// for the per-record flow.
pub struct EngineConsumer {
    rules: Arc<RuleSetHandle>,
    store: Arc<dyn RuleStore>,
    enrichment: Arc<dyn EnrichmentSource>,
    pool: TemporalPool,
    emitter: Arc<FireEmitter>,
    shutdown: CancellationToken,
    pending: Mutex<PendingState>,
    /// Highest canonicalized block seen per chain — the block clock stamped
    /// onto every [`EventCtx`] (see the module docs).
    watermarks: Mutex<HashMap<Chain, u64>>,
}

impl EngineConsumer {
    pub fn new(
        rules: Arc<RuleSetHandle>,
        store: Arc<dyn RuleStore>,
        enrichment: Arc<dyn EnrichmentSource>,
        pool: TemporalPool,
        emitter: Arc<FireEmitter>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            rules,
            store,
            enrichment,
            pool,
            emitter,
            shutdown,
            pending: Mutex::new(PendingState::new(DEFAULT_PENDING_CAPACITY)),
            watermarks: Mutex::new(HashMap::new()),
        }
    }

    /// Drive the consumer off Kafka until shutdown or a fatal subscribe error,
    /// via the shared [`run_consumer`] loop.
    pub async fn run(
        self,
        consumer: StreamConsumer,
        retry_backoff: Duration,
        shutdown: &CancellationToken,
    ) -> Result<()> {
        let topics = consumed_topics();
        let topic_refs: Vec<&str> = topics.iter().map(String::as_str).collect();
        run_consumer(
            consumer,
            &topic_refs,
            CONSUMER,
            retry_backoff,
            self,
            shutdown,
        )
        .await
    }

    /// The block clock for `chain` — 0 until the first `BlockCanonicalized`
    /// arrives (temporal windows simply can't anchor before the chain stream
    /// does; instant rules are unaffected).
    fn watermark(&self, chain: Chain) -> u64 {
        *self
            .watermarks
            .lock()
            .expect("watermark lock")
            .get(&chain)
            .unwrap_or(&0)
    }

    /// The one place a record's outcome becomes an offset action: `Stopped`
    /// leaves the offset for redelivery (shutdown in motion), every other
    /// error maps through the shared retry/skip decision, and success checks
    /// `shutdown` the way the attribution consumer does — if it fired
    /// mid-publish-retry, some event may not be on the wire, so the offset is
    /// not committed past it.
    fn verdict(&self, result: Result<(), EngineError>) -> Handled {
        match result {
            Ok(()) if self.shutdown.is_cancelled() => Handled::Stop,
            Ok(()) => Handled::Commit,
            Err(EngineError::Stopped) => Handled::Stop,
            Err(err) => handled_for(err.is_transient(), err, CONSUMER),
        }
    }

    /// Evaluate one consumed event for a set of subject addresses: build all
    /// ctxs (enrichment reads — side-effect free, so a transient fault here
    /// retries via redelivery with nothing half-applied), evaluate instant
    /// rules, step temporal machines, then flush (the commit barrier).
    async fn evaluate(
        &self,
        subjects: Vec<(AccountAddress, EventFacts)>,
        chain: Chain,
        at: DateTime<Utc>,
        trigger: &'static str,
    ) -> Result<(), EngineError> {
        let set = self.rules.load();
        if set.is_empty() || subjects.is_empty() {
            return Ok(());
        }
        let block = self.watermark(chain);

        // Phase 1: prefetch — no side effects yet.
        let mut ctxs = Vec::with_capacity(subjects.len());
        for (address, facts) in subjects {
            let counterparty = match &facts {
                EventFacts::Transfer { counterparty, .. } => Some(*counterparty),
                _ => None,
            };
            let enrichment = self
                .enrichment
                .enrichment(&address, counterparty.as_ref(), set.needs(), at)
                .await?;
            ctxs.push(EventCtx {
                address,
                block,
                facts,
                enrichment,
            });
        }

        // Phase 2: instant rules — emit per match.
        for ctx in &ctxs {
            for rule in set.evaluate(ctx) {
                self.emitter
                    .emit(chain, Fire::instant(rule, ctx, trigger))
                    .await;
            }
        }

        // Phase 3+4: temporal steps, then the flush barrier the offset commit
        // rides on. `step`/`flush` fail only when the workers are gone
        // (`PoolError::Closed`) — shutdown, not a per-record fault.
        if set.temporal_rules().next().is_some() {
            for ctx in ctxs {
                self.pool
                    .step(ctx)
                    .await
                    .map_err(|_| EngineError::Stopped)?;
            }
            self.pool.flush().await.map_err(|_| EngineError::Stopped)?;
        }

        Ok(())
    }

    /// One incident, with the addresses/confidence its provisional alert
    /// carried: an [`EventFacts::Incident`] ctx per distinct address.
    async fn evaluate_incident(
        &self,
        incident: &IncidentCreated,
        facts: &AlertFacts,
        chain: Chain,
        at: DateTime<Utc>,
    ) -> Result<(), EngineError> {
        let unique: std::collections::BTreeSet<AccountAddress> =
            facts.addresses.iter().copied().collect();
        let subjects = unique
            .into_iter()
            .map(|address| {
                (
                    address,
                    EventFacts::Incident {
                        kind: incident.kind,
                        confidence: facts.confidence,
                    },
                )
            })
            .collect();
        self.evaluate(subjects, chain, at, "IncidentCreated").await
    }

    /// Intelligence state changed for `addresses`: a [`EventFacts::StateChanged`]
    /// ctx per distinct address — the enrichment refresh *is* the payload (§9:
    /// one source of truth for state, never an event-payload copy).
    async fn evaluate_state_change(
        &self,
        addresses: Vec<AccountAddress>,
        chain: Chain,
        at: DateTime<Utc>,
        trigger: &'static str,
    ) -> Result<(), EngineError> {
        let unique: std::collections::BTreeSet<AccountAddress> = addresses.into_iter().collect();
        let subjects = unique
            .into_iter()
            .map(|address| (address, EventFacts::StateChanged))
            .collect();
        self.evaluate(subjects, chain, at, trigger).await
    }

    /// `EntityMerged` fans the state change out to the surviving entity's
    /// current members — a merge changes what is true of *every* one of them.
    async fn evaluate_entity_merged(
        &self,
        surviving_id: events::primitives::EntityId,
        chain: Chain,
        at: DateTime<Utc>,
    ) -> Result<(), EngineError> {
        let members = self.enrichment.entity_members(surviving_id).await?;
        self.evaluate_state_change(members, chain, at, "EntityMerged")
            .await
    }
}

#[async_trait]
impl EventHandler for EngineConsumer {
    async fn handle(&self, envelope: EventEnvelope) -> Handled {
        let at = envelope.occurred_at;
        let chain = envelope.chain;
        match envelope.payload {
            DomainEvent::BlockCanonicalized(block) => {
                let mut watermarks = self.watermarks.lock().expect("watermark lock");
                let entry = watermarks.entry(chain).or_insert(0);
                // Monotonic: a reorg's replacement block never winds the clock
                // backwards (the pure temporal core closes windows by block
                // arithmetic, so an over-advanced clock is safe; a rewound one
                // could re-open a closed window).
                *entry = (*entry).max(block.block.number);
                Handled::Commit
            }

            DomainEvent::RuleCreated(created) => {
                tracing::info!(rule_id = %created.rule_id, "rule created; refreshing the set");
                let result = refresh_rules(self.store.as_ref(), &self.rules).await;
                self.verdict(result.map(|_| ()).map_err(EngineError::from))
            }

            DomainEvent::PreliminaryAlertCreated(alert) => {
                let facts = AlertFacts {
                    addresses: alert.addresses,
                    confidence: alert.confidence,
                };
                let ready = self
                    .pending
                    .lock()
                    .expect("pending lock")
                    .learn_alert(alert.alert_id, facts.clone());
                match ready {
                    Some(pending) => {
                        let result = self
                            .evaluate_incident(&pending.incident, &facts, pending.chain, pending.at)
                            .await;
                        self.verdict(result)
                    }
                    None => Handled::Commit,
                }
            }

            DomainEvent::IncidentCreated(incident) => {
                let ready = self
                    .pending
                    .lock()
                    .expect("pending lock")
                    .facts_or_buffer(incident, chain, at);
                match ready {
                    Some((incident, facts)) => {
                        let result = self.evaluate_incident(&incident, &facts, chain, at).await;
                        self.verdict(result)
                    }
                    // Buffered until its alert arrives — nothing to evaluate.
                    None => Handled::Commit,
                }
            }

            DomainEvent::RiskScoreUpdated(update) => {
                let result = self
                    .evaluate_state_change(vec![update.address], chain, at, "RiskScoreUpdated")
                    .await;
                self.verdict(result)
            }
            DomainEvent::LabelAdded(label) => {
                let result = self
                    .evaluate_state_change(vec![label.address], chain, at, "LabelAdded")
                    .await;
                self.verdict(result)
            }
            DomainEvent::SanctionHit(hit) => {
                let result = self
                    .evaluate_state_change(vec![hit.address], chain, at, "SanctionHit")
                    .await;
                self.verdict(result)
            }

            DomainEvent::EntityMerged(merged) => {
                let result = self
                    .evaluate_entity_merged(merged.surviving_id, chain, at)
                    .await;
                self.verdict(result)
            }

            other => {
                tracing::warn!(
                    event = other.event_type(),
                    "unexpected event on rule-engine topics; skipping"
                );
                Handled::Commit
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Action, Condition, TemporalConstraint};
    use crate::state_store::TtlPolicy;
    use crate::test_util::{
        InMemoryEnrichment, InMemoryRuleStore, InMemoryTemporalStore, RecordingActionSink,
        RuleBuilder,
    };
    use crate::worker::PoolConfig;
    use event_bus::test_util::RecordingSink;
    use events::chain::BlockCanonicalized;
    use events::detection::PreliminaryAlertCreated;
    use events::intelligence::{EntityMerged, RiskScoreUpdated, SanctionHit};
    use events::primitives::{
        AlertKind, BlockRef, CustomerId, DetectorRef, EntityId, LabelKind, Severity,
    };
    use events::rule_engine::RuleCreated;
    use uuid::Uuid;

    fn addr(byte: u8) -> AccountAddress {
        AccountAddress::repeat_byte(byte)
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    fn envelope(payload: DomainEvent) -> EventEnvelope {
        EventEnvelope::with_metadata(Uuid::new_v4(), at(1_000), Chain::ETHEREUM, payload)
    }

    fn sanction_hit(address: AccountAddress) -> DomainEvent {
        DomainEvent::SanctionHit(SanctionHit {
            address,
            list: "ofac_sdn".into(),
            entry: "SDN-1".into(),
        })
    }

    fn risk_updated(address: AccountAddress) -> DomainEvent {
        DomainEvent::RiskScoreUpdated(RiskScoreUpdated {
            address,
            entity_id: None,
            score: 91,
            confidence: Confidence::new(0.9),
            factors: vec![],
            model_version: "risk-v1".into(),
        })
    }

    fn block_canonicalized(number: u64) -> DomainEvent {
        DomainEvent::BlockCanonicalized(BlockCanonicalized {
            block: BlockRef::new(number, Default::default()),
        })
    }

    fn preliminary_alert(alert_id: AlertId, addresses: Vec<AccountAddress>) -> DomainEvent {
        DomainEvent::PreliminaryAlertCreated(PreliminaryAlertCreated {
            alert_id,
            detector: DetectorRef {
                id: "sandwich".into(),
                version: "1.0.0".into(),
                config_hash: "deadbeef".into(),
            },
            addresses,
            kind: AlertKind::Sandwich,
            confidence: Confidence::new(0.9),
            provisional: true,
        })
    }

    fn incident_created(alert_id: AlertId) -> DomainEvent {
        DomainEvent::IncidentCreated(IncidentCreated {
            incident_id: events::primitives::IncidentId::new(),
            alert_id,
            kind: AlertKind::Sandwich,
            txs: vec![],
            profit: 5.0,
            victim_loss: 2.0,
            severity: Severity::High,
        })
    }

    struct Harness {
        consumer: EngineConsumer,
        store: Arc<InMemoryRuleStore>,
        enrichment: Arc<InMemoryEnrichment>,
        sink: Arc<RecordingSink>,
        actions: Arc<RecordingActionSink>,
        temporal_store: Arc<InMemoryTemporalStore>,
        _drain: tokio::task::JoinHandle<()>,
    }

    /// Build the consumer over doubles, with `rules` pre-created and compiled
    /// and the fire-drain task running (as the binary wires it).
    async fn harness(rules: Vec<crate::model::Rule>) -> Harness {
        let store = Arc::new(InMemoryRuleStore::new());
        for rule in &rules {
            store.create_rule(rule, at(1)).await.expect("create");
        }
        let enabled = store.enabled_rules().await.expect("load");
        let handle = Arc::new(RuleSetHandle::new(
            CompiledRuleSet::compile(&enabled).expect("compile"),
        ));

        let enrichment = Arc::new(InMemoryEnrichment::new());
        let sink = Arc::new(RecordingSink::default());
        let actions = Arc::new(RecordingActionSink::new());
        let shutdown = CancellationToken::new();
        let emitter = Arc::new(
            FireEmitter::new(sink.clone(), actions.clone(), shutdown.clone())
                .with_publish_backoff(Duration::from_millis(1)),
        );

        let temporal_store = Arc::new(InMemoryTemporalStore::new());
        let (fires_tx, fires_rx) = mpsc::channel(64);
        let pool = TemporalPool::spawn(
            PoolConfig {
                partitions: 2,
                mailbox: 16,
                ttl: TtlPolicy::default(),
                retry_backoff: Duration::from_millis(5),
                cache_entries: 16,
            },
            handle.clone(),
            temporal_store.clone(),
            fires_tx,
            shutdown.clone(),
        );
        let drain = tokio::spawn(drain_fires(emitter.clone(), fires_rx));

        let consumer = EngineConsumer::new(
            handle,
            store.clone(),
            enrichment.clone(),
            pool,
            emitter,
            shutdown,
        );
        Harness {
            consumer,
            store,
            enrichment,
            sink,
            actions,
            temporal_store,
            _drain: drain,
        }
    }

    fn is_triggered(e: &DomainEvent) -> bool {
        matches!(e, DomainEvent::RuleTriggered(_))
    }
    fn is_alert_created(e: &DomainEvent) -> bool {
        matches!(e, DomainEvent::RuleAlertCreated(_))
    }

    /// Wait until `check` passes (the temporal fire path crosses two tasks) —
    /// bounded so a broken path fails the test instead of hanging it.
    async fn wait_for(check: impl Fn() -> bool) {
        for _ in 0..200 {
            if check() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("condition not reached within the deadline");
    }

    fn sanction_rule(owner: CustomerId) -> crate::model::Rule {
        RuleBuilder::new(owner)
            .name("Any sanctions hit")
            .condition(Condition::SanctionMatch { list: None })
            .action(Action::SlackAlert {
                channel: "#compliance".into(),
            })
            .build()
    }

    /// A `SanctionHit` delivers a StateChanged ctx: the instant rule fires,
    /// both §2 events are published, and the alert routes to the rule's owner
    /// only (the delivery half of the §9 isolation contract).
    #[tokio::test]
    async fn sanction_hit_fires_instant_rule_and_emits_both_events() {
        let owner = CustomerId::new();
        let other = CustomerId::new();
        let mut rules = vec![sanction_rule(owner)];
        // Another customer's rule that does NOT match this event.
        rules.push(
            RuleBuilder::new(other)
                .name("High risk")
                .condition(Condition::RiskScore {
                    gt: Some(99),
                    lt: None,
                })
                .build(),
        );
        let h = harness(rules).await;
        h.enrichment.set_sanctions(addr(0x05), &["ofac_sdn"]);

        let verdict = h.consumer.handle(envelope(sanction_hit(addr(0x05)))).await;
        assert_eq!(verdict, Handled::Commit);

        assert_eq!(h.sink.count(is_triggered), 1);
        assert_eq!(h.sink.count(is_alert_created), 1);
        let alert_created = h
            .sink
            .events()
            .into_iter()
            .find_map(|e| match e {
                DomainEvent::RuleAlertCreated(a) => Some(a),
                _ => None,
            })
            .expect("RuleAlertCreated");
        assert_eq!(alert_created.address, addr(0x05));

        let deliveries = h.actions.deliveries();
        assert_eq!(deliveries.len(), 1, "one action on the matched rule");
        assert_eq!(deliveries[0].0.owner, owner, "routed to the rule's owner");
        assert_eq!(deliveries[0].0.alert_id, alert_created.alert_id);
    }

    /// An `IncidentCreated` that outruns its `PreliminaryAlertCreated` is
    /// buffered; the alert's arrival replays it with the alert's addresses
    /// and confidence.
    #[tokio::test]
    async fn incident_before_its_alert_is_buffered_then_replayed() {
        let owner = CustomerId::new();
        let rule = RuleBuilder::new(owner)
            .name("Sandwich incidents")
            .condition(Condition::IncidentKind {
                kind: AlertKind::Sandwich,
                min_confidence: Confidence::new(0.8),
            })
            .build();
        let h = harness(vec![rule]).await;

        let alert_id = AlertId::new();
        assert_eq!(
            h.consumer
                .handle(envelope(incident_created(alert_id)))
                .await,
            Handled::Commit,
            "buffered, not lost"
        );
        assert!(h.sink.events().is_empty(), "nothing to evaluate yet");

        h.consumer
            .handle(envelope(preliminary_alert(alert_id, vec![addr(0x01)])))
            .await;
        assert_eq!(h.sink.count(is_triggered), 1);
        assert_eq!(h.sink.count(is_alert_created), 1);
    }

    /// `EntityMerged` fans the state change out to the surviving entity's
    /// members: only the member whose enrichment satisfies the rule fires.
    #[tokio::test]
    async fn entity_merged_fans_out_to_members() {
        let owner = CustomerId::new();
        let rule = RuleBuilder::new(owner)
            .name("MEV bot entity")
            .condition(Condition::EntityLabel {
                kind: LabelKind::MevBot,
                min_confidence: Confidence::new(0.5),
            })
            .build();
        let h = harness(vec![rule]).await;

        let entity = EntityId::new();
        h.enrichment
            .set_members(entity, vec![addr(0x01), addr(0x02)]);
        h.enrichment
            .set_entity_labels(addr(0x02), &[(LabelKind::MevBot, 0.9)]);

        h.consumer
            .handle(envelope(DomainEvent::EntityMerged(EntityMerged {
                surviving_id: entity,
                absorbed_id: EntityId::new(),
                evidence_ref: "incident:test".into(),
            })))
            .await;

        assert_eq!(h.sink.count(is_triggered), 1, "only the labeled member");
        let triggered = h
            .sink
            .events()
            .into_iter()
            .find_map(|e| match e {
                DomainEvent::RuleTriggered(t) => Some(t),
                _ => None,
            })
            .unwrap();
        assert_eq!(triggered.address, addr(0x02));
    }

    /// The full temporal path: two matching events within the window (block
    /// clock fed by `BlockCanonicalized`) complete a frequency rule via the
    /// pool; the drained fire publishes both §2 events with the evidence
    /// window.
    #[tokio::test]
    async fn temporal_frequency_rule_fires_through_the_pool() {
        let owner = CustomerId::new();
        let risky = Condition::RiskScore {
            gt: Some(80),
            lt: None,
        };
        let rule = RuleBuilder::new(owner)
            .name("Repeatedly risky")
            .condition(risky.clone())
            .temporal(TemporalConstraint::Frequency {
                condition: Box::new(risky),
                count: 2,
                within_blocks: 100,
            })
            .action(Action::WebhookAlert {
                url: "https://alerts.example.com/hook".into(),
            })
            .build();
        let h = harness(vec![rule]).await;
        h.enrichment.set_risk_score(addr(0x07), 95);

        h.consumer.handle(envelope(block_canonicalized(100))).await;
        h.consumer.handle(envelope(risk_updated(addr(0x07)))).await;
        assert_eq!(h.sink.count(is_alert_created), 0, "one hit is not enough");

        h.consumer.handle(envelope(block_canonicalized(150))).await;
        h.consumer.handle(envelope(risk_updated(addr(0x07)))).await;

        let sink = h.sink.clone();
        wait_for(move || sink.count(is_alert_created) == 1).await;
        let triggered = h
            .sink
            .events()
            .into_iter()
            .find_map(|e| match e {
                DomainEvent::RuleTriggered(t) => Some(t),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            triggered.matched_events,
            vec!["block:100".to_owned(), "block:150".to_owned()],
            "the evidence window rides RuleTriggered"
        );
        // The fired machine reset — its state is gone from the store.
        assert!(h.temporal_store.is_empty());
        // And the webhook action was handed to the sink, routed to the owner.
        let deliveries = h.actions.deliveries();
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].0.owner, owner);
        assert_eq!(deliveries[0].0.matched_blocks, vec![100, 150]);
    }

    /// `refresh_rules` reports what it did — a swapped set is
    /// distinguishable from a kept-stale one, so callers can meter
    /// degradation instead of reading logs.
    #[tokio::test]
    async fn refresh_reports_the_swapped_set_size() {
        let store = InMemoryRuleStore::new();
        store
            .create_rule(&sanction_rule(CustomerId::new()), at(1))
            .await
            .expect("create");
        let handle = RuleSetHandle::new(CompiledRuleSet::compile(&[]).expect("compile empty"));

        let outcome = refresh_rules(&store, &handle).await.expect("refresh");
        assert!(matches!(outcome, RefreshOutcome::Swapped(1)));
        assert_eq!(handle.load().len(), 1);
    }

    /// `RuleCreated` refreshes the live set: a rule created after boot starts
    /// matching as soon as its event lands.
    #[tokio::test]
    async fn rule_created_refreshes_the_set() {
        let h = harness(vec![]).await;
        h.enrichment.set_sanctions(addr(0x05), &["ofac_sdn"]);

        // Before the refresh: empty set, nothing fires.
        h.consumer.handle(envelope(sanction_hit(addr(0x05)))).await;
        assert!(h.sink.events().is_empty());

        // The customer creates a rule (as POST /v1/rules does), and its
        // RuleCreated event lands here.
        let rule = sanction_rule(CustomerId::new());
        h.store.create_rule(&rule, at(2)).await.expect("create");
        h.consumer
            .handle(envelope(DomainEvent::RuleCreated(RuleCreated {
                rule_id: rule.id,
                owner: rule.owner,
                definition: serde_json::to_value(&rule).unwrap(),
            })))
            .await;

        h.consumer.handle(envelope(sanction_hit(addr(0x05)))).await;
        assert_eq!(h.sink.count(is_alert_created), 1);
    }

    /// A transient enrichment fault leaves the offset for redelivery (§4) —
    /// and because prefetch precedes every side effect, nothing was emitted.
    #[tokio::test]
    async fn transient_enrichment_fault_retries_with_no_side_effects() {
        let h = harness(vec![sanction_rule(CustomerId::new())]).await;
        h.enrichment.set_sanctions(addr(0x05), &["ofac_sdn"]);
        h.enrichment.inject_transient_faults(1);

        let verdict = h.consumer.handle(envelope(sanction_hit(addr(0x05)))).await;
        assert_eq!(verdict, Handled::Retry);
        assert!(h.sink.events().is_empty(), "no partial emission");

        // The redelivery succeeds.
        let verdict = h.consumer.handle(envelope(sanction_hit(addr(0x05)))).await;
        assert_eq!(verdict, Handled::Commit);
        assert_eq!(h.sink.count(is_alert_created), 1);
    }

    /// Unrelated events on the subscribed topics are skipped, not wedged on.
    #[tokio::test]
    async fn unexpected_events_are_skipped() {
        let h = harness(vec![]).await;
        let verdict = h
            .consumer
            .handle(envelope(DomainEvent::BlockFinalized(
                events::chain::BlockFinalized {
                    block: BlockRef::new(1, Default::default()),
                },
            )))
            .await;
        assert_eq!(verdict, Handled::Commit);
    }
}
