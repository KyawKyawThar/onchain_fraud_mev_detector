//! Attribution on `IncidentCreated` (§8, Sprint 7 t4) — the Kafka consumer that
//! ties the t1–t3 seams together: a confirmed incident's addresses get
//! clustered into entities, the association flywheel labels the resulting
//! cluster's members, the incident is attributed to those entities, and every
//! real-world fact this pass discovers is emitted back onto the backbone.
//!
//! ## Where the incident's addresses come from
//!
//! `IncidentCreated` (§7) deliberately carries no addresses — only
//! `alert_id`/`txs`/figures — because the schema is locked (§2) and the fast
//! path is attribution-blind (§6/§8). The addresses live on the
//! `PreliminaryAlertCreated` that preceded it, correlated by the one id that
//! spans the whole lifecycle: `alert_id`. So this consumer subscribes to
//! *both* topics: `PreliminaryAlertCreated` teaches it `alert_id → addresses`,
//! `IncidentCreated` is the trigger.
//!
//! The two events are **not** guaranteed to arrive in causal order at this
//! consumer: `PreliminaryAlertCreated` is chain-partitioned (§20's default)
//! while `IncidentCreated` is keyed under its own alert business key (§7) —
//! different topics, different partitions, and Kafka gives no cross-topic
//! ordering guarantee. In a healthy pipeline the alert clears this consumer
//! first (simulation takes seconds), but a cross-partition reorder is still
//! possible, so an `IncidentCreated` that outruns its alert is **buffered**,
//! not dropped — the same tolerance `simulation::projection`'s `OrphanBuffer`
//! gives a terminal event that outruns its `IncidentCreated`. Both the learned
//! address book and the pending-incident buffer are FIFO-bounded
//! ([`DEFAULT_PENDING_CAPACITY`]): an alert/incident flood that never
//! correlates must not grow memory without bound.
//!
//! ## The attribution pass, per incident
//!
//! For every distinct address the incident's alert named:
//!
//! 1. **Sanctions** (§8.5): an exact-match hit emits `SanctionHit` immediately
//!    — independent of clustering, since a sanctioned address is a hard fact
//!    about *that address*, not about whatever entity it resolves to.
//! 2. **Clustering** (§8.2): [`cluster_address`] resolves (or creates) the
//!    entity this address belongs to. A fresh entity emits `EntityCreated`; a
//!    unification of pre-existing entities emits `EntityMerged` for each
//!    absorbed id.
//! 3. **The association flywheel** (§8.1/§8.6): once an entity is resolved,
//!    every one of *its* members (not just the incident's own addresses) is
//!    checked — if any member already carries a directly-known bad-actor label
//!    ([`BAD_ACTOR_KINDS`]), every other member lacking one of
//!    [`FLAGGED_KINDS`] gets a derived `ScammerAssociate` label at the §8.1
//!    `EntityDerived` confidence band, emitting `LabelAdded` for each newly
//!    stored one.
//!
//! Finally, every distinct entity resolved across the incident's addresses
//! gets an [`AttributionRecord`] (upserted, keyed `(incident_id, entity_id)`),
//! and one `AttributionUpdated` is emitted summarizing the incident's entities
//! and the label kinds active on its addresses.
//!
//! ## What this consumer deliberately does not emit
//!
//! `LabelUpdated`, `LabelRevoked` and `EntitySplit` are in the schema (§8) but
//! have no producer *here*: this pass only ever adds labels (the association
//! flywheel) and creates/merges entities (clustering) — it never corrects a
//! label's value, revokes one, or reverses a merge, so emitting any of those
//! three from `IncidentCreated` attribution would be inventing a fact this
//! pass doesn't know. Those three are real, tested capabilities in this crate
//! (`LabelStore::update_label_value`/`revoke_label`, `EntityStore::split`),
//! just triggered by an *operator*, not by an incident — see the `intelligence
//! label-update|label-revoke|entity-split` CLI subcommands in `main.rs`, which
//! are the actual producers.
//!
//! ## Idempotency (§4/§7)
//!
//! Every *store* write this pass makes is keyed, so a redelivered/retried
//! incident converges rather than duplicates: `cluster_address` is idempotent
//! (§8.2), derived labels use a deterministic id ([`seeded_label_id`]) so
//! `LabelAdded` fires only once per claim, and `record_attribution` is a
//! keyed upsert. `SanctionHit` and `AttributionUpdated` are re-emitted on
//! every redelivery (a hard alert and a summary respectively — restating the
//! current state is truthful, if not deduplicated), the same at-least-once
//! stance the rest of the backbone takes: consumers of the event stream are
//! expected to tolerate a redelivered fact, not the producer to suppress it.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use event_bus::{publish_resilient, run_consumer, EventHandler, EventSink, Handled};
use events::intelligence::{
    AttributionUpdated, EntityCreated, EntityMerged, LabelAdded, SanctionHit,
};
use events::primitives::{AccountAddress, AlertId, Chain, Confidence, EntityId};
use events::simulation::IncidentCreated;
use events::{DomainEvent, EventEnvelope};
use rdkafka::consumer::StreamConsumer;
use tokio_util::sync::CancellationToken;

use crate::adjacency::AdjacencyStore;
use crate::cache::{CacheError, HotCache};
use crate::cluster::{cluster_address, ClusterError, ClusterLimits, ClusterSeams};
use crate::merge_actor::MergeActorHandle;
use crate::model::{AttributionRecord, LabelKind, LabelRecord, LabelSource};
use crate::seed::seeded_label_id;
use crate::store::{StoreError, StoreSeams};

/// Label kinds that mark an address as a *directly known* bad actor — the
/// association flywheel's trigger (§8.1/§8.6). `SanctionedEntity` is included
/// alongside `KnownScammer` because a sanctions hit is exactly as strong a
/// direct signal.
const BAD_ACTOR_KINDS: &[LabelKind] = &[LabelKind::KnownScammer, LabelKind::SanctionedEntity];

/// Label kinds that already mark an address as flagged, directly or by prior
/// association — skipped when deciding whether a member needs a *fresh*
/// derived label, so an already-flagged member is never relabeled.
const FLAGGED_KINDS: &[LabelKind] = &[
    LabelKind::KnownScammer,
    LabelKind::SanctionedEntity,
    LabelKind::ScammerAssociate,
];

/// The `source_detail` every association-flywheel label carries. Distinct from
/// any feed's `source_detail` (§8.1) so [`seeded_label_id`]'s deterministic id
/// can never collide with a seeded feed label for the same address/kind/value.
const ASSOCIATION_SOURCE_DETAIL: &str = "entity_clustering_v1";

/// Attribution confidence (§8.3) when the resolved entity is exactly the
/// incident address itself — no clustering signal was needed to name it, so
/// there is nothing left to be wrong about.
const SINGLETON_ATTRIBUTION_CONFIDENCE: f64 = 1.0;

/// Attribution confidence (§8.3) when clustering unified the address with
/// other members. The four §8.2 heuristics (funder/deployer/profit-receiver/
/// code-hash) are strong signals, not certainty, hence the reduced band —
/// deliberately the same simple two-tier rule as [`LabelSource::default_confidence`]'s
/// provenance bands, not a weighted function of cluster size/depth (a
/// documented simplification, not an oversight: revisit once Sprint 8's risk
/// scoring needs a finer-grained signal here).
const CLUSTERED_ATTRIBUTION_CONFIDENCE: f64 = 0.75;

/// One incident address's contribution to an [`Attributor::attribute`] pass —
/// see [`Attributor::attribute_one_address`].
struct AddressOutcome {
    /// The entity this address resolved to, or `None` if the address is
    /// itself an infrastructure hub (§8.2) with no entity to attribute to.
    entity_id: Option<EntityId>,
    /// This address's own active label kinds, folded into the incident-wide
    /// `AttributionUpdated` summary regardless of the entity outcome.
    label_kinds: Vec<&'static str>,
}

/// The two event types this consumer subscribes to: the address source and
/// the trigger. An explicit, closed list (not a `mev.events.*` regex) so a
/// renamed/missing topic fails loudly rather than silently matching nothing —
/// the same discipline as every other consumer on the backbone.
const CONSUMED_EVENT_TYPES: &[&str] = &["PreliminaryAlertCreated", "IncidentCreated"];

/// Bound on both the learned alert→addresses map and the incidents-awaiting-
/// addresses buffer (mirrors `simulation::projection::DEFAULT_ORPHAN_CAPACITY`)
/// — an unbounded map is a memory-exhaustion vector under a flood of alerts or
/// incidents that never correlate.
pub const DEFAULT_PENDING_CAPACITY: usize = 100_000;

/// The topics the consumer subscribes to (one per [`CONSUMED_EVENT_TYPES`] entry).
pub fn consumed_topics() -> Vec<String> {
    CONSUMED_EVENT_TYPES
        .iter()
        .map(|ty| events::topic_for(ty))
        .collect()
}

/// Build the consumer. Manual offset commit (`enable.auto.commit=false`) ties the
/// commit to a fully-processed pass; `earliest` means a fresh group attributes from
/// the start of retained history (cf. the projection/dispatcher consumers).
pub fn build_consumer(brokers: &str, group_id: &str) -> Result<StreamConsumer> {
    rdkafka::ClientConfig::new()
        .set("bootstrap.servers", brokers)
        .set("group.id", group_id)
        .set("enable.auto.commit", "false")
        .set("auto.offset.reset", "earliest")
        .create()
        .context("creating Kafka consumer")
}

/// A `HashMap` bounded to `capacity` distinct keys, FIFO-evicting the oldest on
/// overflow — the same bounded-memory discipline as
/// `simulation::projection`'s `OrphanBuffer`, shared here by both maps this
/// consumer buffers (learned alert addresses, and incidents awaiting them): an
/// attacker (or a stalled upstream partition) flooding either one that never
/// correlates must not grow memory without bound.
struct BoundedFifoMap<K, V> {
    capacity: usize,
    what: &'static str,
    entries: HashMap<K, V>,
    order: VecDeque<K>,
}

impl<K: Eq + Hash + Copy + std::fmt::Display, V> BoundedFifoMap<K, V> {
    fn new(capacity: usize, what: &'static str) -> Self {
        Self {
            capacity,
            what,
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Insert/overwrite `key`. Evicts the oldest distinct key first if this is
    /// a *new* key and the map is at capacity.
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

    /// Remove and return the value for `key`, if buffered.
    fn take(&mut self, key: &K) -> Option<V> {
        self.entries.remove(key)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
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
                            "attribution consumer's bounded buffer is full; evicting the \
                             oldest entry — check for a stalled upstream partition"
                        );
                        break;
                    }
                    // Already drained by `take`: freed a slot for free, keep popping.
                }
                None => break,
            }
        }
    }
}

/// The pending state the consumer buffers across the two topics, behind one
/// lock (mirrors `ProjectionConsumer`'s `Mutex<IncidentProjection>` — one
/// consumer instance, so no real contention).
struct PendingState {
    /// `alert_id → addresses`, learned from `PreliminaryAlertCreated`.
    addresses: BoundedFifoMap<AlertId, Vec<AccountAddress>>,
    /// `IncidentCreated` events that outran their alert's addresses, keyed by
    /// `alert_id`, buffered until [`PreliminaryAlertCreated`](events::detection::PreliminaryAlertCreated)
    /// links them.
    incidents: BoundedFifoMap<AlertId, (IncidentCreated, Chain, DateTime<Utc>)>,
}

impl PendingState {
    fn new(capacity: usize) -> Self {
        Self {
            addresses: BoundedFifoMap::new(capacity, "alert address book"),
            incidents: BoundedFifoMap::new(capacity, "pending incidents"),
        }
    }
}

/// A failure attributing one incident. Wraps every seam's error and forwards
/// the shared retry/skip decision (§4): a transient fault leaves the offset
/// for redelivery (every write here is idempotent, so a retry converges); a
/// permanent one is logged and skipped so one poison incident can't wedge the
/// stream.
#[derive(Debug, thiserror::Error)]
pub enum AttributionError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Cluster(#[from] ClusterError),
    #[error(transparent)]
    Cache(#[from] CacheError),
}

impl AttributionError {
    /// Whether retrying the same incident could plausibly succeed.
    pub fn is_transient(&self) -> bool {
        match self {
            AttributionError::Store(err) => err.is_transient(),
            AttributionError::Cluster(err) => err.is_transient(),
            AttributionError::Cache(err) => err.is_transient(),
        }
    }
}

/// The attribution consumer: every store/graph seam this pass touches, plus
/// the event sink it publishes discovered facts to.
pub struct Attributor {
    stores: StoreSeams,
    graph: Arc<dyn AdjacencyStore>,
    cache: Arc<dyn HotCache>,
    sink: Arc<dyn EventSink>,
    shutdown: CancellationToken,
    publish_backoff: Duration,
    cluster_limits: ClusterLimits,
    pending: Mutex<PendingState>,
    /// Serializes `cluster::cluster_address`'s decide-and-write sequence per
    /// entity (§17, t5) — shared with every other in-process caller (the
    /// `intelligence cluster` CLI spawns its own, since it's a separate
    /// process). See `merge_actor`'s module docs for what this does and
    /// doesn't cover.
    merge_actor: MergeActorHandle,
}

impl Attributor {
    /// Build the consumer over its seams. `shutdown` aborts publish-retry loops
    /// for a graceful drain, the same seam `Dispatcher`/`Scheduler` take.
    pub fn new(
        stores: StoreSeams,
        graph: Arc<dyn AdjacencyStore>,
        cache: Arc<dyn HotCache>,
        sink: Arc<dyn EventSink>,
        shutdown: CancellationToken,
        merge_actor: MergeActorHandle,
    ) -> Self {
        Self {
            stores,
            graph,
            cache,
            sink,
            shutdown,
            publish_backoff: event_bus::PUBLISH_BACKOFF,
            cluster_limits: ClusterLimits::default(),
            pending: Mutex::new(PendingState::new(DEFAULT_PENDING_CAPACITY)),
            merge_actor,
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
            "attribution",
            retry_backoff,
            self,
            shutdown,
        )
        .await
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

    /// Attribute one incident (see the module docs for the full pass). `at` is
    /// the incident's event-time, used as the `as_of`/`created_at` instant for
    /// every label/attribution read and write (§18 — replay-deterministic).
    #[tracing::instrument(skip_all, fields(incident_id = %incident.incident_id, addresses = addresses.len()))]
    async fn attribute(
        &self,
        incident: &IncidentCreated,
        addresses: &[AccountAddress],
        chain: Chain,
        at: DateTime<Utc>,
    ) -> Result<(), AttributionError> {
        let unique_addresses: std::collections::BTreeSet<AccountAddress> =
            addresses.iter().copied().collect();

        let mut entity_ids: Vec<EntityId> = Vec::new();
        let mut seen_entities: HashSet<EntityId> = HashSet::new();
        let mut label_kinds: std::collections::BTreeSet<&'static str> =
            std::collections::BTreeSet::new();

        for address in &unique_addresses {
            let outcome = self
                .attribute_one_address(address, incident, chain, at)
                .await?;
            label_kinds.extend(outcome.label_kinds);

            let Some(entity_id) = outcome.entity_id else {
                continue;
            };
            if seen_entities.insert(entity_id) {
                entity_ids.push(entity_id);
                // The association flywheel runs once per *distinct* entity
                // resolved this pass, not once per incident address.
                self.label_associates(entity_id, chain, at).await?;
            }
        }

        for &entity_id in &entity_ids {
            let confidence = self.attribution_confidence(entity_id).await?;
            self.stores
                .attributions
                .record_attribution(&AttributionRecord {
                    incident_id: incident.incident_id,
                    entity_id,
                    confidence,
                    evidence: format!(
                        "incident {} attributed via entity clustering",
                        incident.incident_id
                    ),
                    attributed_at: at,
                })
                .await?;
        }

        // Deterministic emission order regardless of `HashSet` iteration.
        entity_ids.sort_by_key(|id| id.0);
        self.publish(
            chain,
            DomainEvent::AttributionUpdated(AttributionUpdated {
                incident_id: incident.incident_id,
                entity_ids,
                labels: label_kinds.into_iter().map(str::to_owned).collect(),
            }),
        )
        .await;

        Ok(())
    }

    /// One incident address's contribution to the pass: sanctions (§8.5) and
    /// clustering (§8.2) are independent of each other, so both always run;
    /// their discovered events are published here, and what the caller needs
    /// to finish the job (the resolved entity, if any, and this address's own
    /// active label kinds for the `AttributionUpdated` summary) comes back as
    /// data rather than being threaded through shared mutable state — this is
    /// the one piece of `attribute` that's per-address rather than
    /// per-incident, split out so it reads and tests as its own unit.
    async fn attribute_one_address(
        &self,
        address: &AccountAddress,
        incident: &IncidentCreated,
        chain: Chain,
        at: DateTime<Utc>,
    ) -> Result<AddressOutcome, AttributionError> {
        // 1. Sanctions (§8.5) — a hard fact about this address, independent of
        // whatever entity it resolves to below.
        for entry in self.stores.sanctions.sanction_matches(address).await? {
            self.publish(
                chain,
                DomainEvent::SanctionHit(SanctionHit {
                    address: *address,
                    list: entry.list_name,
                    entry: entry.entry,
                }),
            )
            .await;
        }

        // The incident's own active labels feed the `AttributionUpdated`
        // summary regardless of what clustering below finds.
        let label_kinds = self
            .stores
            .labels
            .labels_for(address, at)
            .await?
            .into_iter()
            .map(|label| <&'static str>::from(label.kind))
            .collect();

        // 2. Clustering (§8.2) — resolve or create the entity this address
        // belongs to.
        let evidence = format!("incident:{}", incident.incident_id);
        let Some(outcome) = cluster_address(
            ClusterSeams {
                graph: self.graph.as_ref(),
                entities: self.stores.entities.as_ref(),
                merge_actor: &self.merge_actor,
            },
            chain,
            address,
            &evidence,
            Some(incident.incident_id),
            at,
            self.cluster_limits,
        )
        .await?
        else {
            // The address is itself an infrastructure hub (§8.2) — no entity
            // to attribute to.
            return Ok(AddressOutcome {
                entity_id: None,
                label_kinds,
            });
        };

        if let Some(seed) = outcome.created_seed {
            self.publish(
                chain,
                DomainEvent::EntityCreated(EntityCreated {
                    entity_id: outcome.entity_id,
                    seed_address: seed,
                }),
            )
            .await;
        }
        for absorbed in &outcome.absorbed {
            self.publish(
                chain,
                DomainEvent::EntityMerged(EntityMerged {
                    surviving_id: outcome.entity_id,
                    absorbed_id: *absorbed,
                    evidence_ref: evidence.clone(),
                }),
            )
            .await;
        }

        Ok(AddressOutcome {
            entity_id: Some(outcome.entity_id),
            label_kinds,
        })
    }

    /// §8.3-adjacent confidence for one attribution link: full certainty when
    /// the entity is just the address itself (no clustering signal was needed
    /// to name it), the heuristic band when clustering unified it with other
    /// members — the four §8.2 signals are strong but not certain.
    async fn attribution_confidence(
        &self,
        entity_id: EntityId,
    ) -> Result<Confidence, AttributionError> {
        let member_count = self
            .stores
            .entities
            .entity(entity_id)
            .await?
            .map(|entity| entity.addresses.len())
            .unwrap_or(1);
        Ok(if member_count <= 1 {
            Confidence::new(SINGLETON_ATTRIBUTION_CONFIDENCE)
        } else {
            Confidence::new(CLUSTERED_ATTRIBUTION_CONFIDENCE)
        })
    }

    /// The association flywheel (§8.1/§8.6): if any member of `entity_id`
    /// already carries a directly-known bad-actor label ([`BAD_ACTOR_KINDS`]),
    /// every other member lacking one of [`FLAGGED_KINDS`] gets a derived
    /// `ScammerAssociate` label — `EntityDerived` provenance, the §8.1 reduced
    /// confidence band. The deterministic label id ([`seeded_label_id`]) makes
    /// a re-run an idempotent no-op: `LabelAdded` fires only for a label newly
    /// stored, and the hot cache is evicted only when one lands.
    async fn label_associates(
        &self,
        entity_id: EntityId,
        chain: Chain,
        at: DateTime<Utc>,
    ) -> Result<(), AttributionError> {
        let Some(entity) = self.stores.entities.entity(entity_id).await? else {
            return Ok(());
        };
        if entity.addresses.len() < 2 {
            return Ok(());
        }

        let mut flagged_by: Option<AccountAddress> = None;
        for member in &entity.addresses {
            let member_labels = self.stores.labels.labels_for(member, at).await?;
            if member_labels
                .iter()
                .any(|label| BAD_ACTOR_KINDS.contains(&label.kind))
            {
                flagged_by = Some(*member);
                break;
            }
        }
        let Some(flagged_by) = flagged_by else {
            return Ok(());
        };

        for member in &entity.addresses {
            if *member == flagged_by {
                continue;
            }
            let existing = self.stores.labels.labels_for(member, at).await?;
            if existing
                .iter()
                .any(|label| FLAGGED_KINDS.contains(&label.kind))
            {
                continue;
            }

            let value = format!("clustered with {flagged_by:#x}");
            let derived = LabelRecord {
                label_id: seeded_label_id(
                    ASSOCIATION_SOURCE_DETAIL,
                    member,
                    LabelKind::ScammerAssociate,
                    &value,
                ),
                address: *member,
                kind: LabelKind::ScammerAssociate,
                value,
                confidence: LabelSource::EntityDerived.default_confidence(),
                source: LabelSource::EntityDerived,
                source_detail: ASSOCIATION_SOURCE_DETAIL.to_owned(),
                created_at: at,
                valid_until: None,
            };

            if self.stores.labels.add_label(&derived).await? {
                self.cache.evict(member).await?;
                self.publish(
                    chain,
                    DomainEvent::LabelAdded(LabelAdded {
                        address: derived.address,
                        kind: <&str>::from(derived.kind).to_owned(),
                        value: derived.value.clone(),
                        confidence: derived.confidence,
                        source: <&str>::from(derived.source).to_owned(),
                    }),
                )
                .await;
            }
        }
        Ok(())
    }

    /// Attribute, then translate the outcome into the offset action: a
    /// transient/permanent store fault maps through [`handled_for`]; success
    /// checks `shutdown` the same way `Dispatcher`/`Scheduler` do — if it fired
    /// mid-publish-retry, some event above may not be on the wire, so the
    /// offset is left for redelivery rather than committed past an
    /// under-audited incident.
    async fn dispatch(
        &self,
        incident: &IncidentCreated,
        addresses: &[AccountAddress],
        chain: Chain,
        at: DateTime<Utc>,
    ) -> Handled {
        match self.attribute(incident, addresses, chain, at).await {
            Ok(()) if self.shutdown.is_cancelled() => Handled::Stop,
            Ok(()) => Handled::Commit,
            Err(err) => event_bus::handled_for(err.is_transient(), err, "attribution"),
        }
    }
}

#[async_trait]
impl EventHandler for Attributor {
    async fn handle(&self, envelope: EventEnvelope) -> Handled {
        let at = envelope.occurred_at;
        let chain = envelope.chain;
        match envelope.payload {
            DomainEvent::PreliminaryAlertCreated(alert) => {
                let ready = {
                    let mut pending = self
                        .pending
                        .lock()
                        .expect("attribution pending mutex poisoned");
                    pending
                        .addresses
                        .put(alert.alert_id, alert.addresses.clone());
                    pending.incidents.take(&alert.alert_id)
                };
                match ready {
                    Some((incident, chain, at)) => {
                        self.dispatch(&incident, &alert.addresses, chain, at).await
                    }
                    None => Handled::Commit,
                }
            }
            DomainEvent::IncidentCreated(incident) => {
                let addresses = {
                    let pending = self
                        .pending
                        .lock()
                        .expect("attribution pending mutex poisoned");
                    pending.addresses.get(&incident.alert_id).cloned()
                };
                match addresses {
                    Some(addresses) => self.dispatch(&incident, &addresses, chain, at).await,
                    None => {
                        let mut pending = self
                            .pending
                            .lock()
                            .expect("attribution pending mutex poisoned");
                        pending
                            .incidents
                            .put(incident.alert_id, (incident, chain, at));
                        Handled::Commit
                    }
                }
            }
            other => {
                tracing::warn!(
                    event = other.event_type(),
                    "unexpected event on attribution topics; skipping"
                );
                Handled::Commit
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge_actor::MergeActor;
    use crate::model::{AdjacencyEdge, EdgeKind, SanctionEntry};
    use crate::store::{AttributionStore, EntityStore, LabelStore, SanctionsStore};
    use crate::test_util::{
        store_seams, InMemoryAdjacency, InMemoryHotCache, InMemoryIntelligenceStore,
    };
    use alloy_primitives::Address;
    use events::detection::PreliminaryAlertCreated;
    use events::primitives::{AlertKind, DetectorRef, Severity};
    use uuid::Uuid;

    fn addr(byte: u8) -> AccountAddress {
        Address::repeat_byte(byte)
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    use event_bus::test_util::RecordingSink;

    fn preliminary_alert(
        alert_id: AlertId,
        addresses: Vec<AccountAddress>,
    ) -> PreliminaryAlertCreated {
        PreliminaryAlertCreated {
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
        }
    }

    fn incident_created(alert_id: AlertId) -> IncidentCreated {
        IncidentCreated {
            incident_id: events::primitives::IncidentId::new(),
            alert_id,
            kind: AlertKind::Sandwich,
            txs: vec![],
            profit: 5.0,
            victim_loss: 2.0,
            severity: Severity::High,
        }
    }

    fn envelope(payload: DomainEvent, at: DateTime<Utc>) -> EventEnvelope {
        EventEnvelope::with_metadata(Uuid::new_v4(), at, Chain::ETHEREUM, payload)
    }

    struct Harness {
        attributor: Attributor,
        sink: Arc<RecordingSink>,
        store: Arc<InMemoryIntelligenceStore>,
    }

    fn harness() -> Harness {
        let store = Arc::new(InMemoryIntelligenceStore::new());
        let graph = Arc::new(InMemoryAdjacency::new());
        let cache = Arc::new(InMemoryHotCache::new());
        let sink = Arc::new(RecordingSink::default());
        let attributor = Attributor::new(
            store_seams(&store),
            graph,
            cache,
            sink.clone(),
            CancellationToken::new(),
            MergeActor::spawn(),
        );
        Harness {
            attributor,
            sink,
            store,
        }
    }

    fn is_entity_created(e: &DomainEvent) -> bool {
        matches!(e, DomainEvent::EntityCreated(_))
    }
    fn is_entity_merged(e: &DomainEvent) -> bool {
        matches!(e, DomainEvent::EntityMerged(_))
    }
    fn is_sanction_hit(e: &DomainEvent) -> bool {
        matches!(e, DomainEvent::SanctionHit(_))
    }
    fn is_label_added(e: &DomainEvent) -> bool {
        matches!(e, DomainEvent::LabelAdded(_))
    }
    fn is_attribution_updated(e: &DomainEvent) -> bool {
        matches!(e, DomainEvent::AttributionUpdated(_))
    }

    /// An `IncidentCreated` that overtakes its `PreliminaryAlertCreated` (a
    /// cross-topic reorder) is buffered, not dropped, and processed the moment
    /// the alert's addresses are learned.
    #[tokio::test]
    async fn incident_before_its_alert_is_buffered_then_replayed() {
        let h = harness();
        let alert_id = AlertId::new();
        let incident = incident_created(alert_id);

        assert_eq!(
            h.attributor
                .handle(envelope(
                    DomainEvent::IncidentCreated(incident.clone()),
                    at(10)
                ))
                .await,
            Handled::Commit,
            "buffered, not lost"
        );
        assert!(
            h.sink.events().is_empty(),
            "nothing to attribute until addresses are known"
        );

        let alert = preliminary_alert(alert_id, vec![addr(1)]);
        assert_eq!(
            h.attributor
                .handle(envelope(DomainEvent::PreliminaryAlertCreated(alert), at(5)))
                .await,
            Handled::Commit
        );

        assert_eq!(
            h.sink.count(is_attribution_updated),
            1,
            "the buffered incident replayed once its addresses arrived"
        );
    }

    /// A fresh address with no prior entity/adjacency seeds a brand-new entity
    /// — `EntityCreated` fires, and the singleton link gets full confidence.
    #[tokio::test]
    async fn a_fresh_address_creates_an_entity_and_attributes_at_full_confidence() {
        let h = harness();
        let alert_id = AlertId::new();
        let incident = incident_created(alert_id);

        h.attributor
            .handle(envelope(
                DomainEvent::PreliminaryAlertCreated(preliminary_alert(alert_id, vec![addr(1)])),
                at(5),
            ))
            .await;
        h.attributor
            .handle(envelope(
                DomainEvent::IncidentCreated(incident.clone()),
                at(10),
            ))
            .await;

        assert_eq!(h.sink.count(is_entity_created), 1);
        let attribution = h
            .sink
            .events()
            .into_iter()
            .find_map(|e| match e {
                DomainEvent::AttributionUpdated(a) => Some(a),
                _ => None,
            })
            .expect("AttributionUpdated emitted");
        assert_eq!(attribution.incident_id, incident.incident_id);
        assert_eq!(attribution.entity_ids.len(), 1);

        let attributions = h
            .store
            .attributions_for_incident(incident.incident_id)
            .await
            .unwrap();
        assert_eq!(attributions.len(), 1);
        assert_eq!(attributions[0].confidence.get(), 1.0);
    }

    /// Two addresses that already belong to two different entities, unified by
    /// an adjacency signal, merge into one — `EntityMerged` fires and the
    /// incident attributes to the single survivor at the clustered (reduced)
    /// confidence band.
    #[tokio::test]
    async fn clustering_two_owned_addresses_merges_and_attributes_once() {
        let h = harness();
        let alert_id = AlertId::new();
        let incident = incident_created(alert_id);

        let e1 = EntityId::new();
        let e2 = EntityId::new();
        h.store
            .create_entity(e1, &addr(1), "prior", at(1))
            .await
            .unwrap();
        h.store
            .create_entity(e2, &addr(2), "prior", at(1))
            .await
            .unwrap();

        let graph = InMemoryAdjacency::new();
        graph
            .append(&[AdjacencyEdge {
                chain: Chain::ETHEREUM,
                src: addr(1),
                dst: addr(2),
                kind: EdgeKind::Funded,
                evidence: "0xtx".into(),
                block_number: 1,
                observed_at: at(1),
            }])
            .await
            .unwrap();
        // Swap in the seeded graph (the harness's is empty) by rebuilding.
        let attributor = Attributor::new(
            store_seams(&h.store),
            Arc::new(graph),
            Arc::new(InMemoryHotCache::new()),
            h.sink.clone(),
            CancellationToken::new(),
            MergeActor::spawn(),
        );

        attributor
            .handle(envelope(
                DomainEvent::PreliminaryAlertCreated(preliminary_alert(
                    alert_id,
                    vec![addr(1), addr(2)],
                )),
                at(5),
            ))
            .await;
        attributor
            .handle(envelope(
                DomainEvent::IncidentCreated(incident.clone()),
                at(10),
            ))
            .await;

        assert_eq!(h.sink.count(is_entity_merged), 1);
        let attributions = h
            .store
            .attributions_for_incident(incident.incident_id)
            .await
            .unwrap();
        assert_eq!(
            attributions.len(),
            1,
            "both addresses resolved to one entity"
        );
        assert_eq!(attributions[0].confidence.get(), 0.75);
    }

    /// A sanctioned address emits `SanctionHit` immediately (§8.5).
    #[tokio::test]
    async fn a_sanctioned_address_emits_sanction_hit() {
        let h = harness();
        let alert_id = AlertId::new();
        h.store
            .seed_sanctions(&[SanctionEntry {
                address: addr(1),
                list_name: "ofac_sdn".into(),
                entry: "OFAC SDN digital-currency address".into(),
                listed_at: None,
            }])
            .await
            .unwrap();

        h.attributor
            .handle(envelope(
                DomainEvent::PreliminaryAlertCreated(preliminary_alert(alert_id, vec![addr(1)])),
                at(5),
            ))
            .await;
        h.attributor
            .handle(envelope(
                DomainEvent::IncidentCreated(incident_created(alert_id)),
                at(10),
            ))
            .await;

        assert_eq!(h.sink.count(is_sanction_hit), 1);
    }

    /// The association flywheel: a known-scammer member's entity-mate gets a
    /// derived `ScammerAssociate` label, and a re-run does not re-emit it.
    #[tokio::test]
    async fn association_flywheel_labels_cluster_mates_once() {
        let h = harness();
        let alert_id = AlertId::new();

        let scammer = LabelRecord::new(
            addr(1),
            LabelKind::KnownScammer,
            "known scammer",
            LabelSource::Manual,
            "operator",
            at(1),
        );
        h.store.add_label(&scammer).await.unwrap();

        let graph = InMemoryAdjacency::new();
        graph
            .append(&[AdjacencyEdge {
                chain: Chain::ETHEREUM,
                src: addr(1),
                dst: addr(2),
                kind: EdgeKind::Funded,
                evidence: "0xtx".into(),
                block_number: 1,
                observed_at: at(1),
            }])
            .await
            .unwrap();
        let attributor = Attributor::new(
            store_seams(&h.store),
            Arc::new(graph),
            Arc::new(InMemoryHotCache::new()),
            h.sink.clone(),
            CancellationToken::new(),
            MergeActor::spawn(),
        );

        async fn run(attributor: &Attributor, alert_id: AlertId) {
            attributor
                .handle(envelope(
                    DomainEvent::PreliminaryAlertCreated(preliminary_alert(
                        alert_id,
                        vec![addr(1), addr(2)],
                    )),
                    at(5),
                ))
                .await;
            attributor
                .handle(envelope(
                    DomainEvent::IncidentCreated(incident_created(alert_id)),
                    at(10),
                ))
                .await;
        }

        run(&attributor, alert_id).await;
        assert_eq!(
            h.sink.count(is_label_added),
            1,
            "addr(2) gets a derived ScammerAssociate label; addr(1) is already flagged"
        );
        let labels = h.store.labels_for(&addr(2), at(1_000)).await.unwrap();
        assert!(labels.iter().any(
            |l| l.kind == LabelKind::ScammerAssociate && l.source == LabelSource::EntityDerived
        ));

        // Re-run (a redelivered/retried incident) must not duplicate the label.
        run(&attributor, AlertId::new()).await;
        assert_eq!(
            h.sink.count(is_label_added),
            1,
            "the deterministic label id makes the second pass a no-op"
        );
    }

    /// A `BoundedFifoMap` evicts the oldest distinct key once full, and taking
    /// a key frees its slot without a spurious extra eviction.
    #[test]
    fn bounded_fifo_map_evicts_oldest_first() {
        let mut map: BoundedFifoMap<AlertId, u8> = BoundedFifoMap::new(2, "test");
        let a = AlertId::new();
        let b = AlertId::new();
        let c = AlertId::new();

        map.put(a, 1);
        map.put(b, 2);
        assert_eq!(map.len(), 2);

        map.put(c, 3);
        assert_eq!(map.len(), 2, "still bounded");
        assert!(map.get(&a).is_none(), "oldest evicted");
        assert!(map.get(&b).is_some());
        assert!(map.get(&c).is_some());

        assert_eq!(map.take(&b), Some(2));
        assert_eq!(map.len(), 1);
    }
}
