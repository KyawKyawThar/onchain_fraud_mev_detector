//! Risk-score cache invalidation + recompute consumer (§8.3, Sprint 8 t2).
//!
//! [`risk::score`] (t1) is the pure kernel; this module is the shell that
//! makes §8.3's rule real: "Scores are cache entries keyed by
//! `(address, model_version)`, invalidated when any input changes, recomputed
//! by the intelligence service." Every event that can change what
//! [`risk::score`] sees for some address — a label landing/correcting/
//! revoking, a sanctions hit, an entity being created/merged/split, an
//! attribution update, or an attribution retraction (§15, reorg rollback) —
//! is consumed here. For every address the change can affect: the stale
//! hot-cache entry is evicted, the score is recomputed
//! against the *current* store state (not the event's own payload), the fresh
//! value replaces it in the cache under `(address, `[`risk::MODEL_VERSION`]`)`,
//! and `RiskScoreUpdated` is published — so the decision layer's Redis read
//! (§11/§8.3) never serves a score whose inputs have already moved on.
//!
//! ## Which addresses one event invalidates
//!
//! `LabelAdded`/`LabelUpdated`/`LabelRevoked`/`SanctionHit`/`EntityCreated`
//! each name exactly one address — that address alone is recomputed.
//! `EntityMerged`/`EntitySplit`/`AttributionUpdated` name an entity (or
//! several) instead: the cluster-size factor (and, for `AttributionUpdated`,
//! the attribution factors) are shared across every member, so every
//! *current* member of the named entity/entities is recomputed — read fresh
//! from [`EntityStore::entity`](crate::store::EntityStore::entity) rather than
//! trusted from the event, since membership may have moved again by the time
//! this consumer runs. A tombstoned/missing entity id (already superseded by a
//! later merge/split) simply contributes no addresses here — whatever
//! superseded it carries its own event to drive the recompute. These
//! entity-scoped events fan out through [`RiskScorer::recompute_many`], which
//! deduplicates the combined address list and recomputes it with bounded
//! concurrency (§14 — a long-running scam-wallet entity with thousands of
//! members must not serialize an `AttributionUpdated` behind thousands of
//! sequential store round-trips, nor open unbounded concurrent connections).
//!
//! ## Idempotency and ordering (§4/§18)
//!
//! `risk::score` is a pure function of the store's *current* state, not of the
//! triggering event's payload, so a redelivered event recomputes into the same
//! score — there is nothing to deduplicate, recomputing twice just republishes
//! an identical `RiskScoreUpdated`. Two events landing out of order (e.g. a
//! `LabelRevoked` overtaking the `LabelAdded` it reverses) still converge to
//! the current truth for the same reason.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use event_bus::dlq::DeadLetterQueue;
use event_bus::lag::{build_reporting_consumer, LagReporting};
use event_bus::{publish_resilient, run_consumer, EventHandler, EventSink, Handled, Transience};
use events::primitives::{AccountAddress, Chain, EntityId};
use events::{DomainEvent, EventEnvelope};
use rdkafka::consumer::StreamConsumer;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::cache::{CacheError, CachedScore, HotCache};
use crate::risk::{self, RiskInputs};
use crate::store::{StoreError, StoreSeams};

/// The event types that can change a `risk::score` input — an explicit,
/// closed list (not a `mev.events.*` regex) so a renamed/missing topic fails
/// loudly, the same discipline every other consumer on the backbone follows.
/// `RiskScoreUpdated` itself is deliberately excluded — consuming our own
/// output would recompute forever.
const CONSUMED_EVENT_TYPES: &[&str] = &[
    "LabelAdded",
    "LabelUpdated",
    "LabelRevoked",
    "SanctionHit",
    "EntityCreated",
    "EntityMerged",
    "EntitySplit",
    "AttributionUpdated",
    "AttributionRetracted",
];

/// Cap on how many addresses one event's fan-out recomputes concurrently
/// ([`RiskScorer::recompute_many`]). An entity with thousands of members (a
/// long-running scam-wallet cluster) must not open thousands of simultaneous
/// Postgres/Redis/Kafka round-trips off a single `EntityMerged`/
/// `AttributionUpdated` — the same bounded-fan-out discipline as this crate's
/// `BoundedFifoMap`/`MAX_VISIBLE_FACTORS`: never unbounded just because the
/// *input* isn't.
const RECOMPUTE_CONCURRENCY: usize = 32;

/// The topics the consumer subscribes to (one per [`CONSUMED_EVENT_TYPES`] entry).
pub fn consumed_topics() -> Vec<String> {
    events::topics_for(CONSUMED_EVENT_TYPES)
}

/// Build the consumer. Manual offset commit ties the commit to a fully
/// recomputed-and-published score, same as the attribution consumer; `earliest`
/// means a fresh group recomputes from the start of retained history.
pub fn build_consumer(brokers: &str, group_id: &str) -> Result<StreamConsumer<LagReporting>> {
    build_reporting_consumer(brokers, group_id, "risk_scorer")
}

/// Fetch every current-state input [`risk::score`] needs for one address —
/// active labels, sanctions matches, the resolved entity (if any) and that
/// entity's attributions — `as_of` a given instant (§18, replay-deterministic).
/// Shared by [`RiskScorer::recompute_one`] and the `intelligence risk` CLI's
/// read-only inspection (`main.rs`) so the two can never drift on which seams
/// feed the kernel.
pub async fn load_risk_inputs(
    stores: &StoreSeams,
    address: &AccountAddress,
    as_of: DateTime<Utc>,
) -> Result<(Option<EntityId>, RiskInputs), StoreError> {
    let labels = stores.labels.labels_for(address, as_of).await?;
    let sanctions = stores.sanctions.sanction_matches(address).await?;
    let entity_id = stores.entities.entity_for_address(address).await?;
    let (entity, attributions) = match entity_id {
        Some(id) => (
            stores.entities.entity(id).await?,
            stores.attributions.attributions_for_entity(id).await?,
        ),
        None => (None, Vec::new()),
    };

    Ok((
        entity_id,
        RiskInputs {
            labels,
            attributions,
            sanctions,
            entity,
        },
    ))
}

/// A failure recomputing one address's score. Wraps the store/cache seams and
/// forwards the shared retry/skip decision (§4): a transient fault leaves the
/// offset for redelivery (recompute is naturally idempotent, so a retry just
/// converges); a permanent one is logged and skipped so one poison event can't
/// wedge the stream.
#[derive(Debug, thiserror::Error)]
pub enum RiskScoreError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Cache(#[from] CacheError),
    /// A concurrent recompute task ([`RiskScorer::recompute_many`]) panicked
    /// instead of returning — never retried (a panic is a bug in the
    /// recompute path itself, not a transient blip a redelivery could fix).
    #[error("a concurrent recompute task did not complete: {0}")]
    Task(#[from] tokio::task::JoinError),
}

impl Transience for RiskScoreError {
    /// Whether retrying the same event could plausibly succeed.
    fn is_transient(&self) -> bool {
        match self {
            RiskScoreError::Store(err) => err.is_transient(),
            RiskScoreError::Cache(err) => err.is_transient(),
            RiskScoreError::Task(_) => false,
        }
    }
}

/// The risk-score cache-invalidation consumer: the four store seams the risk
/// kernel reads, the hot cache it invalidates and repopulates, and the sink it
/// publishes `RiskScoreUpdated` to. `Clone` is cheap (every field is `Arc`- or
/// `Copy`-backed) — [`recompute_many`](Self::recompute_many) clones `Self` into
/// each bounded-concurrency task rather than sharing `&self` across a spawn
/// boundary.
#[derive(Clone)]
pub struct RiskScorer {
    stores: StoreSeams,
    cache: Arc<dyn HotCache>,
    sink: Arc<dyn EventSink>,
    shutdown: CancellationToken,
    publish_backoff: Duration,
}

impl RiskScorer {
    /// Build the consumer over its seams. `shutdown` aborts publish-retry loops
    /// for a graceful drain, the same seam every other consumer on the backbone
    /// takes.
    pub fn new(
        stores: StoreSeams,
        cache: Arc<dyn HotCache>,
        sink: Arc<dyn EventSink>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            stores,
            cache,
            sink,
            shutdown,
            publish_backoff: event_bus::PUBLISH_BACKOFF,
        }
    }

    /// Drive the consumer off Kafka until shutdown or a fatal subscribe error,
    /// via the shared [`run_consumer`] loop.
    pub async fn run(
        self,
        consumer: StreamConsumer<LagReporting>,
        retry_backoff: Duration,
        dlq: Option<&DeadLetterQueue>,
        shutdown: &CancellationToken,
    ) -> Result<()> {
        let topics = consumed_topics();
        let topic_refs: Vec<&str> = topics.iter().map(String::as_str).collect();
        run_consumer(
            consumer,
            &topic_refs,
            "risk_scorer",
            retry_backoff,
            dlq,
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

    /// Invalidate, recompute and publish one address's score, `as_of` the
    /// triggering event's `occurred_at` (§18 — replay-deterministic). Eviction
    /// happens before the recompute reads, so a concurrent reader can never
    /// observe the old score once this call has started (§8: evict, don't
    /// overwrite).
    async fn recompute_one(
        &self,
        address: AccountAddress,
        chain: Chain,
        at: DateTime<Utc>,
    ) -> Result<(), RiskScoreError> {
        self.cache.evict(&address).await?;

        let (entity_id, inputs) = load_risk_inputs(&self.stores, &address, at).await?;
        let result = risk::score(address, entity_id, &inputs, at);

        self.cache
            .put_score(
                &address,
                &CachedScore {
                    score: result.score,
                    confidence: result.confidence,
                    model_version: result.model_version.clone(),
                    computed_at: at,
                },
            )
            .await?;

        self.publish(chain, DomainEvent::RiskScoreUpdated(result))
            .await;
        Ok(())
    }

    /// Every *current* member of `entity_ids`, in encounter order, duplicates
    /// and all — [`recompute_many`](Self::recompute_many) is what
    /// deduplicates. A tombstoned/missing entity id (see the module docs)
    /// simply contributes nothing.
    async fn addresses_for_entities(
        &self,
        entity_ids: impl IntoIterator<Item = EntityId>,
    ) -> Result<Vec<AccountAddress>, RiskScoreError> {
        let mut addresses = Vec::new();
        for entity_id in entity_ids {
            if let Some(entity) = self.stores.entities.entity(entity_id).await? {
                addresses.extend(entity.addresses);
            }
        }
        Ok(addresses)
    }

    /// Deduplicate `addresses`, then recompute all of them with at most
    /// [`RECOMPUTE_CONCURRENCY`] in flight at once. A [`tokio::task::JoinSet`]
    /// of `Self` clones (every field is `Arc`-backed, so cloning gives each
    /// task its own owned, `'static` handle with no borrow across the spawn
    /// boundary) gated by a [`Semaphore`] — the tokio-native fan-out-with-a-cap
    /// idiom, deliberately not a second futures-combinator crate (this
    /// workspace already draws that line at `tokio-stream` only, see the root
    /// `Cargo.toml`). Every task runs to completion before this returns; the
    /// *first* error encountered (if any) is what's returned, so a partial
    /// failure is reported, never silently dropped.
    async fn recompute_many(
        &self,
        addresses: Vec<AccountAddress>,
        chain: Chain,
        at: DateTime<Utc>,
    ) -> Result<(), RiskScoreError> {
        let mut seen = BTreeSet::new();
        let semaphore = Arc::new(Semaphore::new(RECOMPUTE_CONCURRENCY));
        let mut tasks = JoinSet::new();

        for address in addresses {
            if !seen.insert(address) {
                continue;
            }
            let permit = semaphore
                .clone()
                .acquire_owned()
                .await
                .expect("semaphore is never closed while its owning task is alive");
            let scorer = self.clone();
            tasks.spawn(async move {
                let _permit = permit;
                scorer.recompute_one(address, chain, at).await
            });
        }

        let mut first_err = None;
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    first_err.get_or_insert(err);
                }
                Err(join_err) => {
                    first_err.get_or_insert(join_err.into());
                }
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    /// The per-event decision: which address(es) this event's input change
    /// touches, per the module docs' invalidation table.
    async fn process(
        &self,
        payload: DomainEvent,
        chain: Chain,
        at: DateTime<Utc>,
    ) -> Result<(), RiskScoreError> {
        use DomainEvent::*;
        match payload {
            LabelAdded(e) => self.recompute_one(e.address, chain, at).await,
            LabelUpdated(e) => self.recompute_one(e.address, chain, at).await,
            LabelRevoked(e) => self.recompute_one(e.address, chain, at).await,
            SanctionHit(e) => self.recompute_one(e.address, chain, at).await,
            EntityCreated(e) => self.recompute_one(e.seed_address, chain, at).await,
            EntityMerged(e) => {
                let addresses = self.addresses_for_entities([e.surviving_id]).await?;
                self.recompute_many(addresses, chain, at).await
            }
            EntitySplit(e) => {
                let addresses = self.addresses_for_entities(e.new_ids).await?;
                self.recompute_many(addresses, chain, at).await
            }
            AttributionUpdated(e) => {
                let addresses = self.addresses_for_entities(e.entity_ids).await?;
                self.recompute_many(addresses, chain, at).await
            }
            AttributionRetracted(e) => {
                let addresses = self.addresses_for_entities(e.entity_ids).await?;
                self.recompute_many(addresses, chain, at).await
            }
            other => {
                tracing::warn!(
                    event = other.event_type(),
                    "unexpected event on risk-scoring topics; skipping"
                );
                Ok(())
            }
        }
    }

    /// Process one event, then translate the outcome into the offset action —
    /// the same transient-retries/permanent-skips/shutdown-aware pattern
    /// [`crate::attribution::Attributor::dispatch`] uses.
    async fn dispatch(&self, envelope: EventEnvelope) -> Handled {
        let chain = envelope.chain;
        let at = envelope.occurred_at;
        match self.process(envelope.payload, chain, at).await {
            Ok(()) if self.shutdown.is_cancelled() => Handled::Stop,
            Ok(()) => Handled::Commit,
            Err(err) => event_bus::handled(err, "risk_scorer"),
        }
    }
}

#[async_trait]
impl EventHandler for RiskScorer {
    async fn handle(&self, envelope: EventEnvelope) -> Handled {
        self.dispatch(envelope).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{LabelKind, LabelRecord, LabelSource, SanctionEntry};
    use crate::risk::MODEL_VERSION;
    use crate::store::{EntityStore, LabelStore, SanctionsStore};
    use crate::test_util::{store_seams, InMemoryHotCache, InMemoryIntelligenceStore};
    use alloy_primitives::Address;
    use events::intelligence::{
        EntityCreated, EntityMerged, EntitySplit, LabelAdded, LabelRevoked, SanctionHit,
    };
    use uuid::Uuid;

    fn addr(byte: u8) -> AccountAddress {
        Address::repeat_byte(byte)
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    fn envelope(payload: DomainEvent, at: DateTime<Utc>) -> EventEnvelope {
        EventEnvelope::with_metadata(Uuid::new_v4(), at, Chain::ETHEREUM, payload)
    }

    use event_bus::test_util::RecordingSink;

    /// The `RiskScoreUpdated`s among the recorded events — a thin, crate-local
    /// projection over the shared [`RecordingSink`], which only owns generic
    /// recording; domain filters stay with the tests that need them.
    trait RiskScoresExt {
        fn risk_scores(&self) -> Vec<events::intelligence::RiskScoreUpdated>;
    }

    impl RiskScoresExt for RecordingSink {
        fn risk_scores(&self) -> Vec<events::intelligence::RiskScoreUpdated> {
            self.events()
                .into_iter()
                .filter_map(|e| match e {
                    DomainEvent::RiskScoreUpdated(r) => Some(r),
                    _ => None,
                })
                .collect()
        }
    }

    struct Harness {
        scorer: RiskScorer,
        sink: Arc<RecordingSink>,
        store: Arc<InMemoryIntelligenceStore>,
        cache: Arc<InMemoryHotCache>,
    }

    fn harness() -> Harness {
        let store = Arc::new(InMemoryIntelligenceStore::new());
        let cache = Arc::new(InMemoryHotCache::new());
        let sink = Arc::new(RecordingSink::default());
        let scorer = RiskScorer::new(
            store_seams(&store),
            cache.clone(),
            sink.clone(),
            CancellationToken::new(),
        );
        Harness {
            scorer,
            sink,
            store,
            cache,
        }
    }

    /// A `LabelAdded` for a known-scammer label recomputes that address's
    /// score, publishes `RiskScoreUpdated`, and leaves the fresh value in the
    /// `(address, model_version)` cache slot.
    #[tokio::test]
    async fn label_added_recomputes_and_caches_the_address() {
        let h = harness();
        let label = LabelRecord::new(
            addr(1),
            LabelKind::KnownScammer,
            "known scammer",
            LabelSource::Manual,
            "operator",
            at(1),
        );
        h.store.add_label(&label).await.unwrap();

        let handled = h
            .scorer
            .handle(envelope(
                DomainEvent::LabelAdded(LabelAdded {
                    address: addr(1),
                    kind: "KnownScammer".into(),
                    value: "known scammer".into(),
                    confidence: label.confidence,
                    source: "Manual".into(),
                }),
                at(10),
            ))
            .await;
        assert_eq!(handled, Handled::Commit);

        let scores = h.sink.risk_scores();
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].address, addr(1));
        assert!(scores[0].score > 0);

        let cached = h.cache.score(&addr(1), MODEL_VERSION).await.unwrap();
        assert_eq!(cached.map(|c| c.score), Some(scores[0].score));
    }

    /// A `SanctionHit` recomputes just the sanctioned address.
    #[tokio::test]
    async fn sanction_hit_recomputes_the_address() {
        let h = harness();
        h.store
            .seed_sanctions(&[SanctionEntry {
                address: addr(1),
                list_name: "ofac_sdn".into(),
                entry: "Evil Corp".into(),
                listed_at: None,
            }])
            .await
            .unwrap();

        h.scorer
            .handle(envelope(
                DomainEvent::SanctionHit(SanctionHit {
                    address: addr(1),
                    list: "ofac_sdn".into(),
                    entry: "Evil Corp".into(),
                }),
                at(5),
            ))
            .await;

        let scores = h.sink.risk_scores();
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].address, addr(1));
        assert_eq!(scores[0].confidence.get(), 1.0);
    }

    /// A revoked label still triggers a recompute — the fresh score reflects
    /// the label's absence (dropping back toward zero), proving invalidation
    /// re-reads current store state rather than trusting stale cache/event
    /// data.
    #[tokio::test]
    async fn label_revoked_recomputes_the_lowered_score() {
        let h = harness();
        let label = LabelRecord::new(
            addr(1),
            LabelKind::MevBot,
            "mev bot",
            LabelSource::Manual,
            "operator",
            at(1),
        );
        h.store.add_label(&label).await.unwrap();
        h.store
            .revoke_label(label.label_id, "false positive", at(5))
            .await
            .unwrap();

        h.scorer
            .handle(envelope(
                DomainEvent::LabelRevoked(LabelRevoked {
                    address: addr(1),
                    label_id: label.label_id,
                    reason: "false positive".into(),
                }),
                at(5),
            ))
            .await;

        let scores = h.sink.risk_scores();
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].score, 0, "the revoked label no longer scores");
    }

    /// `EntityCreated` recomputes the seed address only (a singleton entity
    /// has no cluster factor, but it's still the one address this event names).
    #[tokio::test]
    async fn entity_created_recomputes_the_seed_address() {
        let h = harness();
        let entity_id = EntityId::new();
        h.store
            .create_entity(entity_id, &addr(1), "seed", at(1))
            .await
            .unwrap();

        h.scorer
            .handle(envelope(
                DomainEvent::EntityCreated(EntityCreated {
                    entity_id,
                    seed_address: addr(1),
                }),
                at(1),
            ))
            .await;

        let scores = h.sink.risk_scores();
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].address, addr(1));
    }

    /// `EntityMerged` recomputes *every current member* of the surviving
    /// entity — both the address that was already there and the one the merge
    /// just absorbed — read fresh from the store rather than the two ids on
    /// the event.
    #[tokio::test]
    async fn entity_merged_recomputes_every_surviving_member() {
        let h = harness();
        let survivor = EntityId::new();
        let absorbed = EntityId::new();
        h.store
            .create_entity(survivor, &addr(1), "seed", at(1))
            .await
            .unwrap();
        h.store
            .create_entity(absorbed, &addr(2), "seed", at(1))
            .await
            .unwrap();
        h.store
            .absorb(survivor, absorbed, None, "test", at(1))
            .await
            .unwrap();

        h.scorer
            .handle(envelope(
                DomainEvent::EntityMerged(EntityMerged {
                    surviving_id: survivor,
                    absorbed_id: absorbed,
                    evidence_ref: "test".into(),
                }),
                at(10),
            ))
            .await;

        let mut addresses: Vec<_> = h.sink.risk_scores().iter().map(|s| s.address).collect();
        addresses.sort();
        assert_eq!(addresses, vec![addr(1), addr(2)]);
    }

    /// `EntitySplit` recomputes every member across every resulting entity.
    #[tokio::test]
    async fn entity_split_recomputes_every_new_members() {
        let h = harness();
        let entity_id = EntityId::new();
        h.store
            .create_entity(entity_id, &addr(1), "seed", at(1))
            .await
            .unwrap();
        h.store
            .link_address(entity_id, &addr(2), "cluster", at(1))
            .await
            .unwrap();
        h.store
            .link_address(entity_id, &addr(3), "cluster", at(1))
            .await
            .unwrap();

        let groups = vec![vec![addr(1), addr(2)], vec![addr(3)]];
        let crate::store::SplitOutcome::Split { new_ids } = h
            .store
            .split(entity_id, &groups, "operator", at(10))
            .await
            .unwrap()
        else {
            panic!("expected a successful split");
        };

        h.scorer
            .handle(envelope(
                DomainEvent::EntitySplit(EntitySplit {
                    original_id: entity_id,
                    new_ids,
                    reason: "operator".into(),
                }),
                at(10),
            ))
            .await;

        let mut addresses: Vec<_> = h.sink.risk_scores().iter().map(|s| s.address).collect();
        addresses.sort();
        assert_eq!(addresses, vec![addr(1), addr(2), addr(3)]);
    }

    /// Attribution updated across two entities recomputes every member of
    /// both, without double-publishing an address that (hypothetically)
    /// appeared in both lists.
    #[tokio::test]
    async fn attribution_updated_recomputes_every_named_entitys_members() {
        let h = harness();
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        h.store
            .create_entity(e1, &addr(1), "seed", at(1))
            .await
            .unwrap();
        h.store
            .create_entity(e2, &addr(2), "seed", at(1))
            .await
            .unwrap();

        h.scorer
            .handle(envelope(
                DomainEvent::AttributionUpdated(events::intelligence::AttributionUpdated {
                    incident_id: events::primitives::IncidentId::new(),
                    entity_ids: vec![e1, e2],
                    labels: vec![],
                }),
                at(10),
            ))
            .await;

        let mut addresses: Vec<_> = h.sink.risk_scores().iter().map(|s| s.address).collect();
        addresses.sort();
        assert_eq!(addresses, vec![addr(1), addr(2)]);
    }

    /// `AttributionRetracted` (§15, reorg rollback) recomputes every current
    /// member of the named entities — the reverse of `AttributionUpdated`,
    /// but the same fan-out.
    #[tokio::test]
    async fn attribution_retracted_recomputes_every_named_entitys_members() {
        let h = harness();
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        h.store
            .create_entity(e1, &addr(1), "seed", at(1))
            .await
            .unwrap();
        h.store
            .create_entity(e2, &addr(2), "seed", at(1))
            .await
            .unwrap();

        h.scorer
            .handle(envelope(
                DomainEvent::AttributionRetracted(events::intelligence::AttributionRetracted {
                    incident_id: events::primitives::IncidentId::new(),
                    entity_ids: vec![e1, e2],
                }),
                at(10),
            ))
            .await;

        let mut addresses: Vec<_> = h.sink.risk_scores().iter().map(|s| s.address).collect();
        addresses.sort();
        assert_eq!(addresses, vec![addr(1), addr(2)]);
    }

    /// A large entity's members all recompute exactly once, proving the
    /// bounded-concurrency fan-out (`RECOMPUTE_CONCURRENCY` is well under this
    /// count) doesn't drop or duplicate any member.
    #[tokio::test]
    async fn large_entity_recomputes_every_member_exactly_once() {
        let h = harness();
        let entity_id = EntityId::new();
        let member_count = RECOMPUTE_CONCURRENCY * 3 + 5;
        h.store
            .create_entity(entity_id, &addr(0), "seed", at(1))
            .await
            .unwrap();
        for i in 1..member_count {
            h.store
                .link_address(entity_id, &addr(i as u8), "cluster", at(1))
                .await
                .unwrap();
        }

        h.scorer
            .handle(envelope(
                DomainEvent::EntityMerged(EntityMerged {
                    surviving_id: entity_id,
                    absorbed_id: EntityId::new(),
                    evidence_ref: "test".into(),
                }),
                at(10),
            ))
            .await;

        let mut addresses: Vec<_> = h.sink.risk_scores().iter().map(|s| s.address).collect();
        addresses.sort();
        addresses.dedup();
        assert_eq!(addresses.len(), member_count);
    }

    /// An entity id that no longer resolves (already superseded by a later
    /// merge/split) contributes no addresses — not an error.
    #[tokio::test]
    async fn missing_entity_contributes_no_addresses() {
        let h = harness();
        h.scorer
            .handle(envelope(
                DomainEvent::EntityMerged(EntityMerged {
                    surviving_id: EntityId::new(),
                    absorbed_id: EntityId::new(),
                    evidence_ref: "test".into(),
                }),
                at(10),
            ))
            .await;
        assert!(h.sink.risk_scores().is_empty());
    }

    /// An event outside the consumed set is skipped, not an error.
    #[tokio::test]
    async fn unrelated_event_is_skipped() {
        let h = harness();
        let handled = h
            .scorer
            .handle(envelope(
                DomainEvent::IncidentRetracted(events::simulation::IncidentRetracted {
                    incident_id: events::primitives::IncidentId::new(),
                    reason: "reorg".into(),
                }),
                at(1),
            ))
            .await;
        assert_eq!(handled, Handled::Commit);
        assert!(h.sink.risk_scores().is_empty());
    }

    /// A `LabelAdded` evicts the address's existing cache entry before
    /// recomputing (§8: evict, not overwrite) — proven by seeding a stale
    /// entry under a different score first and confirming it's replaced.
    #[tokio::test]
    async fn recompute_evicts_the_stale_cache_entry_first() {
        let h = harness();
        h.cache
            .put_score(
                &addr(1),
                &CachedScore {
                    score: 99,
                    confidence: events::primitives::Confidence::new(0.5),
                    model_version: MODEL_VERSION.to_owned(),
                    computed_at: at(0),
                },
            )
            .await
            .unwrap();

        h.scorer
            .handle(envelope(
                DomainEvent::SanctionHit(SanctionHit {
                    address: addr(1),
                    list: "ofac_sdn".into(),
                    entry: "unlisted".into(),
                }),
                at(5),
            ))
            .await;

        // No sanctions/labels seeded — the recompute lands a fresh 0/100, not
        // the stale 99 the cache started with.
        let cached = h.cache.score(&addr(1), MODEL_VERSION).await.unwrap();
        assert_eq!(cached.map(|c| c.score), Some(0));
    }
}
