//! Roll back scores/merges on reorg (§8.2, §15, Sprint 8 t3).
//!
//! Unlike `detection`/`simulation`'s in-memory, snapshot-per-block state
//! (`detection::state::CrossBlockState`, `simulation::reorg::OrphanedBlocks`),
//! every store this crate maintains is durable Postgres with **no block
//! number or hash anywhere** — labels, entities, attributions all key off
//! `label_id`/`entity_id`/`incident_id`, never a block. So this consumer does
//! not key off `BlockReverted` directly (there is nothing in these stores a
//! block could look up); it keys off [`events::simulation::IncidentRetracted`]
//! instead — the event a reorg already produces once simulation's
//! block→incident join withdraws an incident (§15), and the one durable link
//! this crate's own stores carry: `attributions` is keyed `(incident_id,
//! entity_id)`, and every [`crate::model::MergeLogEntry`] records the incident
//! (if any) whose attribution-driven clustering caused it. Reusing that join
//! means this consumer's rollback is real today, not a stub — it just stays
//! dormant until `simulation::reorg`'s own `IncidentIndex` (currently
//! `EmptyIncidentIndex`) starts actually producing `IncidentRetracted`.
//!
//! ## What one retraction undoes
//!
//! 1. **Attribution**: [`AttributionStore::retract_attributions_for_incident`](crate::store::AttributionStore::retract_attributions_for_incident)
//!    deletes every `(incident_id, entity_id)` row this incident wrote, and
//!    this consumer publishes [`AttributionRetracted`] naming the affected
//!    entities — the score-recompute trigger `risk_scorer.rs` already reacts
//!    to the same way it reacts to `AttributionUpdated` (its factors just
//!    shrink instead of grow).
//! 2. **Merges**: every unreverted [`MergeLogEntry`](crate::model::MergeLogEntry)
//!    this incident caused is reversed via
//!    [`EntityStore::reverse_merge`](crate::store::EntityStore::reverse_merge)
//!    — splitting the survivor back into exactly the addresses the merge
//!    moved and everything else it currently owns. A successful reversal
//!    publishes [`events::intelligence::EntitySplit`], which `risk_scorer.rs`
//!    already consumes to recompute every member of both resulting entities.
//!    A merge whose survivor has moved on since (a later merge/split touched
//!    the same addresses) is [`Unreversible`](crate::store::ReversalOutcome::Unreversible)
//!    — logged and left alone rather than silently undoing unrelated history,
//!    the same honest-limitation stance `simulation::reorg`'s
//!    `EmptyIncidentIndex` takes on an unbuilt join.
//!
//! Scores themselves are never rolled back directly — per `risk_scorer.rs`'s
//! own docs, a score is a pure function of current store state, so undoing
//! its *inputs* (attribution, entity membership) and letting the existing
//! `AttributionRetracted`/`EntitySplit` recompute triggers fire is the whole
//! rollback; there is no separate score history to restore.
//!
//! ## Idempotency (§4/§7)
//!
//! A redelivered `IncidentRetracted` is a no-op: `retract_attributions_for_incident`
//! returns `vec![]` once the rows are gone (nothing to publish), and
//! `reverse_merge` reports [`AlreadyReverted`](crate::store::ReversalOutcome::AlreadyReverted)
//! once `reverted_at` is set, so a retried or replayed retraction converges
//! rather than double-splitting an already-reversed merge.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use event_bus::dlq::DeadLetterQueue;
use event_bus::lag::{build_reporting_consumer, LagReporting};
use event_bus::{publish_resilient, run_consumer, EventHandler, EventSink, Handled, Transience};
use events::intelligence::{AttributionRetracted, EntitySplit};
use events::primitives::Chain;
use events::simulation::IncidentRetracted;
use events::{DomainEvent, EventEnvelope};
use rdkafka::consumer::StreamConsumer;
use tokio_util::sync::CancellationToken;

use crate::store::{ReversalOutcome, StoreError, StoreSeams};

/// The one event this consumer subscribes to.
const CONSUMED_EVENT_TYPES: &[&str] = &["IncidentRetracted"];

/// The topics the consumer subscribes to (one per [`CONSUMED_EVENT_TYPES`] entry).
pub fn consumed_topics() -> Vec<String> {
    events::topics_for(CONSUMED_EVENT_TYPES)
}

/// Build the consumer. Manual offset commit ties the commit to a fully
/// processed retraction (redelivery is safe — every write here is
/// idempotent); `earliest` means a fresh group processes retained retractions
/// from the start, the same discipline every other consumer on this backbone
/// follows.
pub fn build_consumer(brokers: &str, group_id: &str) -> Result<StreamConsumer<LagReporting>> {
    build_reporting_consumer(brokers, group_id, "reorg")
}

/// A failure rolling back one incident. Wraps the store seam's error and
/// forwards the shared retry/skip decision (§4): a transient fault leaves the
/// offset for redelivery (every write here is idempotent, so a retry
/// converges); a permanent one is logged and skipped so one poison retraction
/// can't wedge the stream.
#[derive(Debug, thiserror::Error)]
pub enum ReorgError {
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl Transience for ReorgError {
    /// Whether retrying the same retraction could plausibly succeed.
    fn is_transient(&self) -> bool {
        match self {
            ReorgError::Store(err) => err.is_transient(),
        }
    }
}

/// The reorg-rollback consumer: the store seams it retracts attribution/
/// merges through, and the sink it publishes discovered facts to.
pub struct ReorgConsumer {
    stores: StoreSeams,
    sink: Arc<dyn EventSink>,
    shutdown: CancellationToken,
    publish_backoff: Duration,
}

impl ReorgConsumer {
    /// Build the consumer over its seams. `shutdown` aborts publish-retry
    /// loops for a graceful drain, the same seam every other consumer on the
    /// backbone takes.
    pub fn new(stores: StoreSeams, sink: Arc<dyn EventSink>, shutdown: CancellationToken) -> Self {
        Self {
            stores,
            sink,
            shutdown,
            publish_backoff: event_bus::PUBLISH_BACKOFF,
        }
    }

    /// Drive the consumer off Kafka until shutdown or a fatal subscribe
    /// error, via the shared [`run_consumer`] loop.
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
            "reorg",
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

    /// Roll back one retracted incident: withdraw its attributions, then
    /// reverse every merge it caused (see the module docs). `at` is the
    /// retraction's event-time, stamped on every event this pass publishes.
    #[tracing::instrument(skip_all, fields(incident_id = %retracted.incident_id))]
    async fn process(
        &self,
        retracted: &IncidentRetracted,
        chain: Chain,
        at: DateTime<Utc>,
    ) -> Result<(), ReorgError> {
        let mut entity_ids = self
            .stores
            .attributions
            .retract_attributions_for_incident(retracted.incident_id)
            .await?;
        if !entity_ids.is_empty() {
            // Deterministic emission order regardless of the store's return order.
            entity_ids.sort_by_key(|id| id.0);
            self.publish(
                chain,
                DomainEvent::AttributionRetracted(AttributionRetracted {
                    incident_id: retracted.incident_id,
                    entity_ids,
                }),
            )
            .await;
        }

        let merges = self
            .stores
            .entities
            .merges_for_incident(retracted.incident_id)
            .await?;
        for merge in merges {
            match self
                .stores
                .entities
                .reverse_merge(merge.merge_id, at)
                .await?
            {
                ReversalOutcome::Reversed {
                    split_id,
                    continuing_id,
                } => {
                    tracing::info!(
                        merge_id = %merge.merge_id,
                        surviving_id = %merge.surviving_id,
                        absorbed_id = %merge.absorbed_id,
                        "reversed a merge caused by a retracted incident"
                    );
                    self.publish(
                        chain,
                        DomainEvent::EntitySplit(EntitySplit {
                            original_id: merge.surviving_id,
                            new_ids: vec![split_id, continuing_id],
                            reason: format!(
                                "block reorg: incident {} retracted, merge {} (absorbed {} \
                                 into {}) reversed",
                                retracted.incident_id,
                                merge.merge_id,
                                merge.absorbed_id,
                                merge.surviving_id
                            ),
                        }),
                    )
                    .await;
                }
                ReversalOutcome::AlreadyReverted => {
                    // A redelivered retraction — this merge was already
                    // reversed by an earlier delivery. Nothing to do.
                }
                ReversalOutcome::Unreversible(reason) => {
                    tracing::warn!(
                        merge_id = %merge.merge_id,
                        incident_id = %retracted.incident_id,
                        reason = %reason,
                        "merge could not be automatically reversed on incident retraction; \
                         left logged for manual review"
                    );
                }
            }
        }

        Ok(())
    }

    /// Roll back, then translate the outcome into the offset action — the
    /// same transient-retries/permanent-skips/shutdown-aware pattern
    /// [`crate::attribution::Attributor::dispatch`] and
    /// [`crate::risk_scorer::RiskScorer::dispatch`] use.
    async fn dispatch(&self, envelope: EventEnvelope) -> Handled {
        let chain = envelope.chain;
        let at = envelope.occurred_at;
        match envelope.payload {
            DomainEvent::IncidentRetracted(retracted) => {
                match self.process(&retracted, chain, at).await {
                    Ok(()) if self.shutdown.is_cancelled() => Handled::Stop,
                    Ok(()) => Handled::Commit,
                    Err(err) => event_bus::handled(err, "reorg"),
                }
            }
            other => {
                tracing::warn!(
                    event = other.event_type(),
                    "unexpected event on the reorg topic; skipping"
                );
                Handled::Commit
            }
        }
    }
}

#[async_trait]
impl EventHandler for ReorgConsumer {
    async fn handle(&self, envelope: EventEnvelope) -> Handled {
        self.dispatch(envelope).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AttributionRecord;
    use crate::store::{AttributionStore, EntityStore, MergeOutcome};
    use crate::test_util::{store_seams, InMemoryIntelligenceStore};
    use alloy_primitives::Address;
    use events::primitives::{AccountAddress, Confidence, EntityId, IncidentId};
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

    struct Harness {
        consumer: ReorgConsumer,
        sink: Arc<RecordingSink>,
        store: Arc<InMemoryIntelligenceStore>,
    }

    fn harness() -> Harness {
        let store = Arc::new(InMemoryIntelligenceStore::new());
        let sink = Arc::new(RecordingSink::default());
        let consumer =
            ReorgConsumer::new(store_seams(&store), sink.clone(), CancellationToken::new());
        Harness {
            consumer,
            sink,
            store,
        }
    }

    /// Retracting an incident with no attribution and no merges is a
    /// committable no-op — publishes nothing.
    #[tokio::test]
    async fn retracting_an_untouched_incident_is_a_committable_noop() {
        let h = harness();
        let incident_id = IncidentId::new();
        let handled = h
            .consumer
            .handle(envelope(
                DomainEvent::IncidentRetracted(IncidentRetracted {
                    incident_id,
                    reason: "test".into(),
                }),
                at(10),
            ))
            .await;
        assert_eq!(handled, Handled::Commit);
        assert!(h.sink.events().is_empty());
    }

    /// Retracting an incident deletes its attribution rows and publishes
    /// `AttributionRetracted` naming the affected entities.
    #[tokio::test]
    async fn retracting_an_incident_removes_its_attributions() {
        let h = harness();
        let incident_id = IncidentId::new();
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
        for entity_id in [e1, e2] {
            h.store
                .record_attribution(&AttributionRecord {
                    incident_id,
                    entity_id,
                    confidence: Confidence::new(0.75),
                    evidence: "test".into(),
                    attributed_at: at(1),
                })
                .await
                .unwrap();
        }

        let handled = h
            .consumer
            .handle(envelope(
                DomainEvent::IncidentRetracted(IncidentRetracted {
                    incident_id,
                    reason: "reorg".into(),
                }),
                at(10),
            ))
            .await;
        assert_eq!(handled, Handled::Commit);

        assert!(h
            .store
            .attributions_for_incident(incident_id)
            .await
            .unwrap()
            .is_empty());

        let retracted = h
            .sink
            .events()
            .into_iter()
            .find_map(|e| match e {
                DomainEvent::AttributionRetracted(r) => Some(r),
                _ => None,
            })
            .expect("AttributionRetracted published");
        assert_eq!(retracted.incident_id, incident_id);
        let mut entity_ids = retracted.entity_ids;
        entity_ids.sort_by_key(|id| id.0);
        let mut expected = vec![e1, e2];
        expected.sort_by_key(|id| id.0);
        assert_eq!(entity_ids, expected);

        // Redelivery is a no-op: nothing left to retract, nothing published.
        let sink2 = Arc::new(RecordingSink::default());
        let consumer2 = ReorgConsumer::new(
            store_seams(&h.store),
            sink2.clone(),
            CancellationToken::new(),
        );
        consumer2
            .handle(envelope(
                DomainEvent::IncidentRetracted(IncidentRetracted {
                    incident_id,
                    reason: "reorg".into(),
                }),
                at(20),
            ))
            .await;
        assert!(sink2.events().is_empty());
    }

    /// Retracting the incident that caused a merge reverses it — the survivor
    /// splits back into exactly the addresses the merge moved and everything
    /// else it owns — and publishes `EntitySplit`.
    #[tokio::test]
    async fn retracting_an_incident_reverses_its_merge() {
        let h = harness();
        let incident_id = IncidentId::new();
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
        assert!(matches!(
            h.store
                .absorb(survivor, absorbed, Some(incident_id), "test", at(2))
                .await
                .unwrap(),
            MergeOutcome::Merged { .. }
        ));

        let handled = h
            .consumer
            .handle(envelope(
                DomainEvent::IncidentRetracted(IncidentRetracted {
                    incident_id,
                    reason: "reorg".into(),
                }),
                at(10),
            ))
            .await;
        assert_eq!(handled, Handled::Commit);

        let split = h
            .sink
            .events()
            .into_iter()
            .find_map(|e| match e {
                DomainEvent::EntitySplit(s) => Some(s),
                _ => None,
            })
            .expect("EntitySplit published");
        assert_eq!(split.original_id, survivor);
        assert_eq!(split.new_ids.len(), 2);

        // addr(2) (the moved address) and addr(1) (the survivor's own) now
        // belong to two different, fresh entities.
        let owner1 = h.store.entity_for_address(&addr(1)).await.unwrap().unwrap();
        let owner2 = h.store.entity_for_address(&addr(2)).await.unwrap().unwrap();
        assert_ne!(owner1, owner2);
        assert!(split.new_ids.contains(&owner1));
        assert!(split.new_ids.contains(&owner2));

        // The merge log entry is marked reverted — a redelivered retraction
        // won't try to reverse it again.
        assert!(h
            .store
            .merges_for_incident(incident_id)
            .await
            .unwrap()
            .is_empty());
    }

    /// A merge whose survivor has moved on since (a later merge absorbed the
    /// survivor itself) is left alone — logged as unreversible, not silently
    /// undone or crashed on.
    #[tokio::test]
    async fn a_merge_whose_survivor_moved_on_is_left_unreversed() {
        let h = harness();
        let incident_id = IncidentId::new();
        let survivor = EntityId::new();
        let absorbed = EntityId::new();
        let later = EntityId::new();
        h.store
            .create_entity(survivor, &addr(1), "seed", at(1))
            .await
            .unwrap();
        h.store
            .create_entity(absorbed, &addr(2), "seed", at(1))
            .await
            .unwrap();
        h.store
            .create_entity(later, &addr(3), "seed", at(1))
            .await
            .unwrap();
        h.store
            .absorb(survivor, absorbed, Some(incident_id), "test", at(2))
            .await
            .unwrap();
        // A later, unrelated merge absorbs the survivor itself — its
        // membership (and its very activeness) has moved on.
        h.store
            .absorb(later, survivor, None, "unrelated", at(3))
            .await
            .unwrap();

        let handled = h
            .consumer
            .handle(envelope(
                DomainEvent::IncidentRetracted(IncidentRetracted {
                    incident_id,
                    reason: "reorg".into(),
                }),
                at(10),
            ))
            .await;
        assert_eq!(
            handled,
            Handled::Commit,
            "an unreversible merge still commits"
        );

        assert!(
            h.sink
                .events()
                .iter()
                .all(|e| !matches!(e, DomainEvent::EntitySplit(_))),
            "no split published for a merge that couldn't be safely reversed"
        );
        // The merge log entry stays unreverted for an operator to resolve.
        assert_eq!(
            h.store
                .merges_for_incident(incident_id)
                .await
                .unwrap()
                .len(),
            1
        );
    }
}
