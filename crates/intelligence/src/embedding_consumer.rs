//! The **invalidation** half of the §20.3 embedding job (Sprint 19 t1) — the
//! `RiskScoreUpdated`-style recompute the task names.
//!
//! [`crate::embedding_sweep`] is the primary path, but a schedule alone is not
//! enough: the incident-history and own-label families are pure functions of
//! store state that some event just changed, and waiting out a whole sweep
//! interval would make the vector wrong about exactly the addresses it matters
//! most for — a freshly sanctioned one, say. So this consumer runs beside the
//! sweep, over the same [`Embedder`] core.
//!
//! ## Which addresses one event invalidates
//!
//! `LabelAdded`/`LabelUpdated`/`LabelRevoked`/`SanctionHit`/`EntityCreated`
//! each name one address: that address alone. `EntityMerged`/`EntitySplit`/
//! `AttributionUpdated`/`AttributionRetracted` name entities, whose incident
//! history and cluster size are shared by every member — so every *current*
//! member is recomputed, read fresh from the entity store rather than trusted
//! from the event (membership may have moved again since), exactly as
//! [`crate::risk_scorer`] does.
//!
//! ## The one fan-out this deliberately refuses
//!
//! Labelling an address also changes the counterparty-type distribution of
//! everyone who ever transacted with it. Fanning out there is the single
//! unbounded path in this design: a `LabelAdded` on a CEX hot wallet or a
//! router would invalidate millions of addresses off one event — the same
//! collapse the §8.2 hub-node degree cap exists to refuse.
//!
//! So counterparty-distribution drift is left to the scheduled sweep, and its
//! staleness bound is one sweep interval. **This is the concrete reason the
//! job is scheduled as well as event-driven**, rather than either alone.

use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use event_bus::dlq::DeadLetterQueue;
use event_bus::lag::{build_reporting_consumer, LagReporting};
use event_bus::{run_consumer, EventHandler, Handled};
use events::{DomainEvent, EventEnvelope};
use rdkafka::consumer::StreamConsumer;
use tokio_util::sync::CancellationToken;

use crate::embedding_job::{Embedder, EmbeddingError, Trigger};

/// The event types that can change what the kernel sees for some address — an
/// explicit, closed list (not a `mev.events.*` regex) so a renamed or missing
/// topic fails loudly, the same discipline every consumer on the backbone
/// follows.
///
/// `AddressEmbeddingUpdated` is deliberately absent: consuming our own output
/// would recompute forever. `RiskScoreUpdated` too — it is *derived from* the
/// same inputs this job reads, so consuming it would double every recompute
/// without adding a single fact.
pub const CONSUMED_EVENT_TYPES: &[&str] = &[
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

/// The topics the consumer subscribes to (one per [`CONSUMED_EVENT_TYPES`]).
pub fn consumed_topics() -> Vec<String> {
    events::topics_for(CONSUMED_EVENT_TYPES)
}

/// Build the consumer. Manual offset commit ties the commit to a fully
/// computed-and-published vector, same as this service's other consumers;
/// `earliest` means a fresh group embeds from the start of retained history.
pub fn build_consumer(brokers: &str, group_id: &str) -> Result<StreamConsumer<LagReporting>> {
    build_reporting_consumer(brokers, group_id, "embedding_job")
}

/// The invalidation consumer: a thin event→addresses mapping over
/// [`Embedder`]. It owns no compute of its own — that is the point of the
/// split, and why the sweep and this consumer share one page-concurrency bound
/// rather than two.
#[derive(Clone)]
pub struct EmbeddingConsumer {
    embedder: Embedder,
}

impl EmbeddingConsumer {
    pub fn new(embedder: Embedder) -> Self {
        Self { embedder }
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
            "embedding_job",
            retry_backoff,
            dlq,
            self,
            shutdown,
        )
        .await
    }

    /// The per-event decision: which address(es) this input change touches,
    /// per the module docs' invalidation table.
    async fn process(&self, payload: DomainEvent, at: DateTime<Utc>) -> Result<(), EmbeddingError> {
        use DomainEvent::*;
        let addresses = match payload {
            LabelAdded(e) => vec![e.address],
            LabelUpdated(e) => vec![e.address],
            LabelRevoked(e) => vec![e.address],
            SanctionHit(e) => vec![e.address],
            EntityCreated(e) => vec![e.seed_address],
            EntityMerged(e) => {
                self.embedder
                    .addresses_for_entities(&[e.surviving_id])
                    .await?
            }
            EntitySplit(e) => self.embedder.addresses_for_entities(&e.new_ids).await?,
            AttributionUpdated(e) => self.embedder.addresses_for_entities(&e.entity_ids).await?,
            AttributionRetracted(e) => self.embedder.addresses_for_entities(&e.entity_ids).await?,
            other => {
                tracing::warn!(
                    event = other.event_type(),
                    "unexpected event on embedding topics; skipping"
                );
                return Ok(());
            }
        };
        self.embedder
            .compute(&addresses, at, Trigger::Event)
            .await
            .map(|_| ())
    }

    /// Process one event, then translate the outcome into the offset action —
    /// the same transient-retries / permanent-skips / shutdown-aware pattern
    /// every consumer in this crate uses.
    async fn dispatch(&self, envelope: EventEnvelope) -> Handled {
        match self.process(envelope.payload, envelope.occurred_at).await {
            Ok(()) if self.embedder.shutdown().is_cancelled() => Handled::Stop,
            Ok(()) => Handled::Commit,
            Err(err) => event_bus::handled(err, "embedding_job"),
        }
    }
}

#[async_trait]
impl EventHandler for EmbeddingConsumer {
    async fn handle(&self, envelope: EventEnvelope) -> Handled {
        self.dispatch(envelope).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adjacency::AdjacencyStore;
    use crate::embedding::v1;
    use crate::embedding_job::tests::{addr, adjacency_edge, at, harness, EmbeddingsExt, CHAIN};
    use crate::embedding_sweep::{EmbeddingSweep, SweepLimits, SweepState};
    use crate::model::LabelSource;
    use crate::store::EntityStore;
    use events::intelligence::{AttributionUpdated, EntityMerged, LabelAdded, SanctionHit};
    use events::primitives::{Confidence, EntityId, IncidentId};
    use uuid::Uuid;

    const DAY: i64 = 86_400;

    fn envelope(payload: DomainEvent, at: DateTime<Utc>) -> EventEnvelope {
        EventEnvelope::with_metadata(Uuid::new_v4(), at, CHAIN, payload)
    }

    fn label_added(address: u8) -> DomainEvent {
        DomainEvent::LabelAdded(LabelAdded {
            address: addr(address),
            kind: "MevBot".into(),
            value: "bot".into(),
            confidence: LabelSource::Heuristic.default_confidence(),
            source: "Heuristic".into(),
        })
    }

    // ── The consumed topic set ───────────────────────────────────────

    /// Consuming our own output would recompute forever; consuming
    /// `RiskScoreUpdated` would double every recompute while adding no fact
    /// this job doesn't already read from the store.
    #[test]
    fn the_job_does_not_consume_its_own_output_or_risk_scores() {
        let topics = consumed_topics();
        assert!(!topics
            .iter()
            .any(|t| t.ends_with("AddressEmbeddingUpdated")));
        assert!(!topics.iter().any(|t| t.ends_with("RiskScoreUpdated")));
        // `topics_for` asserts every name is a real variant, so a typo or a
        // renamed event fails right here rather than at subscribe time.
        assert_eq!(topics.len(), CONSUMED_EVENT_TYPES.len());
    }

    // ── Invalidation fan-out ─────────────────────────────────────────

    #[tokio::test]
    async fn a_label_event_recomputes_exactly_the_named_address() {
        let h = harness();
        h.graph
            .append(&[adjacency_edge(1, 2, 0), adjacency_edge(3, 1, DAY)])
            .await
            .unwrap();

        let consumer = EmbeddingConsumer::new(h.embedder.clone());
        let handled = consumer.handle(envelope(label_added(1), at(2 * DAY))).await;

        assert_eq!(handled, Handled::Commit);
        let published = h.sink.embeddings();
        assert_eq!(published.len(), 1, "only the labeled address is recomputed");
        assert_eq!(published[0].address, addr(1));
        assert_eq!(published[0].embedding_version, v1::VERSION);
    }

    /// The one fan-out this design refuses. A counterparty being labeled *does*
    /// change this address's counterparty distribution — but fanning out there
    /// means a `LabelAdded` on a router invalidating millions off one event.
    /// The sweep is what picks it up, and this test pins both halves of that
    /// bargain.
    #[tokio::test]
    async fn a_counterparty_label_does_not_fan_out_but_the_sweep_catches_it() {
        let h = harness();
        h.graph.append(&[adjacency_edge(1, 2, 0)]).await.unwrap();

        let consumer = EmbeddingConsumer::new(h.embedder.clone());
        consumer
            .handle(envelope(
                DomainEvent::SanctionHit(SanctionHit {
                    address: addr(2),
                    list: "ofac_sdn".into(),
                    entry: "Evil Corp".into(),
                }),
                at(3_600),
            ))
            .await;

        let published = h.sink.embeddings();
        assert_eq!(published.len(), 1);
        assert_eq!(
            published[0].address,
            addr(2),
            "only the sanctioned address, not the address it transacted with"
        );

        // …and the sweep is what eventually reaches address 1.
        let mut state = SweepState::default();
        EmbeddingSweep::new(h.embedder.clone(), SweepLimits::default())
            .tick(&mut state, at(3_600), &CancellationToken::new())
            .await
            .unwrap();
        let swept: Vec<_> = h
            .sink
            .embeddings()
            .into_iter()
            .skip(1)
            .map(|e| e.address)
            .collect();
        assert!(swept.contains(&addr(1)));
    }

    #[tokio::test]
    async fn an_entity_event_recomputes_every_current_member() {
        let h = harness();
        let entity_id = EntityId::new();
        h.store
            .create_entity(entity_id, &addr(1), "test", at(0))
            .await
            .unwrap();
        h.store
            .link_address(entity_id, &addr(2), "test", at(0))
            .await
            .unwrap();

        let handled = EmbeddingConsumer::new(h.embedder.clone())
            .handle(envelope(
                DomainEvent::EntityMerged(EntityMerged {
                    surviving_id: entity_id,
                    absorbed_id: EntityId::new(),
                    evidence_ref: "common-funder".into(),
                }),
                at(DAY),
            ))
            .await;

        assert_eq!(handled, Handled::Commit);
        let mut recomputed: Vec<_> = h.sink.embeddings().into_iter().map(|e| e.address).collect();
        recomputed.sort();
        assert_eq!(recomputed, vec![addr(1), addr(2)]);
    }

    /// Membership is read fresh from the store, never trusted from the event:
    /// an entity that has since been tombstoned contributes nothing, and
    /// whatever superseded it carries its own event.
    #[tokio::test]
    async fn an_unknown_entity_contributes_no_addresses() {
        let h = harness();
        let handled = EmbeddingConsumer::new(h.embedder.clone())
            .handle(envelope(
                DomainEvent::AttributionUpdated(AttributionUpdated {
                    incident_id: IncidentId::new(),
                    entity_ids: vec![EntityId::new()],
                    labels: vec![],
                }),
                at(DAY),
            ))
            .await;
        assert_eq!(handled, Handled::Commit);
        assert!(h.sink.embeddings().is_empty());
    }

    #[tokio::test]
    async fn an_unexpected_event_is_skipped_not_wedged() {
        let h = harness();
        let handled = EmbeddingConsumer::new(h.embedder.clone())
            .handle(envelope(
                DomainEvent::RiskScoreUpdated(events::intelligence::RiskScoreUpdated {
                    address: addr(1),
                    entity_id: None,
                    score: 10,
                    confidence: Confidence::new(0.5),
                    factors: vec![],
                    model_version: "risk-v1".into(),
                }),
                at(DAY),
            ))
            .await;
        assert_eq!(handled, Handled::Commit);
        assert!(h.sink.embeddings().is_empty());
    }

    // ── Idempotency (§4/§18) ─────────────────────────────────────────

    /// The kernel reads current store state, not the event payload, so a
    /// redelivered event recomputes to the identical vector — and change
    /// detection then means the redelivery publishes *nothing at all*.
    #[tokio::test]
    async fn a_redelivered_event_publishes_nothing_the_second_time() {
        let h = harness();
        h.graph.append(&[adjacency_edge(1, 2, 0)]).await.unwrap();
        let consumer = EmbeddingConsumer::new(h.embedder.clone());

        assert_eq!(
            consumer.handle(envelope(label_added(1), at(DAY))).await,
            Handled::Commit
        );
        assert_eq!(
            consumer.handle(envelope(label_added(1), at(DAY))).await,
            Handled::Commit
        );

        assert_eq!(
            h.sink.embeddings().len(),
            1,
            "the redelivery converged on the identical vector and wrote nothing"
        );
    }

    /// A transient store fault must leave the offset uncommitted so the event
    /// is redelivered — the recompute is idempotent, so a retry converges.
    #[tokio::test]
    async fn a_transient_store_failure_is_retried_not_committed() {
        let h = harness();
        h.graph.append(&[adjacency_edge(1, 2, 0)]).await.unwrap();
        h.embeddings.fail_next();

        let handled = EmbeddingConsumer::new(h.embedder.clone())
            .handle(envelope(
                DomainEvent::SanctionHit(SanctionHit {
                    address: addr(1),
                    list: "ofac_sdn".into(),
                    entry: "Evil Corp".into(),
                }),
                at(DAY),
            ))
            .await;

        assert_eq!(handled, Handled::Retry);
        assert!(
            h.sink.embeddings().is_empty(),
            "nothing is published when the durable write failed"
        );
    }
}
