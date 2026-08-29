//! The thin consumer (§7 slow path): one `IncidentCreated` in, one draft job
//! recorded, offset committed — in milliseconds.
//!
//! # The rule this module exists to obey
//!
//! `event_bus::run_consumer` awaits its handler *before* committing. A
//! completion over an incident's audit stream takes minutes, so a handler that
//! called the model directly would blow `max.poll.interval.ms`: the member is
//! evicted, the partition rebalances, the record is redelivered, and the same
//! expensive call starts again somewhere else — with the first one still
//! running and still billing. That is not a tuning problem (raising the poll
//! interval trades it for a fleet that takes minutes to notice a dead pod);
//! it is the reason the work does not belong in the handler at all.
//!
//! So this handler does exactly one durable write and returns. The work
//! happens in [`crate::worker`], on the other side of the queue.
//!
//! # Idempotency
//!
//! `DraftStore::enqueue` is keyed on `(kind, subject_id)`, so a redelivered
//! `IncidentCreated` resolves to the draft that already exists. That is the
//! §7 dedup requirement, and here it is also the money: a second row would be
//! a second billed narrative of the same incident.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use event_bus::dlq::DeadLetterQueue;
use event_bus::lag::{build_reporting_consumer, LagReporting};
use event_bus::{handled, EventHandler, Handled};
use events::{DomainEvent, EventEnvelope};
use rdkafka::consumer::StreamConsumer;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::metrics;
use crate::model::DraftJob;
use crate::store::{DraftQueue, Enqueued};

/// Log/span label for this consumer.
pub const CONSUMER: &str = "copilot";

/// The one §20.4 event type this service consumes today. An explicit closed
/// list, not a topic regex — the same discipline as every consumer on the
/// backbone. (t4's rule drafts arrive over HTTP, not Kafka: a customer typing
/// a sentence is a request, not a fact about the chain.)
const CONSUMED_EVENT_TYPES: &[&str] = &["IncidentCreated"];

pub fn consumed_topics() -> Vec<String> {
    events::topics_for(CONSUMED_EVENT_TYPES)
}

/// Build the consumer: the shared lag-reporting shape, so
/// `kafka_consumer_lag` — the keeping-up signal ops page on — is exported
/// without this crate touching rdkafka config.
pub fn build_consumer(brokers: &str, group_id: &str) -> Result<StreamConsumer<LagReporting>> {
    build_reporting_consumer(brokers, group_id, CONSUMER)
}

/// Records a draft job per incident and wakes the worker pool.
///
/// Holds a [`DraftQueue`] — one method — and no `LlmClient`. Both are the
/// same design decision expressed in the type: the code that runs inside
/// `run_consumer`'s handler is structurally incapable of doing anything slow,
/// so the eviction/rebalance/redelivery loop this crate exists to avoid
/// cannot be re-introduced by an edit.
#[derive(Debug)]
pub struct CopilotConsumer {
    store: Arc<dyn DraftQueue>,
    /// Handed to the worker pool so a fresh job is drained now rather than at
    /// the next poll tick. A *hint*, never the mechanism: the pool's own
    /// polling is what covers jobs enqueued by other pods and leases that
    /// expired, so losing a notification costs latency, not work.
    wake: Arc<Notify>,
}

impl CopilotConsumer {
    pub fn new(store: Arc<dyn DraftQueue>, wake: Arc<Notify>) -> Self {
        Self { store, wake }
    }

    /// Subscribe and consume until `shutdown` fires.
    pub async fn run(
        self,
        consumer: StreamConsumer<LagReporting>,
        retry_backoff: Duration,
        dlq: Option<&DeadLetterQueue>,
        shutdown: &CancellationToken,
    ) -> Result<()> {
        let topics = consumed_topics();
        let topics: Vec<&str> = topics.iter().map(String::as_str).collect();
        event_bus::run_consumer(
            consumer,
            &topics,
            CONSUMER,
            retry_backoff,
            dlq,
            self,
            shutdown,
        )
        .await
    }
}

#[async_trait]
impl EventHandler for CopilotConsumer {
    async fn handle(&self, envelope: EventEnvelope) -> Handled {
        let DomainEvent::IncidentCreated(incident) = &envelope.payload else {
            // Another type on a topic this consumer subscribes to: nothing is
            // wrong with the record, so it is committed, not dead-lettered.
            return Handled::Commit;
        };

        let job = DraftJob::narrative(incident.incident_id, envelope.chain);
        match self.store.enqueue(&job, Utc::now()).await {
            Ok(outcome) => {
                let kind = job.kind.as_wire_str();
                match outcome {
                    Enqueued::Queued(draft_id) => {
                        metrics::record_enqueued(kind, "queued");
                        tracing::info!(
                            %draft_id,
                            incident_id = %incident.incident_id,
                            severity = ?incident.severity,
                            "draft job recorded"
                        );
                        // Only a *new* job is worth waking the pool for.
                        self.wake.notify_one();
                    }
                    Enqueued::AlreadyQueued(draft_id) => {
                        metrics::record_enqueued(kind, "duplicate");
                        tracing::debug!(
                            %draft_id,
                            incident_id = %incident.incident_id,
                            "incident already has a draft; redelivery absorbed"
                        );
                    }
                }
                Handled::Commit
            }
            // The shared retry-or-park decision: a store blip leaves the
            // offset for redelivery (enqueue is idempotent, so a redelivery is
            // free); a malformed row is parked on the DLQ.
            Err(err) => handled(err, CONSUMER),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DraftKind, DraftStatus};
    use crate::test_util::{incident_created, InMemoryDraftStore};
    use events::primitives::IncidentId;

    fn consumer(store: Arc<InMemoryDraftStore>) -> CopilotConsumer {
        CopilotConsumer::new(store, Arc::new(Notify::new()))
    }

    #[tokio::test]
    async fn an_incident_becomes_exactly_one_queued_draft() {
        let store = Arc::new(InMemoryDraftStore::default());
        let handler = consumer(store.clone());
        let incident = IncidentId::new();

        assert!(matches!(
            handler.handle(incident_created(incident)).await,
            Handled::Commit
        ));

        let drafts = store.drafts();
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].kind, DraftKind::IncidentNarrative);
        assert_eq!(drafts[0].status, DraftStatus::Queued);
        assert_eq!(drafts[0].subject_id, incident.0);
    }

    #[tokio::test]
    async fn a_redelivery_does_not_buy_a_second_narrative() {
        let store = Arc::new(InMemoryDraftStore::default());
        let handler = consumer(store.clone());
        let incident = IncidentId::new();

        handler.handle(incident_created(incident)).await;
        handler.handle(incident_created(incident)).await;

        assert_eq!(
            store.drafts().len(),
            1,
            "at-least-once delivery must not mean twice-billed"
        );
    }

    #[tokio::test]
    async fn the_handler_commits_without_calling_a_model() {
        // The §7 constraint, stated as a test: the handler's whole job is one
        // store write. It holds no LLM client, so it *cannot* take minutes.
        let store = Arc::new(InMemoryDraftStore::default());
        let handler = consumer(store.clone());
        let started = std::time::Instant::now();
        handler.handle(incident_created(IncidentId::new())).await;
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn a_store_blip_leaves_the_offset_for_redelivery() {
        let store = Arc::new(InMemoryDraftStore::default().failing_transiently());
        let handler = consumer(store);
        assert!(matches!(
            handler.handle(incident_created(IncidentId::new())).await,
            Handled::Retry
        ));
    }

    #[tokio::test]
    async fn an_unrelated_event_is_committed_not_dead_lettered() {
        let store = Arc::new(InMemoryDraftStore::default());
        let handler = consumer(store.clone());
        assert!(matches!(
            handler.handle(crate::test_util::envelope(0)).await,
            Handled::Commit
        ));
        assert!(store.drafts().is_empty());
    }
}
