//! The incident/job **persistence consumer** (§7, §14, Sprint 6 t5) — the effectful
//! shell that lands the pure [`IncidentProjection`](crate::projection) fold in Postgres +
//! ClickHouse.
//!
//! It consumes the simulation result-path events off Kafka, folds each into the in-memory
//! projection (which supplies the §7 idempotency + reorder tolerance, once, where it is
//! unit-tested without infrastructure), and write-throughs the result to the two stores
//! §14 assigns the simulation service:
//!
//! - **Postgres** (mutable read model): the confirmed-incident row and the in-flight job
//!   row, via [`IncidentStore`].
//! - **ClickHouse** (append-only firehose): one analytics row per real change, via
//!   [`IncidentAnalytics`].
//!
//! Built on the shared [`event_bus::run_consumer`] loop like [`dispatcher`](crate::dispatcher):
//! the subscribe/decode/trace/commit mechanics live there; this module supplies only the
//! per-event decision as an [`EventHandler`]. At-least-once — the offset commits only after
//! the write-through succeeds, and a store fault leaves it for redelivery.
//!
//! ## Why write-through is safe under redelivery
//!
//! Every write is idempotent, so re-processing a redelivered event converges:
//!
//! - **The incident row is upserted on both `Updated` and `Duplicate`.** The
//!   [`IncidentRecord`] the fold yields is always the current merged truth, so the upsert
//!   is a no-op when nothing changed — *and* re-running it on a redelivered `Duplicate`
//!   closes the one gap that would otherwise lose data: a store fault → `Retry` →
//!   redelivery re-folds to `Duplicate`, and if we only wrote on `Updated` the row a failed
//!   write never persisted would be dropped. So the queryable read model stays exact.
//! - **The analytics row is appended only on `Updated`.** Gating on a *real* change keeps
//!   the append dedup-consistent: a worker crash-rerun re-emits identical figures under a
//!   fresh event id, which the content-based fold reports as a `Duplicate` — so it does not
//!   double-count. The narrow cost is that a store fault landing *between* a successful
//!   incident upsert and the analytics append, followed by a Kafka redelivery (re-folded to
//!   `Duplicate`), drops that one analytics row. Acceptable: the analytics table is a
//!   trend firehose, not a system of record (the event store is), and the Postgres read
//!   model — the queryable truth — stays exact via the upsert above. Exactly-once analytics
//!   (event-id dedup) is a documented follow-up.

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use async_trait::async_trait;
use event_bus::{run_consumer, EventHandler, Handled};
use events::{DomainEvent, EventEnvelope};
use rdkafka::consumer::StreamConsumer;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use crate::projection::{Applied, IncidentProjection, IncidentRecord};
use crate::store::{AnalyticsRow, IncidentAnalytics, IncidentStore, JobUpdate, PersistError};

/// The result-path event types the projection consumes. `SimulationRequested` is here for
/// in-flight *job* tracking (the fold ignores it); the other four drive the incident read
/// model. An explicit, closed list (not a `mev.events.*` regex) so a renamed/missing topic
/// fails loudly rather than silently matching nothing — same discipline as the dispatcher.
const CONSUMED_EVENT_TYPES: &[&str] = &[
    "SimulationRequested",
    "SimulationCompleted",
    "IncidentCreated",
    "IncidentRetracted",
    "IncidentFinalized",
];

/// The topics the projection subscribes to (one per [`CONSUMED_EVENT_TYPES`] entry).
pub fn consumed_topics() -> Vec<String> {
    CONSUMED_EVENT_TYPES
        .iter()
        .map(|ty| events::topic_for(ty))
        .collect()
}

/// Build the consumer. Manual offset commit (`enable.auto.commit=false`) ties the commit to
/// a successful write-through; `earliest` means a fresh group projects from the start of
/// retained history (cf. the dispatcher / event-store consumers).
pub fn build_consumer(brokers: &str, group_id: &str) -> Result<StreamConsumer> {
    rdkafka::ClientConfig::new()
        .set("bootstrap.servers", brokers)
        .set("group.id", group_id)
        .set("enable.auto.commit", "false")
        .set("auto.offset.reset", "earliest")
        .create()
        .context("creating Kafka consumer")
}

/// The persistence consumer: the in-memory fold plus the two store seams. The fold is
/// behind a `Mutex` because [`EventHandler::handle`] is `&self` (one consumer, so no
/// contention in practice); the stores are `Arc<dyn …>` so tests swap in doubles.
pub struct ProjectionConsumer {
    projection: Mutex<IncidentProjection>,
    store: Arc<dyn IncidentStore>,
    analytics: Arc<dyn IncidentAnalytics>,
}

impl ProjectionConsumer {
    /// Build the consumer over its two stores with a fresh, empty projection.
    pub fn new(store: Arc<dyn IncidentStore>, analytics: Arc<dyn IncidentAnalytics>) -> Self {
        Self {
            projection: Mutex::new(IncidentProjection::new()),
            store,
            analytics,
        }
    }

    /// Drive the consumer off Kafka until shutdown or a fatal subscribe error, via the
    /// shared [`run_consumer`] loop. `retry_backoff` paces a store-fault redelivery.
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
            "projection",
            retry_backoff,
            self,
            shutdown,
        )
        .await
    }
}

#[async_trait]
impl EventHandler for ProjectionConsumer {
    async fn handle(&self, envelope: EventEnvelope) -> Handled {
        // 1. In-flight job tracking — derived straight from the event type, independent of
        //    the incident fold (the SQL upsert is itself idempotent + monotonic).
        if let Some(job) = JobUpdate::from_event(&envelope) {
            if let Err(err) = self.store.record_job(&job).await {
                return handled_for(err, "recording job state");
            }
        }

        // 2. Fold into the incident read model, then read back the affected row (cloned so
        //    the lock is released before any await). `apply` never panics (§4), so the
        //    mutex is not poisoned in practice.
        let (verdict, record) = {
            let mut projection = self.projection.lock().expect("projection mutex poisoned");
            let verdict = projection.apply(&envelope);
            let record = record_of(&projection, &envelope.payload).cloned();
            (verdict, record)
        };

        match verdict {
            // A non-result event (or `SimulationRequested`, whose job row is done above):
            // nothing to persist to the incident model.
            Applied::Ignored => Handled::Commit,
            Applied::Updated | Applied::Duplicate => {
                let Some(record) = record else {
                    // A terminal event that arrived before its `IncidentCreated`: the fold
                    // buffered it as an orphan and will replay it (and persist) when the
                    // creation links the row. Nothing to write yet.
                    return Handled::Commit;
                };

                // Upsert on both verdicts (idempotent) so a redelivery after a failed write
                // still lands the row — see the module docs.
                if let Err(err) = self.store.upsert_incident(&record).await {
                    return handled_for(err, "incident upsert");
                }

                // Analytics only on a real change (dedup-consistent with crash-reruns).
                if verdict == Applied::Updated {
                    let row = AnalyticsRow::from_event(&envelope, &record);
                    if let Err(err) = self.analytics.append(&row).await {
                        return handled_for(err, "analytics append");
                    }
                }

                Handled::Commit
            }
        }
    }
}

/// Map a [`PersistError`] to the offset action (§4). A **transient** fault (I/O, pool,
/// server) leaves the offset for redelivery — safe, since every write is idempotent. A
/// **permanent** one (a programming/encoding/schema bug that will fail identically every
/// time) is logged loudly and **committed** (skipped) so a single poison event can't wedge
/// the stream. `what` names the failing write for the log.
fn handled_for(err: PersistError, what: &str) -> Handled {
    if err.is_transient() {
        tracing::warn!(error = %err, "{what} failed (transient); leaving offset to retry");
        Handled::Retry
    } else {
        tracing::error!(
            error = %err,
            "{what} failed permanently; skipping event so it cannot wedge the stream"
        );
        Handled::Commit
    }
}

/// The incident row a result-path event affects: alert-keyed events resolve directly,
/// incident-keyed terminals resolve via the fold's learned `incident_id → alert_id` link
/// (`None` until the linking `IncidentCreated` has been folded — an orphaned terminal).
fn record_of<'p>(
    projection: &'p IncidentProjection,
    payload: &DomainEvent,
) -> Option<&'p IncidentRecord> {
    match payload {
        DomainEvent::SimulationCompleted(completed) => projection.record(&completed.alert_id),
        DomainEvent::IncidentCreated(created) => projection.record(&created.alert_id),
        DomainEvent::IncidentRetracted(retracted) => {
            projection.record_for_incident(&retracted.incident_id)
        }
        DomainEvent::IncidentFinalized(finalized) => {
            projection.record_for_incident(&finalized.incident_id)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use chrono::{DateTime, Utc};
    use events::primitives::{AlertId, AlertKind, Chain, IncidentId, Severity};
    use events::simulation::{
        IncidentCreated, IncidentRetracted, SimulationCompleted, SimulationRequested,
    };
    use revm::primitives::B256;
    use uuid::Uuid;

    use crate::store::{JobState, JobUpdate, PersistError};

    /// Records every incident upsert + job update, and can be told to fail — transiently
    /// (a closed pool → `Retry`) or permanently (a decode/schema bug → skip) — to exercise
    /// both offset branches.
    #[derive(Default)]
    struct RecordingStore {
        incidents: Mutex<Vec<IncidentRecord>>,
        jobs: Mutex<Vec<JobUpdate>>,
        fail_transient: bool,
        fail_permanent: bool,
    }

    #[async_trait]
    impl IncidentStore for RecordingStore {
        async fn upsert_incident(&self, record: &IncidentRecord) -> Result<(), PersistError> {
            if self.fail_transient {
                return Err(PersistError::Postgres(sqlx::Error::PoolClosed));
            }
            if self.fail_permanent {
                // A decode fault is a programming bug — permanent, never succeeds on retry.
                return Err(PersistError::Postgres(sqlx::Error::Decode(
                    "bad row".into(),
                )));
            }
            self.incidents.lock().unwrap().push(record.clone());
            Ok(())
        }
        async fn record_job(&self, job: &JobUpdate) -> Result<(), PersistError> {
            self.jobs.lock().unwrap().push(job.clone());
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingAnalytics {
        rows: Mutex<Vec<AnalyticsRow>>,
    }

    #[async_trait]
    impl IncidentAnalytics for RecordingAnalytics {
        async fn append(&self, row: &AnalyticsRow) -> Result<(), PersistError> {
            self.rows.lock().unwrap().push(row.clone());
            Ok(())
        }
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).expect("valid timestamp")
    }

    fn env(payload: DomainEvent, occurred_at: DateTime<Utc>) -> EventEnvelope {
        EventEnvelope::with_metadata(Uuid::new_v4(), occurred_at, Chain::ETHEREUM, payload)
    }

    fn completed(alert: AlertId, confirmed: bool) -> DomainEvent {
        DomainEvent::SimulationCompleted(SimulationCompleted {
            alert_id: alert,
            profit: if confirmed { 5.0 } else { 0.0 },
            victim_loss: 2.0,
            confirmed,
        })
    }

    fn created(alert: AlertId, incident: IncidentId) -> DomainEvent {
        DomainEvent::IncidentCreated(IncidentCreated {
            incident_id: incident,
            alert_id: alert,
            kind: AlertKind::Sandwich,
            txs: vec![B256::repeat_byte(0x01)],
            profit: 5.0,
            victim_loss: 2.0,
            severity: Severity::High,
        })
    }

    fn consumer() -> (
        ProjectionConsumer,
        Arc<RecordingStore>,
        Arc<RecordingAnalytics>,
    ) {
        let store = Arc::new(RecordingStore::default());
        let analytics = Arc::new(RecordingAnalytics::default());
        let consumer = ProjectionConsumer::new(store.clone(), analytics.clone());
        (consumer, store, analytics)
    }

    #[tokio::test]
    async fn a_confirmed_incident_writes_postgres_and_appends_analytics() {
        let (consumer, store, analytics) = consumer();
        let alert = AlertId::new();
        let incident = IncidentId::new();

        assert_eq!(
            consumer.handle(env(completed(alert, true), at(10))).await,
            Handled::Commit
        );
        assert_eq!(
            consumer.handle(env(created(alert, incident), at(11))).await,
            Handled::Commit
        );

        // The incident read model was upserted for each folded event.
        let incidents = store.incidents.lock().unwrap();
        assert_eq!(incidents.len(), 2);
        assert_eq!(incidents.last().unwrap().incident_id, Some(incident));

        // The job row was marked completed by the SimulationCompleted.
        let jobs = store.jobs.lock().unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].state, JobState::Completed);
        assert_eq!(jobs[0].alert_id, alert);

        // One analytics row per real change.
        assert_eq!(analytics.rows.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn simulation_requested_records_an_in_flight_job_without_an_incident() {
        let (consumer, store, analytics) = consumer();
        let alert = AlertId::new();

        let requested = DomainEvent::SimulationRequested(SimulationRequested {
            alert_id: alert,
            evidence: serde_json::json!({ "detector": "sandwich" }),
        });
        assert_eq!(
            consumer.handle(env(requested, at(5))).await,
            Handled::Commit
        );

        let jobs = store.jobs.lock().unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].state, JobState::Requested);
        // No incident row, no analytics — the fold ignores SimulationRequested.
        assert!(store.incidents.lock().unwrap().is_empty());
        assert!(analytics.rows.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_duplicate_event_re_upserts_the_row_but_appends_no_analytics() {
        let (consumer, store, analytics) = consumer();
        let alert = AlertId::new();

        let first = env(completed(alert, true), at(10));
        consumer.handle(first.clone()).await;
        // Exact redelivery: the fold reports Duplicate.
        assert_eq!(consumer.handle(first).await, Handled::Commit);

        // Upserted twice (idempotent — closes the failed-write/redelivery gap) …
        assert_eq!(store.incidents.lock().unwrap().len(), 2);
        // … but analytics appended only for the first, real change (no double count).
        assert_eq!(analytics.rows.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_transient_store_fault_leaves_the_offset_for_redelivery() {
        let store = Arc::new(RecordingStore {
            fail_transient: true,
            ..Default::default()
        });
        let analytics = Arc::new(RecordingAnalytics::default());
        let consumer = ProjectionConsumer::new(store.clone(), analytics.clone());

        let alert = AlertId::new();
        assert_eq!(
            consumer.handle(env(completed(alert, true), at(10))).await,
            Handled::Retry,
            "a transient upsert fault must not commit the offset"
        );
        assert!(analytics.rows.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_permanent_store_fault_skips_the_event_rather_than_wedging_the_stream() {
        let store = Arc::new(RecordingStore {
            fail_permanent: true,
            ..Default::default()
        });
        let analytics = Arc::new(RecordingAnalytics::default());
        let consumer = ProjectionConsumer::new(store.clone(), analytics.clone());

        let alert = AlertId::new();
        assert_eq!(
            consumer.handle(env(completed(alert, true), at(10))).await,
            Handled::Commit,
            "a permanent fault is skipped (committed) so one poison event can't wedge the stream (§4)"
        );
        assert!(analytics.rows.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_terminal_before_its_creation_persists_nothing_until_linked() {
        let (consumer, store, _analytics) = consumer();
        let incident = IncidentId::new();
        let alert = AlertId::new();

        // IncidentRetracted overtakes IncidentCreated across partitions: orphan-buffered.
        let retracted = DomainEvent::IncidentRetracted(IncidentRetracted {
            incident_id: incident,
            reason: "reorg".into(),
        });
        assert_eq!(
            consumer.handle(env(retracted, at(20))).await,
            Handled::Commit
        );
        assert!(
            store.incidents.lock().unwrap().is_empty(),
            "nothing to persist while the terminal is orphaned"
        );

        // The creation links the row and replays the retraction — now it persists, retracted.
        consumer.handle(env(created(alert, incident), at(10))).await;
        let incidents = store.incidents.lock().unwrap();
        let row = incidents.last().expect("row persisted after linking");
        assert_eq!(row.status, crate::projection::IncidentStatus::Retracted);
    }

    #[test]
    fn consumed_topics_are_the_five_result_path_topics() {
        let topics = consumed_topics();
        assert_eq!(topics.len(), 5);
        assert!(topics.contains(&"mev.events.SimulationCompleted".to_string()));
        assert!(topics.contains(&"mev.events.IncidentRetracted".to_string()));
    }
}
