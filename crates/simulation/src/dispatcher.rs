//! The dispatcher (§7, Sprint 5 t1) — a **thin** Kafka consumer that turns the
//! provisional-alert stream into queued simulation work.
//!
//! Mirroring detection's [`scheduler`](../../detection/src/scheduler.rs), the
//! decision is split from the broker I/O so it's testable with no Kafka and no
//! RabbitMQ:
//!
//! - `Dispatcher::process` is the **core**: given one `PreliminaryAlertCreated`
//!   (and its chain), it publishes the [`SimulationJob`](crate::command::SimulationJob)
//!   command to RabbitMQ and emits the `SimulationRequested` audit event to Kafka,
//!   returning a [`Handled`] verdict. Testable against in-memory sinks.
//! - The [`EventHandler`] impl + [`Dispatcher::run`] plug that core into the shared
//!   [`event_bus::run_consumer`] loop — the subscribe/decode/trace/commit mechanics
//!   live there, once, so the dispatcher carries only its per-alert decision.
//!   At-least-once, so a crash re-delivers rather than drops.
//!
//! ## Why a thin consumer, and what at-least-once buys us
//!
//! The dispatcher does no enrichment and holds no state — it is a pure fan-out from
//! one Kafka topic to one RabbitMQ queue (plus the audit event). At-least-once on
//! both ends is safe because the downstream is idempotent (§7): a redelivered
//! `SimulationJob` re-confirms the same `alert_id` (the simulation cache is
//! `(block, tx_set)`-keyed, the result `alert_id`-keyed), and a duplicate
//! `SimulationRequested` is deduped at the projection. So the dispatcher never
//! needs exactly-once machinery — it commits its Kafka offset only after the job is
//! queued, and a crash in between simply re-dispatches.
//!
//! Ordering: the command broker is order-free by design (jobs are independent,
//! §7), so unlike detection there is no committer stage or per-chain ordering
//! constraint to preserve here — a single in-line commit suffices.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use event_bus::dlq::DeadLetterQueue;
use event_bus::lag::{build_reporting_consumer, LagReporting};
use event_bus::{run_consumer, EventHandler, EventSink, Handled};
use events::detection::PreliminaryAlertCreated;
use events::primitives::Chain;
use events::{DomainEvent, EventEnvelope};
use rdkafka::consumer::StreamConsumer;
use tokio_util::sync::CancellationToken;

use crate::command::job_for_alert;
use crate::queue::{self, JobSink};

/// The one topic the dispatcher consumes: provisional alerts (§6 → §7). An explicit
/// name (not a `mev.events.*` regex) so a renamed/missing topic fails loudly rather
/// than silently matching nothing (cf. detection/event-store consumers).
pub fn consumed_topic() -> String {
    events::topic_for("PreliminaryAlertCreated")
}

/// Build the consumer. Manual offset commit (`enable.auto.commit=false`) is what
/// ties the commit to a job being queued; `earliest` means a fresh group dispatches
/// from the start of retained history (cf. detection/event-store).
pub fn build_consumer(brokers: &str, group_id: &str) -> Result<StreamConsumer<LagReporting>> {
    build_reporting_consumer(brokers, group_id, "dispatcher")
}

/// The dispatcher: holds the two publish seams and turns each provisional alert into
/// a queued `SimulationJob` plus a `SimulationRequested` audit event.
pub struct Dispatcher {
    /// RabbitMQ work-queue sink — where the `SimulationJob` command goes (§7).
    job_sink: Arc<dyn JobSink>,
    /// Kafka event sink — where the `SimulationRequested` audit event goes (§7).
    event_sink: Arc<dyn EventSink>,
    shutdown: CancellationToken,
    /// Back-off between transient publish retries; a field so tests can shrink it.
    publish_backoff: Duration,
}

impl Dispatcher {
    /// Build a dispatcher over the two sinks. `shutdown` aborts the publish retry
    /// loops for a graceful drain.
    pub fn new(
        job_sink: Arc<dyn JobSink>,
        event_sink: Arc<dyn EventSink>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            job_sink,
            event_sink,
            shutdown,
            publish_backoff: queue::PUBLISH_BACKOFF,
        }
    }

    /// Dispatch one provisional alert — the **core**, free of Kafka receive/commit.
    ///
    /// Publishes the `SimulationJob` command to RabbitMQ first (the actual work
    /// dispatch), then emits the `SimulationRequested` audit event to Kafka — so a
    /// successful audit fact implies the job really was queued.
    async fn process(&self, chain: Chain, alert: &PreliminaryAlertCreated) -> Handled {
        let (job, requested) = job_for_alert(chain, alert);

        // The command is the critical step, and each way it can fail wants a
        // different offset action.
        match queue::publish_resilient(
            self.job_sink.as_ref(),
            &job,
            self.publish_backoff,
            &self.shutdown,
        )
        .await
        {
            Ok(()) => {}
            // `sim.jobs` is at its length bound: the worker pool is behind and cannot
            // grow further. Leave the alert uncommitted and retry it. `run_consumer`
            // re-fetches this record after the backoff and keeps polling meanwhile,
            // so the backlog waits in Kafka (durable, replayable, alerting on lag)
            // instead of in broker memory.
            Err(queue::JobUndelivered::Rejected) => {
                crate::metrics::record_dispatch_rejected();
                tracing::warn!(
                    alert_id = %alert.alert_id,
                    "sim.jobs is at its length bound; retrying the alert from Kafka"
                );
                return Handled::Retry;
            }
            Err(queue::JobUndelivered::Abandoned(undelivered)) => {
                return event_bus::handled_undelivered(undelivered, "dispatcher");
            }
        }

        // The job is on the queue; record the request as an auditable fact (§7).
        // The command itself never enters the event store — only this does. An
        // audit event abandoned at shutdown leaves the offset for redelivery (the
        // re-dispatch is idempotent); one that can never be encoded is skipped.
        match event_bus::publish_resilient(
            self.event_sink.as_ref(),
            EventEnvelope::new(chain, DomainEvent::SimulationRequested(requested)),
            self.publish_backoff,
            &self.shutdown,
        )
        .await
        {
            Ok(()) => Handled::Commit,
            Err(undelivered) => event_bus::handled_undelivered(undelivered, "dispatcher"),
        }
    }

    /// Drive the dispatcher off Kafka until shutdown or a fatal subscribe error, via
    /// the shared [`run_consumer`] loop (subscribe, decode, trace, commit). The
    /// dispatcher supplies only the per-alert decision ([`EventHandler`]).
    pub async fn run(
        self,
        consumer: StreamConsumer<LagReporting>,
        dlq: Option<&DeadLetterQueue>,
    ) -> Result<()> {
        let topic = consumed_topic();
        let shutdown = self.shutdown.clone();
        let backoff = self.publish_backoff;
        run_consumer(
            consumer,
            &[topic.as_str()],
            "dispatcher",
            backoff,
            dlq,
            self,
            &shutdown,
        )
        .await
    }
}

#[async_trait]
impl EventHandler for Dispatcher {
    /// Dispatch a `PreliminaryAlertCreated`; any other event type on the topic is a
    /// no-op (belt-and-braces — the subscription is single-topic).
    async fn handle(&self, envelope: EventEnvelope) -> Handled {
        let chain = envelope.chain;
        match envelope.payload {
            DomainEvent::PreliminaryAlertCreated(alert) => self.process(chain, &alert).await,
            other => {
                tracing::warn!(
                    event = other.event_type(),
                    "unexpected event on alert topic; skipping"
                );
                Handled::Commit
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use event_bus::PublishError;
    use events::primitives::{
        AlertId, AlertKind, Confidence, DetectorRef, Severity, SuggestedAction,
    };

    use crate::command::SimulationJob;
    use crate::queue::JobError;

    use alloy_primitives::Address;

    /// In-memory `JobSink` recording every queued command.
    #[derive(Default)]
    struct RecordingJobSink {
        jobs: Mutex<Vec<SimulationJob>>,
    }

    #[async_trait]
    impl JobSink for RecordingJobSink {
        async fn publish(&self, job: &SimulationJob) -> Result<(), JobError> {
            self.jobs.lock().unwrap().push(job.clone());
            Ok(())
        }
    }

    /// In-memory `EventSink` recording every emitted audit event.
    #[derive(Default)]
    struct RecordingEventSink {
        events: Mutex<Vec<DomainEvent>>,
    }

    #[async_trait]
    impl EventSink for RecordingEventSink {
        async fn publish(&self, envelope: EventEnvelope) -> Result<(), PublishError> {
            self.events.lock().unwrap().push(envelope.payload);
            Ok(())
        }
    }

    fn an_alert() -> PreliminaryAlertCreated {
        PreliminaryAlertCreated {
            alert_id: AlertId::new(),
            detector: DetectorRef {
                id: "sandwich".into(),
                version: "1.2.0".into(),
                config_hash: "deadbeef".into(),
            },
            addresses: vec![Address::repeat_byte(0x11)],
            kind: AlertKind::Sandwich,
            confidence: Confidence::new(0.8),
            provisional: true,
            impact_usd: None,
            severity: Severity::Low,
            suggested_action: SuggestedAction::Monitor,
        }
    }

    #[tokio::test]
    async fn process_queues_a_job_and_emits_the_audit_event() {
        let jobs = Arc::new(RecordingJobSink::default());
        let events = Arc::new(RecordingEventSink::default());
        let dispatcher = Dispatcher::new(jobs.clone(), events.clone(), CancellationToken::new());

        let alert = an_alert();
        assert_eq!(
            dispatcher.process(Chain::ETHEREUM, &alert).await,
            Handled::Commit,
            "a fully dispatched alert is committable"
        );

        // Exactly one SimulationJob queued, keyed by the alert.
        let queued = jobs.jobs.lock().unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].alert_id, alert.alert_id);
        assert_eq!(queued[0].chain, Chain::ETHEREUM);

        // Exactly one SimulationRequested audit event emitted, same alert_id.
        let emitted = events.events.lock().unwrap();
        assert_eq!(emitted.len(), 1);
        match &emitted[0] {
            DomainEvent::SimulationRequested(req) => assert_eq!(req.alert_id, alert.alert_id),
            other => panic!("expected SimulationRequested, got {}", other.event_type()),
        }
    }

    #[tokio::test]
    async fn process_abandons_the_offset_when_shutdown_interrupts_a_transient_failure() {
        /// A sink that always fails transiently, so `publish_resilient` retries
        /// until shutdown rather than giving up.
        #[derive(Default)]
        struct DeadSink;
        #[async_trait]
        impl JobSink for DeadSink {
            async fn publish(&self, _job: &SimulationJob) -> Result<(), JobError> {
                Err(JobError::Delivery("broker down".into()))
            }
        }

        let events = Arc::new(RecordingEventSink::default());
        let shutdown = CancellationToken::new();
        shutdown.cancel(); // so the retry loop gives up immediately
        let dispatcher = Dispatcher::new(Arc::new(DeadSink), events.clone(), shutdown);

        assert_eq!(
            dispatcher.process(Chain::ETHEREUM, &an_alert()).await,
            Handled::Stop,
            "a job left un-queued by shutdown must leave the offset for redelivery"
        );
        // The audit event must not be emitted for a job that was never queued.
        assert!(events.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn process_skips_a_poison_job_that_can_never_be_queued() {
        /// A sink whose every publish is a *permanent* failure — the same outcome
        /// an encode bug would have. It must be skipped (parked on the DLQ, then
        /// committed), not retried forever, even though we are not shutting down.
        #[derive(Default)]
        struct PoisonSink;
        #[async_trait]
        impl JobSink for PoisonSink {
            async fn publish(&self, _job: &SimulationJob) -> Result<(), JobError> {
                Err(JobError::Encode(
                    serde_json::from_str::<u8>("not a number").unwrap_err(),
                ))
            }
        }

        let events = Arc::new(RecordingEventSink::default());
        // Note: shutdown is *not* cancelled — this is the regression guard for the
        // poison hot-loop (a permanent failure used to neither commit nor stop).
        let dispatcher = Dispatcher::new(
            Arc::new(PoisonSink),
            events.clone(),
            CancellationToken::new(),
        );

        assert!(
            matches!(
                dispatcher.process(Chain::ETHEREUM, &an_alert()).await,
                Handled::Skip { .. }
            ),
            "a job that can never be queued is skipped (and dead-lettered), not retried forever"
        );
        // No audit fact for a job that was never queued.
        assert!(events.events.lock().unwrap().is_empty());
    }

    /// A full `sim.jobs` (the broker nacks under `x-overflow: reject-publish`) is a
    /// `Retry`, attempted once. `run_consumer` re-fetches the record after the
    /// backoff and keeps polling, so the backlog waits on Kafka. Spinning inside
    /// the handler instead would stop the consumer polling and get it evicted
    /// from its group.
    #[tokio::test]
    async fn a_full_work_queue_retries_the_alert_from_kafka() {
        #[derive(Default)]
        struct FullQueue(Mutex<u32>);
        #[async_trait]
        impl JobSink for FullQueue {
            async fn publish(&self, _job: &SimulationJob) -> Result<(), JobError> {
                *self.0.lock().unwrap() += 1;
                Err(JobError::Rejected)
            }
        }

        let jobs = Arc::new(FullQueue::default());
        let events = Arc::new(RecordingEventSink::default());
        let dispatcher = Dispatcher::new(jobs.clone(), events.clone(), CancellationToken::new());

        assert_eq!(
            dispatcher.process(Chain::ETHEREUM, &an_alert()).await,
            Handled::Retry,
            "a full queue leaves the alert uncommitted for Kafka to redeliver"
        );
        assert_eq!(*jobs.0.lock().unwrap(), 1, "one attempt, no inline spin");
        assert!(
            events.events.lock().unwrap().is_empty(),
            "no audit fact for a job that was not queued"
        );
    }

    #[tokio::test]
    async fn handle_dispatches_alerts_and_ignores_other_event_types() {
        let jobs = Arc::new(RecordingJobSink::default());
        let events = Arc::new(RecordingEventSink::default());
        let dispatcher = Dispatcher::new(jobs.clone(), events.clone(), CancellationToken::new());

        // A non-alert event on the topic is a committable no-op — nothing queued.
        let other = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::BlockFinalized(events::chain::BlockFinalized {
                block: events::primitives::BlockRef::new(1, Default::default()),
            }),
        );
        assert_eq!(dispatcher.handle(other).await, Handled::Commit);
        assert!(jobs.jobs.lock().unwrap().is_empty());

        // A provisional alert is dispatched: one job queued.
        let alert_env = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::PreliminaryAlertCreated(an_alert()),
        );
        assert_eq!(dispatcher.handle(alert_env).await, Handled::Commit);
        assert_eq!(jobs.jobs.lock().unwrap().len(), 1);
    }

    #[test]
    fn consumed_topic_is_the_preliminary_alert_topic() {
        assert_eq!(consumed_topic(), "mev.events.PreliminaryAlertCreated");
    }
}
