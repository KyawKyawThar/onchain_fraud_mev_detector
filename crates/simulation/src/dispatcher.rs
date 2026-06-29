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
//!   returning what to do with the offset. Testable against in-memory sinks.
//! - [`Dispatcher::run`] is the **async loop**: it pulls `PreliminaryAlertCreated`
//!   records off Kafka, runs `process`, and commits the offset once the alert is
//!   dispatched — at-least-once, so a crash re-delivers rather than drops.
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

use anyhow::{Context, Result};
use event_bus::EventSink;
use events::detection::PreliminaryAlertCreated;
use events::primitives::Chain;
use events::{DomainEvent, EventEnvelope};
use rdkafka::consumer::{CommitMode, Consumer, StreamConsumer};
use rdkafka::message::Headers;
use rdkafka::Message;
use std::time::Duration;
use telemetry::propagation::{self, HeaderCarrier};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

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
pub fn build_consumer(brokers: &str, group_id: &str) -> Result<StreamConsumer> {
    rdkafka::ClientConfig::new()
        .set("bootstrap.servers", brokers)
        .set("group.id", group_id)
        .set("enable.auto.commit", "false")
        .set("auto.offset.reset", "earliest")
        .create()
        .context("creating Kafka consumer")
}

/// Decode one envelope into the provisional alert the dispatcher acts on, or `None`
/// for any other event type (belt-and-braces — it subscribes only to the one topic).
pub fn alert_from_envelope(envelope: EventEnvelope) -> Option<PreliminaryAlertCreated> {
    match envelope.payload {
        DomainEvent::PreliminaryAlertCreated(alert) => Some(alert),
        _ => None,
    }
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
    async fn process(&self, chain: Chain, alert: &PreliminaryAlertCreated) -> Disposition {
        let (job, requested) = job_for_alert(chain, alert);

        // The command is the critical step. `publish_resilient` returns `false` for
        // two reasons we must treat *differently*: a shutdown mid-retry (leave the
        // offset so redelivery re-dispatches), versus a permanent encode failure
        // (poison — commit to skip it, or the same record redelivers forever).
        if !queue::publish_resilient(
            self.job_sink.as_ref(),
            &job,
            self.publish_backoff,
            &self.shutdown,
        )
        .await
        {
            return if self.shutdown.is_cancelled() {
                Disposition::Abandon
            } else {
                tracing::error!(alert_id = %alert.alert_id, "dropping un-queueable job (poison); skipping");
                Disposition::Commit
            };
        }

        // The job is on the queue; record the request as an auditable fact (§7).
        // The command itself never enters the event store — only this does.
        event_bus::publish_resilient(
            self.event_sink.as_ref(),
            EventEnvelope::new(chain, DomainEvent::SimulationRequested(requested)),
            self.publish_backoff,
            &self.shutdown,
        )
        .await;

        // If shutdown fired during the audit publish, the event may not be on the
        // wire — leave the offset so redelivery re-dispatches (idempotent) and
        // re-audits, rather than committing past an un-audited alert.
        if self.shutdown.is_cancelled() {
            Disposition::Abandon
        } else {
            Disposition::Commit
        }
    }

    /// Drive the dispatcher off Kafka until shutdown or a fatal subscribe error.
    /// For each `PreliminaryAlertCreated`: run `process`, and commit
    /// the offset once the alert is dispatched. Continues the producer's distributed
    /// trace across the broker (§19).
    pub async fn run(self, consumer: StreamConsumer) -> Result<()> {
        let topic = consumed_topic();
        consumer
            .subscribe(&[topic.as_str()])
            .with_context(|| format!("subscribing to {topic}"))?;
        tracing::info!(%topic, "dispatcher subscribed");

        loop {
            let msg = tokio::select! {
                biased;
                () = self.shutdown.cancelled() => {
                    tracing::info!("dispatcher stopping");
                    return Ok(());
                }
                received = consumer.recv() => match received {
                    Ok(msg) => msg,
                    Err(err) => {
                        tracing::error!(error = %err, "Kafka receive error");
                        continue;
                    }
                },
            };

            // Continue the producer's trace as this alert's dispatch span parent.
            let span = tracing::info_span!(
                "dispatch_alert",
                topic = msg.topic(),
                partition = msg.partition(),
                offset = msg.offset(),
            );
            propagation::set_parent_from_headers(&span, &header_carrier(&msg));

            match self.handle_message(&msg).instrument(span).await {
                Disposition::Commit => {
                    if let Err(err) = consumer.commit_message(&msg, CommitMode::Async) {
                        tracing::error!(error = %err, "offset commit failed");
                    }
                }
                Disposition::Abandon => {
                    // Shutting down before this alert was dispatched — stop without
                    // committing, so redelivery on restart re-dispatches it.
                    tracing::info!("dispatcher stopping (alert left for redelivery)");
                    return Ok(());
                }
            }
        }
    }

    /// Decode one record and dispatch it, returning what to do with its offset. A
    /// poison record (no payload / undecodable / wrong type) is skipped — committed
    /// so it can't wedge the stream, the same discipline as the event-store consumer.
    async fn handle_message(&self, msg: &rdkafka::message::BorrowedMessage<'_>) -> Disposition {
        let Some(payload) = msg.payload() else {
            tracing::error!("record has no payload; skipping");
            return Disposition::Commit;
        };
        let envelope = match EventEnvelope::from_json_slice(payload) {
            Ok(envelope) => envelope,
            Err(err) => {
                tracing::error!(error = %err, "undecodable event; skipping");
                return Disposition::Commit;
            }
        };
        let chain = envelope.chain;
        let Some(alert) = alert_from_envelope(envelope) else {
            // A type we don't act on slipped through the single-topic subscription.
            tracing::warn!("unexpected event type on alert topic; skipping");
            return Disposition::Commit;
        };

        self.process(chain, &alert).await
    }
}

/// What to do with a consumed message's offset after handling it.
enum Disposition {
    /// Handled — advance the offset. Either the alert was dispatched (job queued
    /// *and* audited) or the record was un-actionable poison skipped so it can't
    /// wedge the stream.
    Commit,
    /// Shutting down before the alert was fully dispatched — leave the offset so
    /// redelivery on restart re-dispatches it (at-least-once, §7).
    Abandon,
}

/// Lift a record's headers into a [`HeaderCarrier`] (UTF-8 values only, as W3C
/// `traceparent`/`tracestate` are). Mirrors the detection/event-store consumers.
fn header_carrier(msg: &rdkafka::message::BorrowedMessage<'_>) -> HeaderCarrier {
    let mut map = std::collections::HashMap::new();
    if let Some(headers) = msg.headers() {
        for header in headers.iter() {
            if let Some(value) = header.value {
                if let Ok(value) = std::str::from_utf8(value) {
                    map.insert(header.key.to_owned(), value.to_owned());
                }
            }
        }
    }
    HeaderCarrier::from_map(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use event_bus::PublishError;
    use events::primitives::{AlertId, AlertKind, Confidence, DetectorRef};

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
        }
    }

    #[tokio::test]
    async fn process_queues_a_job_and_emits_the_audit_event() {
        let jobs = Arc::new(RecordingJobSink::default());
        let events = Arc::new(RecordingEventSink::default());
        let dispatcher = Dispatcher::new(jobs.clone(), events.clone(), CancellationToken::new());

        let alert = an_alert();
        assert!(
            matches!(
                dispatcher.process(Chain::ETHEREUM, &alert).await,
                Disposition::Commit
            ),
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

        assert!(
            matches!(
                dispatcher.process(Chain::ETHEREUM, &an_alert()).await,
                Disposition::Abandon
            ),
            "a job left un-queued by shutdown must leave the offset for redelivery"
        );
        // The audit event must not be emitted for a job that was never queued.
        assert!(events.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn process_skips_a_poison_job_that_can_never_be_queued() {
        /// A sink whose every publish is a *permanent* failure — the same outcome
        /// an encode bug would have. It must be skipped (committed), not retried
        /// forever, even though we are not shutting down.
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
                Disposition::Commit
            ),
            "a job that can never be queued is skipped, not retried forever"
        );
        // No audit fact for a job that was never queued.
        assert!(events.events.lock().unwrap().is_empty());
    }

    #[test]
    fn alert_from_envelope_decodes_only_preliminary_alerts() {
        let alert_env = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::PreliminaryAlertCreated(an_alert()),
        );
        assert!(alert_from_envelope(alert_env).is_some());

        let other = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::BlockFinalized(events::chain::BlockFinalized {
                block: events::primitives::BlockRef::new(1, Default::default()),
            }),
        );
        assert!(alert_from_envelope(other).is_none());
    }

    #[test]
    fn consumed_topic_is_the_preliminary_alert_topic() {
        assert_eq!(consumed_topic(), "mev.events.PreliminaryAlertCreated");
    }
}
