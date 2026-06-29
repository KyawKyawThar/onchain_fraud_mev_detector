//! The RabbitMQ command-publishing seam (§7) — how the dispatcher (and, later, any
//! requeue path) ships a [`SimulationJob`] onto the `sim.jobs` work queue. The
//! command broker analogue of `event-bus`'s `EventSink`/`KafkaEventSink`.
//!
//! [`JobSink`] is the object-safe seam the dispatcher writes against, so its logic
//! is unit-testable against an in-memory sink with no broker. [`RabbitJobSink`] is
//! the production impl: a lapin channel with **publisher confirms** enabled, so a
//! publish resolves only once RabbitMQ has accepted (and, on a durable queue,
//! persisted) the message — the at-least-once ack we need so a queued job is never
//! silently lost.
//!
//! Delivery is at-least-once: a publish is awaited and a failure surfaces to the
//! caller. A redelivered job is harmless — processing is idempotent and the result
//! is keyed by `alert_id` (§7) — so [`publish_resilient`] retries a transient
//! broker blip until it succeeds or shutdown, and only gives up on a permanent
//! (encode) failure that can never succeed.
//!
//! The queue *topology* (the durable, quorum, dead-letter `sim.jobs.dlx` declaration)
//! lives in [`crate::topology`], declared once at boot. This sink publishes to the
//! queue by name via the default exchange; it does not declare it, so it can't
//! conflict with that declaration's arguments.

use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use lapin::options::{BasicPublishOptions, ConfirmSelectOptions};
use lapin::publisher_confirm::Confirmation;
use lapin::{BasicProperties, Channel, Connection, ConnectionProperties};
use tokio_util::sync::CancellationToken;

use crate::command::SimulationJob;

/// Default back-off between retries of a transient publish failure, so a broker
/// blip doesn't hot-loop the dispatcher. Mirrors `event_bus::PUBLISH_BACKOFF`.
pub const PUBLISH_BACKOFF: Duration = Duration::from_secs(1);

/// AMQP `delivery_mode = 2` — persistent. On a durable queue (declared in t2) the
/// message survives a broker restart; pairing a transient message with a durable
/// queue would silently lose jobs across a bounce.
const DELIVERY_MODE_PERSISTENT: u8 = 2;

/// Open a RabbitMQ connection, handing lapin tokio's executor + reactor so it runs
/// on the service's single runtime rather than spinning up its own threads. Shared
/// by the publish sink ([`RabbitJobSink::connect`]) and the one-time topology
/// declaration ([`crate::topology::declare_sim_topology`]) so the connection setup
/// lives in one place.
pub(crate) async fn amqp_connect(url: &str) -> Result<Connection> {
    let options = ConnectionProperties::default()
        .with_executor(tokio_executor_trait::Tokio::current())
        .with_reactor(tokio_reactor_trait::Tokio);
    Connection::connect(url, options)
        .await
        .context("connecting to RabbitMQ")
}

/// Why publishing one command failed. Transport-agnostic (the delivery detail is a
/// `String`, not a `lapin` type) so the [`JobSink`] seam doesn't leak AMQP into the
/// dispatcher — the same discipline as `event_bus::PublishError`.
#[derive(Debug, thiserror::Error)]
pub enum JobError {
    /// The broker rejected, nacked, or never acked the message (connection drop,
    /// timeout, …). Retriable: the same job can be re-published once it recovers.
    #[error("rabbitmq publish failed: {0}")]
    Delivery(String),

    /// The job could not be serialized — a bug in our own types, identical on
    /// every retry. Not retriable.
    #[error("encoding simulation job failed")]
    Encode(#[from] serde_json::Error),
}

impl JobError {
    /// Whether re-publishing the *same* job could plausibly succeed later. A
    /// delivery failure is transient (broker recovers); an encode failure is not.
    pub fn is_transient(&self) -> bool {
        matches!(self, JobError::Delivery(_))
    }
}

/// Where simulation commands go after the dispatcher builds them. Object-safe so
/// the dispatcher can hold a `dyn JobSink` and swap the broker for a test double
/// without generics rippling through it.
#[async_trait]
pub trait JobSink: Send + Sync {
    /// Publish one command, returning only once the broker has accepted it
    /// (at-least-once). An `Err` means the job is *not* queued; the caller uses
    /// [`JobError::is_transient`] to decide whether to retry it.
    async fn publish(&self, job: &SimulationJob) -> Result<(), JobError>;
}

/// The production [`JobSink`]: a lapin channel with publisher confirms.
pub struct RabbitJobSink {
    /// Held for the sink's lifetime — dropping the connection closes the channel.
    _connection: Connection,
    channel: Channel,
    /// The `sim.jobs` queue name; the routing key on the default exchange.
    queue: String,
}

impl RabbitJobSink {
    /// Connect to RabbitMQ at `url` (an `amqp://…` URI) and prepare a
    /// confirm-mode channel publishing to `queue`. lapin is handed tokio's
    /// executor + reactor so it runs on the service's single runtime rather than
    /// spinning up its own threads.
    ///
    /// Does **not** declare the queue — topology is Sprint 5 t2 (see module docs).
    pub async fn connect(url: &str, queue: String) -> Result<Self> {
        let connection = amqp_connect(url).await?;
        let channel = connection
            .create_channel()
            .await
            .context("opening a RabbitMQ channel")?;
        // Publisher confirms: turn each publish into an awaited broker ack, the
        // at-least-once guarantee `publish` relies on.
        channel
            .confirm_select(ConfirmSelectOptions::default())
            .await
            .context("enabling RabbitMQ publisher confirms")?;
        tracing::info!(queue = %queue, "RabbitMQ job sink connected (confirm mode)");
        Ok(Self {
            _connection: connection,
            channel,
            queue,
        })
    }
}

#[async_trait]
impl JobSink for RabbitJobSink {
    async fn publish(&self, job: &SimulationJob) -> Result<(), JobError> {
        let payload = job.to_json_vec()?; // serde_json::Error → JobError::Encode

        // Persistent + carries the queue priority (§7); the worker decodes the
        // JSON body. Published to the default exchange ("") with the queue name as
        // the routing key — the direct-to-queue idiom.
        let properties = BasicProperties::default()
            .with_delivery_mode(DELIVERY_MODE_PERSISTENT)
            .with_priority(job.priority.get())
            .with_content_type("application/json".into());

        let confirm = self
            .channel
            .basic_publish(
                "",
                &self.queue,
                BasicPublishOptions::default(),
                &payload,
                properties,
            )
            .await
            .map_err(|err| JobError::Delivery(err.to_string()))?
            // The returned future resolves when the broker confirms the message.
            .await
            .map_err(|err| JobError::Delivery(err.to_string()))?;

        // A nack means the broker could not take responsibility for the message
        // (e.g. it couldn't be persisted) — treat it as a transient delivery
        // failure so `publish_resilient` retries rather than dropping the job.
        if matches!(confirm, Confirmation::Nack(_)) {
            return Err(JobError::Delivery(
                "broker nacked the publish (message not confirmed)".into(),
            ));
        }
        Ok(())
    }
}

/// Publish one command through `sink`, retrying a *transient* failure (broker blip)
/// over `backoff` until it succeeds or `shutdown` is cancelled — so a momentary
/// outage doesn't drop a job whose alert has already streamed past on Kafka. A
/// *permanent* failure (encode bug) is logged and skipped — it can never succeed.
///
/// Mirrors `event_bus::publish_resilient`; the two brokers share one retry shape.
/// Returns `true` if the job was queued, `false` if it was abandoned (shutdown or a
/// permanent failure) — the dispatcher uses this to decide whether to advance its
/// Kafka offset.
pub async fn publish_resilient(
    sink: &dyn JobSink,
    job: &SimulationJob,
    backoff: Duration,
    shutdown: &CancellationToken,
) -> bool {
    loop {
        match sink.publish(job).await {
            Ok(()) => return true,
            Err(err) if err.is_transient() => {
                tracing::warn!(
                    error = %err,
                    alert_id = %job.alert_id,
                    "transient job publish failure; retrying after backoff"
                );
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => {
                        tracing::error!(
                            alert_id = %job.alert_id,
                            "shutdown during job publish retry; job not queued"
                        );
                        return false;
                    }
                    _ = tokio::time::sleep(backoff) => {}
                }
            }
            Err(err) => {
                tracing::error!(
                    error = %err,
                    alert_id = %job.alert_id,
                    "permanent job publish failure; dropping job"
                );
                return false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use events::primitives::{AlertId, AlertKind, Chain, Confidence, DetectorRef};

    use crate::command::{Priority, SimulationJob};

    /// A sink that fails transiently `remaining_failures` times, then records — to
    /// prove `publish_resilient` retries over a broker blip.
    struct FlakySink {
        remaining_failures: Mutex<u32>,
        delivered: Mutex<Vec<AlertId>>,
    }

    #[async_trait]
    impl JobSink for FlakySink {
        async fn publish(&self, job: &SimulationJob) -> Result<(), JobError> {
            let mut left = self.remaining_failures.lock().unwrap();
            if *left > 0 {
                *left -= 1;
                return Err(JobError::Delivery("broker blip".into()));
            }
            self.delivered.lock().unwrap().push(job.alert_id);
            Ok(())
        }
    }

    fn a_job() -> SimulationJob {
        SimulationJob {
            alert_id: AlertId::new(),
            chain: Chain::ETHEREUM,
            kind: AlertKind::Sandwich,
            detector: DetectorRef {
                id: "sandwich".into(),
                version: "1.2.0".into(),
                config_hash: "deadbeef".into(),
            },
            addresses: vec![],
            confidence: Confidence::new(0.5),
            priority: Priority::new(5),
        }
    }

    #[test]
    fn delivery_failure_is_transient_encode_is_not() {
        assert!(JobError::Delivery("x".into()).is_transient());
        let encode = JobError::Encode(serde_json::from_str::<u8>("not a number").unwrap_err());
        assert!(!encode.is_transient());
    }

    #[tokio::test]
    async fn resilient_publish_retries_a_transient_failure_until_it_succeeds() {
        let sink = FlakySink {
            remaining_failures: Mutex::new(2),
            delivered: Mutex::new(vec![]),
        };
        let job = a_job();
        let queued = publish_resilient(
            &sink,
            &job,
            Duration::from_millis(1),
            &CancellationToken::new(),
        )
        .await;
        assert!(queued);
        assert_eq!(*sink.delivered.lock().unwrap(), vec![job.alert_id]);
    }

    #[tokio::test]
    async fn resilient_publish_gives_up_on_shutdown_rather_than_blocking_forever() {
        let sink = FlakySink {
            remaining_failures: Mutex::new(u32::MAX), // never succeeds
            delivered: Mutex::new(vec![]),
        };
        let shutdown = CancellationToken::new();
        shutdown.cancel(); // already cancelled → the retry select takes this arm
        let queued = publish_resilient(&sink, &a_job(), Duration::from_secs(3600), &shutdown).await;
        assert!(!queued);
        assert!(sink.delivered.lock().unwrap().is_empty());
    }
}
