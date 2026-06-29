//! The RabbitMQ **consume** seam (§7, §17) — how a worker pulls a `SimulationJob`
//! off the `sim.jobs` work queue and acks/redelivers/dead-letters it per job. The
//! competing-consumer counterpart to [`crate::queue`]'s publish-side `JobSink`.
//!
//! ## Competing consumers, per-job ack
//!
//! Each worker opens its own confirm-free consume channel with a bounded **prefetch
//! QoS** (`basic_qos`), so the broker hands it at most `prefetch` unacked jobs at a
//! time. Run N workers (in-process tasks and/or replicas) and they *compete* for the
//! one queue — RabbitMQ's native model and the reason simulation isn't a Kafka
//! consumer group (no partition-count ceiling on parallelism, §7). Queue depth stays
//! the single backpressure/autoscaling signal (§17).
//!
//! Delivery is **manual-ack** (`no_ack = false`): a job is acked only after its
//! simulation result is durably published. A worker that dies mid-run never acks, so
//! the quorum queue redelivers the job to another worker (at-least-once, §7) — which
//! is safe because processing is idempotent (the result is `alert_id`-keyed).
//!
//! ## The ack handle is a seam too
//!
//! [`JobDelivery`] carries the decoded job plus a [`DeliveryAck`] handle, not a raw
//! lapin `Acker`, so the worker's disposition logic (ack / requeue / dead-letter) is
//! unit-testable against an in-memory double that records what happened with no
//! broker. [`RabbitJobSource`] is the production [`JobSource`]; an undecodable body
//! is dead-lettered at the source (it can never become a job), so the worker only
//! ever sees well-formed deliveries.

use anyhow::{Context, Result};
use async_trait::async_trait;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicQosOptions};
use lapin::types::FieldTable;
use lapin::{Channel, Connection, Consumer};
use tokio_stream::StreamExt;

use crate::command::SimulationJob;
use crate::queue::amqp_connect;

/// How a worker disposes of one delivery once it has decided the outcome — the §7
/// work-queue vocabulary. Lives next to the consume seam because it *is* the broker's
/// set of per-job verbs; the worker chooses one, the [`DeliveryAck`] enacts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Result published — remove the job from the queue.
    Ack,
    /// Transient fault — return the job for redelivery (at-least-once).
    Requeue,
    /// Poison — route to the dead-letter exchange for quarantine.
    DeadLetter,
}

/// Settles one delivery with the chosen [`Disposition`]. One method, so the
/// disposition→broker-action mapping has a single home; object-safe so a test double
/// can record what it was asked to do.
#[async_trait]
pub trait DeliveryAck: Send + Sync {
    async fn settle(&self, disposition: Disposition) -> Result<()>;
}

/// One job pulled off `sim.jobs`, with its ack handle. Consuming `self` on each
/// disposition makes double-acking unrepresentable.
pub struct JobDelivery {
    /// The decoded command to run.
    pub job: SimulationJob,
    /// Whether the broker has delivered this job before (a prior worker took it and
    /// didn't ack). Surfaced for logging/metrics; the work itself is idempotent.
    pub redelivered: bool,
    ack: Box<dyn DeliveryAck>,
}

impl JobDelivery {
    /// Wrap a decoded job with its ack handle.
    pub fn new(job: SimulationJob, redelivered: bool, ack: Box<dyn DeliveryAck>) -> Self {
        Self {
            job,
            redelivered,
            ack,
        }
    }

    /// Settle the delivery with the worker's chosen disposition. Consumes `self` so
    /// a delivery can't be settled twice.
    pub async fn settle(self, disposition: Disposition) -> Result<()> {
        self.ack.settle(disposition).await
    }
}

/// A stream of jobs to drain. Object-safe so the worker runs against an in-memory
/// source in tests. `recv` yields well-formed jobs only (undecodable bodies are
/// dead-lettered internally); `None` means the stream closed (channel/connection
/// gone) and the worker should stop.
#[async_trait]
pub trait JobSource: Send {
    async fn recv(&mut self) -> Option<JobDelivery>;
}

/// The production [`JobSource`]: a lapin `Consumer` over `sim.jobs` with a bounded
/// prefetch and manual ack.
pub struct RabbitJobSource {
    /// Held for the source's lifetime — dropping the connection closes the channel,
    /// which **requeues** any unacked in-flight job (the redelivery path, §7).
    _connection: Connection,
    _channel: Channel,
    consumer: Consumer,
}

impl RabbitJobSource {
    /// Connect and start consuming `queue` with at most `prefetch` unacked jobs in
    /// flight. lapin is handed tokio's executor + reactor (via [`amqp_connect`]) so
    /// it shares the worker's runtime.
    ///
    /// Does **not** declare the queue — topology is declared once at boot
    /// ([`crate::topology`]); a worker only consumes.
    pub async fn connect(url: &str, queue: &str, prefetch: u16) -> Result<Self> {
        let connection = amqp_connect(url).await?;
        let channel = connection
            .create_channel()
            .await
            .context("opening a RabbitMQ consume channel")?;
        // Bound how many unacked jobs this consumer holds — the competing-consumer
        // fairness + backpressure knob (§17). Per-consumer (global = false).
        channel
            .basic_qos(prefetch, BasicQosOptions::default())
            .await
            .context("setting consumer prefetch (QoS)")?;
        // Manual ack: `no_ack = false` so a crash before ack redelivers the job.
        let consumer = channel
            .basic_consume(
                queue,
                "", // broker-generated consumer tag
                BasicConsumeOptions::default(),
                FieldTable::default(),
            )
            .await
            .with_context(|| format!("starting consumer on {queue}"))?;
        tracing::info!(
            queue,
            prefetch,
            "RabbitMQ job source consuming (manual ack)"
        );
        Ok(Self {
            _connection: connection,
            _channel: channel,
            consumer,
        })
    }
}

#[async_trait]
impl JobSource for RabbitJobSource {
    async fn recv(&mut self) -> Option<JobDelivery> {
        loop {
            match self.consumer.next().await {
                Some(Ok(delivery)) => match serde_json::from_slice::<SimulationJob>(&delivery.data)
                {
                    Ok(job) => {
                        let redelivered = delivery.redelivered;
                        return Some(JobDelivery::new(
                            job,
                            redelivered,
                            Box::new(RabbitAck(delivery.acker)),
                        ));
                    }
                    Err(err) => {
                        // A body we can't decode can never become a job — quarantine
                        // it (don't requeue: it would loop) and pull the next one.
                        tracing::error!(error = %err, "undecodable job body; dead-lettering");
                        let _ = delivery
                            .acker
                            .nack(BasicNackOptions {
                                multiple: false,
                                requeue: false,
                            })
                            .await;
                        continue;
                    }
                },
                Some(Err(err)) => {
                    // Channel/connection error — the stream is done; let the worker
                    // stop and the supervisor restart it.
                    tracing::error!(error = %err, "consume stream error; closing job source");
                    return None;
                }
                None => return None,
            }
        }
    }
}

/// Production [`DeliveryAck`] over a lapin `Acker`. The single place the §7
/// dispositions map onto AMQP verbs: ack drops the job; `nack(requeue = true)`
/// returns it for redelivery; `nack(requeue = false)` routes it to the queue's
/// dead-letter exchange.
struct RabbitAck(lapin::acker::Acker);

#[async_trait]
impl DeliveryAck for RabbitAck {
    async fn settle(&self, disposition: Disposition) -> Result<()> {
        match disposition {
            Disposition::Ack => self
                .0
                .ack(BasicAckOptions::default())
                .await
                .context("acking job"),
            Disposition::Requeue => self
                .0
                .nack(BasicNackOptions {
                    multiple: false,
                    requeue: true,
                })
                .await
                .context("requeueing job"),
            Disposition::DeadLetter => self
                .0
                .nack(BasicNackOptions {
                    multiple: false,
                    requeue: false,
                })
                .await
                .context("dead-lettering job"),
        }
    }
}
