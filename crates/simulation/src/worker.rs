//! The simulation worker (§7, §17) — the back half of the slow path. Drains the
//! `sim.jobs` work queue, runs revm on the rayon pool (CPU off the async reactor),
//! publishes the result back onto Kafka, and acks the job per the §7 work-queue
//! semantics.
//!
//! Split pure-decision / drain-loop like the dispatcher:
//!
//! - [`Worker::process`] is the **core**: resolve the job to a scenario, apply the
//!   reorg generation check, simulate it on rayon, publish the result events, and
//!   return the [`Disposition`] — what to do with the delivery. Testable against
//!   in-memory doubles with no broker and no EVM.
//! - [`Worker::run`] is the **drain loop**: pull a [`JobDelivery`] off a
//!   [`JobSource`], run `process`, and settle the delivery (ack / requeue /
//!   dead-letter). `select!` on the shutdown token for a graceful drain.
//!
//! ## Per-job ack/redelivery (§7)
//!
//! A job is **acked only after its result is durably published**. The three failure
//! modes settle differently, and that mapping is the whole point of the task:
//!
//! - **Success** → `ack`. Done; drop it from the queue.
//! - **Transient** (resolver/simulation/RPC blip, or shutdown mid-publish) →
//!   `requeue`. At-least-once: the job redelivers and re-runs. Safe because the
//!   result is `alert_id`-keyed and downstream dedups it.
//! - **Poison** (unresolvable, or a malformed/hostile bundle the EVM rejects) →
//!   `dead_letter`. Quarantine to the DLX rather than loop. The quorum queue's
//!   `x-delivery-limit` is the backstop for a worker that *crashes* mid-run (the job
//!   redelivers, and after N failed deliveries dead-letters automatically).
//! - **Reorg-cancelled** (the resolved block was orphaned, §15) → `ack`. The §7
//!   "generation check on the consumer" ([`crate::reorg`]): the job is obsolete, not
//!   poison, so it is dropped cleanly (no result published, no DLX noise) rather than
//!   simulating an orphaned block into a phantom incident.
//!
//! ## revm on rayon (§17)
//!
//! The simulation runs on a shared [`rayon::ThreadPool`] — *the* worker pool. The
//! async drain tasks (one per competing consumer) bridge to it via a oneshot, so the
//! reactor is never blocked on revm CPU. Horizontal scale is more replicas (§20);
//! per-replica concurrency is more drain tasks feeding the one bounded pool.

use std::sync::Arc;
use std::time::Duration;

use event_bus::{EventSink, Transience};
use events::EventEnvelope;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::command::SimulationJob;
use crate::consumer::JobSource;
// `Disposition` is the queue vocabulary (defined next to the consume seam), but it's
// also what `process` returns — re-export it so `worker::Disposition` still resolves.
pub use crate::consumer::Disposition;
use crate::queue::PUBLISH_BACKOFF;
use crate::reorg::OrphanGuard;
use crate::resolver::JobResolver;
use crate::result::events_for_outcome;
use crate::simulator::{SimError, SimulationOutcome, SimulationRequest, Simulator};

/// Map a failure's transient/permanent classification onto the queue disposition:
/// a transient fault is requeued for redelivery, a permanent ("poison") one is
/// dead-lettered. The single rule both the resolve and simulate steps follow.
fn disposition_for(transient: bool) -> Disposition {
    if transient {
        Disposition::Requeue
    } else {
        Disposition::DeadLetter
    }
}

/// A simulation worker. Cheap to clone (all shared state is behind `Arc`), so the
/// binary spawns one per in-process competing consumer over the same rayon pool.
#[derive(Clone)]
pub struct Worker {
    /// Turns a queued command into a runnable scenario (event-store evidence +
    /// chain fork in production; a stub today — see [`crate::resolver`]).
    resolver: Arc<dyn JobResolver>,
    /// The reorg generation check (§7, §15): after resolving a job, the worker cancels
    /// it if its block was orphaned rather than simulating an orphaned block into a
    /// phantom incident. Fed by each replica's `BlockReverted` consumer
    /// ([`crate::reorg::run_revert_tracker`]); [`NeverOrphaned`](crate::reorg::NeverOrphaned)
    /// disables it.
    orphaned: Arc<dyn OrphanGuard>,
    /// The revm engine — runs on the rayon pool, never the reactor.
    simulator: Arc<dyn Simulator>,
    /// *The* worker pool: the shared rayon pool every simulation runs on (§17).
    pool: Arc<rayon::ThreadPool>,
    /// Where results re-enter the backbone (`SimulationCompleted` / `IncidentCreated`).
    event_sink: Arc<dyn EventSink>,
    /// Aborts publish retries + the drain loop for a graceful shutdown.
    shutdown: CancellationToken,
    /// Back-off between transient result-publish retries; a field so tests shrink it.
    publish_backoff: Duration,
}

impl Worker {
    /// Build a worker over its seams and the shared rayon pool. `orphaned` is the reorg
    /// generation check; pass [`NeverOrphaned`](crate::reorg::NeverOrphaned) to disable
    /// cancellation.
    pub fn new(
        resolver: Arc<dyn JobResolver>,
        orphaned: Arc<dyn OrphanGuard>,
        simulator: Arc<dyn Simulator>,
        pool: Arc<rayon::ThreadPool>,
        event_sink: Arc<dyn EventSink>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            resolver,
            orphaned,
            simulator,
            pool,
            event_sink,
            shutdown,
            publish_backoff: PUBLISH_BACKOFF,
        }
    }

    /// Handle one job — the **core**, free of the consume/ack loop. Resolve →
    /// simulate (on rayon) → publish the result(s) → return the disposition.
    pub async fn process(&self, job: &SimulationJob) -> Disposition {
        // 1. Resolve the alert to a runnable `(block, tx_set)` scenario.
        let request = match self.resolver.resolve(job).await {
            Ok(request) => request,
            Err(err) => {
                let disposition = disposition_for(err.is_transient());
                tracing::warn!(error = %err, alert_id = %job.alert_id, ?disposition, "resolve failed");
                return disposition;
            }
        };

        // 1a. Reorg generation check (§7, §15): the job carries no block, but resolving
        //     it revealed one. If that block was orphaned by a reorg, the job is
        //     obsolete — drop it (ack, publish nothing) rather than simulate an orphaned
        //     block into a phantom incident. Acking (not dead-lettering) because a
        //     reorg-cancelled job is expected, not poison needing inspection.
        let block = request.block_ref();
        if self.orphaned.is_orphaned(&block) {
            tracing::info!(
                alert_id = %job.alert_id,
                block = block.number,
                "cancelling job for orphaned block (reorg); publishing no result"
            );
            return Disposition::Ack;
        }

        // 2. Run revm on the rayon pool — CPU never on the reactor (§17).
        let outcome = match self.simulate(request).await {
            Ok(outcome) => outcome,
            Err(err) => {
                let disposition = disposition_for(err.is_transient());
                tracing::warn!(error = %err, alert_id = %job.alert_id, ?disposition, "simulation failed");
                return disposition;
            }
        };
        tracing::info!(
            alert_id = %job.alert_id,
            confirmed = outcome.confirmed,
            profit = outcome.profit,
            "simulation finished"
        );

        // 3. Publish the result(s) back onto Kafka (at-least-once). The command
        //    never re-enters the event store — only its outcome does (§7).
        for event in events_for_outcome(&outcome) {
            event_bus::publish_resilient(
                self.event_sink.as_ref(),
                EventEnvelope::new(job.chain, event),
                self.publish_backoff,
                &self.shutdown,
            )
            .await;
        }

        // 4. Ack only if the result truly made it out. If shutdown interrupted a
        //    publish retry, some event may not be on the wire — requeue so
        //    redelivery re-runs and re-publishes (idempotent), rather than acking
        //    past an unpublished result.
        if self.shutdown.is_cancelled() {
            Disposition::Requeue
        } else {
            Disposition::Ack
        }
    }

    /// Run one scenario on the shared rayon pool, bridging back to async via a
    /// oneshot. A dropped task (pool shut down) surfaces as a transient fault so the
    /// job redelivers rather than vanishing.
    async fn simulate(&self, request: SimulationRequest) -> Result<SimulationOutcome, SimError> {
        let simulator = self.simulator.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pool.spawn(move || {
            let outcome = simulator.simulate(&request);
            // Receiver gone (worker dropped) → nothing to do; drop the result.
            let _ = tx.send(outcome);
        });
        rx.await.unwrap_or_else(|_| {
            Err(SimError::Transient(
                "simulation task was dropped before completing".into(),
            ))
        })
    }

    /// Drain `source` until shutdown or the source closes. For each delivery: run
    /// `process`, then settle the delivery per the returned disposition.
    pub async fn run(self, mut source: impl JobSource) -> anyhow::Result<()> {
        tracing::info!("simulation worker draining sim.jobs");
        loop {
            let delivery = tokio::select! {
                biased;
                () = self.shutdown.cancelled() => {
                    tracing::info!("simulation worker stopping (in-flight unacked jobs redeliver)");
                    return Ok(());
                }
                received = source.recv() => match received {
                    Some(delivery) => delivery,
                    None => {
                        tracing::info!("job source closed; simulation worker stopping");
                        return Ok(());
                    }
                },
            };

            let span = tracing::info_span!(
                "simulate_job",
                alert_id = %delivery.job.alert_id,
                redelivered = delivery.redelivered,
            );
            let disposition = self.process(&delivery.job).instrument(span).await;
            // A failed settle isn't fatal — the broker redelivers an unsettled job.
            if let Err(err) = delivery.settle(disposition).await {
                tracing::error!(error = %err, ?disposition, "failed to settle delivery");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;
    use events::primitives::Severity;
    use events::DomainEvent;

    use crate::consumer::JobDelivery;
    use crate::reorg::{NeverOrphaned, SharedOrphanedBlocks};
    use crate::resolver::{JobResolver, ResolveError};
    use crate::simulator::{
        BlockParams, SimError, SimulationOutcome, SimulationRequest, Simulator,
    };
    use crate::test_util::{empty_request, sample_job, test_pool, AckRecorder, RecordingEventSink};

    use events::chain::BlockReverted;
    use events::primitives::BlockRef;
    use revm::primitives::B256;

    /// A resolver that always returns a canned request, or a canned error.
    struct CannedResolver(Result<(), ResolveErrorKind>);
    enum ResolveErrorKind {
        Transient,
        Poison,
    }
    #[async_trait]
    impl JobResolver for CannedResolver {
        async fn resolve(&self, job: &SimulationJob) -> Result<SimulationRequest, ResolveError> {
            match &self.0 {
                Ok(()) => Ok(empty_request(job)),
                Err(ResolveErrorKind::Transient) => Err(ResolveError::Transient("blip".into())),
                Err(ResolveErrorKind::Poison) => Err(ResolveError::Unresolvable("nope".into())),
            }
        }
    }

    /// A simulator that returns a canned outcome, or a canned error.
    struct CannedSimulator(Result<bool, bool>); // Ok(confirmed) | Err(is_transient)
    impl Simulator for CannedSimulator {
        fn simulate(&self, req: &SimulationRequest) -> Result<SimulationOutcome, SimError> {
            match self.0 {
                Ok(confirmed) => Ok(SimulationOutcome {
                    alert_id: req.alert_id,
                    kind: req.kind,
                    profit: if confirmed { 5.0 } else { 0.0 },
                    victim_loss: 0.0,
                    confirmed,
                    severity: Severity::Medium,
                    txs: vec![],
                }),
                Err(true) => Err(SimError::Transient("blip".into())),
                Err(false) => Err(SimError::Poison("hostile".into())),
            }
        }
    }

    fn worker(
        resolver: Arc<dyn JobResolver>,
        simulator: Arc<dyn Simulator>,
        events: Arc<RecordingEventSink>,
    ) -> Worker {
        let mut w = Worker::new(
            resolver,
            Arc::new(NeverOrphaned),
            simulator,
            test_pool(),
            events,
            CancellationToken::new(),
        );
        w.publish_backoff = Duration::from_millis(1);
        w
    }

    #[tokio::test]
    async fn a_confirmed_job_publishes_two_events_and_acks() {
        let events = Arc::new(RecordingEventSink::default());
        let w = worker(
            Arc::new(CannedResolver(Ok(()))),
            Arc::new(CannedSimulator(Ok(true))),
            events.clone(),
        );

        let disposition = w.process(&sample_job()).await;
        assert_eq!(disposition, Disposition::Ack);

        let emitted = events.events();
        assert_eq!(emitted.len(), 2, "SimulationCompleted + IncidentCreated");
        assert!(matches!(emitted[0], DomainEvent::SimulationCompleted(_)));
        assert!(matches!(emitted[1], DomainEvent::IncidentCreated(_)));
    }

    #[tokio::test]
    async fn an_unconfirmed_job_publishes_only_completed_and_acks() {
        let events = Arc::new(RecordingEventSink::default());
        let w = worker(
            Arc::new(CannedResolver(Ok(()))),
            Arc::new(CannedSimulator(Ok(false))),
            events.clone(),
        );

        assert_eq!(w.process(&sample_job()).await, Disposition::Ack);
        let emitted = events.events();
        assert_eq!(emitted.len(), 1);
        assert!(matches!(emitted[0], DomainEvent::SimulationCompleted(_)));
    }

    #[tokio::test]
    async fn an_unresolvable_job_is_dead_lettered_without_publishing() {
        let events = Arc::new(RecordingEventSink::default());
        let w = worker(
            Arc::new(CannedResolver(Err(ResolveErrorKind::Poison))),
            Arc::new(CannedSimulator(Ok(true))),
            events.clone(),
        );

        assert_eq!(w.process(&sample_job()).await, Disposition::DeadLetter);
        assert!(events.events().is_empty(), "poison never publishes");
    }

    #[tokio::test]
    async fn a_transient_resolve_fault_requeues() {
        let events = Arc::new(RecordingEventSink::default());
        let w = worker(
            Arc::new(CannedResolver(Err(ResolveErrorKind::Transient))),
            Arc::new(CannedSimulator(Ok(true))),
            events.clone(),
        );
        assert_eq!(w.process(&sample_job()).await, Disposition::Requeue);
        assert!(events.events().is_empty());
    }

    #[tokio::test]
    async fn a_poison_simulation_is_dead_lettered_and_transient_requeues() {
        let events = Arc::new(RecordingEventSink::default());

        let poison = worker(
            Arc::new(CannedResolver(Ok(()))),
            Arc::new(CannedSimulator(Err(false))),
            events.clone(),
        );
        assert_eq!(poison.process(&sample_job()).await, Disposition::DeadLetter);

        let transient = worker(
            Arc::new(CannedResolver(Ok(()))),
            Arc::new(CannedSimulator(Err(true))),
            events.clone(),
        );
        assert_eq!(transient.process(&sample_job()).await, Disposition::Requeue);

        assert!(events.events().is_empty(), "neither fault publishes");
    }

    /// A job whose resolved block was orphaned by a reorg is cancelled (§7, §15): the
    /// worker acks it and publishes nothing, so no incident is created for an orphaned
    /// block. The generation check runs *after* resolve (the job carries no block).
    #[tokio::test]
    async fn a_job_for_an_orphaned_block_is_cancelled_without_simulating() {
        /// Resolves every job to a scenario stamped with a fixed block hash.
        struct BlockResolver(B256);
        #[async_trait]
        impl JobResolver for BlockResolver {
            async fn resolve(
                &self,
                job: &SimulationJob,
            ) -> Result<SimulationRequest, ResolveError> {
                let mut req = empty_request(job);
                req.block = BlockParams {
                    number: 100,
                    hash: self.0,
                    ..BlockParams::default()
                };
                Ok(req)
            }
        }

        let hash = B256::repeat_byte(0xaa);
        let orphaned = SharedOrphanedBlocks::new();
        orphaned.record(&BlockReverted {
            block: BlockRef::new(100, hash),
            replaced_by: B256::repeat_byte(0xbb),
        });

        let events = Arc::new(RecordingEventSink::default());
        let mut w = Worker::new(
            Arc::new(BlockResolver(hash)),
            orphaned,
            Arc::new(CannedSimulator(Ok(true))),
            test_pool(),
            events.clone(),
            CancellationToken::new(),
        );
        w.publish_backoff = Duration::from_millis(1);

        assert_eq!(
            w.process(&sample_job()).await,
            Disposition::Ack,
            "a reorg-cancelled job is acked (dropped), not dead-lettered"
        );
        assert!(
            events.events().is_empty(),
            "no result is published for an orphaned block"
        );
    }

    /// Shutdown interrupting the publish path requeues rather than acking past an
    /// unpublished result — the at-least-once guard.
    #[tokio::test]
    async fn shutdown_during_processing_requeues() {
        let events = Arc::new(RecordingEventSink::default());
        let shutdown = CancellationToken::new();
        let mut w = Worker::new(
            Arc::new(CannedResolver(Ok(()))),
            Arc::new(NeverOrphaned),
            Arc::new(CannedSimulator(Ok(true))),
            test_pool(),
            events.clone(),
            shutdown.clone(),
        );
        w.publish_backoff = Duration::from_millis(1);
        shutdown.cancel(); // already cancelled before processing

        assert_eq!(w.process(&sample_job()).await, Disposition::Requeue);
    }

    /// End-to-end through the drain loop: one job on an in-memory source is processed
    /// and the delivery is acked.
    #[tokio::test]
    async fn run_drains_a_source_and_acks_each_delivery() {
        struct OneShotSource(Option<JobDelivery>);
        #[async_trait]
        impl JobSource for OneShotSource {
            async fn recv(&mut self) -> Option<JobDelivery> {
                self.0.take()
            }
        }

        let events = Arc::new(RecordingEventSink::default());
        let recorder = AckRecorder::default();
        let delivery = JobDelivery::new(sample_job(), false, Box::new(recorder.clone()));

        let w = worker(
            Arc::new(CannedResolver(Ok(()))),
            Arc::new(CannedSimulator(Ok(true))),
            events.clone(),
        );
        w.run(OneShotSource(Some(delivery))).await.unwrap();

        assert_eq!(recorder.settled(), Some(Disposition::Ack));
        assert_eq!(events.events().len(), 2);
    }
}
