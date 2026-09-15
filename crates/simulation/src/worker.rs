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
use std::time::{Duration, Instant};

use event_bus::usage::UsageFact;
use event_bus::{AcceptLoss, EventSink, Transience, Undelivered};
use events::primitives::Chain;
use events::system::UsageEventType;
use events::{DomainEvent, EventEnvelope};
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
use crate::result::{events_for_outcome, EthUsdPrice};
use crate::simulator::{SimError, SimulationOutcome, SimulationRequest, Simulator};

/// Default for `SIMULATION_JOB_DEADLINE_SECS`: one job's resolve + simulate budget.
///
/// It is a term in the pod's shutdown budget, not a free choice. A job in flight
/// at SIGTERM runs to its settle, so the grace period must cover this, plus
/// [`DEADLINE_OVERSHOOT_ALLOWANCE`], plus [`MAX_RESULT_EVENTS`] × the Kafka send
/// timeout. `tests/grace_period.rs` checks that sum against the manifest.
pub const DEFAULT_JOB_DEADLINE: Duration = Duration::from_secs(45);

/// How far past its deadline a simulation is assumed to run. The deadline is
/// checked between transactions, so this is one transaction's worst case. The
/// assumption is watched, not trusted: `simulation_job_deadline_overshoot_seconds`
/// measures it, and `SimulationDeadlineOvershootAboveAllowance` fires above it.
pub const DEADLINE_OVERSHOOT_ALLOWANCE: Duration = Duration::from_secs(5);

/// The most result events one job publishes: `SimulationCompleted`, plus
/// `IncidentCreated` when the alert is confirmed. Pinned by a test here.
pub const MAX_RESULT_EVENTS: usize = 2;

const USAGE_IS_APPROXIMATE: &str =
    "usage metering is approximate by design (§13); results, not usage, settle the job";

/// The ack decision, from what publishing the results did, and nothing else.
///
/// In particular not the shutdown token. A job whose results landed during a
/// drain is done, and requeueing it would re-run revm for nothing. A result that
/// can never be encoded fails identically on every re-run, so it is quarantined
/// rather than cycled through `x-delivery-limit`.
fn settle(results: Result<(), Undelivered>) -> Disposition {
    match results {
        Ok(()) => Disposition::Ack,
        Err(Undelivered::Shutdown) => Disposition::Requeue,
        Err(Undelivered::Permanent) => Disposition::DeadLetter,
    }
}

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
    /// Wall-clock budget for one job's resolve + simulate.
    job_deadline: Duration,
    /// ETH→USD reference for restamping a confirmed incident's scoring triple
    /// from its (ETH) figures (§7 — see [`crate::result::events_for_outcome`]).
    eth_usd_price: EthUsdPrice,
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
        eth_usd_price: EthUsdPrice,
    ) -> Self {
        Self {
            resolver,
            orphaned,
            simulator,
            pool,
            event_sink,
            shutdown,
            publish_backoff: PUBLISH_BACKOFF,
            job_deadline: DEFAULT_JOB_DEADLINE,
            eth_usd_price,
        }
    }

    /// Override the per-job deadline (`SIMULATION_JOB_DEADLINE_SECS`).
    pub fn with_job_deadline(mut self, job_deadline: Duration) -> Self {
        self.job_deadline = job_deadline;
        self
    }

    /// Handle one job — resolve → simulate (on rayon) → publish the result(s) →
    /// return the disposition, timing the whole call regardless of how it
    /// resolves (§19 — a slow resolver or a long revm run are both latency this
    /// should surface). The actual work is [`Self::process_inner`]; this is the
    /// one seam every job passes through, so it's the single metrics call site.
    #[tracing::instrument(skip_all, fields(alert_id = %job.alert_id))]
    pub async fn process(&self, job: &SimulationJob) -> Disposition {
        let started = std::time::Instant::now();
        let disposition = self.process_inner(job).await;
        crate::metrics::record_job_duration(started.elapsed());
        disposition
    }

    /// The core, free of timing/the consume/ack loop. Resolve → simulate (on
    /// rayon), both inside the job's deadline → publish the results → settle →
    /// meter.
    async fn process_inner(&self, job: &SimulationJob) -> Disposition {
        let deadline = Instant::now() + self.job_deadline;

        // 1. Resolve the alert to a runnable `(block, tx_set)` scenario. The resolver
        //    is async and cancellable, so the deadline simply times it out.
        let resolved = tokio::time::timeout_at(deadline.into(), self.resolver.resolve(job)).await;
        let request = match resolved {
            Ok(Ok(request)) => request,
            Ok(Err(err)) => {
                let disposition = disposition_for(err.is_transient());
                tracing::warn!(error = %err, alert_id = %job.alert_id, ?disposition, "resolve failed");
                return disposition;
            }
            Err(_elapsed) => {
                crate::metrics::record_deadline_exceeded("resolve", Duration::ZERO);
                tracing::warn!(
                    alert_id = %job.alert_id,
                    job_deadline = ?self.job_deadline,
                    "resolve passed the job deadline; requeueing"
                );
                return Disposition::Requeue;
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
        let outcome = match self.simulate(request, deadline).await {
            Ok(outcome) => outcome,
            Err(SimError::DeadlineExceeded { overshoot }) => {
                crate::metrics::record_deadline_exceeded("simulate", overshoot);
                tracing::warn!(
                    alert_id = %job.alert_id,
                    ?overshoot,
                    "simulation passed the job deadline; requeueing"
                );
                return Disposition::Requeue;
            }
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
        crate::metrics::record_job_outcome(outcome.confirmed);

        // 3. Publish the results back onto Kafka (at-least-once), then settle on what
        //    actually landed. The command never re-enters the event store — only its
        //    outcome does (§7).
        let result_events = events_for_outcome(&outcome, self.eth_usd_price);
        let incidents_created = result_events
            .iter()
            .filter(|e| matches!(e, DomainEvent::IncidentCreated(_)))
            .count() as u64;
        let disposition = settle(self.publish_results(job.chain, result_events).await);

        // 4. Meter a job once it is done: on `Ack` only, since a requeued job is
        //    metered by the run that acks it. Skipped during a drain, because each
        //    usage publish can take the Kafka send timeout and the grace-period
        //    budget covers results, not metering. One `SimulationRun` per job; a
        //    confirmed alert also mints `IncidentGenerated`. Neither is attributable
        //    to a customer (§13).
        if disposition == Disposition::Ack && !self.shutdown.is_cancelled() {
            UsageFact::new(UsageEventType::SimulationRun, 1)
                .record(
                    self.event_sink.as_ref(),
                    job.chain,
                    self.publish_backoff,
                    &self.shutdown,
                )
                .await
                .accept_loss(USAGE_IS_APPROXIMATE);
            if incidents_created > 0 {
                UsageFact::new(UsageEventType::IncidentGenerated, incidents_created)
                    .record(
                        self.event_sink.as_ref(),
                        job.chain,
                        self.publish_backoff,
                        &self.shutdown,
                    )
                    .await
                    .accept_loss(USAGE_IS_APPROXIMATE);
            }
        }
        disposition
    }

    /// Publish a job's results in order, stopping at the first that does not land.
    /// Once one is undelivered the job will be requeued anyway, and during a drain
    /// every further attempt could spend a whole send timeout of the grace period.
    async fn publish_results(
        &self,
        chain: Chain,
        events: Vec<DomainEvent>,
    ) -> Result<(), Undelivered> {
        for event in events {
            event_bus::publish_resilient(
                self.event_sink.as_ref(),
                EventEnvelope::new(chain, event),
                self.publish_backoff,
                &self.shutdown,
            )
            .await?;
        }
        Ok(())
    }

    /// Run one scenario on the shared rayon pool, bridging back to async via a
    /// oneshot. A dropped task (pool shut down) surfaces as a transient fault so the
    /// job redelivers rather than vanishing.
    async fn simulate(
        &self,
        request: SimulationRequest,
        deadline: Instant,
    ) -> Result<SimulationOutcome, SimError> {
        let simulator = self.simulator.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pool.spawn(move || {
            let outcome = simulator.simulate_by(&request, deadline);
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
    ///
    /// Shutdown is only observed *between* jobs: a job already taken runs to its
    /// settle, which is what the pod's termination grace period is sized for. Jobs
    /// prefetched but not started return to the queue when the source drops.
    pub async fn run(self, mut source: impl JobSource) -> anyhow::Result<()> {
        tracing::info!("simulation worker draining sim.jobs");
        loop {
            let delivery = tokio::select! {
                biased;
                () = self.shutdown.cancelled() => {
                    tracing::info!("simulation worker stopping (prefetched, unstarted jobs return to the queue)");
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
                    txs: vec![],
                    victim: None,
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
            EthUsdPrice::try_new(2_000.0).unwrap(),
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

        let emitted = events.non_usage_events();
        assert_eq!(emitted.len(), 2, "SimulationCompleted + IncidentCreated");
        assert!(
            emitted.len() <= MAX_RESULT_EVENTS,
            "the grace-period budget assumes at most MAX_RESULT_EVENTS results"
        );
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
        let emitted = events.non_usage_events();
        assert_eq!(emitted.len(), 1);
        assert!(matches!(emitted[0], DomainEvent::SimulationCompleted(_)));
    }

    #[tokio::test]
    async fn a_confirmed_job_meters_both_simulation_run_and_incident_generated() {
        let events = Arc::new(RecordingEventSink::default());
        let w = worker(
            Arc::new(CannedResolver(Ok(()))),
            Arc::new(CannedSimulator(Ok(true))),
            events.clone(),
        );

        w.process(&sample_job()).await;

        let usage: Vec<_> = events
            .events()
            .into_iter()
            .filter_map(|e| match e {
                DomainEvent::UsageRecorded(u) => Some(u),
                _ => None,
            })
            .collect();
        assert_eq!(usage.len(), 2, "SimulationRun + IncidentGenerated");
        assert!(usage.iter().all(|u| u.customer_id.is_none()));
        assert_eq!(
            usage[0].event_type,
            events::system::UsageEventType::SimulationRun.as_wire_str()
        );
        assert_eq!(
            usage[1].event_type,
            events::system::UsageEventType::IncidentGenerated.as_wire_str()
        );
    }

    #[tokio::test]
    async fn an_unconfirmed_job_meters_only_simulation_run() {
        let events = Arc::new(RecordingEventSink::default());
        let w = worker(
            Arc::new(CannedResolver(Ok(()))),
            Arc::new(CannedSimulator(Ok(false))),
            events.clone(),
        );

        w.process(&sample_job()).await;

        let usage: Vec<_> = events
            .events()
            .into_iter()
            .filter_map(|e| match e {
                DomainEvent::UsageRecorded(u) => Some(u),
                _ => None,
            })
            .collect();
        assert_eq!(usage.len(), 1, "no incident, so no IncidentGenerated fact");
        assert_eq!(
            usage[0].event_type,
            events::system::UsageEventType::SimulationRun.as_wire_str()
        );
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
            EthUsdPrice::try_new(2_000.0).unwrap(),
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

    /// A worker whose shutdown has already fired, publishing into `sink`.
    fn draining_worker(sink: Arc<dyn EventSink>) -> Worker {
        let shutdown = CancellationToken::new();
        let mut w = Worker::new(
            Arc::new(CannedResolver(Ok(()))),
            Arc::new(NeverOrphaned),
            Arc::new(CannedSimulator(Ok(true))),
            test_pool(),
            sink,
            shutdown.clone(),
            EthUsdPrice::try_new(2_000.0).unwrap(),
        );
        w.publish_backoff = Duration::from_millis(1);
        shutdown.cancel();
        w
    }

    /// A worker over `sink`, not shutting down.
    fn worker_over(sink: Arc<dyn EventSink>) -> Worker {
        let mut w = Worker::new(
            Arc::new(CannedResolver(Ok(()))),
            Arc::new(NeverOrphaned),
            Arc::new(CannedSimulator(Ok(true))),
            test_pool(),
            sink,
            CancellationToken::new(),
            EthUsdPrice::try_new(2_000.0).unwrap(),
        );
        w.publish_backoff = Duration::from_millis(1);
        w
    }

    #[test]
    fn settle_decides_on_delivery_alone() {
        assert_eq!(settle(Ok(())), Disposition::Ack);
        assert_eq!(settle(Err(Undelivered::Shutdown)), Disposition::Requeue);
        assert_eq!(settle(Err(Undelivered::Permanent)), Disposition::DeadLetter);
    }

    /// A result that can never be encoded is quarantined, not cycled through
    /// redeliveries that would each re-run revm to fail the same way.
    #[tokio::test]
    async fn an_unencodable_result_is_dead_lettered_and_not_metered() {
        struct Unencodable;
        #[async_trait]
        impl EventSink for Unencodable {
            async fn publish(
                &self,
                _envelope: EventEnvelope,
            ) -> Result<(), event_bus::PublishError> {
                Err(event_bus::PublishError::Encode(
                    events::EventError::UnsupportedSchemaVersion {
                        found: 999,
                        supported: 1,
                    },
                ))
            }
        }

        let w = worker_over(Arc::new(Unencodable));
        assert_eq!(w.process(&sample_job()).await, Disposition::DeadLetter);
    }

    /// Results stop at the first that does not land: the job is requeued either
    /// way, and during a drain each further attempt could cost a whole send timeout.
    #[tokio::test]
    async fn publishing_stops_at_the_first_undelivered_result() {
        struct CountingDown(std::sync::Mutex<u32>);
        #[async_trait]
        impl EventSink for CountingDown {
            async fn publish(
                &self,
                _envelope: EventEnvelope,
            ) -> Result<(), event_bus::PublishError> {
                *self.0.lock().unwrap() += 1;
                Err(event_bus::PublishError::Delivery("broker down".into()))
            }
        }

        let sink = Arc::new(CountingDown(std::sync::Mutex::new(0)));
        let w = draining_worker(sink.clone());
        assert_eq!(w.process(&sample_job()).await, Disposition::Requeue);
        assert_eq!(
            *sink.0.lock().unwrap(),
            1,
            "a confirmed job has two results; only the first is attempted"
        );
    }

    #[tokio::test]
    async fn a_resolve_that_outlives_the_job_deadline_is_requeued() {
        struct Hanging;
        #[async_trait]
        impl JobResolver for Hanging {
            async fn resolve(
                &self,
                _job: &SimulationJob,
            ) -> Result<SimulationRequest, ResolveError> {
                std::future::pending().await
            }
        }

        let events = Arc::new(RecordingEventSink::default());
        let w = Worker::new(
            Arc::new(Hanging),
            Arc::new(NeverOrphaned),
            Arc::new(CannedSimulator(Ok(true))),
            test_pool(),
            events.clone(),
            CancellationToken::new(),
            EthUsdPrice::try_new(2_000.0).unwrap(),
        )
        .with_job_deadline(Duration::from_millis(20));
        assert_eq!(w.process(&sample_job()).await, Disposition::Requeue);
        assert!(events.events().is_empty(), "nothing published or metered");
    }

    #[tokio::test]
    async fn a_simulation_past_its_deadline_is_requeued_not_dead_lettered() {
        struct Late;
        impl Simulator for Late {
            fn simulate(&self, _req: &SimulationRequest) -> Result<SimulationOutcome, SimError> {
                unreachable!("the worker always calls simulate_by")
            }
            fn simulate_by(
                &self,
                _req: &SimulationRequest,
                _deadline: Instant,
            ) -> Result<SimulationOutcome, SimError> {
                Err(SimError::DeadlineExceeded {
                    overshoot: Duration::from_millis(3),
                })
            }
        }

        let events = Arc::new(RecordingEventSink::default());
        let w = worker(
            Arc::new(CannedResolver(Ok(()))),
            Arc::new(Late),
            events.clone(),
        );
        assert_eq!(w.process(&sample_job()).await, Disposition::Requeue);
        assert!(events.events().is_empty());
    }

    /// Shutdown interrupting a failing publish requeues rather than acking past an
    /// unpublished result — the at-least-once guard.
    #[tokio::test]
    async fn shutdown_interrupting_an_undelivered_result_requeues() {
        struct BrokerDown;
        #[async_trait]
        impl EventSink for BrokerDown {
            async fn publish(
                &self,
                _envelope: EventEnvelope,
            ) -> Result<(), event_bus::PublishError> {
                Err(event_bus::PublishError::Delivery("broker down".into()))
            }
        }

        let w = draining_worker(Arc::new(BrokerDown));
        assert_eq!(w.process(&sample_job()).await, Disposition::Requeue);
    }

    /// A job that finishes and publishes while the pod drains is done. Requeueing it
    /// — the old rule, keyed on the shutdown token — re-ran revm and re-metered
    /// `SimulationRun` on every scale-down.
    #[tokio::test]
    async fn a_result_delivered_during_shutdown_is_acked_not_rerun() {
        let events = Arc::new(RecordingEventSink::default());
        let w = draining_worker(events.clone());

        assert_eq!(w.process(&sample_job()).await, Disposition::Ack);
        assert_eq!(events.non_usage_events().len(), 2, "both results landed");
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
        assert_eq!(events.non_usage_events().len(), 2);
    }
}
