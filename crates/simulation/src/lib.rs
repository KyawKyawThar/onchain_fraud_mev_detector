//! Simulation service (§7) — the slow path that confirms or retracts a provisional
//! alert with revm, asynchronously, off the alert critical path.
//!
//! Sprint 5 builds both halves around the RabbitMQ `sim.jobs` work queue:
//!
//! ```text
//! PreliminaryAlertCreated   (Kafka, domain event)
//!         │
//!         ▼
//!   dispatcher  (thin Kafka consumer)                              [t1, front half]
//!         │  publishes a SimulationJob COMMAND ───────► RabbitMQ sim.jobs queue
//!         └  emits SimulationRequested (audit) ───────► Kafka (event store)
//!                                                              │  competing consumers
//!                                                              ▼
//!   worker pool  (revm on rayon, per-job ack/redelivery)             [t3, back half]
//!         │  runs the simulation, then publishes the result ──► Kafka:
//!         └  SimulationCompleted / IncidentCreated
//! ```
//!
//! **Front half (t1):**
//! - [`command`] — the [`SimulationJob`](command::SimulationJob) command and the
//!   pure `PreliminaryAlertCreated → (SimulationJob, SimulationRequested)` mapping.
//! - [`queue`] — the [`JobSink`](queue::JobSink) RabbitMQ publish seam + the
//!   at-least-once `publish_resilient` policy.
//! - [`topology`] — the one-time `sim.jobs` queue + DLX declaration
//!   ([`declare_sim_topology`](topology::declare_sim_topology)).
//! - [`dispatcher`] — the [`Dispatcher`](dispatcher::Dispatcher): consume alerts,
//!   queue jobs, emit the audit event, commit.
//!
//! **Back half (t3) — the worker pool:**
//! - [`consumer`] — the [`JobSource`](consumer::JobSource) consume seam: competing
//!   consumers over `sim.jobs` with prefetch + manual per-job ack/redelivery.
//! - [`resolver`] — the [`JobResolver`](resolver::JobResolver) seam turning a job
//!   into a runnable scenario (stubbed; chain-fork resolution is a follow-up).
//! - [`simulator`] — the revm engine: re-execute a bundle, diff balances, decide
//!   confirm/retract. Runs on the rayon pool, off the async reactor (§17). Hardened
//!   against hostile honeypot bytecode with gas/step caps + a panic sandbox (§7).
//! - [`cache`] — the [`CachingSimulator`](cache::CachingSimulator) decorator:
//!   memoize outcomes by `(block, tx_set)` so a redelivered or replayed bundle is a
//!   cache hit, not duplicate revm work (§7 hardening).
//! - [`result`] — the pure `SimulationOutcome → {SimulationCompleted, IncidentCreated}`
//!   mapping.
//! - [`worker`] — the [`Worker`](worker::Worker): drain → resolve → simulate on
//!   rayon → publish → ack/requeue/dead-letter.
//!
//! **Result → incident read model (Sprint 6):**
//! - [`projection`] — the [`IncidentProjection`](projection::IncidentProjection):
//!   the pure, idempotent, commutative fold that reasserts ordering at the
//!   projection (§7), so a redelivered `SimulationCompleted` is a no-op and the
//!   confirm/retract/finalize lifecycle lands correctly regardless of partition
//!   arrival order. The read-model core the Postgres/ClickHouse store plugs into.
//!
//! **Persistence (§14, Sprint 6 t5) — the `simulation-projection` binary:**
//! - [`store`] — the write-through seams behind the fold:
//!   [`IncidentStore`](store::IncidentStore) (Postgres — the mutable in-flight-job +
//!   confirmed-incident read model) and [`IncidentAnalytics`](store::IncidentAnalytics)
//!   (ClickHouse — the append-only incident-analytics firehose).
//! - [`ch_migrate`] — the ClickHouse migration runner for the analytics table (ported
//!   from the event store); Postgres migrations live in `crates/db/migrations`, applied
//!   by sqlx-cli.
//! - [`projection_consumer`] — the [`ProjectionConsumer`](projection_consumer::ProjectionConsumer):
//!   consume the result path, fold, and write through to both stores, at-least-once.
//!
//! **Reorg handling (§15, Sprint 6 t4):**
//! - [`reorg`] — the two `BlockReverted` reactions: the worker-side generation check
//!   ([`OrphanedBlocks`](reorg::OrphanedBlocks) + [`OrphanGuard`](reorg::OrphanGuard))
//!   that cancels a resolved job for an orphaned block (§7), and the service-side
//!   [`ReorgConsumer`](reorg::ReorgConsumer) that retracts incidents from orphaned
//!   blocks via `IncidentRetracted` ([`plan_retractions`](reorg::plan_retractions) +
//!   the [`IncidentIndex`](reorg::IncidentIndex) block→incident seam).
//!
//! - [`config`] — env-resolved [`Config`](config::Config), shared by both binaries.

pub mod cache;
pub mod ch_migrate;
pub mod command;
pub mod config;
pub mod consumer;
pub mod dispatcher;
pub mod projection;
pub mod projection_consumer;
pub mod queue;
pub mod reorg;
pub mod resolver;
pub mod result;
pub mod simulator;
pub mod store;
pub mod topology;
pub mod worker;

/// Shared test doubles (recording sinks, canned scenarios), behind the `test-util`
/// feature so the crate's own tests and the `tests/` integration crate reuse one set
/// — mirroring `detector-api::test_util`.
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;
