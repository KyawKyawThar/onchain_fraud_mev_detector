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
//!   confirm/retract. Runs on the rayon pool, off the async reactor (§17).
//! - [`result`] — the pure `SimulationOutcome → {SimulationCompleted, IncidentCreated}`
//!   mapping.
//! - [`worker`] — the [`Worker`](worker::Worker): drain → resolve → simulate on
//!   rayon → publish → ack/requeue/dead-letter.
//!
//! - [`config`] — env-resolved [`Config`](config::Config), shared by both binaries.

pub mod command;
pub mod config;
pub mod consumer;
pub mod dispatcher;
pub mod queue;
pub mod resolver;
pub mod result;
pub mod simulator;
pub mod topology;
pub mod worker;

/// Shared test doubles (recording sinks, canned scenarios), behind the `test-util`
/// feature so the crate's own tests and the `tests/` integration crate reuse one set
/// — mirroring `detector-api::test_util`.
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;
