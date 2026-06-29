//! Simulation service (§7) — the slow path that confirms or retracts a provisional
//! alert with revm, asynchronously, off the alert critical path.
//!
//! Sprint 5 builds the **front half** — the dispatch boundary between the Kafka
//! event backbone and the RabbitMQ work queue:
//!
//! ```text
//! PreliminaryAlertCreated   (Kafka, domain event)
//!         │
//!         ▼
//!   dispatcher  (thin Kafka consumer — this crate)
//!         │  publishes a SimulationJob COMMAND ───────► RabbitMQ sim.jobs queue
//!         └  emits SimulationRequested (audit) ───────► Kafka (event store)
//! ```
//!
//! - [`command`] — the [`SimulationJob`](command::SimulationJob) command and the
//!   pure `PreliminaryAlertCreated → (SimulationJob, SimulationRequested)` mapping.
//! - [`queue`] — the [`JobSink`](queue::JobSink) RabbitMQ publish seam + the
//!   at-least-once `publish_resilient` policy.
//! - [`dispatcher`] — the [`Dispatcher`](dispatcher::Dispatcher): consume alerts,
//!   queue jobs, emit the audit event, commit.
//! - [`config`] — env-resolved [`Config`](config::Config).
//!
//! The worker pool that drains `sim.jobs` (revm on rayon, task 3) and the
//! result→incident path (Sprint 6) build on the [`queue`] seam.

pub mod command;
pub mod config;
pub mod dispatcher;
pub mod queue;
