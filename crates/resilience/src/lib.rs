//! Shared resilience primitives for calling something that can be slow,
//! rate-limited, or down.
//!
//! Two state machines, both pure functions of (state, time) with the clock
//! passed in so they are deterministic and testable without sleeping:
//!
//! * [`circuit::CircuitBreaker`] — stop hammering a dependency that is failing,
//!   and probe it back to health. Written for §5's RPC endpoint pool; promoted
//!   here when the §20.4 LLM seam became its second consumer, in a different
//!   domain, with the same requirement.
//! * [`backoff::Backoff`] — bounded exponential retry with **jitter** and a cap
//!   on how long a server-directed `retry-after` may park a worker.
//!
//! # Why these are shared rather than copied
//!
//! The `db::redis` rule exists because `intelligence::cache` and
//! `rule_engine::state_store` independently hand-rolled byte-identical
//! connection and error-classification logic, and nothing would have caught
//! them drifting apart. Retry loops are worse: this workspace has four
//! (`notification::http_delivery`, `notification::email_delivery`,
//! `rule_engine::webhook`, and — before this crate — the LLM client), all
//! implementing the same doubling backoff, **none** of them jittered. That is
//! not a style inconsistency; a deterministic backoff means every replica hit
//! by one rate-limit wave retries in the same millisecond, forever.
//!
//! Those three existing loops are deliberately *not* retrofitted in the same
//! change that introduces this crate — each is on a customer-visible delivery
//! path with its own tests. They are the natural next adopters.
//!
//! # No I/O, no runtime
//!
//! Nothing here awaits, allocates a connection, or reads a clock of its own.
//! A caller decides what "now" is and what to do with a decision, which is
//! what lets the same breaker guard an HTTP endpoint, an RPC endpoint, and a
//! model provider without any of them appearing in this crate's dependencies.

pub mod backoff;
pub mod circuit;

pub use backoff::{Backoff, RetryDecision};
pub use circuit::{BreakerConfig, CircuitBreaker, CircuitState};
