//! Load testing the fast path (readiness Epic D).
//!
//! §6 states a target — a preliminary alert in **under one second** — and that
//! number is the platform's headline latency claim. Until this crate it had
//! never been measured against a saturated pipeline, and the instrumentation
//! that existed could not have caught a breach: `detector_detect_duration_seconds`
//! times one `detect` call, which is microseconds on a header-only block and
//! stays microseconds however deep the queue in front of it gets. A dashboard
//! built on it is green precisely when the claim is most likely to be false.
//!
//! So two things had to happen, and this crate is the second of them:
//!
//! 1. `detection::metrics::FAST_PATH_SECONDS` — the fast path's own clock, from
//!    the block's `occurred_at` to its alert's publication, spanning the broker
//!    hop and the work queue that a saturated pipeline actually fills.
//! 2. This harness: offer load at a target throughput, drain, read that series,
//!    and return an exit code.
//!
//! # The shape of the argument
//!
//! A load test is a claim about a system under a specified load, and it is only
//! as good as the weakest link in that sentence. Each module owns one link, and
//! each is written to fail loudly rather than flatter the result:
//!
//! - [`profile`] — what "target throughput" means, with its derivation
//!   committed alongside the numbers.
//! - [`source`] — the `LoadSource` seam every driver implements, which is what
//!   makes the *procedure* in [`run`] testable against in-memory doubles rather
//!   than only against a broker and six minutes.
//! - [`chain`] — the block generator, which stamps each block with the time it
//!   was *due* rather than the time it was sent, so the harness's own lateness
//!   lands inside the measurement instead of hiding it (coordinated omission).
//! - [`api`] — the qps driver, measuring latency client-side, where the accept
//!   queue is visible.
//! - [`run`] — warm up, load, **drain**, measure. The drain is not politeness:
//!   the blocks still queued when the load stops are the slowest ones, and
//!   measuring without them reports the p99 of the subset that kept up.
//! - [`scrape`] — bucket arithmetic. A bucketed quantile is a bound, so the
//!   verdict is "≥99% at or below the budget", which the shared ladder decides
//!   exactly; a threshold with no bucket boundary is reported undecidable
//!   rather than interpolated.
//! - [`slo`] — committed budgets, a measurement that carries its **unit**, and
//!   a **three-way** verdict. Held, breached, or *inconclusive*: a load test has
//!   more ways to be uninformative than to fail, and every one of them yields a
//!   clean-looking p99 over a handful of samples.
//! - [`gates`] — every rule that can change the exit code, in one enumerable
//!   registry, with a test that fails the build if a committed budget has no
//!   gate reading it.
//! - [`report`] — the numbers, the load they were measured under, and what a
//!   green run still does not prove.
//!
//! # What the exit codes mean
//!
//! `0` the budgets held · `1` a budget was breached · `2` the run could not
//! decide. Two is not a soft pass: an unloaded system, an undrained pipeline or
//! an empty SLO series all land there, and a nightly job that treats `2` as
//! success has re-created the problem this crate exists to solve.

pub mod api;
pub mod chain;
pub mod gates;
pub mod profile;
pub mod report;
pub mod run;
pub mod scrape;
pub mod slo;
pub mod source;
