//! §19 metric names and the recording calls behind them. Public so the
//! binary's dashboards and alert rules reference the names rather than
//! re-typing them.
//!
//! The LLM call's own metrics — latency, tokens, stop reasons, cache hit rate
//! — belong to `llm::metrics` and are recorded by the `MeteredClient`
//! decorator. Nothing here duplicates them: these measure the *queue*, which
//! is the part `llm` cannot see.

use std::time::Instant;

/// Counter (labeled by `kind`, `outcome`): drafts enqueued by the consumer.
/// `outcome` is `queued` or `duplicate` — a steady stream of duplicates means
/// redelivery, which is normal; a *rising* one means the consumer group is
/// rebalancing in a loop.
pub const DRAFTS_ENQUEUED_TOTAL: &str = "copilot_drafts_enqueued_total";

/// Counter (labeled by `kind`, `status`): drafts a worker finished, by the
/// status they landed in. `blocked` here is the refusal/truncation rate — the
/// number that says whether the prompt is drawing declines.
pub const DRAFTS_FINISHED_TOTAL: &str = "copilot_drafts_finished_total";

/// Counter (labeled by `kind`): jobs leased by this pod's worker pool.
pub const JOBS_CLAIMED_TOTAL: &str = "copilot_jobs_claimed_total";

/// Gauge: draft jobs this pod currently holds a lease on. Compare against the
/// configured concurrency to see whether the pool is saturated.
pub const JOBS_IN_FLIGHT: &str = "copilot_jobs_in_flight";

/// Histogram (labeled by `kind`, `status`), seconds: how long a claimed job
/// took end to end — audit-stream read, model call and bookkeeping. The
/// §14 timed-wrapper split: `Worker::run` times, `run_inner` works.
pub const JOB_DURATION_SECONDS: &str = "copilot_job_duration_seconds";

pub fn record_enqueued(kind: &'static str, outcome: &'static str) {
    metrics::counter!(DRAFTS_ENQUEUED_TOTAL, "kind" => kind, "outcome" => outcome).increment(1);
}

/// Counter (labeled by `kind`): drafts this pod leased but carries no
/// generator for — released, not failed. **Alert on any non-zero rate.** It
/// means either a misconfigured fleet, or a kind nobody serves, which
/// circulates on the queue indefinitely because a release does not consume an
/// attempt (see `worker::DraftWorkerPool::serves`).
pub const DRAFTS_UNSERVABLE_TOTAL: &str = "copilot_drafts_unservable_total";

pub fn record_unservable(kind: &'static str) {
    metrics::counter!(DRAFTS_UNSERVABLE_TOTAL, "kind" => kind).increment(1);
}

pub fn record_claimed(kind: &'static str, count: u64) {
    if count > 0 {
        metrics::counter!(JOBS_CLAIMED_TOTAL, "kind" => kind).increment(count);
    }
}

pub fn set_in_flight(count: usize) {
    metrics::gauge!(JOBS_IN_FLIGHT).set(count as f64);
}

/// Record one finished job. `status` is the draft's landing status, so the
/// counter and the histogram are sliceable the same way.
pub fn record_finished(kind: &'static str, status: &'static str, started: Instant) {
    metrics::counter!(DRAFTS_FINISHED_TOTAL, "kind" => kind, "status" => status).increment(1);
    metrics::histogram!(JOB_DURATION_SECONDS, "kind" => kind, "status" => status)
        .record(started.elapsed().as_secs_f64());
}
