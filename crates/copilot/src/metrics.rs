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

/// Counter (labeled by `outcome`): `IncidentNarrativeDrafted` announcements —
/// `published`, `failed` (the publish will be retried), or `unannounceable`
/// (a ready draft with no answer or no prompt provenance: a corrupt row whose
/// claim is deliberately *kept*, so it cannot loop).
///
/// A sustained `failed` rate means the audit trail is missing drafting
/// records that the copilot store nonetheless holds — the two views of §20.4
/// diverging, which is exactly the state an auditor must never discover for
/// themselves.
pub const NARRATIVES_ANNOUNCED_TOTAL: &str = "copilot_narratives_announced_total";

pub fn record_announced(outcome: &'static str) {
    metrics::counter!(NARRATIVES_ANNOUNCED_TOTAL, "outcome" => outcome).increment(1);
}

/// Counter (labeled by `reason`): drafts blocked by the §20.4 citation check
/// — `no_claims`, `uncited`, or `fabricated`.
///
/// **`fabricated` is the one to alert on.** It means the model cited event ids
/// that were not in the window it was shown, which is the failure this whole
/// feature exists to make impossible to act on. A rising `uncited` rate is a
/// prompt-quality signal instead: the model is writing confident prose without
/// grounding it.
pub const GROUNDING_REJECTED_TOTAL: &str = "copilot_grounding_rejected_total";

/// Histogram: share of a landed narrative's claims that carry a citation.
///
/// Recorded for every checked draft, passing or not, so the threshold can be
/// tuned against the distribution rather than against the rejections it
/// already produced (a sample of only the failures cannot tell you where the
/// line should be).
pub const GROUNDING_CITED_RATIO: &str = "copilot_grounding_cited_ratio";

pub fn record_grounding(
    summary: &crate::grounding::GroundingSummary,
    rejected: Option<&'static str>,
) {
    metrics::histogram!(GROUNDING_CITED_RATIO).record(summary.cited_ratio());
    if let Some(reason) = rejected {
        metrics::counter!(GROUNDING_REJECTED_TOTAL, "reason" => reason).increment(1);
    }
}

/// Counter (labeled by `reason`): rule drafts refused by §9's parse boundary —
/// `malformed` (not a rule document), `invalid` (§9 rejected it) or
/// `uncompilable` (the compiler did).
///
/// This is the rule-shaped twin of [`GROUNDING_REJECTED_TOTAL`], and it is a
/// *health* signal rather than an incident one: every count here is the safety
/// mechanism working — a hallucinated rule that could never run. Alert on the
/// rate relative to `copilot_drafts_finished_total{kind="rule_draft"}`, because
/// a rising share means the prompt or the schema has drifted from §9's
/// vocabulary and customers are paying for drafts they cannot activate.
pub const RULE_DRAFTS_REJECTED_TOTAL: &str = "copilot_rule_drafts_rejected_total";

/// Record one rule draft's landing. `None` means it compiled.
pub fn record_rule_draft(rejected: Option<&'static str>) {
    if let Some(reason) = rejected {
        metrics::counter!(RULE_DRAFTS_REJECTED_TOTAL, "reason" => reason).increment(1);
    }
}

/// Counter (labeled by `outcome`): drafts landed by the Batch API backfill —
/// the same `answered`/`errored`/`canceled`/`expired` vocabulary the seam
/// reports, plus `orphaned` for a result whose draft had moved on.
pub const BACKFILL_LANDED_TOTAL: &str = "copilot_backfill_landed_total";

/// Counter: incidents the backfill enqueued (labeled `outcome`: `queued` or
/// `duplicate` — a re-run over an overlapping window is normal and cheap,
/// because the enqueue is idempotent).
pub const BACKFILL_ENQUEUED_TOTAL: &str = "copilot_backfill_enqueued_total";

/// Counter: drafts a batch ended without accounting for — released back to
/// the queue so the drain can close the batch.
///
/// **Alert on any non-zero rate.** It means the provider returned a results
/// stream this build could not match to the drafts it submitted, which is
/// either a wire-format drift or a bug in how `custom_id`s are minted.
pub const BACKFILL_STRAGGLERS_TOTAL: &str = "copilot_backfill_stragglers_total";

pub fn record_backfill_stragglers(count: u64) {
    if count > 0 {
        metrics::counter!(BACKFILL_STRAGGLERS_TOTAL).increment(count);
    }
}

pub fn record_backfill_landed(outcome: &'static str) {
    metrics::counter!(BACKFILL_LANDED_TOTAL, "outcome" => outcome).increment(1);
}

pub fn record_backfill_enqueued(outcome: &'static str) {
    metrics::counter!(BACKFILL_ENQUEUED_TOTAL, "outcome" => outcome).increment(1);
}

/// Counter (labeled by `verdict`): human review decisions (§20.4 — the
/// approval boundary a draft must cross before it leaves the platform).
/// `approve`/`reject`, which together are the only way a draft ever becomes
/// usable.
pub const REVIEWS_TOTAL: &str = "copilot_reviews_total";

pub fn record_review(verdict: &'static str) {
    metrics::counter!(REVIEWS_TOTAL, "verdict" => verdict).increment(1);
}
