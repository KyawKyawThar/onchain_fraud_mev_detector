//! Call-side metrics for the LLM seam (§19, §20.4).
//!
//! One function, [`record_completion`], called from exactly one place —
//! [`crate::MeteredClient`] — so the numbers cannot drift between backends or
//! between call sites. That is the same single-call-site discipline
//! `inference::metrics::record_inference` follows, and for the same reason: a
//! path that forgot to count itself vanishes from the dashboard with no
//! compile error to catch it.
//!
//! Everything goes through the [`metrics`] facade, a near-free no-op until a
//! binary installs the Prometheus exporter (`telemetry::metrics::init`), so
//! this library and its tests stay exporter-agnostic (conventions §8).
//!
//! # Labels
//!
//! `model`, `purpose`, and one of `stop_reason`/`reason`/`kind` — nothing
//! else. In particular:
//!
//! - **no `customer`.** Per-customer spend is a §13 billing question, answered
//!   from the `UsageRecorded` stream the same decorator publishes, where a
//!   customer id is a *column* and not a time series. A customer label here
//!   would multiply every series in this file by the size of the customer base;
//! - **no refusal `category`.** It is an open set the server controls, and a
//!   new policy category must not be able to spawn series in our Prometheus.
//!   The category is logged instead, at the one place a refusal is observed.

use std::time::Duration;

use crate::client::{LlmError, TokenUsage};

/// Counter: seam calls, labeled `{model, purpose, stop_reason}` on success and
/// `{model, purpose, stop_reason="error"}` on failure — so
/// `sum by (purpose) (rate(...))` is the call rate regardless of outcome, and
/// the `stop_reason` breakdown is the answer-quality view (how much output is
/// truncated, how often the model declines).
pub const CALLS_TOTAL: &str = "llm_calls_total";

/// Counter: failed calls by [`LlmError::reason`]. Separate from
/// [`CALLS_TOTAL`]'s error bucket because an alert wants the *reason* split
/// (sustained `auth` is a paging incident; `rate_limited` is a capacity one).
pub const FAILURES_TOTAL: &str = "llm_call_failures_total";

/// Histogram: wall time of one seam call in seconds, *including* the
/// backend's internal retries — the number a caller's own timeout has to be
/// larger than.
pub const SECONDS: &str = "llm_call_duration_seconds";

/// Counter: tokens, labeled `{model, purpose, kind}` where `kind` is one of
/// `input`/`output`/`cache_write`/`cache_read`.
///
/// The four kinds are four prices, so this is also the cheapest cost signal
/// there is: a PromQL rule multiplying each `kind` by its rate gives spend per
/// purpose without waiting for the billing rollup. Not the billing record
/// itself — that is the `UsageRecorded` stream (§13), which is customer-keyed,
/// exact, and reconcilable; this is the dashboard's view of the same event.
pub const TOKENS_TOTAL: &str = "llm_tokens_total";

/// Counter: retry attempts, labeled `{purpose, reason}` — the reason being the
/// fault that provoked the retry, so a sustained `rate_limited` rate (capacity)
/// is distinguishable from `transport` (network) without reading logs.
///
/// Its single call site is [`crate::RetryingClient`]. It is *not* recorded
/// inside the HTTP backend: retries are a policy decision made one layer up,
/// and counting them where the policy lives is what keeps the two from
/// disagreeing about what an attempt was.
pub const RETRIES_TOTAL: &str = "llm_retries_total";

/// Counter: admission decisions, labeled `{purpose, outcome}` where outcome is
/// `admitted`, `at_capacity` or `spend_ceiling`.
///
/// The shed rate is the signal that the bulkhead is doing something — and, if
/// it is sustained, that the fleet is sized wrong rather than that the provider
/// is slow. Both are invisible without this.
pub const ADMISSION_TOTAL: &str = "llm_admission_total";

/// Counter: calls refused because the circuit breaker was open, labeled
/// `{purpose}`. Refusals are cheap and fast, so they would otherwise look like
/// a healthy, very quick service.
pub const BREAKER_REJECTED_TOTAL: &str = "llm_breaker_rejected_total";

/// Gauge: the breaker's state as `0` closed / `1` half-open / `2` open.
///
/// A gauge because the question a dashboard asks is "is it open *now*", and it
/// is published on every call so the series does not disappear while the
/// breaker is healthy — a missing series and a healthy one must not look the
/// same (the same argument `model_feature_drift` makes for publishing unmoved
/// features).
pub const BREAKER_STATE: &str = "llm_breaker_state";

/// Counter: cache lookups, labeled `{purpose, outcome}` (`hit`/`miss`).
///
/// Deliberately its own family rather than an outcome on [`CALLS_TOTAL`]: a
/// hit is not a call to the provider, and folding it in would make the call
/// rate — the number the provider's rate limit is spent against — wrong.
pub const CACHE_TOTAL: &str = "llm_cache_total";

/// One retry attempt. Single call site: [`crate::RetryingClient`].
pub fn record_retry(purpose: &'static str, reason: &'static str) {
    metrics::counter!(RETRIES_TOTAL, "purpose" => purpose, "reason" => reason).increment(1);
}

/// One admission decision. Single call site: [`crate::AdmittedClient`].
pub fn record_admission(purpose: &'static str, outcome: &'static str) {
    metrics::counter!(ADMISSION_TOTAL, "purpose" => purpose, "outcome" => outcome).increment(1);
}

/// The breaker's verdict for one call. Single call site:
/// [`crate::BreakerClient`]. `rejected` is `true` when the call never
/// happened.
pub fn record_breaker(purpose: &'static str, state: resilience::CircuitState, rejected: bool) {
    metrics::gauge!(BREAKER_STATE).set(match state {
        resilience::CircuitState::Closed => 0.0,
        resilience::CircuitState::HalfOpen => 1.0,
        resilience::CircuitState::Open => 2.0,
    });
    if rejected {
        metrics::counter!(BREAKER_REJECTED_TOTAL, "purpose" => purpose).increment(1);
    }
}

/// One cache lookup. Single call site: [`crate::CachingClient`].
pub fn record_cache(purpose: &'static str, outcome: &'static str) {
    metrics::counter!(CACHE_TOTAL, "purpose" => purpose, "outcome" => outcome).increment(1);
}

/// Record one completed (or failed) call. The single call site is
/// [`crate::MeteredClient`].
///
/// A failure still counts a call and its latency: an under-reported denominator
/// is the failure mode conventions §14 exists to prevent — it makes a service
/// that is failing every request look like one with a flawless success rate.
/// Tokens are only known on success, so a failed call adds nothing to
/// [`TOKENS_TOTAL`]. That is a real (and deliberate) under-count: the API may
/// well have consumed input tokens for a request it then failed, and it does
/// not tell us how many. Reconciliation is against the provider's own usage
/// reporting, not against this counter.
pub fn record_completion(
    model: &str,
    purpose: &'static str,
    elapsed: Duration,
    outcome: Result<(&str, &TokenUsage), &LlmError>,
) {
    let model = model.to_owned();
    let stop_reason = match outcome {
        Ok((stop_reason, _)) => stop_reason.to_owned(),
        Err(_) => "error".to_owned(),
    };

    metrics::counter!(
        CALLS_TOTAL,
        "model" => model.clone(),
        "purpose" => purpose,
        "stop_reason" => stop_reason,
    )
    .increment(1);
    metrics::histogram!(
        SECONDS,
        "model" => model.clone(),
        "purpose" => purpose,
    )
    .record(elapsed.as_secs_f64());

    match outcome {
        Ok((_, usage)) => {
            for (kind, tokens) in token_kinds(usage) {
                if tokens == 0 {
                    continue;
                }
                metrics::counter!(
                    TOKENS_TOTAL,
                    "model" => model.clone(),
                    "purpose" => purpose,
                    "kind" => kind,
                )
                .increment(tokens);
            }
        }
        Err(err) => {
            metrics::counter!(
                FAILURES_TOTAL,
                "model" => model,
                "purpose" => purpose,
                "reason" => err.reason(),
            )
            .increment(1);
        }
    }
}

/// The four billable token kinds of one call, in a fixed order — shared by the
/// metrics above and the `UsageRecorded` facts [`crate::MeteredClient`]
/// publishes, so a `kind` label and a usage SKU can never describe different
/// numbers.
pub(crate) fn token_kinds(usage: &TokenUsage) -> [(&'static str, u64); 4] {
    [
        ("input", usage.input_tokens),
        ("output", usage.output_tokens),
        ("cache_write", usage.cache_creation_input_tokens),
        ("cache_read", usage.cache_read_input_tokens),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_token_kinds_are_the_four_distinct_rates() {
        let usage = TokenUsage {
            input_tokens: 1,
            output_tokens: 2,
            cache_creation_input_tokens: 3,
            cache_read_input_tokens: 4,
        };
        assert_eq!(
            token_kinds(&usage),
            [
                ("input", 1),
                ("output", 2),
                ("cache_write", 3),
                ("cache_read", 4)
            ]
        );
        assert_eq!(
            token_kinds(&usage).iter().map(|(_, n)| n).sum::<u64>(),
            usage.total(),
            "the kinds must account for every token the total claims"
        );
    }
}
