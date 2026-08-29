//! [`RetryingClient`] — the retry *loop*, over the shared retry *policy*.
//!
//! # Why this is a decorator and not a loop inside the HTTP client
//!
//! It was originally written inside `AnthropicClient`, which was wrong for
//! three reasons that only show up later:
//!
//! * a second backend would have had to reimplement it;
//! * the policy could not be exercised against
//!   [`crate::test_util::StubClient`] — the double sits *at* the seam, and the
//!   loop was below it, so the one component whose whole job is "fail twice,
//!   then succeed" could not be pointed at the retry logic;
//! * and it put the loop below the breaker and the bulkhead, so a retry storm
//!   would have re-entered the provider without passing either.
//!
//! As a decorator it composes: retries sit *outside* [`crate::BreakerClient`],
//! so every attempt consults the breaker (an open circuit short-circuits the
//! whole loop instantly) and every attempt feeds the breaker's failure
//! signal — and *outside* [`crate::AdmittedClient`], so a permit is held for
//! the HTTP call and released during the backoff sleep instead of being
//! occupied by a sleeping task.
//!
//! # Two clocks
//!
//! This loop rides out a blip on a seconds clock. It deliberately does not
//! retry [`LlmError::retry_now`]-false failures — a shed call, an open
//! breaker, a 400 — because whatever caused them is still true in 200ms, and
//! spending the attempt budget on them only delays the honest failure. Those
//! come back classified *transient* so the job queue above re-runs the work on
//! its own minutes-to-hours clock. `resilience::Backoff` enforces the same
//! split for a `retry-after` longer than this process will hold a worker.

use resilience::{Backoff, RetryDecision};
use tokio_util::sync::CancellationToken;

use crate::client::{Completion, CompletionRequest, LlmClient, LlmError};
use crate::metrics::record_retry;

/// Wraps any [`LlmClient`] in a bounded, jittered retry loop.
#[derive(Debug)]
pub struct RetryingClient<C> {
    inner: C,
    backoff: Backoff,
    shutdown: CancellationToken,
}

impl<C: LlmClient> RetryingClient<C> {
    /// `shutdown` cancels an in-flight backoff, so a SIGTERM during a
    /// rate-limit wait exits promptly instead of sleeping out the drain
    /// window.
    pub fn new(inner: C, backoff: Backoff, shutdown: CancellationToken) -> Self {
        Self {
            inner,
            backoff,
            shutdown,
        }
    }

    pub fn inner(&self) -> &C {
        &self.inner
    }
}

#[async_trait::async_trait]
impl<C: LlmClient> LlmClient for RetryingClient<C> {
    fn model(&self) -> &str {
        self.inner.model()
    }

    async fn complete(&self, request: &CompletionRequest) -> Result<Completion, LlmError> {
        let mut attempt = 1_u32;
        loop {
            let err = match self.inner.complete(request).await {
                Ok(completion) => return Ok(completion),
                Err(err) => err,
            };

            // Not worth another attempt *now* — a bad request, a rejected
            // credential, a shed call, an open breaker.
            if !err.retry_now() {
                return Err(self.finish(attempt, err));
            }

            match self.backoff.decide(attempt, err.retry_after()) {
                RetryDecision::GiveUp => return Err(self.finish(attempt, err)),
                RetryDecision::Wait(delay) => {
                    record_retry(request.purpose, err.reason());
                    tracing::warn!(
                        attempt,
                        purpose = request.purpose,
                        wait_ms = delay.as_millis() as u64,
                        error = %err,
                        "llm call failed transiently; backing off"
                    );
                    tokio::select! {
                        biased;
                        () = self.shutdown.cancelled() => return Err(self.finish(attempt, err)),
                        () = tokio::time::sleep(delay) => {}
                    }
                    attempt += 1;
                }
            }
        }
    }
}

impl<C> RetryingClient<C> {
    /// Report the outcome. A failure on the *first* attempt is returned as
    /// itself — wrapping it would add a layer of "after 1 attempt(s)" noise to
    /// every 400 in the logs. Anything later is wrapped, so the log says how
    /// much was spent before giving up.
    fn finish(&self, attempt: u32, err: LlmError) -> LlmError {
        if attempt <= 1 {
            err
        } else {
            LlmError::Exhausted {
                attempts: attempt,
                last: Box::new(err),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::TokenUsage;
    use crate::test_util::StubClient;
    use event_bus::Transience;
    use std::time::Duration;

    fn backoff(attempts: u32) -> Backoff {
        Backoff::new(
            Duration::from_millis(1),
            Duration::from_millis(4),
            Duration::from_secs(30),
            attempts,
        )
    }

    fn retrying(inner: StubClient, attempts: u32) -> RetryingClient<StubClient> {
        RetryingClient::new(inner, backoff(attempts), CancellationToken::new())
    }

    /// The case the decorator exists for — and the case that could not be
    /// written at all while the loop lived inside the HTTP backend.
    #[tokio::test]
    async fn a_transient_blip_is_ridden_out() {
        let client = retrying(
            StubClient::failing_then_answering(
                2,
                || LlmError::Unavailable {
                    status: 503,
                    reason: "overloaded".into(),
                },
                "the draft",
            ),
            4,
        );

        let completion = client
            .complete(&CompletionRequest::new("narrative", "go"))
            .await
            .expect("the third attempt succeeds");
        assert_eq!(completion.text, "the draft");
        assert_eq!(client.inner().call_count(), 3);
    }

    #[tokio::test]
    async fn the_budget_is_bounded_and_the_last_error_survives() {
        let client = retrying(
            StubClient::failing(|| LlmError::Transport {
                reason: "connection reset".into(),
            }),
            3,
        );

        let err = client
            .complete(&CompletionRequest::new("narrative", "go"))
            .await
            .expect_err("never succeeds");
        assert_eq!(client.inner().call_count(), 3, "3 attempts, not 3 retries");
        match err {
            LlmError::Exhausted { attempts, last } => {
                assert_eq!(attempts, 3);
                assert_eq!(last.reason(), "transport");
            }
            other => panic!("expected exhaustion, got {other}"),
        }
    }

    /// A 400 is our bug: retrying it burns the budget and the rate limit for a
    /// result that cannot change.
    #[tokio::test]
    async fn a_permanent_failure_is_not_retried_and_is_not_wrapped() {
        let client = retrying(
            StubClient::failing(|| LlmError::Invalid {
                status: 400,
                reason: "bad schema".into(),
            }),
            5,
        );

        let err = client
            .complete(&CompletionRequest::new("rule_draft", "go"))
            .await
            .expect_err("permanent");
        assert_eq!(client.inner().call_count(), 1);
        assert!(matches!(err, LlmError::Invalid { .. }), "{err}");
        assert!(!err.is_transient());
    }

    /// The `retry_now` split: a shed call is transient for the queue above but
    /// must not be retried here — the ceiling it hit is still there.
    #[tokio::test]
    async fn a_shed_call_is_not_retried_but_stays_transient() {
        let client = retrying(
            StubClient::failing(|| LlmError::Shed {
                reason: "at_capacity",
            }),
            5,
        );

        let err = client
            .complete(&CompletionRequest::new("backfill", "go"))
            .await
            .expect_err("shed");
        assert_eq!(
            client.inner().call_count(),
            1,
            "no retry into our own bulkhead"
        );
        assert!(
            err.is_transient(),
            "the queue above should re-run this later"
        );
    }

    /// The finding this policy was written for: an hour-long `retry-after`
    /// must hand back rather than park the worker.
    #[tokio::test]
    async fn a_retry_after_past_the_cap_gives_up_immediately() {
        let client = retrying(
            StubClient::failing(|| LlmError::RateLimited {
                retry_after: Some(Duration::from_secs(3_600)),
            }),
            5,
        );

        let started = std::time::Instant::now();
        let err = client
            .complete(&CompletionRequest::new("narrative", "go"))
            .await
            .expect_err("capped");
        assert!(started.elapsed() < Duration::from_secs(1), "slept the hour");
        assert_eq!(client.inner().call_count(), 1);
        assert!(err.is_transient(), "still the queue's job to re-run");
    }

    #[tokio::test]
    async fn shutdown_cuts_the_backoff_short() {
        let shutdown = CancellationToken::new();
        let client = RetryingClient::new(
            StubClient::failing(|| LlmError::Transport {
                reason: "reset".into(),
            }),
            Backoff::new(
                Duration::from_secs(3_600),
                Duration::from_secs(3_600),
                Duration::from_secs(3_600),
                5,
            ),
            shutdown.clone(),
        );
        shutdown.cancel();

        let started = std::time::Instant::now();
        client
            .complete(&CompletionRequest::new("narrative", "go"))
            .await
            .expect_err("cancelled");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_refusal_is_a_success_and_is_never_retried() {
        let client = retrying(
            StubClient::answering("")
                .with_stop_reason(crate::StopReason::Refusal { category: None })
                .with_usage(TokenUsage {
                    input_tokens: 10,
                    ..TokenUsage::default()
                }),
            5,
        );

        let completion = client
            .complete(&CompletionRequest::new("narrative", "go"))
            .await
            .expect("a refusal returns Ok");
        assert!(!completion.stop_reason.is_complete());
        assert_eq!(client.inner().call_count(), 1);
    }
}
