//! [`BreakerClient`] — stop calling a provider that is already failing.
//!
//! Without it, a provider outage costs a full attempt budget × a full timeout
//! *per job*: with the defaults here that is three attempts of up to five
//! minutes each, so a worker spends a quarter of an hour discovering something
//! the previous nine jobs already knew. Multiply by the fleet and the outage
//! becomes a self-inflicted queue backlog that outlives the outage itself.
//!
//! The state machine is `resilience::CircuitBreaker` — the same one §5's RPC
//! endpoint pool uses, promoted to a shared crate rather than copied, because
//! a second hand-rolled breaker is exactly the drift the `db::redis` rule
//! exists to prevent.
//!
//! # What counts as a failure
//!
//! Only faults that mean *the provider is unwell*:
//!
//! | Outcome | Trips the breaker? | Why |
//! |---|---|---|
//! | `Transport`, `Unavailable` (5xx) | **yes** | the dependency is down or sick |
//! | `RateLimited` (429) | no | we are too fast; that is admission control's job, and opening here would convert a capacity signal into an outage |
//! | `Auth`, `Invalid`, `Decode` | no | our bug or our config — the provider is answering correctly, and a breaker would flap forever without fixing it |
//! | `Shed`, `CircuitOpen` | n/a | the call never reached the provider |
//! | any `Ok`, **including a refusal** | success | the provider answered |
//!
//! Getting the 429 row wrong is the classic mistake: rate limits are the most
//! frequent "failure" a healthy integration sees, so counting them would leave
//! the breaker open most of the time under normal load.
//!
//! An [`LlmError::Exhausted`] is classified by its cause — `reason()` already
//! unwraps — so a retry loop that spent itself on transport faults reports one
//! failure to the breaker, not zero.

use std::time::Instant;

use resilience::{BreakerConfig, CircuitBreaker};

use crate::client::{Completion, CompletionRequest, LlmClient, LlmError};
use crate::metrics::record_breaker;

/// Wraps any [`LlmClient`] in a circuit breaker.
#[derive(Debug)]
pub struct BreakerClient<C> {
    inner: C,
    breaker: CircuitBreaker,
}

impl<C: LlmClient> BreakerClient<C> {
    pub fn new(inner: C, config: BreakerConfig) -> Self {
        Self {
            inner,
            breaker: CircuitBreaker::new(config),
        }
    }

    pub fn inner(&self) -> &C {
        &self.inner
    }

    /// The breaker's state right now — for a health endpoint, and for tests.
    pub fn state(&self) -> resilience::CircuitState {
        self.breaker.state(Instant::now())
    }
}

/// Whether a failure means the *provider* is unwell. See the module docs for
/// the whole table, and in particular why a 429 is not on this list.
fn indicates_provider_fault(err: &LlmError) -> bool {
    matches!(err.reason(), "transport" | "unavailable")
}

#[async_trait::async_trait]
impl<C: LlmClient> LlmClient for BreakerClient<C> {
    fn model(&self) -> &str {
        self.inner.model()
    }

    async fn complete(&self, request: &CompletionRequest) -> Result<Completion, LlmError> {
        // `allows` also performs the open→half-open transition once the
        // cooldown elapses, so the next call after a cooldown *is* the trial.
        if !self.breaker.allows(Instant::now()) {
            record_breaker(request.purpose, self.state(), true);
            return Err(LlmError::CircuitOpen);
        }

        let outcome = self.inner.complete(request).await;
        match &outcome {
            // The provider answered. A refusal is an answer.
            Ok(_) => self.breaker.on_success(),
            Err(err) if indicates_provider_fault(err) => self.breaker.on_failure(Instant::now()),
            // Our bug, our config, or our own bulkhead — none of which the
            // provider can fix by being rested.
            Err(_) => {}
        }
        record_breaker(request.purpose, self.state(), false);
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::StubClient;
    use resilience::CircuitState;
    use std::time::Duration;

    fn config() -> BreakerConfig {
        BreakerConfig {
            failure_threshold: 2,
            open_cooldown: Duration::from_millis(20),
            success_threshold: 1,
        }
    }

    fn request() -> CompletionRequest {
        CompletionRequest::new("narrative", "go")
    }

    #[tokio::test]
    async fn consecutive_provider_faults_open_the_circuit_and_stop_the_calls() {
        let client = BreakerClient::new(
            StubClient::failing(|| LlmError::Unavailable {
                status: 503,
                reason: "overloaded".into(),
            }),
            config(),
        );

        client.complete(&request()).await.expect_err("1");
        client.complete(&request()).await.expect_err("2 — trips");
        assert_eq!(client.state(), CircuitState::Open);

        let err = client.complete(&request()).await.expect_err("refused");
        assert!(matches!(err, LlmError::CircuitOpen), "{err}");
        assert_eq!(
            client.inner().call_count(),
            2,
            "the third call must never reach the provider"
        );
    }

    /// The row that is easiest to get wrong: rate limits are the most common
    /// "failure" a healthy integration sees, so tripping on them would leave
    /// the breaker open under perfectly normal load.
    #[tokio::test]
    async fn rate_limits_do_not_open_the_circuit() {
        let client = BreakerClient::new(
            StubClient::failing(|| LlmError::RateLimited { retry_after: None }),
            config(),
        );

        for _ in 0..10 {
            client.complete(&request()).await.expect_err("429");
        }
        assert_eq!(client.state(), CircuitState::Closed);
        assert_eq!(client.inner().call_count(), 10);
    }

    /// A wrong API key would otherwise flap the breaker forever while fixing
    /// nothing — it is a config error, not a sick dependency.
    #[tokio::test]
    async fn our_own_errors_do_not_open_the_circuit() {
        for make in [
            || LlmError::Auth {
                reason: "invalid x-api-key".into(),
            },
            || LlmError::Invalid {
                status: 400,
                reason: "bad schema".into(),
            },
        ] {
            let client = BreakerClient::new(StubClient::failing(make), config());
            for _ in 0..5 {
                client.complete(&request()).await.expect_err("ours");
            }
            assert_eq!(client.state(), CircuitState::Closed);
        }
    }

    #[tokio::test]
    async fn the_circuit_probes_back_to_closed_after_the_cooldown() {
        let client = BreakerClient::new(
            StubClient::failing_then_answering(
                2,
                || LlmError::Transport {
                    reason: "reset".into(),
                },
                "recovered",
            ),
            config(),
        );

        client.complete(&request()).await.expect_err("1");
        client.complete(&request()).await.expect_err("2 — trips");
        assert!(client.complete(&request()).await.is_err(), "open");

        tokio::time::sleep(Duration::from_millis(30)).await;
        // The cooldown has elapsed: this call is the half-open trial, and the
        // stub has moved on to answering.
        let completion = client.complete(&request()).await.expect("trial succeeds");
        assert_eq!(completion.text, "recovered");
        assert_eq!(client.state(), CircuitState::Closed);
    }

    /// A refusal is the provider working correctly, so it must reset the
    /// failure run rather than counting toward a trip.
    #[tokio::test]
    async fn a_refusal_counts_as_the_provider_answering() {
        let client = BreakerClient::new(
            StubClient::answering("").with_stop_reason(crate::StopReason::Refusal {
                category: Some("cyber".into()),
            }),
            config(),
        );
        for _ in 0..5 {
            client.complete(&request()).await.expect("Ok");
        }
        assert_eq!(client.state(), CircuitState::Closed);
    }

    /// A spent retry loop reports one provider fault, not none — otherwise a
    /// breaker sitting above a retry decorator would never see anything.
    #[tokio::test]
    async fn an_exhausted_retry_is_classified_by_its_cause() {
        let client = BreakerClient::new(
            StubClient::failing(|| LlmError::Exhausted {
                attempts: 3,
                last: Box::new(LlmError::Transport {
                    reason: "reset".into(),
                }),
            }),
            config(),
        );
        client.complete(&request()).await.expect_err("1");
        client.complete(&request()).await.expect_err("2 — trips");
        assert_eq!(client.state(), CircuitState::Open);
    }
}
