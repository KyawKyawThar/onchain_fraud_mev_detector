//! The composition root: one place that knows the **order** of the decorator
//! stack, and why.
//!
//! Every layer in this crate is an [`LlmClient`] wrapping an [`LlmClient`],
//! which makes them freely composable — and that is exactly the danger. Four
//! decorators have 24 orderings; most compile, several are subtly wrong, and
//! none of the wrong ones fail a test that isn't looking for them. A backfill
//! that bills twice for cache hits, or a bulkhead permit held through a
//! ten-minute backoff, is not a crash. It is a slightly worse invoice and a
//! slightly slower fleet, discovered a quarter later.
//!
//! So the order is not a call-site decision. [`LlmStack::build`] is the only
//! supported way to assemble a client, and this module is where the reasoning
//! lives:
//!
//! ```text
//! CachingClient        ─ a hit costs nothing: no permit, no breaker signal,
//!   │                    no provider call, no token bill
//!   MeteredClient      ─ one bill + one latency observation per logical call
//!     │                  (latency therefore includes retries, which is the
//!     │                  number a caller's own timeout must exceed)
//!     RetryingClient   ─ bounded, jittered, `retry-after` capped
//!       │
//!       BreakerClient  ─ consulted on *every* attempt, so an open circuit
//!         │              short-circuits the whole retry loop instantly, and
//!         │              every attempt feeds its failure signal
//!         AdmittedClient ─ a permit covers the HTTP call only, and is
//!           │              released while the retry above sleeps
//!           AnthropicClient ─ one request, one response
//! ```
//!
//! The four placements that matter, each with the bug it prevents:
//!
//! * **Cache outermost.** A hit must not consume an admission permit, must not
//!   be billed as a zero-token call, and must not appear in the call rate the
//!   provider's rate limit is spent against. Below the meter it would corrupt
//!   all three.
//! * **Meter above retry.** Metering is per *logical* call: three attempts of
//!   one draft are one bill and one latency sample, not three. Below the retry
//!   loop, a flaky hour would look like three times the traffic.
//! * **Retry above the breaker.** An open circuit must abort the loop rather
//!   than being re-consulted after each sleep, and each attempt must count
//!   toward the breaker's verdict. Inverted, a retry loop hammers straight past
//!   an open circuit.
//! * **Admission innermost.** A permit represents *an in-flight provider call*.
//!   Held across a backoff sleep it would represent a sleeping task instead, and
//!   the bulkhead would throttle on waiting rather than on work.
//!
//! # What is deliberately not in the stack
//!
//! No layer here makes the call *durable*. If the process dies mid-completion
//! the work is lost, and re-running it is the job queue's business. That is a
//! constraint on the service above (see [`crate`] docs): the model must not be
//! called from inside a message-consumer callback, because a multi-minute
//! handler stalls the consumer's partition and turns a slow provider into a
//! rebalance loop that re-does — and re-bills — the work.

use std::sync::Arc;
use std::time::Duration;

use event_bus::EventSink;
use events::primitives::Chain;
use resilience::{Backoff, BreakerConfig};
use tokio_util::sync::CancellationToken;

use crate::admission::{AdmittedClient, CallAdmission, LocalAdmission, UnlimitedAdmission};
use crate::anthropic::AnthropicClient;
use crate::breaker::BreakerClient;
use crate::cache::{CachingClient, CompletionCache, InMemoryCache, NoCache};
use crate::client::LlmClient;
use crate::config::LlmConfig;
use crate::metered::MeteredClient;
use crate::retry::RetryingClient;

/// Assembles the decorator stack. Build it once at boot and hand the process
/// the resulting `Arc<dyn LlmClient>`.
pub struct LlmStack {
    config: LlmConfig,
    sink: Arc<dyn EventSink>,
    chain: Chain,
    shutdown: CancellationToken,
    admission: Option<Arc<dyn CallAdmission>>,
    cache: Option<Arc<dyn CompletionCache>>,
    usage_backoff: Duration,
}

impl LlmStack {
    /// Start from a config, the metering sink, the deployment's chain stamp and
    /// the shutdown token.
    ///
    /// Admission and cache default to the in-process implementations sized by
    /// `config`; override either with a store-backed one
    /// ([`with_admission`](Self::with_admission) /
    /// [`with_cache`](Self::with_cache)) from a service crate that is allowed a
    /// store edge.
    pub fn new(
        config: LlmConfig,
        sink: Arc<dyn EventSink>,
        chain: Chain,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            config,
            sink,
            chain,
            shutdown,
            admission: None,
            cache: None,
            usage_backoff: Duration::from_secs(1),
        }
    }

    /// Use a shared, org-wide admission policy instead of the per-process one.
    ///
    /// This is the override that matters at scale: a per-pod semaphore cannot
    /// express a provider limit that applies to the whole organisation (see
    /// [`crate::admission`]).
    pub fn with_admission(mut self, admission: Arc<dyn CallAdmission>) -> Self {
        self.admission = Some(admission);
        self
    }

    /// Use a durable, cross-pod cache instead of the process-local one — for
    /// the copilot, its drafts table keyed by request digest.
    pub fn with_cache(mut self, cache: Arc<dyn CompletionCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Backoff between retries of a transiently-failed `UsageRecorded` publish.
    pub fn with_usage_backoff(mut self, backoff: Duration) -> Self {
        self.usage_backoff = backoff;
        self
    }

    /// The admission policy this stack will use — resolved here so a boot log
    /// can report it before [`build`](Self::build) consumes the builder.
    fn resolve_admission(&self) -> Arc<dyn CallAdmission> {
        if let Some(admission) = &self.admission {
            return admission.clone();
        }
        if self.config.admission.max_in_flight == 0 {
            Arc::new(UnlimitedAdmission)
        } else {
            Arc::new(LocalAdmission::new(self.config.admission))
        }
    }

    fn resolve_cache(&self) -> Arc<dyn CompletionCache> {
        if let Some(cache) = &self.cache {
            return cache.clone();
        }
        if self.config.cache_capacity == 0 {
            Arc::new(NoCache)
        } else {
            Arc::new(InMemoryCache::new(
                self.config.cache_capacity,
                self.config.cache_ttl,
            ))
        }
    }

    /// Assemble the stack in the one supported order.
    pub fn build(self) -> Result<Arc<dyn LlmClient>, reqwest::Error> {
        let admission = self.resolve_admission();
        let cache = self.resolve_cache();
        let backoff = Backoff::new(
            self.config.retry_backoff,
            self.config.retry_backoff_max,
            self.config.retry_after_cap,
            self.config.max_attempts,
        );
        let breaker = BreakerConfig {
            failure_threshold: self.config.breaker_failure_threshold,
            open_cooldown: self.config.breaker_open_cooldown,
            success_threshold: 1,
        };

        tracing::info!(
            model = %self.config.model,
            max_in_flight = self.config.admission.max_in_flight,
            spend_ceiling = self.config.admission.spend_ceiling,
            attempts = self.config.max_attempts,
            retry_after_cap_secs = self.config.retry_after_cap.as_secs(),
            breaker_threshold = self.config.breaker_failure_threshold,
            cache_capacity = self.config.cache_capacity,
            fallbacks = self.config.fallbacks,
            "llm stack assembled"
        );

        let transport = AnthropicClient::new(self.config)?;
        Ok(Arc::new(CachingClient::new(
            MeteredClient::new(
                RetryingClient::new(
                    BreakerClient::new(AdmittedClient::new(transport, admission), breaker),
                    backoff,
                    self.shutdown.clone(),
                ),
                self.sink,
                self.chain,
                self.usage_backoff,
                self.shutdown,
            ),
            cache,
        )))
    }

    /// Assemble the stack and verify the credential and model at boot.
    ///
    /// Prefer this in a binary: a wrong `ANTHROPIC_API_KEY` or a model this
    /// organisation cannot reach becomes a refused rollout instead of a
    /// surprise on the first incident of the day. The check costs no tokens
    /// (`GET /v1/models/{id}`).
    ///
    /// The verification runs against a *bare* client rather than through the
    /// stack: it is a config check, and routing it through the breaker and the
    /// bulkhead would let a boot probe trip a circuit that has no traffic yet.
    pub async fn build_verified(self) -> anyhow::Result<Arc<dyn LlmClient>> {
        AnthropicClient::new(self.config.clone())?
            .verify_credentials()
            .await?;
        Ok(self.build()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{Admission, AdmissionConfig, Denied};
    use crate::cache::CacheKey;
    use crate::client::{CompletionRequest, TokenUsage};
    use crate::test_util::StubClient;
    use crate::{LlmError, StopReason};
    use event_bus::test_util::RecordingSink;
    use events::DomainEvent;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::CompositeKey;
    use std::sync::Mutex;

    type Series = Vec<(
        CompositeKey,
        Option<::metrics::Unit>,
        Option<::metrics::SharedString>,
        DebugValue,
    )>;

    /// The stack, but over a scripted double instead of the HTTP backend — so
    /// the *ordering* properties can be asserted without a provider.
    fn stack_over(
        inner: StubClient,
        admission: Arc<dyn CallAdmission>,
        cache: Arc<dyn CompletionCache>,
        sink: Arc<RecordingSink>,
    ) -> impl LlmClient {
        let shutdown = CancellationToken::new();
        CachingClient::new(
            MeteredClient::new(
                RetryingClient::new(
                    BreakerClient::new(
                        AdmittedClient::new(inner, admission),
                        BreakerConfig::default(),
                    ),
                    Backoff::new(
                        Duration::from_millis(1),
                        Duration::from_millis(2),
                        Duration::from_secs(30),
                        3,
                    ),
                    shutdown.clone(),
                ),
                sink,
                Chain::ETHEREUM,
                Duration::from_millis(1),
                shutdown,
            ),
            cache,
        )
    }

    fn usage_facts(sink: &RecordingSink) -> usize {
        sink.events()
            .into_iter()
            .filter(|e| matches!(e, DomainEvent::UsageRecorded(_)))
            .count()
    }

    /// **Cache outermost.** The second identical call must not reach the
    /// provider, must not be billed, and must not consume a permit.
    #[tokio::test]
    async fn a_cache_hit_costs_nothing_anywhere_in_the_stack() {
        let sink = Arc::new(RecordingSink::default());
        let admission = Arc::new(CountingAdmission::default());
        let inner = StubClient::answering("the draft").with_usage(TokenUsage {
            input_tokens: 100,
            output_tokens: 50,
            ..TokenUsage::default()
        });
        let client = stack_over(
            inner,
            admission.clone(),
            Arc::new(InMemoryCache::new(16, Duration::from_secs(60))),
            sink.clone(),
        );

        let request = CompletionRequest::new("narrative", "incident 7");
        assert_eq!(client.complete(&request).await.unwrap().text, "the draft");
        assert_eq!(client.complete(&request).await.unwrap().text, "the draft");

        assert_eq!(admission.admitted(), 1, "a hit must not take a permit");
        assert_eq!(
            usage_facts(&sink),
            2,
            "one call, two token kinds — the hit bills nothing"
        );
    }

    /// **Meter above retry.** Three attempts of one draft are one bill, not
    /// three — but the provider really was called three times.
    /// A plain `#[test]` with its own current-thread runtime, not a
    /// `#[tokio::test]`: `with_local_recorder` installs the recorder on *this*
    /// thread, so the future has to be driven here too.
    #[test]
    fn retries_are_one_logical_call_for_metering() {
        let sink = Arc::new(RecordingSink::default());
        let admission = Arc::new(CountingAdmission::default());
        let inner = StubClient::failing_then_answering(
            2,
            || LlmError::Unavailable {
                status: 503,
                reason: "overloaded".into(),
            },
            "recovered",
        )
        .with_usage(TokenUsage {
            input_tokens: 10,
            ..TokenUsage::default()
        });

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let client = stack_over(inner, admission.clone(), Arc::new(NoCache), sink.clone());

        ::metrics::with_local_recorder(&recorder, || {
            runtime.block_on(async {
                client
                    .complete(&CompletionRequest::new("narrative", "go"))
                    .await
                    .expect("the third attempt succeeds");
            });
        });
        let series: Series = snapshotter.snapshot().into_vec();

        let calls = match series
            .iter()
            .find(|(k, _, _, _)| k.key().name() == crate::metrics::CALLS_TOTAL)
            .map(|entry| &entry.3)
        {
            Some(DebugValue::Counter(n)) => Some(*n),
            _ => None,
        };
        assert_eq!(calls, Some(1), "one logical call, not one per attempt");
        assert_eq!(usage_facts(&sink), 1, "one bill");
        assert_eq!(admission.admitted(), 3, "three real provider attempts");
    }

    /// **Admission innermost.** A shed call must be shed *before* any provider
    /// attempt, and the retry loop must not hammer our own bulkhead.
    #[tokio::test]
    async fn a_shed_call_never_reaches_the_provider_and_is_not_retried() {
        let sink = Arc::new(RecordingSink::default());
        let admission = Arc::new(CountingAdmission {
            refuse: true.into(),
            ..CountingAdmission::default()
        });
        let inner = StubClient::answering("never reached");
        let client = stack_over(inner, admission.clone(), Arc::new(NoCache), sink.clone());

        let err = client
            .complete(&CompletionRequest::new("backfill", "go"))
            .await
            .expect_err("shed");
        assert!(matches!(err, LlmError::Shed { .. }), "{err}");
        assert_eq!(admission.attempts(), 1, "no retry into our own bulkhead");
        assert_eq!(usage_facts(&sink), 0);
    }

    /// A failure that was never cached must be retried on the next delivery —
    /// caching a failure would make a transient outage permanent.
    #[tokio::test]
    async fn a_failure_is_not_cached() {
        let sink = Arc::new(RecordingSink::default());
        let cache = Arc::new(InMemoryCache::new(16, Duration::from_secs(60)));
        let client = stack_over(
            StubClient::failing(|| LlmError::Invalid {
                status: 400,
                reason: "bad schema".into(),
            }),
            Arc::new(UnlimitedAdmission),
            cache.clone(),
            sink,
        );

        client
            .complete(&CompletionRequest::new("rule_draft", "go"))
            .await
            .expect_err("400");
        assert!(cache.is_empty(), "a failure must not be memoised");
    }

    /// A refusal *is* cached: it will refuse again, and a redelivery loop
    /// should not pay for the same decline repeatedly.
    #[tokio::test]
    async fn a_refusal_is_cached() {
        let sink = Arc::new(RecordingSink::default());
        let cache = Arc::new(InMemoryCache::new(16, Duration::from_secs(60)));
        let admission = Arc::new(CountingAdmission::default());
        let client = stack_over(
            StubClient::answering("").with_stop_reason(StopReason::Refusal { category: None }),
            admission.clone(),
            cache.clone(),
            sink,
        );

        let request = CompletionRequest::new("narrative", "go");
        client.complete(&request).await.expect("Ok");
        client.complete(&request).await.expect("served from cache");
        assert_eq!(admission.admitted(), 1);
    }

    /// An admission double that counts what reached it.
    #[derive(Debug, Default)]
    struct CountingAdmission {
        refuse: std::sync::atomic::AtomicBool,
        attempts: std::sync::atomic::AtomicUsize,
        admitted: std::sync::atomic::AtomicUsize,
        usage: Mutex<Vec<u64>>,
    }

    impl CountingAdmission {
        fn attempts(&self) -> usize {
            self.attempts.load(std::sync::atomic::Ordering::Relaxed)
        }

        fn admitted(&self) -> usize {
            self.admitted.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    impl CallAdmission for CountingAdmission {
        fn try_admit(&self, _purpose: &'static str) -> Result<Admission, Denied> {
            self.attempts
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if self.refuse.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(Denied::AtCapacity);
            }
            self.admitted
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(Admission::granted())
        }

        fn record_usage(&self, _purpose: &'static str, usage: &TokenUsage) {
            self.usage.lock().unwrap().push(usage.total());
        }
    }

    /// A sanity check that the default sizing is conservative — this is a
    /// *per-pod* number multiplied by the replica count against an org-wide
    /// provider limit, so a large default here is a fleet-wide 429 storm.
    #[test]
    fn the_default_in_flight_ceiling_is_conservative() {
        assert!(AdmissionConfig::default().max_in_flight <= 8);
    }

    /// Cache keys are what the stack dedups on; if this ever stopped including
    /// the model, a fallback would serve the wrong model's answer.
    #[test]
    fn the_cache_key_pins_the_model() {
        let request = CompletionRequest::new("narrative", "go");
        assert_ne!(
            CacheKey::new("claude-opus-5", &request),
            CacheKey::new("claude-opus-4-8", &request)
        );
    }
}
