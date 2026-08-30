//! [`MeteredClient`] — the one place an LLM call is measured (§19) and metered
//! (§13).
//!
//! Conventions §14 asks for a thin observed outer around an inner that owns
//! the logic. Here — as with `inference::ObservedEngine` — that outer is a
//! **decorator over the seam**, which is strictly stronger for the same cost:
//!
//! - it meters *any* backend, so a second one can't ship unbilled;
//! - it meters the test double too, so the copilot's tests can assert on the
//!   `UsageRecorded` facts a real call would emit;
//! - it can't miss a call path — [`LlmClient::complete`] is the only one;
//! - and it keeps `AnthropicClient` about HTTP and nothing else.
//!
//! Its place in the stack is fixed by [`crate::stack`]: **above** the retry
//! loop, so three attempts of one draft are one bill and one latency sample
//! rather than three, and **below** the cache, so a hit is not billed as a
//! zero-token call. Assemble it through [`crate::LlmStack`] rather than by
//! hand.
//!
//! Wrapping is not idempotent — a nested `MeteredClient<MeteredClient<_>>`
//! compiles and would bill every token twice. Wrap exactly once and hand the
//! process an `Arc<dyn LlmClient>` it cannot re-wrap by accident.
//!
//! # Why the facts are published inline
//!
//! `event_bus::usage::UsageFact::record` retries a broker blip until it
//! succeeds or shutdown fires, which means metering can stall the caller. That
//! is the **background-producer** contract, and it is the right one here: the
//! copilot is a consumer-driven background path with nobody waiting on the
//! answer, and a lost token fact is an unbillable, unreconcilable hole (§13).
//! The API service's drop-on-backpressure `UsageRecorder` exists for the
//! opposite trade — a customer waiting on an HTTP response — and this seam is
//! never on that path. Don't unify them.
//!
//! # What a failed call does not bill
//!
//! Tokens are only known from a successful response body, so a failed call
//! publishes no fact. A refusal, by contrast, *is* a successful call with real
//! usage attached, and is billed like any other — which is also why it is
//! logged here at `warn` with its category: it is the one outcome that costs
//! money and returns no answer.

use std::sync::Arc;
use std::time::{Duration, Instant};

use event_bus::usage::UsageFact;
use event_bus::EventSink;
use events::primitives::Chain;
use events::system::UsageEventType;
use tokio_util::sync::CancellationToken;

use tracing::Instrument;

use crate::client::{Completion, CompletionRequest, LlmClient, LlmError, StopReason, TokenUsage};
use crate::metrics::record_completion;

/// An [`LlmClient`] that records every call through [`crate::metrics`],
/// publishes its token usage as [`UsageRecorded`](events::system::UsageRecorded)
/// facts, and delegates to `C`.
pub struct MeteredClient<C> {
    inner: C,
    sink: Arc<dyn EventSink>,
    chain: Chain,
    backoff: Duration,
    shutdown: CancellationToken,
}

impl<C: std::fmt::Debug> std::fmt::Debug for MeteredClient<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeteredClient")
            .field("inner", &self.inner)
            .field("chain", &self.chain)
            .finish_non_exhaustive()
    }
}

impl<C: LlmClient> MeteredClient<C> {
    /// Wrap `inner`. Call this **once**, at the boot site that owns the client
    /// (see the module docs).
    ///
    /// `chain` is the deployment's chain stamp for the usage envelopes —
    /// copilot work is not chain-derived, but every envelope on the backbone
    /// carries one, and partitioning falls back to it for a fact with no
    /// customer in scope.
    pub fn new(
        inner: C,
        sink: Arc<dyn EventSink>,
        chain: Chain,
        backoff: Duration,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            inner,
            sink,
            chain,
            backoff,
            shutdown,
        }
    }

    /// The wrapped client — for a caller that needs a backend-specific method
    /// the seam deliberately doesn't expose.
    pub fn inner(&self) -> &C {
        &self.inner
    }

    async fn meter(&self, request: &CompletionRequest, usage: &TokenUsage) {
        publish_usage(
            &*self.sink,
            self.chain,
            self.backoff,
            &self.shutdown,
            request.customer_id,
            usage,
            Billing::Standard,
        )
        .await;
    }
}

#[async_trait::async_trait]
impl<C: LlmClient> LlmClient for MeteredClient<C> {
    fn model(&self) -> &str {
        self.inner.model()
    }

    async fn complete(&self, request: &CompletionRequest) -> Result<Completion, LlmError> {
        // The LLM hop is the slowest span in any copilot trace by two orders of
        // magnitude; without one, a multi-minute call is an unexplained gap in
        // Tempo between two fast spans (§19). Named `llm.complete` so it sorts
        // with the other outbound-dependency spans.
        let span = tracing::info_span!(
            "llm.complete",
            purpose = request.purpose,
            model = self.inner.model(),
            prompt = request.prompt.map(|p| p.id()).unwrap_or_default(),
            request_digest = %request.digest(),
        );

        let started = Instant::now();
        let outcome = self.inner.complete(request).instrument(span).await;
        let elapsed = started.elapsed();

        match &outcome {
            Ok(completion) => {
                // Label by the model that *answered*: a rescued refusal is
                // billed at the fallback model's rates, and a dashboard that
                // attributed it to the requested model would be wrong about
                // both cost and behaviour.
                record_completion(
                    &completion.model,
                    request.purpose,
                    elapsed,
                    Ok((completion.stop_reason.as_str(), &completion.usage)),
                );
                if let StopReason::Refusal { category } = &completion.stop_reason {
                    tracing::warn!(
                        purpose = request.purpose,
                        model = %completion.model,
                        category = category.as_deref().unwrap_or("unspecified"),
                        tokens = completion.usage.total(),
                        "llm declined the request; billed with no answer"
                    );
                }
                self.meter(request, &completion.usage).await;
            }
            Err(err) => record_completion(self.inner.model(), request.purpose, elapsed, Err(err)),
        }

        outcome
    }
}

/// Which price list a call's tokens are billed against.
///
/// The Batch API charges half of the synchronous rate, so the two cannot share
/// a SKU: a `llm_input_tokens` quantity that silently mixes both is only
/// priceable if the reader also knows the split, which is the very thing the
/// fold threw away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Billing {
    /// A synchronous `POST /v1/messages` call.
    Standard,
    /// A request that rode the Batch API ([`crate::batch`]) at half price.
    Batch,
}

/// One call's usage as billable §13 facts — the same four kinds, in the same
/// order, as [`crate::metrics::token_kinds`].
///
/// Four SKUs and not one, because they are four different rates: a bill cannot
/// be reconstructed from a single "tokens" number, and a metering event that
/// can't be priced is not metering. `billing` picks which of the two price
/// lists those four SKUs name.
pub(crate) fn usage_facts(usage: &TokenUsage, billing: Billing) -> [(UsageEventType, u64); 4] {
    let (input, output, cache_write, cache_read) = match billing {
        Billing::Standard => (
            UsageEventType::LlmInputTokens,
            UsageEventType::LlmOutputTokens,
            UsageEventType::LlmCacheWriteTokens,
            UsageEventType::LlmCacheReadTokens,
        ),
        Billing::Batch => (
            UsageEventType::LlmBatchInputTokens,
            UsageEventType::LlmBatchOutputTokens,
            UsageEventType::LlmBatchCacheWriteTokens,
            UsageEventType::LlmBatchCacheReadTokens,
        ),
    };
    [
        (input, usage.input_tokens),
        (output, usage.output_tokens),
        (cache_write, usage.cache_creation_input_tokens),
        (cache_read, usage.cache_read_input_tokens),
    ]
}

/// Publish one call's usage as `UsageRecorded` facts.
///
/// The single metering write in this crate, shared by [`MeteredClient`] and
/// [`crate::batch::MeteredBatchClient`] — a second copy for the batch path is
/// how the two would come to disagree about what a zero-token kind, or a
/// customer-less platform call, means (§13).
pub(crate) async fn publish_usage(
    sink: &dyn EventSink,
    chain: Chain,
    backoff: Duration,
    shutdown: &CancellationToken,
    customer_id: Option<events::primitives::CustomerId>,
    usage: &TokenUsage,
    billing: Billing,
) {
    for (event_type, quantity) in usage_facts(usage, billing) {
        // A zero-token kind is not a fact: an envelope saying "0 cache writes"
        // costs a partition write and tells a bill nothing.
        if quantity == 0 {
            continue;
        }
        let mut fact = UsageFact::new(event_type, quantity);
        if let Some(customer_id) = customer_id {
            fact = fact.for_customer(customer_id);
        }
        fact.record(sink, chain, backoff, shutdown).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::StubClient;
    use event_bus::test_util::RecordingSink;
    use events::primitives::CustomerId;
    use events::system::UsageRecorded;
    use events::DomainEvent;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::CompositeKey;

    type Series = Vec<(
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    )>;

    /// Run `f` under a scoped in-memory recorder and return the captured
    /// series — no global install (so tests don't contend), and one
    /// `snapshot()` only (it drains the recorder).
    fn captured(f: impl FnOnce()) -> Series {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, f);
        snapshotter.snapshot().into_vec()
    }

    fn counter(series: &Series, name: &str) -> Option<u64> {
        match series
            .iter()
            .find(|(ck, _, _, _)| ck.key().name() == name)
            .map(|(_, _, _, v)| v)
        {
            Some(DebugValue::Counter(n)) => Some(*n),
            _ => None,
        }
    }

    /// One label's value on the first series named `name`.
    fn label(series: &Series, name: &str, label: &str) -> Option<String> {
        series
            .iter()
            .find(|(ck, _, _, _)| ck.key().name() == name)
            .and_then(|(ck, _, _, _)| {
                ck.key()
                    .labels()
                    .find(|l| l.key() == label)
                    .map(|l| l.value().to_owned())
            })
    }

    fn metered(inner: StubClient) -> (Arc<RecordingSink>, MeteredClient<StubClient>) {
        let sink = Arc::new(RecordingSink::default());
        let client = MeteredClient::new(
            inner,
            sink.clone(),
            Chain::ETHEREUM,
            Duration::from_millis(1),
            CancellationToken::new(),
        );
        (sink, client)
    }

    fn usage_facts_of(sink: &RecordingSink) -> Vec<UsageRecorded> {
        sink.events()
            .into_iter()
            .filter_map(|event| match event {
                DomainEvent::UsageRecorded(usage) => Some(usage),
                _ => None,
            })
            .collect()
    }

    /// The metering contract: one fact per *non-zero* token kind, each
    /// attributed to the customer the request named.
    #[tokio::test]
    async fn every_billable_token_kind_becomes_its_own_usage_fact() {
        let customer = CustomerId::new();
        let (sink, client) = metered(StubClient::answering("a narrative").with_usage(TokenUsage {
            input_tokens: 120,
            output_tokens: 900,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 30_000,
        }));

        client
            .complete(&CompletionRequest::new("incident_narrative", "draft").for_customer(customer))
            .await
            .expect("the stub answers");

        let facts = usage_facts_of(&sink);
        let by_type: Vec<(String, u64, Option<CustomerId>)> = facts
            .iter()
            .map(|f| (f.event_type.clone(), f.quantity, f.customer_id))
            .collect();
        assert_eq!(
            by_type,
            vec![
                ("llm_input_tokens".to_owned(), 120, Some(customer)),
                ("llm_output_tokens".to_owned(), 900, Some(customer)),
                ("llm_cache_read_tokens".to_owned(), 30_000, Some(customer)),
            ],
            "a zero kind must not become an envelope"
        );
    }

    /// Platform-internal work has no customer in scope — the fact says so
    /// rather than inventing one (the `Option` discipline §13 relies on).
    #[tokio::test]
    async fn a_call_with_no_customer_meters_without_one() {
        let (sink, client) = metered(StubClient::answering("ok").with_usage(TokenUsage {
            input_tokens: 5,
            ..TokenUsage::default()
        }));

        client
            .complete(&CompletionRequest::new("backfill", "draft"))
            .await
            .unwrap();

        let facts = usage_facts_of(&sink);
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].customer_id, None);
    }

    /// A failure bills nothing — the provider tells us no token counts — but
    /// it must still *count*, or a service failing every call would show a
    /// flawless success rate (conventions §14).
    ///
    /// A plain `#[test]` with its own current-thread runtime, not a
    /// `#[tokio::test]`: `metrics::with_local_recorder` installs the recorder
    /// on *this* thread, so the future has to be driven here too or the
    /// records land in the (absent) global recorder instead.
    #[test]
    fn a_failed_call_publishes_no_usage_but_is_still_counted() {
        let (sink, client) = metered(StubClient::failing(|| LlmError::Unavailable {
            status: 503,
            reason: "overloaded".into(),
        }));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime");

        let series = captured(|| {
            runtime.block_on(async {
                client
                    .complete(&CompletionRequest::new("rule_draft", "alert me when…"))
                    .await
                    .expect_err("the stub fails");
            });
        });

        assert!(usage_facts_of(&sink).is_empty());
        assert_eq!(counter(&series, crate::metrics::CALLS_TOTAL), Some(1));
        assert!(
            label(&series, crate::metrics::CALLS_TOTAL, "stop_reason").as_deref() == Some("error"),
            "a failure is still a call, bucketed as an error"
        );
        assert_eq!(counter(&series, crate::metrics::FAILURES_TOTAL), Some(1));
        assert_eq!(
            label(&series, crate::metrics::FAILURES_TOTAL, "reason").as_deref(),
            Some("unavailable")
        );
        assert_eq!(
            counter(&series, crate::metrics::TOKENS_TOTAL),
            None,
            "a failed call knows no token counts"
        );
    }

    /// A refusal costs money and returns nothing — so it is billed, and it is
    /// labeled as a refusal rather than hidden in the success bucket.
    #[tokio::test]
    async fn a_refusal_is_billed_and_labeled() {
        let (sink, client) = metered(
            StubClient::answering("")
                .with_stop_reason(StopReason::Refusal {
                    category: Some("cyber".into()),
                })
                .with_usage(TokenUsage {
                    input_tokens: 2_000,
                    ..TokenUsage::default()
                }),
        );

        let completion = client
            .complete(&CompletionRequest::new("incident_narrative", "draft"))
            .await
            .expect("a refusal is a successful call");
        assert!(!completion.stop_reason.is_complete());

        let facts = usage_facts_of(&sink);
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].quantity, 2_000);
    }

    /// The two orderings that must never diverge: what the dashboard labels
    /// `kind` and what the bill charges as a SKU.
    #[test]
    fn the_metric_kinds_and_the_billing_skus_describe_the_same_numbers() {
        let usage = TokenUsage {
            input_tokens: 1,
            output_tokens: 2,
            cache_creation_input_tokens: 3,
            cache_read_input_tokens: 4,
        };
        let kinds = crate::metrics::token_kinds(&usage);
        for billing in [Billing::Standard, Billing::Batch] {
            let facts = usage_facts(&usage, billing);
            for (i, (event_type, quantity)) in facts.iter().enumerate() {
                assert_eq!(*quantity, kinds[i].1);
                assert!(
                    event_type.as_wire_str().contains(kinds[i].0),
                    "{} should describe the {} kind",
                    event_type.as_wire_str(),
                    kinds[i].0
                );
            }
        }

        // …and the two price lists must not share a single SKU: a batched
        // token costs half a synchronous one.
        let standard: Vec<&str> = usage_facts(&usage, Billing::Standard)
            .iter()
            .map(|(event_type, _)| event_type.as_wire_str())
            .collect();
        let batch: Vec<&str> = usage_facts(&usage, Billing::Batch)
            .iter()
            .map(|(event_type, _)| event_type.as_wire_str())
            .collect();
        assert!(batch.iter().all(|sku| !standard.contains(sku)), "{batch:?}");
    }
}
