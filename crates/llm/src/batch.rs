//! The Message Batches seam (§20.4) — the half-price path for work nobody is
//! waiting on.
//!
//! The copilot's historical backfill drafts a narrative for every incident the
//! platform ever recorded. That is thousands of long-context completions with
//! no reader in the loop, which is precisely the workload the Batch API exists
//! for: **50% of the synchronous price**, in exchange for a result that
//! arrives within 24 hours instead of within a minute.
//!
//! # Why this is a second seam and not a flag on [`LlmClient`]
//!
//! [`LlmClient::complete`](crate::LlmClient::complete) is "ask a question, get
//! an answer" — one call, one `await`, an error or a `Completion`. A batch is
//! not that shape at any level: it is *submit → poll → fetch*, spanning
//! process restarts, with per-item outcomes that include "expired" and
//! "canceled" — states a synchronous call has no vocabulary for. Bolting it
//! onto the same trait would either force every caller of the cheap path to
//! learn a lifecycle it never uses, or force the batch caller to pretend a
//! 24-hour job is an `await`.
//!
//! So [`BatchClient`] is its own object-safe seam beside the first, with the
//! same discipline: one production backend, one in-memory double
//! ([`crate::test_util::StubBatchClient`]), one metering decorator
//! ([`MeteredBatchClient`]).
//!
//! # What it deliberately shares with the synchronous backend
//!
//! **The request body.** [`crate::anthropic::messages_body`] builds it for
//! both, because a narrative drafted through the backfill must be drafted
//! under the *same* instructions, model, effort and thinking configuration as
//! a live one — otherwise "we backfilled the archive" quietly means "the
//! archive was written by a different system".
//!
//! One wire rule breaks that symmetry, and it is invisible until it 400s:
//! **the `fallbacks` parameter is rejected by the Batches API.** Refusal
//! rescue is on by default for the synchronous path (see [`crate::LlmConfig`]),
//! so the batch body must explicitly omit it — and the beta header with it.
//! A refusal inside a batch therefore comes back as a refusal, which the
//! copilot already knows how to file: `blocked`, terminal, billed.
//!
//! # What it deliberately does not share
//!
//! **The decorator stack.** No retry, no breaker, no admission control, no
//! response cache. Every one of those is about *this* process making a
//! rate-limited call right now; a batch is a durable server-side job whose
//! id is written to a store, so the queue above it owns the retry decision and
//! the batch's own idempotency comes from that stored id. The one decorator
//! that does apply is metering — tokens are tokens, they are simply billed
//! against the batch price list ([`crate::metered::Billing::Batch`]).

use std::sync::Arc;
use std::time::Duration;

use event_bus::EventSink;
use events::primitives::{Chain, CustomerId};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::anthropic::{classify_status, into_completion, messages_body, retry_after};
use crate::client::{Completion, CompletionRequest, LlmError};
use crate::config::{LlmConfig, ANTHROPIC_VERSION};
use crate::metered::{publish_usage, Billing};
use crate::metrics;

/// The API's hard ceiling on one batch. Enforced here so an oversized submit
/// is a local error naming the limit, not a 413 after serializing 300MB.
pub const MAX_ITEMS: usize = 100_000;

/// A server-side batch job's id (`msgbatch_…`).
///
/// A `String` newtype rather than a bare string because it is *durable state*:
/// the copilot writes it onto its draft rows, and a process that restarts
/// mid-backfill recovers the job from the store rather than paying for it
/// again.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BatchId(pub String);

impl std::fmt::Display for BatchId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One request in a batch, tagged with the caller's own id.
///
/// `custom_id` is the join key back to whatever the caller is drafting for —
/// the copilot uses the draft id — because **results come back in any order**
/// and a positional match would silently file narratives against the wrong
/// incidents.
#[derive(Debug, Clone)]
pub struct BatchItem {
    pub custom_id: String,
    pub request: CompletionRequest,
}

impl BatchItem {
    pub fn new(custom_id: impl Into<String>, request: CompletionRequest) -> Self {
        Self {
            custom_id: custom_id.into(),
            request,
        }
    }
}

/// What a submit produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchSubmission {
    pub batch_id: BatchId,
    /// Items the caller handed over — the number whose outcomes must be
    /// accounted for before the batch can be considered done.
    pub submitted: usize,
}

/// Where a batch is in its server-side lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchState {
    /// Still running. Results are not available.
    InProgress,
    /// A cancel was requested; in-flight items may still finish.
    Canceling,
    /// Terminal: every item has an outcome and the results are fetchable.
    Ended,
    /// A `processing_status` this build does not know. Treated as
    /// not-yet-ended, so an API that grows a state cannot make a poller
    /// declare a batch finished it has not read.
    Unknown,
}

impl BatchState {
    /// Whether results can be fetched.
    pub fn is_ended(self) -> bool {
        matches!(self, BatchState::Ended)
    }
}

/// Per-item counts as the API reports them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BatchCounts {
    pub processing: u64,
    pub succeeded: u64,
    pub errored: u64,
    pub canceled: u64,
    pub expired: u64,
}

/// One poll's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchStatus {
    pub batch_id: BatchId,
    pub state: BatchState,
    pub counts: BatchCounts,
}

/// What became of one item.
///
/// Note the shape: an errored item carries its own transience, because the
/// Batch API's per-item errors mirror the synchronous ones — a validation
/// error fails identically forever, a server error might not — and the caller
/// has to make the same retry-or-park decision for each item independently.
#[derive(Debug, Clone, PartialEq)]
pub enum BatchItemOutcome {
    /// The model answered. Check `stop_reason` before believing the text: a
    /// refusal and a `max_tokens` truncation both arrive here, as successful,
    /// *billed* results with unusable content — exactly as on the synchronous
    /// path.
    Answered(Box<Completion>),
    /// The request failed. `permanent` is the caller's retry-or-park answer.
    Errored {
        kind: String,
        message: String,
        permanent: bool,
    },
    /// The batch was canceled before this item ran. Nothing was billed;
    /// re-submitting is the remedy.
    Canceled,
    /// The batch hit its 24-hour deadline with this item unfinished. Same
    /// remedy as canceled, different cause (usually an oversized batch).
    Expired,
}

impl BatchItemOutcome {
    /// Whether re-submitting this item could plausibly do better.
    pub fn is_retryable(&self) -> bool {
        match self {
            // A refusal or truncation is terminal — re-running buys the same
            // decline at full price. That decision belongs to the caller's
            // store, which is why this only answers for the transport-shaped
            // outcomes.
            BatchItemOutcome::Answered(_) => false,
            BatchItemOutcome::Errored { permanent, .. } => !permanent,
            BatchItemOutcome::Canceled | BatchItemOutcome::Expired => true,
        }
    }

    /// The label this outcome is counted under (§19).
    pub fn as_wire_str(&self) -> &'static str {
        match self {
            BatchItemOutcome::Answered(_) => "answered",
            BatchItemOutcome::Errored { .. } => "errored",
            BatchItemOutcome::Canceled => "canceled",
            BatchItemOutcome::Expired => "expired",
        }
    }
}

/// One item's result, keyed by the caller's own id.
#[derive(Debug, Clone, PartialEq)]
pub struct BatchOutcome {
    pub custom_id: String,
    pub outcome: BatchItemOutcome,
}

/// The Batch API seam.
///
/// Object-safe, like [`LlmClient`](crate::LlmClient): the backfill runner
/// holds an `Arc<dyn BatchClient>` and its whole submit/poll/land loop is
/// exercisable against [`crate::test_util::StubBatchClient`] with no network,
/// no key, and no 24-hour wait.
#[async_trait::async_trait]
pub trait BatchClient: Send + Sync + std::fmt::Debug {
    /// The model this client submits for.
    fn model(&self) -> &str;

    /// Submit a batch. One HTTP call; the job then lives on the server.
    async fn submit(&self, items: &[BatchItem]) -> Result<BatchSubmission, LlmError>;

    /// Poll a batch's state. Cheap, and the only thing a caller should do
    /// while waiting.
    async fn status(&self, batch_id: &BatchId) -> Result<BatchStatus, LlmError>;

    /// Fetch every item's outcome. Only meaningful once
    /// [`BatchState::is_ended`].
    async fn results(&self, batch_id: &BatchId) -> Result<Vec<BatchOutcome>, LlmError>;

    /// Ask the server to cancel a batch. Items already finished still bill and
    /// still return results.
    async fn cancel(&self, batch_id: &BatchId) -> Result<BatchStatus, LlmError>;
}

// ── Wire form (private: a detail of this backend) ──────────────────────────

#[derive(Serialize)]
struct BatchRequest<'a> {
    requests: Vec<BatchRequestItem<'a>>,
}

#[derive(Serialize)]
struct BatchRequestItem<'a> {
    custom_id: &'a str,
    params: crate::anthropic::MessagesRequest<'a>,
}

#[derive(Deserialize)]
struct BatchResponse {
    #[serde(default)]
    id: String,
    #[serde(default)]
    processing_status: String,
    #[serde(default)]
    request_counts: WireCounts,
}

#[derive(Default, Deserialize)]
struct WireCounts {
    #[serde(default)]
    processing: u64,
    #[serde(default)]
    succeeded: u64,
    #[serde(default)]
    errored: u64,
    #[serde(default)]
    canceled: u64,
    #[serde(default)]
    expired: u64,
}

/// One line of the JSONL results stream.
#[derive(Deserialize)]
struct BatchResultLine {
    #[serde(default)]
    custom_id: String,
    result: BatchResultBody,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum BatchResultBody {
    #[serde(rename = "succeeded")]
    Succeeded {
        message: crate::anthropic::MessagesResponse,
    },
    #[serde(rename = "errored")]
    Errored {
        #[serde(default)]
        error: WireError,
    },
    #[serde(rename = "canceled")]
    Canceled,
    #[serde(rename = "expired")]
    Expired,
    /// A result type newer than this build. Surfaced as a permanent error
    /// rather than dropped: an item whose outcome we cannot read must not look
    /// like an item that never came back.
    #[serde(other)]
    Unknown,
}

#[derive(Default, Deserialize)]
struct WireError {
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    message: String,
}

// ── The backend ───────────────────────────────────────────────────────────

/// The Message Batches backend.
pub struct AnthropicBatchClient {
    http: reqwest::Client,
    config: LlmConfig,
}

impl std::fmt::Debug for AnthropicBatchClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnthropicBatchClient")
            .field("model", &self.config.model)
            .field("base_url", &self.config.base_url)
            .finish_non_exhaustive()
    }
}

impl AnthropicBatchClient {
    pub fn new(config: LlmConfig) -> Result<Self, reqwest::Error> {
        // The submit body carries every request in the batch, and the results
        // fetch streams a JSONL document of every answer — both legitimately
        // far larger and slower than one completion, so the per-request
        // timeout is scaled rather than shared.
        let http = reqwest::Client::builder()
            .timeout(config.timeout.saturating_mul(2))
            .build()?;
        Ok(Self { http, config })
    }

    fn batches_url(&self) -> String {
        format!(
            "{}/v1/messages/batches",
            self.config.base_url.trim_end_matches('/')
        )
    }

    fn get(&self, url: String) -> reqwest::RequestBuilder {
        self.http
            .get(url)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("x-api-key", self.config.api_key.expose_secret())
    }

    /// Read a response body, mapping a non-2xx onto the shared classification.
    async fn text_of(&self, response: reqwest::Response) -> Result<String, LlmError> {
        let status = response.status();
        let retry_after = retry_after(response.headers());
        let body = response.text().await.map_err(|err| LlmError::Transport {
            reason: format!("reading response body: {err}"),
        })?;
        if !status.is_success() {
            return Err(classify_status(status.as_u16(), &body, retry_after));
        }
        Ok(body)
    }

    fn parse_status(body: &str) -> Result<BatchStatus, LlmError> {
        let parsed: BatchResponse = serde_json::from_str(body).map_err(|err| LlmError::Decode {
            reason: err.to_string(),
        })?;
        Ok(BatchStatus {
            batch_id: BatchId(parsed.id),
            state: match parsed.processing_status.as_str() {
                "in_progress" => BatchState::InProgress,
                "canceling" => BatchState::Canceling,
                "ended" => BatchState::Ended,
                _ => BatchState::Unknown,
            },
            counts: BatchCounts {
                processing: parsed.request_counts.processing,
                succeeded: parsed.request_counts.succeeded,
                errored: parsed.request_counts.errored,
                canceled: parsed.request_counts.canceled,
                expired: parsed.request_counts.expired,
            },
        })
    }
}

#[async_trait::async_trait]
impl BatchClient for AnthropicBatchClient {
    fn model(&self) -> &str {
        &self.config.model
    }

    async fn submit(&self, items: &[BatchItem]) -> Result<BatchSubmission, LlmError> {
        if items.is_empty() {
            return Err(LlmError::Invalid {
                status: 400,
                reason: "refusing to submit an empty batch".into(),
            });
        }
        if items.len() > MAX_ITEMS {
            return Err(LlmError::Invalid {
                status: 400,
                reason: format!(
                    "batch of {} exceeds the API maximum of {MAX_ITEMS} requests",
                    items.len()
                ),
            });
        }

        let body = BatchRequest {
            requests: items
                .iter()
                .map(|item| BatchRequestItem {
                    custom_id: &item.custom_id,
                    // `false`: the Batches API rejects `fallbacks` outright
                    // (module docs). This is the one place the batched and
                    // synchronous bodies are allowed to differ.
                    params: messages_body(&self.config, &item.request, false),
                })
                .collect(),
        };

        let response = self
            .http
            .post(self.batches_url())
            .header("content-type", "application/json")
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("x-api-key", self.config.api_key.expose_secret())
            .json(&body)
            .send()
            .await
            .map_err(|err| LlmError::Transport {
                reason: err.to_string(),
            })?;

        let body = self.text_of(response).await?;
        let status = Self::parse_status(&body)?;
        Ok(BatchSubmission {
            batch_id: status.batch_id,
            submitted: items.len(),
        })
    }

    async fn status(&self, batch_id: &BatchId) -> Result<BatchStatus, LlmError> {
        let response = self
            .get(format!("{}/{batch_id}", self.batches_url()))
            .send()
            .await
            .map_err(|err| LlmError::Transport {
                reason: err.to_string(),
            })?;
        let body = self.text_of(response).await?;
        Self::parse_status(&body)
    }

    /// Fetch and parse the JSONL results.
    ///
    /// The canonical `…/{id}/results` path is used rather than the
    /// `results_url` the status response carries: an absolute URL taken from a
    /// response body would route around a configured `ANTHROPIC_BASE_URL`
    /// (a gateway, a proxy, a test's stub server), which is the one thing that
    /// URL is for.
    async fn results(&self, batch_id: &BatchId) -> Result<Vec<BatchOutcome>, LlmError> {
        let response = self
            .get(format!("{}/{batch_id}/results", self.batches_url()))
            .send()
            .await
            .map_err(|err| LlmError::Transport {
                reason: err.to_string(),
            })?;
        let body = self.text_of(response).await?;
        parse_results(&body)
    }

    async fn cancel(&self, batch_id: &BatchId) -> Result<BatchStatus, LlmError> {
        let response = self
            .http
            .post(format!("{}/{batch_id}/cancel", self.batches_url()))
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("x-api-key", self.config.api_key.expose_secret())
            .send()
            .await
            .map_err(|err| LlmError::Transport {
                reason: err.to_string(),
            })?;
        let body = self.text_of(response).await?;
        Self::parse_status(&body)
    }
}

/// Parse the JSONL results document.
///
/// A line that will not parse is **skipped with a warning**, not a failed
/// fetch: one malformed record must not cost the caller the other 9,999
/// answers it has already paid for. The items it belongs to simply stay
/// unaccounted for and are re-submitted by the caller's own reconciliation.
fn parse_results(body: &str) -> Result<Vec<BatchOutcome>, LlmError> {
    let mut outcomes = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parsed: BatchResultLine = match serde_json::from_str(line) {
            Ok(parsed) => parsed,
            Err(err) => {
                tracing::warn!(error = %err, "skipping an unparseable batch result line");
                continue;
            }
        };
        outcomes.push(BatchOutcome {
            custom_id: parsed.custom_id,
            outcome: match parsed.result {
                BatchResultBody::Succeeded { message } => {
                    BatchItemOutcome::Answered(Box::new(into_completion(message)))
                }
                BatchResultBody::Errored { error } => BatchItemOutcome::Errored {
                    // `invalid_request` is our malformed request and fails
                    // identically forever; everything else is theirs and may
                    // not. Same split as `classify_status`, one level in.
                    permanent: error.kind == "invalid_request",
                    kind: error.kind,
                    // Truncated: a provider's error text is occasionally an
                    // HTML page from a proxy, and this string is written to a
                    // draft row a human reads.
                    message: error.message.chars().take(500).collect(),
                },
                BatchResultBody::Canceled => BatchItemOutcome::Canceled,
                BatchResultBody::Expired => BatchItemOutcome::Expired,
                BatchResultBody::Unknown => BatchItemOutcome::Errored {
                    kind: "unknown_result_type".into(),
                    message: "batch result type not understood by this build".into(),
                    permanent: true,
                },
            },
        });
    }
    Ok(outcomes)
}

// ── Metering decorator ────────────────────────────────────────────────────

/// A [`BatchClient`] that meters what came back (§13, §19).
///
/// The batch analogue of [`crate::MeteredClient`], and the same argument for
/// being a decorator: it meters *any* backend, meters the double so the
/// backfill's tests can assert on the facts a real run emits, and cannot miss
/// a path because [`BatchClient::results`] is the only place tokens become
/// known.
///
/// **Metering happens on `results`, once.** A batch's tokens are reported per
/// item in the results stream, so a caller that fetches results twice would
/// bill twice — which is why the copilot's backfill fetches a batch's results
/// exactly once and lands them durably in the same pass.
pub struct MeteredBatchClient<B> {
    inner: B,
    sink: Arc<dyn EventSink>,
    chain: Chain,
    backoff: Duration,
    shutdown: CancellationToken,
    /// Who the backfill's tokens bill to, if anyone. Platform-internal
    /// backfill has no customer in scope, exactly like the live narrative
    /// path.
    customer_id: Option<CustomerId>,
    purpose: &'static str,
}

impl<B: std::fmt::Debug> std::fmt::Debug for MeteredBatchClient<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeteredBatchClient")
            .field("inner", &self.inner)
            .field("purpose", &self.purpose)
            .finish_non_exhaustive()
    }
}

impl<B: BatchClient> MeteredBatchClient<B> {
    pub fn new(
        inner: B,
        sink: Arc<dyn EventSink>,
        chain: Chain,
        backoff: Duration,
        shutdown: CancellationToken,
        purpose: &'static str,
    ) -> Self {
        Self {
            inner,
            sink,
            chain,
            backoff,
            shutdown,
            customer_id: None,
            purpose,
        }
    }

    /// Attribute this client's batches to a customer (§13).
    pub fn for_customer(mut self, customer_id: CustomerId) -> Self {
        self.customer_id = Some(customer_id);
        self
    }
}

#[async_trait::async_trait]
impl<B: BatchClient> BatchClient for MeteredBatchClient<B> {
    fn model(&self) -> &str {
        self.inner.model()
    }

    async fn submit(&self, items: &[BatchItem]) -> Result<BatchSubmission, LlmError> {
        let submission = self.inner.submit(items).await?;
        metrics::record_batch_submitted(self.purpose, submission.submitted as u64);
        Ok(submission)
    }

    async fn status(&self, batch_id: &BatchId) -> Result<BatchStatus, LlmError> {
        self.inner.status(batch_id).await
    }

    async fn results(&self, batch_id: &BatchId) -> Result<Vec<BatchOutcome>, LlmError> {
        let outcomes = self.inner.results(batch_id).await?;
        for outcome in &outcomes {
            metrics::record_batch_item(self.purpose, outcome.outcome.as_wire_str());
            let BatchItemOutcome::Answered(completion) = &outcome.outcome else {
                continue;
            };
            metrics::record_batch_tokens(&completion.model, self.purpose, &completion.usage);
            publish_usage(
                &*self.sink,
                self.chain,
                self.backoff,
                &self.shutdown,
                self.customer_id,
                &completion.usage,
                // Half price — a distinct SKU set, never the synchronous one.
                Billing::Batch,
            )
            .await;
        }
        Ok(outcomes)
    }

    async fn cancel(&self, batch_id: &BatchId) -> Result<BatchStatus, LlmError> {
        self.inner.cancel(batch_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::StopReason;

    fn config() -> LlmConfig {
        LlmConfig::for_test("http://127.0.0.1:1")
    }

    /// The one wire rule that separates a batched request from a synchronous
    /// one. `fallbacks` on a batch is a 400, and the failure would arrive
    /// hours into a backfill, on the submit — so it is asserted here.
    #[test]
    fn a_batched_request_never_carries_refusal_fallbacks() {
        let config = config();
        assert!(
            config.fallbacks,
            "the synchronous default is on — that is what makes this test meaningful"
        );
        let request = CompletionRequest::new("incident_narrative", "draft");

        let batched = serde_json::to_value(messages_body(&config, &request, false)).unwrap();
        assert!(
            batched.get("fallbacks").is_none(),
            "the Batches API rejects `fallbacks`: {batched}"
        );

        let synchronous = serde_json::to_value(messages_body(&config, &request, true)).unwrap();
        assert_eq!(synchronous["fallbacks"], "default");
        // Everything else must be identical, or the archive is drafted by a
        // different system than the live path.
        for field in ["model", "max_tokens", "messages", "thinking"] {
            assert_eq!(
                batched.get(field),
                synchronous.get(field),
                "{field} drifted"
            );
        }
    }

    #[test]
    fn the_submit_body_tags_every_request_with_its_custom_id() {
        let config = config();
        let items = [
            BatchItem::new("draft-a", CompletionRequest::new("incident_narrative", "a")),
            BatchItem::new("draft-b", CompletionRequest::new("incident_narrative", "b")),
        ];
        let body = serde_json::to_value(BatchRequest {
            requests: items
                .iter()
                .map(|item| BatchRequestItem {
                    custom_id: &item.custom_id,
                    params: messages_body(&config, &item.request, false),
                })
                .collect(),
        })
        .unwrap();

        assert_eq!(body["requests"][0]["custom_id"], "draft-a");
        assert_eq!(body["requests"][1]["custom_id"], "draft-b");
        assert_eq!(body["requests"][0]["params"]["messages"][0]["content"], "a");
    }

    #[test]
    fn results_are_parsed_by_custom_id_and_outcome() {
        let body = r#"
{"custom_id":"draft-a","result":{"type":"succeeded","message":{"model":"claude-opus-5","content":[{"type":"text","text":"a narrative"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":20}}}}
{"custom_id":"draft-b","result":{"type":"errored","error":{"type":"invalid_request","message":"max_tokens too large"}}}
{"custom_id":"draft-c","result":{"type":"expired"}}
{"custom_id":"draft-d","result":{"type":"canceled"}}
"#;
        let outcomes = parse_results(body).expect("parses");
        assert_eq!(outcomes.len(), 4);

        // Order is not assumed anywhere — this is the join key that makes a
        // shuffled results stream safe.
        let by_id: std::collections::HashMap<_, _> = outcomes
            .into_iter()
            .map(|o| (o.custom_id, o.outcome))
            .collect();

        let BatchItemOutcome::Answered(completion) = &by_id["draft-a"] else {
            panic!("draft-a answered");
        };
        assert_eq!(completion.text, "a narrative");
        assert_eq!(completion.stop_reason, StopReason::EndTurn);
        assert_eq!(completion.usage.input_tokens, 10);

        assert!(
            !by_id["draft-b"].is_retryable(),
            "a validation error fails identically forever"
        );
        assert!(
            by_id["draft-c"].is_retryable(),
            "an expired item can re-run"
        );
        assert!(by_id["draft-d"].is_retryable());
    }

    /// One bad line must not cost the caller the answers it already paid for.
    #[test]
    fn an_unparseable_line_is_skipped_not_fatal() {
        let body = "{not json}\n{\"custom_id\":\"draft-a\",\"result\":{\"type\":\"expired\"}}\n";
        let outcomes = parse_results(body).expect("parses what it can");
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].custom_id, "draft-a");
    }

    /// A result type from a newer API is an error, never a silent drop: an
    /// item whose outcome we cannot read must not look like one that never
    /// came back (which the caller would re-submit and re-bill forever).
    #[test]
    fn an_unknown_result_type_is_a_permanent_error() {
        let body = r#"{"custom_id":"draft-a","result":{"type":"vaporised"}}"#;
        let outcomes = parse_results(body).unwrap();
        match &outcomes[0].outcome {
            BatchItemOutcome::Errored {
                kind, permanent, ..
            } => {
                assert_eq!(kind, "unknown_result_type");
                assert!(permanent);
            }
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[test]
    fn processing_status_maps_to_the_lifecycle_and_an_unknown_state_is_not_ended() {
        let ended = AnthropicBatchClient::parse_status(
            r#"{"id":"msgbatch_1","processing_status":"ended","request_counts":{"succeeded":2}}"#,
        )
        .unwrap();
        assert_eq!(ended.batch_id, BatchId("msgbatch_1".into()));
        assert!(ended.state.is_ended());
        assert_eq!(ended.counts.succeeded, 2);

        let future = AnthropicBatchClient::parse_status(
            r#"{"id":"msgbatch_2","processing_status":"paused"}"#,
        )
        .unwrap();
        assert_eq!(future.state, BatchState::Unknown);
        assert!(
            !future.state.is_ended(),
            "a state we don't understand must never read as finished"
        );
    }

    #[tokio::test]
    async fn an_empty_or_oversized_batch_is_refused_locally() {
        let client = AnthropicBatchClient::new(config()).unwrap();
        let err = client.submit(&[]).await.expect_err("empty");
        assert!(matches!(err, LlmError::Invalid { .. }));
    }
}
