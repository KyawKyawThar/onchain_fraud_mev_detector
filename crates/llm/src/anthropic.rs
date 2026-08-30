//! The production backend: a thin `reqwest` client over the Claude Messages
//! API (`POST /v1/messages`).
//!
//! There is no official Anthropic Rust SDK, so this crate owns the wire form.
//! "Thin" is a design constraint, not an apology — the surface is deliberately
//! the smallest one that serves §20.4:
//!
//! - one non-streaming request/response, no tool loop, no agent harness. The
//!   copilot asks a question and reads an answer; nothing it does needs the
//!   model to call back into the system, and *not* giving a model tools is the
//!   cheapest way to keep "LLM output is a proposal, never a fact" true;
//! - the wire types below are private. They are a serialization detail of this
//!   one backend, and the seam's vocabulary ([`CompletionRequest`],
//!   [`Completion`]) is what the rest of the workspace programs against;
//! - it does **one HTTP attempt**. Retry, admission control, the circuit
//!   breaker and caching are decorators above the seam (see [`crate::stack`]),
//!   so this file is about the wire and nothing else — and every one of those
//!   policies is exercisable against the in-memory double instead of only
//!   against a live provider.
//!
//! # What is deliberately not here
//!
//! **Streaming** — nothing renders these tokens as they arrive, and a
//! background consumer gains nothing from an SSE parser. It becomes necessary
//! the day a UI streams a narrative, or the day `max_tokens` goes past what a
//! non-streamed response can safely carry.
//!
//! **The Batch API** — §20.4's historical backfill runs at half cost through
//! batches, but that is a different endpoint with a different lifecycle
//! (submit → poll → fetch results) and therefore a different seam:
//! [`crate::batch`]. It shares this module's *wire form* — [`messages_body`],
//! [`into_completion`] and [`classify_status`] are `pub(crate)` for exactly
//! that — because a batched request and a synchronous one must be the same
//! request, or a backfill silently drafts under different rules than the live
//! path. It shares nothing else: the lifecycle, the polling and the half-price
//! metering are the batch client's own.

use std::time::Duration;

use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::client::{
    Completion, CompletionRequest, LlmClient, LlmError, Message, StopReason, Thinking, TokenUsage,
};
use crate::config::{LlmConfig, ANTHROPIC_VERSION, SERVER_SIDE_FALLBACK_BETA};

// ── Wire form (private: a detail of this backend, not of the seam) ─────────

#[derive(Serialize)]
pub(crate) struct MessagesRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    messages: &'a [Message],
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<[SystemBlock<'a>; 1]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    thinking: Option<ThinkingBlock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_config: Option<OutputConfig<'a>>,
    /// The scalar `"default"` form: Anthropic picks the substitute by refusal
    /// category, so no model list of ours can go stale.
    #[serde(skip_serializing_if = "Option::is_none")]
    fallbacks: Option<&'static str>,
}

#[derive(Serialize)]
pub(crate) struct SystemBlock<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    text: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_control: Option<CacheControl>,
}

#[derive(Serialize)]
pub(crate) struct CacheControl {
    #[serde(rename = "type")]
    kind: &'static str,
}

#[derive(Serialize)]
pub(crate) struct ThinkingBlock {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    display: Option<&'static str>,
}

#[derive(Serialize)]
pub(crate) struct OutputConfig<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    effort: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<OutputFormat<'a>>,
}

#[derive(Serialize)]
pub(crate) struct OutputFormat<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    schema: &'a serde_json::Value,
}

#[derive(Deserialize)]
pub(crate) struct MessagesResponse {
    #[serde(default)]
    model: String,
    #[serde(default)]
    content: Vec<ContentBlock>,
    #[serde(default)]
    stop_reason: Option<String>,
    #[serde(default)]
    stop_details: Option<StopDetails>,
    #[serde(default)]
    usage: WireUsage,
}

/// Only `text` is named. Everything else the API can put in `content`
/// (`thinking`, `fallback`, a block type newer than this build) is matched by
/// the catch-all and dropped — a new block type must never be a failed
/// deserialization, the same forward-compatibility stance the event schema
/// takes.
#[derive(Deserialize)]
#[serde(tag = "type")]
pub(crate) enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
pub(crate) struct StopDetails {
    #[serde(default)]
    category: Option<String>,
}

#[derive(Default, Deserialize)]
pub(crate) struct WireUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    cache_creation_input_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: u64,
}

/// The API's error body (`{"type":"error","error":{"type":..,"message":..}}`).
#[derive(Deserialize)]
pub(crate) struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Deserialize)]
pub(crate) struct ErrorBody {
    #[serde(default)]
    message: String,
}

// ── The client ────────────────────────────────────────────────────────────

/// The Claude Messages API backend.
///
/// Holds one `reqwest::Client` (connection pooling is the point — a backfill
/// makes thousands of calls to one host) and is cheap to share behind an
/// `Arc<dyn LlmClient>`.
pub struct AnthropicClient {
    http: reqwest::Client,
    config: LlmConfig,
}

/// `LlmConfig`'s own `Debug` redacts the key; this impl exists because the
/// seam requires `Debug` and `reqwest::Client`'s is noise.
impl std::fmt::Debug for AnthropicClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnthropicClient")
            .field("model", &self.config.model)
            .field("base_url", &self.config.base_url)
            .finish_non_exhaustive()
    }
}

impl AnthropicClient {
    /// Build a client. Cheap — one connection pool, shared by every call.
    pub fn new(config: LlmConfig) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder().timeout(config.timeout).build()?;
        Ok(Self { http, config })
    }

    /// Check at **boot** that the configured credential works and the
    /// configured model exists.
    ///
    /// `GET /v1/models/{model}` rather than a smoke completion: it costs
    /// nothing, consumes no tokens, and still catches the two config errors
    /// that otherwise surface hours later on the first real incident — a
    /// typo'd `ANTHROPIC_API_KEY` and a model id that does not exist (or that
    /// this organisation cannot reach).
    ///
    /// `inference` does the same thing with a boot smoke inference, for the
    /// same reason: a deployment that cannot serve should fail at rollout,
    /// where a rollback is one command, rather than at 3am.
    pub async fn verify_credentials(&self) -> Result<(), LlmError> {
        let url = format!(
            "{}/v1/models/{}",
            self.config.base_url.trim_end_matches('/'),
            self.config.model
        );
        let response = self
            .http
            .get(url)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("x-api-key", self.config.api_key.expose_secret())
            .send()
            .await
            .map_err(|err| LlmError::Transport {
                reason: err.to_string(),
            })?;

        let status = response.status();
        if status.is_success() {
            tracing::info!(
                model = %self.config.model,
                base_url = %self.config.base_url,
                "llm credentials verified"
            );
            return Ok(());
        }
        let retry_after = retry_after(response.headers());
        let body = response.text().await.unwrap_or_default();
        Err(classify_status(status.as_u16(), &body, retry_after))
    }

    /// The `LlmConfig` in force — the boot log's source for what this process
    /// will ask for.
    pub fn config(&self) -> &LlmConfig {
        &self.config
    }

    /// This backend's body for one request: the configured model, and refusal
    /// fallbacks when the deployment asked for them.
    fn build_body<'a>(&'a self, request: &'a CompletionRequest) -> MessagesRequest<'a> {
        messages_body(&self.config, request, self.config.fallbacks)
    }
}

/// The Messages API body shared by the synchronous backend and the Batch API
/// ([`crate::batch`]).
///
/// `fallbacks` is a parameter and not read from the config, because of one
/// wire rule that is invisible until it 400s: **the `fallbacks` parameter is
/// rejected by the Batches API.** The synchronous path wants it on by default
/// (an incident narrative is exactly the shape that draws a false-positive
/// decline); a batched request carrying it is refused outright. One function,
/// two callers, one explicit flag — rather than two bodies that drift.
pub(crate) fn messages_body<'a>(
    config: &'a LlmConfig,
    request: &'a CompletionRequest,
    fallbacks: bool,
) -> MessagesRequest<'a> {
    {
        let thinking = match request.thinking {
            Thinking::Adaptive => Some(ThinkingBlock {
                kind: "adaptive",
                display: None,
            }),
            Thinking::AdaptiveSummarized => Some(ThinkingBlock {
                kind: "adaptive",
                display: Some("summarized"),
            }),
            Thinking::Disabled => Some(ThinkingBlock {
                kind: "disabled",
                display: None,
            }),
        };

        let effort = request
            .effort
            .or(config.effort)
            .map(|effort| effort.as_wire_str());
        let format = request.json_schema.as_ref().map(|schema| OutputFormat {
            kind: "json_schema",
            schema,
        });
        // Omit the whole object when neither half is set, rather than sending
        // an empty one.
        let output_config =
            (effort.is_some() || format.is_some()).then_some(OutputConfig { effort, format });

        MessagesRequest {
            model: &config.model,
            max_tokens: request.max_tokens.unwrap_or(config.max_tokens),
            messages: &request.messages,
            system: request.system.as_ref().map(|system| {
                [SystemBlock {
                    kind: "text",
                    text: &system.text,
                    cache_control: system.cache.then_some(CacheControl { kind: "ephemeral" }),
                }]
            }),
            thinking,
            output_config,
            fallbacks: fallbacks.then_some("default"),
        }
    }
}

impl AnthropicClient {
    /// One HTTP attempt.
    async fn post_completion(&self, request: &CompletionRequest) -> Result<Completion, LlmError> {
        let mut post = self
            .http
            .post(self.config.messages_url())
            .header("content-type", "application/json")
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("x-api-key", self.config.api_key.expose_secret());
        if self.config.fallbacks {
            post = post.header("anthropic-beta", SERVER_SIDE_FALLBACK_BETA);
        }

        let response = post
            .json(&self.build_body(request))
            .send()
            .await
            .map_err(|err| LlmError::Transport {
                reason: err.to_string(),
            })?;

        let status = response.status();
        let retry_after = retry_after(response.headers());
        let body = response.text().await.map_err(|err| LlmError::Transport {
            reason: format!("reading response body: {err}"),
        })?;

        if !status.is_success() {
            return Err(classify_status(status.as_u16(), &body, retry_after));
        }

        let parsed: MessagesResponse =
            serde_json::from_str(&body).map_err(|err| LlmError::Decode {
                reason: err.to_string(),
            })?;
        Ok(into_completion(parsed))
    }
}

#[async_trait::async_trait]
impl LlmClient for AnthropicClient {
    fn model(&self) -> &str {
        &self.config.model
    }

    /// One request, one response, no retry.
    ///
    /// Retrying is [`crate::RetryingClient`]'s job, one layer up, where it can
    /// consult the circuit breaker on every attempt and release its admission
    /// permit while it backs off. A loop here would sit below both.
    async fn complete(&self, request: &CompletionRequest) -> Result<Completion, LlmError> {
        self.post_completion(request).await
    }
}

/// Map an HTTP status onto the seam's classification.
///
/// The split that matters is 429/5xx (theirs, retriable) vs. 4xx (ours,
/// never). 408 and 409 sit on the transient side with the 5xx family: both are
/// timing, not a malformed request.
pub(crate) fn classify_status(status: u16, body: &str, retry_after: Option<Duration>) -> LlmError {
    let reason = error_message(body);
    match status {
        401 | 403 => LlmError::Auth { reason },
        429 => LlmError::RateLimited { retry_after },
        408 | 409 => LlmError::Unavailable { status, reason },
        500..=599 => LlmError::Unavailable { status, reason },
        _ => LlmError::Invalid { status, reason },
    }
}

/// The API's `error.message` when the body is the documented error envelope,
/// otherwise the raw body — truncated, because an HTML error page from a proxy
/// is not worth 40KB of log line.
pub(crate) fn error_message(body: &str) -> String {
    match serde_json::from_str::<ErrorEnvelope>(body) {
        Ok(envelope) if !envelope.error.message.is_empty() => envelope.error.message,
        _ => body.chars().take(500).collect(),
    }
}

/// `retry-after`, in the delta-seconds form the API uses. An HTTP-date form
/// (also legal per RFC 9110) parses to `None` and simply falls back to our own
/// backoff — a wrong wait is worse than a default one.
pub(crate) fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

pub(crate) fn into_completion(response: MessagesResponse) -> Completion {
    // Text blocks only: thinking and fallback-boundary blocks are not the
    // answer, and nothing downstream should be able to quote them as one.
    let text = response
        .content
        .iter()
        .filter_map(|block| match block {
            ContentBlock::Text { text } => Some(text.as_str()),
            ContentBlock::Other => None,
        })
        .collect::<Vec<_>>()
        .join("");

    let stop_reason = match response.stop_reason.as_deref() {
        Some("end_turn") => StopReason::EndTurn,
        Some("max_tokens") => StopReason::MaxTokens,
        Some("refusal") => StopReason::Refusal {
            category: response.stop_details.and_then(|details| details.category),
        },
        Some(other) => StopReason::Other(other.to_owned()),
        // A response with no stop_reason is the streaming shape, which this
        // backend never asks for; treat it as unknown rather than complete.
        None => StopReason::Other("unspecified".to_owned()),
    };

    Completion {
        text,
        stop_reason,
        model: response.model,
        usage: TokenUsage {
            input_tokens: response.usage.input_tokens,
            output_tokens: response.usage.output_tokens,
            cache_creation_input_tokens: response.usage.cache_creation_input_tokens,
            cache_read_input_tokens: response.usage.cache_read_input_tokens,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{Effort, SystemPrompt};
    use event_bus::Transience;

    fn client() -> AnthropicClient {
        AnthropicClient::new(LlmConfig::for_test("http://127.0.0.1:1"))
            .expect("building a client needs no network")
    }

    fn body_of(client: &AnthropicClient, request: &CompletionRequest) -> serde_json::Value {
        serde_json::to_value(client.build_body(request)).expect("serializable")
    }

    /// The request shape the current models require: adaptive thinking (no
    /// `budget_tokens`, which they reject outright), the configured model, and
    /// the system prompt as a cacheable block.
    #[test]
    fn the_default_request_is_the_current_wire_form() {
        let client = client();
        let request = CompletionRequest::new("incident_narrative", "summarise this incident")
            .system(SystemPrompt::cached("you draft SAR narratives"));
        let body = body_of(&client, &request);

        assert_eq!(body["model"], crate::DEFAULT_MODEL);
        assert_eq!(body["thinking"]["type"], "adaptive");
        assert!(body["thinking"].get("display").is_none());
        assert!(
            body.get("budget_tokens").is_none(),
            "budget_tokens is rejected by the current models"
        );
        assert_eq!(body["system"][0]["type"], "text");
        assert_eq!(body["system"][0]["cache_control"]["type"], "ephemeral");
        assert_eq!(body["messages"][0]["role"], "user");
        assert_eq!(body["messages"][0]["content"], "summarise this incident");
        // Refusal rescue is opt-in-by-default for this workload.
        assert_eq!(body["fallbacks"], "default");
        // Nothing asked for effort or a schema, so the object is absent
        // entirely rather than sent empty.
        assert!(body.get("output_config").is_none(), "{body}");
    }

    #[test]
    fn effort_and_schema_ride_inside_output_config() {
        let client = client();
        let schema = serde_json::json!({"type": "object", "properties": {}});
        let request = CompletionRequest::new("rule_draft", "alert me when…")
            .effort(Effort::XHigh)
            .json_schema(schema.clone());
        let body = body_of(&client, &request);

        assert_eq!(body["output_config"]["effort"], "xhigh");
        assert_eq!(body["output_config"]["format"]["type"], "json_schema");
        assert_eq!(body["output_config"]["format"]["schema"], schema);
        // The deprecated top-level spellings must not reappear.
        assert!(body.get("effort").is_none());
        assert!(body.get("output_format").is_none());
    }

    #[test]
    fn a_request_can_override_the_configured_defaults() {
        let mut config = LlmConfig::for_test("http://127.0.0.1:1");
        config.effort = Some(Effort::Low);
        config.fallbacks = false;
        let client = AnthropicClient::new(config).unwrap();

        let request = CompletionRequest::new("rule_draft", "hi")
            .max_tokens(99)
            .effort(Effort::Max)
            .system(SystemPrompt::uncached("no cache"))
            .thinking(Thinking::AdaptiveSummarized);
        let body = body_of(&client, &request);

        assert_eq!(body["max_tokens"], 99);
        assert_eq!(body["output_config"]["effort"], "max");
        assert_eq!(body["thinking"]["display"], "summarized");
        assert!(body["system"][0].get("cache_control").is_none());
        assert!(body.get("fallbacks").is_none());
    }

    #[test]
    fn statuses_map_onto_the_shared_retry_classification() {
        assert!(matches!(
            classify_status(429, "", Some(Duration::from_secs(30))),
            LlmError::RateLimited {
                retry_after: Some(d)
            } if d == Duration::from_secs(30)
        ));
        assert!(classify_status(503, "", None).is_transient());
        assert!(classify_status(529, "", None).is_transient());
        assert!(classify_status(408, "", None).is_transient());
        assert!(!classify_status(401, "", None).is_transient());
        assert!(!classify_status(400, "", None).is_transient());
        assert!(!classify_status(404, "", None).is_transient());
    }

    #[test]
    fn the_api_error_message_beats_the_raw_body() {
        let body = r#"{"type":"error","error":{"type":"invalid_request_error","message":"max_tokens: 1000000 > 128000"}}"#;
        let err = classify_status(400, body, None);
        assert!(err.to_string().contains("128000"), "{err}");

        // A proxy's HTML error page still says *something*, bounded.
        let html = "<html>".repeat(500);
        let err = classify_status(502, &html, None);
        assert!(err.to_string().len() < 600, "{err}");
    }

    /// Only text blocks become the answer; thinking never leaks into it, and
    /// an unknown block type is dropped rather than failing the parse.
    #[test]
    fn only_text_blocks_become_the_answer() {
        let response: MessagesResponse = serde_json::from_str(
            r#"{
                "model": "claude-opus-5",
                "content": [
                    {"type": "thinking", "thinking": "internal reasoning"},
                    {"type": "text", "text": "Hello, "},
                    {"type": "some_future_block", "whatever": 1},
                    {"type": "text", "text": "world."}
                ],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 11, "output_tokens": 3, "cache_read_input_tokens": 900}
            }"#,
        )
        .expect("a forward-compatible parse");

        let completion = into_completion(response);
        assert_eq!(completion.text, "Hello, world.");
        assert_eq!(completion.stop_reason, StopReason::EndTurn);
        assert_eq!(completion.usage.input_tokens, 11);
        assert_eq!(completion.usage.cache_read_input_tokens, 900);
        assert_eq!(completion.usage.cache_creation_input_tokens, 0);
    }

    /// A refusal is an HTTP 200 with empty content — the case that breaks any
    /// caller that reads `content[0]` without checking `stop_reason` first.
    #[test]
    fn a_refusal_parses_as_a_successful_call_with_no_answer() {
        let response: MessagesResponse = serde_json::from_str(
            r#"{
                "model": "claude-opus-5",
                "content": [],
                "stop_reason": "refusal",
                "stop_details": {"type": "refusal", "category": "cyber"},
                "usage": {"input_tokens": 0, "output_tokens": 0}
            }"#,
        )
        .unwrap();

        let completion = into_completion(response);
        assert!(completion.text.is_empty());
        assert!(!completion.stop_reason.is_complete());
        assert_eq!(
            completion.stop_reason,
            StopReason::Refusal {
                category: Some("cyber".into())
            }
        );
    }

    /// The model that *answered*, not the one we asked for — a rescued
    /// refusal must stay attributable in the draft event (§20.4).
    #[test]
    fn the_served_model_comes_from_the_response() {
        let response: MessagesResponse = serde_json::from_str(
            r#"{"model":"claude-opus-4-8","content":[{"type":"text","text":"ok"}],
                "stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}"#,
        )
        .unwrap();
        assert_eq!(into_completion(response).model, "claude-opus-4-8");
    }

    #[test]
    fn retry_after_reads_delta_seconds_and_ignores_the_date_form() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::RETRY_AFTER, "42".parse().unwrap());
        assert_eq!(retry_after(&headers), Some(Duration::from_secs(42)));

        headers.insert(
            reqwest::header::RETRY_AFTER,
            "Wed, 21 Oct 2026 07:28:00 GMT".parse().unwrap(),
        );
        assert_eq!(retry_after(&headers), None);
    }

    /// The backend's contract after the retry loop moved out: **one** attempt,
    /// and the raw classified error — not an `Exhausted` wrapper. Nothing is
    /// listening on port 1, so this is a transport fault.
    #[tokio::test]
    async fn the_backend_makes_exactly_one_attempt() {
        let client = client();
        let err = client
            .complete(&CompletionRequest::new("test", "hi"))
            .await
            .expect_err("nothing is listening");

        assert!(matches!(err, LlmError::Transport { .. }), "{err}");
        assert!(
            err.is_transient() && err.retry_now(),
            "the layer above may retry"
        );
    }

    /// A boot check that cannot reach the provider fails the boot, rather than
    /// letting the first incident of the day discover it.
    #[tokio::test]
    async fn verifying_credentials_surfaces_a_transport_failure() {
        let err = client()
            .verify_credentials()
            .await
            .expect_err("nothing is listening");
        assert!(matches!(err, LlmError::Transport { .. }), "{err}");
    }
}
