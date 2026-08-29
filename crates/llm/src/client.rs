//! The seam itself: [`LlmClient`], the request/response vocabulary it speaks,
//! and the error every backend classifies its failures into.
//!
//! Three shape decisions worth stating, because they are not the obvious ones:
//!
//! - **`complete` is one logical completion.** Whether it retried, was served
//!   from cache, or was refused by admission control is the *stack's* business
//!   (see [`crate::stack`]); a caller sees one call and branches on
//!   [`LlmError`] as a final verdict. Two classification questions come off
//!   that error and they are not the same one:
//!   [`Transience::is_transient`] answers "should the queue above re-run this
//!   work later?", and [`LlmError::retry_now`] answers "would trying again in
//!   200ms help?". A shed call is `true` then `false`.
//! - **A refusal is a successful call, not an error.** Claude's safety
//!   classifiers decline with HTTP 200 and `stop_reason: "refusal"`. It is a
//!   real, billable outcome with real token usage attached, so it comes back
//!   as [`Completion`] carrying [`StopReason::Refusal`] and (usually) empty
//!   text. Modelling it as an `Err` would have thrown away the usage the
//!   metering decorator must record, and would have invited a retry of a
//!   request that will decline again. **Check [`Completion::stop_reason`]
//!   before reading [`Completion::text`].**
//! - **`purpose` is on the request, not the client.** One client serves every
//!   copilot capability; the *call site* names what it is doing
//!   (`"incident_narrative"`, `"rule_draft"`) and that name becomes the
//!   metrics label. `&'static str` on purpose: a label's value set must be
//!   small and known at compile time, and a `String` here would be an open
//!   invitation to label by incident id. Prefer
//!   [`CompletionRequest::for_prompt`], which takes the purpose *and* the
//!   system prompt from one versioned [`PromptDescriptor`] so the two cannot
//!   drift apart.

use std::time::Duration;

use event_bus::Transience;
use events::primitives::CustomerId;

use crate::digest::{ContentDigest, DigestBuilder};
use crate::prompt::PromptDescriptor;

/// Who is speaking in one turn of the conversation.
///
/// No `System` variant: a system prompt is not a turn, it is the
/// [`CompletionRequest::system`] field — which is also where prompt caching
/// puts its breakpoint (§20.4's prompts are versioned artifacts, i.e. a stable
/// prefix worth caching).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Assistant,
}

/// One turn of the conversation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Message {
    pub role: Role,
    pub content: String,
}

impl Message {
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: content.into(),
        }
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: Role::Assistant,
            content: content.into(),
        }
    }
}

/// How much thinking the model does before answering.
///
/// Default [`Thinking::Adaptive`]: the copilot's work — reading a whole audit
/// stream and writing a grounded narrative, or turning prose into a rule that
/// must compile — is exactly the "remotely complicated" case adaptive thinking
/// exists for. Depth is tuned with [`Effort`], not with a token budget: fixed
/// thinking budgets are removed on the current models and are rejected there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Thinking {
    /// The model decides when and how deeply to think. `display` controls
    /// whether a readable *summary* of the reasoning comes back; the raw chain
    /// of thought is never returned by any model.
    #[default]
    Adaptive,
    /// Adaptive thinking with the summary returned. Only worth asking for when
    /// something will actually show it to a human — the summary is billed the
    /// same either way, but it is dead weight in a log.
    AdaptiveSummarized,
    /// No thinking. Present because the seam should not decide for a caller
    /// that has a cheap, mechanical prompt — but prefer
    /// [`Effort::Low`] with thinking on, which is cheaper *and* avoids the
    /// disabled-thinking failure modes (reasoning leaking into the visible
    /// answer).
    Disabled,
}

/// The overall token spend / thoroughness dial (`output_config.effort`).
///
/// `None` on a request means "don't send the field" — the API's own default
/// (`high`). Named rather than numeric because these are the API's five
/// levels, not a scale we invented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effort {
    Low,
    Medium,
    High,
    XHigh,
    Max,
}

impl Effort {
    /// The wire string (`XHigh` → `"xhigh"`).
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Effort::Low => "low",
            Effort::Medium => "medium",
            Effort::High => "high",
            Effort::XHigh => "xhigh",
            Effort::Max => "max",
        }
    }
}

impl std::str::FromStr for Effort {
    type Err = UnknownEffort;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "low" => Ok(Effort::Low),
            "medium" => Ok(Effort::Medium),
            "high" => Ok(Effort::High),
            "xhigh" => Ok(Effort::XHigh),
            "max" => Ok(Effort::Max),
            other => Err(UnknownEffort {
                value: other.to_owned(),
            }),
        }
    }
}

/// A configured effort level that isn't one of the API's five — caught at
/// boot by [`crate::LlmConfig::from_env`], never at first call.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown effort level {value:?} (expected low|medium|high|xhigh|max)")]
pub struct UnknownEffort {
    pub value: String,
}

/// The versioned system prompt for one call (§20.4: prompts are checked-in,
/// hashed artifacts, stamped into every draft alongside the model id).
///
/// `cache` marks it as a prompt-caching breakpoint. That is the right default
/// for this crate's workload — the same prompt artifact fronts every incident
/// in a backfill, and it is by far the largest stable prefix in the request —
/// but it is a *request* to cache, and prefixes below the model's minimum
/// simply won't cache. Verify with [`TokenUsage::cache_read_input_tokens`]
/// rather than assuming.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemPrompt {
    pub text: String,
    pub cache: bool,
}

impl SystemPrompt {
    /// A cached system prompt — the default for a versioned prompt artifact.
    pub fn cached(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            cache: true,
        }
    }

    /// An uncached system prompt, for a one-off or a prompt small enough that
    /// caching it cannot pay for itself.
    pub fn uncached(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            cache: false,
        }
    }
}

/// One completion to ask for.
///
/// Built through the chained constructors rather than a literal, so adding a
/// knob later is not a breaking change at every call site.
#[derive(Debug, Clone, PartialEq)]
pub struct CompletionRequest {
    /// What this call is *for*, as a metrics label. Keep the value set small
    /// and static (`"incident_narrative"`, `"rule_draft"`) — it is a
    /// Prometheus label, so anything per-incident or per-customer here is a
    /// cardinality incident.
    pub purpose: &'static str,
    /// The versioned prompt artifact this call runs, when it has one (§20.4).
    /// `None` only for the raw path — a boot smoke call, or a test. Carried so
    /// the draft event can be stamped with the exact prompt that produced it,
    /// and so the request digest changes when the prompt is edited underneath
    /// its version.
    pub prompt: Option<&'static PromptDescriptor>,
    pub system: Option<SystemPrompt>,
    pub messages: Vec<Message>,
    /// Overrides [`crate::LlmConfig::max_tokens`] for this one call.
    pub max_tokens: Option<u32>,
    pub thinking: Thinking,
    /// Overrides [`crate::LlmConfig::effort`] for this one call.
    pub effort: Option<Effort>,
    /// A JSON Schema the answer must validate against (`output_config.format`)
    /// — how t4 constrains a draft to the rule engine's wire form. Note what
    /// this is *not*: a guarantee the rule is sensible. The schema constrains
    /// shape; §20.4's safety argument rests on the draft then compiling
    /// through the rule engine's existing parse boundary.
    pub json_schema: Option<serde_json::Value>,
    /// Who the token usage is billed to (§13). `None` for platform-internal
    /// work with no customer in scope — the same `Option` discipline every
    /// other metering producer follows.
    pub customer_id: Option<CustomerId>,
}

impl CompletionRequest {
    /// A single-turn request: one user message, everything else defaulted.
    pub fn new(purpose: &'static str, prompt: impl Into<String>) -> Self {
        Self {
            purpose,
            prompt: None,
            system: None,
            messages: vec![Message::user(prompt)],
            max_tokens: None,
            thinking: Thinking::default(),
            effort: None,
            json_schema: None,
            customer_id: None,
        }
    }

    /// A multi-turn request. Callers that keep their own history hand it in
    /// whole; the seam is stateless and never accumulates a conversation of
    /// its own.
    pub fn with_messages(purpose: &'static str, messages: Vec<Message>) -> Self {
        Self {
            messages,
            ..Self::new(purpose, String::new())
        }
    }

    /// The governed path: purpose and system prompt both come from one
    /// versioned artifact (§20.4).
    ///
    /// Prefer this everywhere a real capability calls the model. It is not
    /// merely convenient — it makes three things impossible: a purpose label
    /// that names a different capability than the prompt serves, a prompt
    /// nobody can attribute a draft to, and an untracked edit to a live
    /// prompt (the artifact's digest is folded into
    /// [`digest`](Self::digest), so an edit is a different request and a
    /// different cache entry).
    pub fn for_prompt(prompt: &'static PromptDescriptor, user: impl Into<String>) -> Self {
        Self {
            purpose: prompt.purpose(),
            prompt: Some(prompt),
            system: Some(prompt.as_system()),
            ..Self::new(prompt.purpose(), user)
        }
    }

    /// Replace the conversation wholesale — for a caller that built its turns
    /// through [`crate::prompt::grounded_message`] (the fenced, untrusted-data
    /// form) rather than from a single string.
    pub fn messages(mut self, messages: Vec<Message>) -> Self {
        self.messages = messages;
        self
    }

    pub fn system(mut self, system: SystemPrompt) -> Self {
        self.system = Some(system);
        self
    }

    pub fn max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }

    pub fn thinking(mut self, thinking: Thinking) -> Self {
        self.thinking = thinking;
        self
    }

    pub fn effort(mut self, effort: Effort) -> Self {
        self.effort = Some(effort);
        self
    }

    pub fn json_schema(mut self, schema: serde_json::Value) -> Self {
        self.json_schema = Some(schema);
        self
    }

    /// Bill this call's tokens to `customer_id` (§13).
    pub fn for_customer(mut self, customer_id: CustomerId) -> Self {
        self.customer_id = Some(customer_id);
        self
    }

    /// A content hash over **everything that could change the answer**.
    ///
    /// Two jobs, and the second is why it is a real digest with
    /// length-prefixed fields rather than a convenience hash:
    ///
    /// * **provenance** — one half of the `(model, prompt, request)` triple a
    ///   draft event is stamped with, the direct analogue of a detector's
    ///   `(id, version, config_hash)`;
    /// * **the cache key** — and a cache key that collides across tenants is a
    ///   data leak, not a stale read. `customer_id` is folded in for exactly
    ///   that reason: two customers asking the identical question about the
    ///   identical incident must not be able to share an entry, because the
    ///   *prompt text* differs by the data each is entitled to see.
    ///
    /// The prompt artifact contributes its digest, not just its id, so editing
    /// a prompt without bumping its version still busts the cache.
    pub fn digest(&self) -> ContentDigest {
        let mut builder = DigestBuilder::new()
            .text("llm.request.v1")
            .text(self.purpose)
            .optional_text(self.prompt.map(|p| p.id()).as_deref())
            .optional_text(self.prompt.map(|p| p.digest().to_hex()).as_deref())
            .optional_text(self.system.as_ref().map(|s| s.text.as_str()))
            .optional_text(self.customer_id.map(|c| c.to_string()).as_deref())
            .optional_text(self.max_tokens.map(|m| m.to_string()).as_deref())
            .text(match self.thinking {
                Thinking::Adaptive => "adaptive",
                Thinking::AdaptiveSummarized => "adaptive+summary",
                Thinking::Disabled => "disabled",
            })
            .optional_text(self.effort.map(|e| e.as_wire_str()))
            // `serde_json::Map` is a `BTreeMap` in this build (the
            // `preserve_order` feature is off), so a schema serialises with
            // sorted keys — the same schema always renders the same bytes.
            .optional_text(self.json_schema.as_ref().map(|s| s.to_string()).as_deref());
        for message in &self.messages {
            builder = builder
                .text(match message.role {
                    Role::User => "user",
                    Role::Assistant => "assistant",
                })
                .text(&message.content);
        }
        builder.finish()
    }
}

/// Why the model stopped.
///
/// Every variant except [`StopReason::EndTurn`] means the text is not a
/// complete answer, which is why this is a typed field a caller must look at
/// rather than a string it can ignore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// The model finished normally — the only reason on which the text is a
    /// complete answer.
    EndTurn,
    /// The output hit `max_tokens`. The text is truncated mid-thought; a
    /// caller that stores it stores a lie. Raise `max_tokens` and re-ask.
    MaxTokens,
    /// A safety classifier or the model itself declined. `category` is
    /// informational, an *open* set, and may be absent even on a refusal —
    /// branch on the variant, never on the category.
    Refusal { category: Option<String> },
    /// Anything else the API reports (`stop_sequence`, `tool_use`,
    /// `pause_turn`, or a reason newer than this build). Kept open rather than
    /// exhaustive so a new stop reason is a value to log, not a deserialization
    /// failure — the same forward-compatibility stance the event schema takes.
    Other(String),
}

impl StopReason {
    /// Whether the text is a complete answer. The one-line guard a caller
    /// should apply before reading [`Completion::text`].
    pub fn is_complete(&self) -> bool {
        matches!(self, StopReason::EndTurn)
    }

    /// Low-cardinality label/log value.
    pub fn as_str(&self) -> &str {
        match self {
            StopReason::EndTurn => "end_turn",
            StopReason::MaxTokens => "max_tokens",
            StopReason::Refusal { .. } => "refusal",
            StopReason::Other(other) => other,
        }
    }
}

/// What one call consumed, straight from the API's `usage` object.
///
/// Four counters and not one total, because they are four different prices:
/// cache writes cost more than fresh input, cache reads cost a fraction of it,
/// and output costs several times either. A single "tokens" number cannot be
/// turned into a bill, so the metering path keeps them apart all the way onto
/// the wire (§13 — one SKU per rate).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TokenUsage {
    /// Input tokens that were neither written to nor read from cache.
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Input tokens written into the prompt cache on this call.
    pub cache_creation_input_tokens: u64,
    /// Input tokens served *from* the prompt cache. Zero across repeated
    /// calls with the same system prompt means caching is silently not
    /// happening — see [`SystemPrompt`].
    pub cache_read_input_tokens: u64,
}

impl TokenUsage {
    /// Every token this call touched. For dashboards and budget alarms — never
    /// for billing, which needs the four rates separately.
    pub fn total(&self) -> u64 {
        self.input_tokens
            + self.output_tokens
            + self.cache_creation_input_tokens
            + self.cache_read_input_tokens
    }
}

/// One completed call.
#[derive(Debug, Clone, PartialEq)]
pub struct Completion {
    /// The concatenated text blocks of the answer. Thinking blocks are *not*
    /// included: they are the model's reasoning, not its answer, and nothing
    /// downstream of this seam should be able to quote them as if they were.
    /// Empty on a pre-output refusal.
    pub text: String,
    pub stop_reason: StopReason,
    /// The model that actually answered, as reported by the API — not the one
    /// the request asked for. With server-side fallbacks enabled those differ
    /// when a refusal is rescued, and §20.4 requires the draft event to be
    /// stamped with the model that really produced it.
    pub model: String,
    pub usage: TokenUsage,
}

/// Why a call did not produce a completion.
///
/// A closed classification, because the two questions a caller asks — "is this
/// worth retrying?" and "what do I put on the failure counter?" — must be
/// answerable without string-matching a provider message.
#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    /// The request never reached the API, or the response never came back
    /// (connect failure, TLS, read timeout). Transient.
    #[error("llm transport failure: {reason}")]
    Transport { reason: String },

    /// Rate limited (429). Transient, and the API usually says how long to
    /// wait — see [`LlmError::retry_after`].
    #[error("llm rate limited{}", .retry_after.map(|d| format!(" (retry after {}s)", d.as_secs())).unwrap_or_default())]
    RateLimited { retry_after: Option<Duration> },

    /// The service failed or is overloaded (5xx, 529). Transient.
    #[error("llm service unavailable: {status} {reason}")]
    Unavailable { status: u16, reason: String },

    /// The credential was rejected (401/403). Permanent: every retry in the
    /// process's lifetime will fail identically, and hammering a rejected key
    /// is how an account gets locked.
    #[error("llm authentication rejected: {reason}")]
    Auth { reason: String },

    /// The API rejected the request as invalid (400/404/413/422 — a schema we
    /// got wrong, a prompt over the context window, a model id that does not
    /// exist). Permanent: it is a bug on our side, identical on every retry.
    #[error("llm request rejected: {status} {reason}")]
    Invalid { status: u16, reason: String },

    /// A 200 whose body we could not make sense of. Permanent for this
    /// response; treated as a bug here or a wire change, both of which need a
    /// human.
    #[error("llm response could not be decoded: {reason}")]
    Decode { reason: String },

    /// Admission control refused the call before it was made: this process is
    /// already at its in-flight ceiling, or past a spend ceiling. Shedding
    /// rather than queueing is deliberate — an unbounded wait queue is how one
    /// caller's burst becomes everyone's latency (the §19 bulkhead argument).
    ///
    /// Transient in the sense that matters to the queue above (it clears with
    /// time), but **never worth retrying in-process**: the ceiling this call
    /// just hit is still there a second later.
    #[error("llm call shed: {reason}")]
    Shed { reason: &'static str },

    /// The circuit breaker is open — the provider has been failing, and this
    /// call is refused without being attempted so a sick dependency is not
    /// hammered and this worker is not spent on a timeout.
    #[error("llm circuit breaker is open")]
    CircuitOpen,

    /// Transient faults kept coming until the attempt budget ran out, the
    /// provider asked for a wait longer than this process will hold a worker,
    /// or shutdown cut the backoff short. Carries the last one so the log says
    /// what was actually failing.
    #[error("llm call failed after {attempts} attempt(s): {last}")]
    Exhausted {
        attempts: u32,
        #[source]
        last: Box<LlmError>,
    },
}

impl LlmError {
    /// How long the API asked us to wait, when it said so (`retry-after`).
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            LlmError::RateLimited { retry_after } => *retry_after,
            LlmError::Exhausted { last, .. } => last.retry_after(),
            _ => None,
        }
    }

    /// The low-cardinality `reason` label for the failure counter — the same
    /// role `InferenceErrorKind::as_str` plays for the serving seam. An
    /// [`LlmError::Exhausted`] reports what it was exhausted *by*, so a run of
    /// rate limiting doesn't hide behind a generic "exhausted" bucket.
    pub fn reason(&self) -> &'static str {
        match self {
            LlmError::Transport { .. } => "transport",
            LlmError::RateLimited { .. } => "rate_limited",
            LlmError::Unavailable { .. } => "unavailable",
            LlmError::Auth { .. } => "auth",
            LlmError::Invalid { .. } => "invalid",
            LlmError::Decode { .. } => "decode",
            LlmError::Shed { .. } => "shed",
            LlmError::CircuitOpen => "circuit_open",
            LlmError::Exhausted { last, .. } => last.reason(),
        }
    }

    /// Whether retrying **right now**, in this process, could plausibly help.
    ///
    /// Deliberately narrower than [`Transience::is_transient`], and the
    /// distinction is the whole point: *there are two clocks*. An in-process
    /// retry loop rides out a blip on a seconds clock; the job queue above
    /// re-runs work on a minutes-to-hours clock. A shed call and an open
    /// breaker are transient on the second clock and pointless on the first —
    /// the ceiling or the outage that caused them is still there in 200ms, and
    /// retrying into it spends the attempt budget for nothing.
    ///
    /// Collapsing the two would give a busy process a retry storm against its
    /// own bulkhead.
    pub fn retry_now(&self) -> bool {
        match self {
            LlmError::Transport { .. }
            | LlmError::RateLimited { .. }
            | LlmError::Unavailable { .. } => true,
            LlmError::Shed { .. }
            | LlmError::CircuitOpen
            | LlmError::Auth { .. }
            | LlmError::Invalid { .. }
            | LlmError::Decode { .. } => false,
            // Already retried to exhaustion by an inner layer.
            LlmError::Exhausted { .. } => false,
        }
    }
}

impl Transience for LlmError {
    /// The workspace's one retry/skip question, answered for this seam:
    /// network faults, rate limits and 5xx can succeed later; a rejected
    /// credential, a malformed request and an undecodable body cannot.
    ///
    /// [`LlmError::Exhausted`] stays classified by its cause on purpose. The
    /// backend's *own* bounded retry is spent, but the consumer loop above
    /// this seam is a different, much longer clock — a broker-level redelivery
    /// minutes later is exactly the right response to a rate limit, and the
    /// wrong response to a 400.
    fn is_transient(&self) -> bool {
        match self {
            LlmError::Transport { .. }
            | LlmError::RateLimited { .. }
            | LlmError::Unavailable { .. }
            // Both clear on their own: the in-flight ceiling drains, the
            // breaker probes back to closed. The queue above should re-run
            // this work later — see `retry_now` for why *this* process should
            // not.
            | LlmError::Shed { .. }
            | LlmError::CircuitOpen => true,
            LlmError::Auth { .. } | LlmError::Invalid { .. } | LlmError::Decode { .. } => false,
            LlmError::Exhausted { last, .. } => last.is_transient(),
        }
    }
}

/// The LLM seam (§20.4).
///
/// Object-safe (the `EventSink`/`InferenceEngine` discipline): the copilot
/// holds an `Arc<dyn LlmClient>` resolved once at boot and never learns what
/// is behind it — so the logic that matters (grounding a claim in event ids,
/// compiling a drafted rule) is unit-testable against
/// [`crate::test_util::StubClient`] with no network, no key, and no cost.
#[async_trait::async_trait]
pub trait LlmClient: Send + Sync + std::fmt::Debug {
    /// The model id this client will ask for, for stamping into a draft event
    /// *before* the call (§20.4). The model that actually answered is
    /// [`Completion::model`], and with fallbacks enabled the two can differ —
    /// prefer the response's when recording what produced a draft.
    fn model(&self) -> &str;

    /// Run one completion. Already retried per this backend's policy; an `Err`
    /// is a final verdict for this attempt at this call site.
    async fn complete(&self, request: &CompletionRequest) -> Result<Completion, LlmError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transience_splits_our_bugs_from_their_blips() {
        assert!(LlmError::Transport {
            reason: "connection reset".into()
        }
        .is_transient());
        assert!(LlmError::RateLimited { retry_after: None }.is_transient());
        assert!(LlmError::Unavailable {
            status: 529,
            reason: "overloaded".into()
        }
        .is_transient());

        assert!(!LlmError::Auth {
            reason: "invalid x-api-key".into()
        }
        .is_transient());
        assert!(!LlmError::Invalid {
            status: 400,
            reason: "max_tokens too large".into()
        }
        .is_transient());
        assert!(!LlmError::Decode {
            reason: "missing usage".into()
        }
        .is_transient());
    }

    /// The interesting half of the classification: a spent attempt budget is
    /// still transient *if the thing that spent it was*, because the consumer
    /// loop above retries on a far longer clock than the backend does.
    #[test]
    fn exhausted_inherits_the_classification_and_reason_of_its_cause() {
        let rate_limited = LlmError::Exhausted {
            attempts: 3,
            last: Box::new(LlmError::RateLimited {
                retry_after: Some(Duration::from_secs(12)),
            }),
        };
        assert!(rate_limited.is_transient());
        assert_eq!(rate_limited.reason(), "rate_limited");
        assert_eq!(rate_limited.retry_after(), Some(Duration::from_secs(12)));

        let rejected = LlmError::Exhausted {
            attempts: 1,
            last: Box::new(LlmError::Invalid {
                status: 400,
                reason: "bad schema".into(),
            }),
        };
        assert!(!rejected.is_transient());
        assert_eq!(rejected.reason(), "invalid");
    }

    #[test]
    fn only_end_turn_is_a_complete_answer() {
        assert!(StopReason::EndTurn.is_complete());
        assert!(!StopReason::MaxTokens.is_complete());
        assert!(!StopReason::Refusal { category: None }.is_complete());
        assert!(!StopReason::Other("tool_use".into()).is_complete());
    }

    #[test]
    fn effort_round_trips_through_its_wire_string() {
        for effort in [
            Effort::Low,
            Effort::Medium,
            Effort::High,
            Effort::XHigh,
            Effort::Max,
        ] {
            assert_eq!(
                effort.as_wire_str().parse::<Effort>().expect("round trip"),
                effort
            );
        }
        assert!("enormous".parse::<Effort>().is_err());
    }

    #[test]
    fn token_usage_totals_all_four_rates() {
        let usage = TokenUsage {
            input_tokens: 10,
            output_tokens: 3,
            cache_creation_input_tokens: 100,
            cache_read_input_tokens: 1_000,
        };
        assert_eq!(usage.total(), 1_113);
    }
}
