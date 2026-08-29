//! Configuration for the Anthropic backend, resolved once at boot through the
//! shared [`telemetry::env`] helpers (the workspace's "env access in one spot"
//! discipline) — so a missing key or a typo'd effort level is a refused boot
//! with the variable named in the log, not a failure on the first incident
//! that happens to need a narrative.
//!
//! **The model id is config, never a call-site literal** (§20.4). Every
//! completion in the process asks for the same configured model, and a draft
//! event is stamped with what actually answered — which is how a narrative
//! written in March stays attributable after the default moves on.

use std::time::Duration;

use anyhow::{Context, Result};
use secrecy::SecretString;
use telemetry::env::{parse_or, required};

use crate::admission::AdmissionConfig;
use crate::client::Effort;

/// The default model (§20.4). Anthropic's current flagship: the copilot's work
/// is long-context reading plus careful, structured writing, and this is the
/// tier that does it well. Override per deployment with `LLM_MODEL`.
pub const DEFAULT_MODEL: &str = "claude-opus-5";

/// The public API. Overridable (`ANTHROPIC_BASE_URL`) so a test can point the
/// client at a local stub server, and so a gateway/proxy deployment is config
/// rather than a fork.
pub const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";

/// The API version header every request carries. Pinned, not "latest": the
/// wire shape this crate deserializes is the one this version promises.
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Beta flag for the `fallbacks: "default"` scalar form. The date is part of
/// the flag's identity and is paired with that exact form — the array form
/// uses a *different* flag, and mixing them is a 400. Don't "update" it.
pub const SERVER_SIDE_FALLBACK_BETA: &str = "server-side-fallback-2026-07-01";

/// Non-streaming default. Large enough that a full SAR narrative does not hit
/// the cap (a truncated draft is worse than none — see
/// [`StopReason::MaxTokens`](crate::StopReason::MaxTokens)), small enough to
/// stay well inside the HTTP timeout for a non-streamed response.
const DEFAULT_MAX_TOKENS: u32 = 16_000;

/// Per-request HTTP timeout. Generous by this workspace's standards on
/// purpose: the copilot is a background path with nobody waiting (§20.4 —
/// narrative generation is never latency-critical), and a thinking model on a
/// long audit stream legitimately takes minutes. Nothing on the fast path
/// calls this seam.
const DEFAULT_TIMEOUT_SECS: u64 = 300;

/// Attempts *in total*, not retries after the first. Three is the same budget
/// the webhook/SMTP delivery paths use, and for the same reason: enough to
/// ride out a blip, few enough that a sustained outage surfaces as a failure
/// instead of a hang.
const DEFAULT_MAX_ATTEMPTS: u32 = 3;

/// First backoff, doubled per attempt. Longer than the delivery paths' — a
/// rate limit is the most likely transient here, and rate limits do not clear
/// in 100ms. A `retry-after` from the API always wins over this, within the
/// cap below. Jitter is applied on top (`resilience::Backoff`).
const DEFAULT_RETRY_BACKOFF_MS: u64 = 2_000;

/// Ceiling on the computed backoff, before jitter.
const DEFAULT_RETRY_BACKOFF_MAX_MS: u64 = 30_000;

/// The longest server-directed `retry-after` this process will sleep through.
///
/// Past it the call fails as *transient* and the job queue above reschedules —
/// because holding a worker (and, if the caller is a consumer, its partition)
/// for a provider's quota window is how a rate limit becomes a rebalance loop
/// that re-does and re-bills the work. There are two clocks; this is the
/// boundary.
const DEFAULT_RETRY_AFTER_CAP_SECS: u64 = 30;

/// Consecutive provider faults that open the circuit.
const DEFAULT_BREAKER_FAILURE_THRESHOLD: u32 = 5;

/// How long the circuit stays open before admitting a trial call.
const DEFAULT_BREAKER_OPEN_SECS: u64 = 30;

/// In-flight calls from **this process**. Deliberately small: the provider's
/// limit is org-wide, so `replicas × this` is what actually hits it.
const DEFAULT_MAX_IN_FLIGHT: usize = 4;

/// Distinct requests memoised in-process. `0` disables caching.
const DEFAULT_CACHE_CAPACITY: usize = 512;

/// How long a memoised completion stays valid. Bounded because a prompt's
/// *inputs* can change without its digest changing (an incident's audit stream
/// grows), so an entry that lived forever would answer a stale question.
const DEFAULT_CACHE_TTL_SECS: u64 = 3_600;

/// Everything the Anthropic backend needs.
///
/// `api_key` is a [`SecretString`], so `Debug` redacts it and an explicit
/// `expose_secret()` is required at the one place it becomes a header.
#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub api_key: SecretString,
    pub base_url: String,
    /// The model every request asks for (`LLM_MODEL`, default
    /// [`DEFAULT_MODEL`]).
    pub model: String,
    pub max_tokens: u32,
    pub timeout: Duration,
    /// Total attempts per call, including the first.
    pub max_attempts: u32,
    /// Backoff before the second attempt; doubles from there, jittered.
    pub retry_backoff: Duration,
    /// Ceiling on the computed backoff, before jitter.
    pub retry_backoff_max: Duration,
    /// The longest server-directed `retry-after` this process will sleep
    /// through; past it the work is handed back to the queue above.
    pub retry_after_cap: Duration,
    /// Consecutive provider faults that open the circuit breaker.
    pub breaker_failure_threshold: u32,
    /// How long the breaker stays open before a trial call.
    pub breaker_open_cooldown: Duration,
    /// The in-process bulkhead and optional spend ceiling.
    pub admission: AdmissionConfig,
    /// Distinct requests memoised in-process; `0` disables caching.
    pub cache_capacity: usize,
    /// How long a memoised completion stays valid.
    pub cache_ttl: Duration,
    /// `output_config.effort`, when the deployment wants to pin one. `None`
    /// sends no field and takes the API's default.
    pub effort: Option<Effort>,
    /// Ask the API to rescue a refusal on another model server-side
    /// (`fallbacks: "default"`, routed by refusal category) instead of
    /// returning it to us.
    ///
    /// **On by default**, because the copilot's inputs are exactly the shape
    /// that draws false-positive declines: an incident narrative is a detailed
    /// description of an on-chain attack, written for a financial-crime
    /// report. A refusal on a legitimate compliance draft is a support ticket;
    /// a rescue is a line in the event stamping which model answered. Off
    /// (`LLM_FALLBACKS=false`) for a deployment that would rather see the
    /// refusal.
    pub fallbacks: bool,
}

impl LlmConfig {
    /// Read from the environment, failing at boot on anything missing or
    /// unparseable.
    ///
    /// | Variable | Default |
    /// |---|---|
    /// | `ANTHROPIC_API_KEY` | *required* |
    /// | `ANTHROPIC_BASE_URL` | [`DEFAULT_BASE_URL`] |
    /// | `LLM_MODEL` | [`DEFAULT_MODEL`] |
    /// | `LLM_MAX_TOKENS` | 16000 |
    /// | `LLM_TIMEOUT_SECS` | 300 |
    /// | `LLM_MAX_ATTEMPTS` | 3 |
    /// | `LLM_RETRY_BACKOFF_MS` | 2000 |
    /// | `LLM_RETRY_BACKOFF_MAX_MS` | 30000 |
    /// | `LLM_RETRY_AFTER_CAP_SECS` | 30 |
    /// | `LLM_BREAKER_FAILURE_THRESHOLD` | 5 |
    /// | `LLM_BREAKER_OPEN_SECS` | 30 |
    /// | `LLM_MAX_IN_FLIGHT` | 4 (`0` = unlimited) |
    /// | `LLM_SPEND_CEILING_TOKENS` | 0 (off) |
    /// | `LLM_SPEND_WINDOW_SECS` | 3600 |
    /// | `LLM_CACHE_CAPACITY` | 512 (`0` = off) |
    /// | `LLM_CACHE_TTL_SECS` | 3600 |
    /// | `LLM_EFFORT` | unset (API default) |
    /// | `LLM_FALLBACKS` | true |
    pub fn from_env() -> Result<Self> {
        let effort = match std::env::var("LLM_EFFORT") {
            Ok(raw) if !raw.trim().is_empty() => {
                Some(raw.parse::<Effort>().context("env var LLM_EFFORT")?)
            }
            _ => None,
        };

        Ok(Self {
            api_key: required("ANTHROPIC_API_KEY")?.into(),
            base_url: parse_or("ANTHROPIC_BASE_URL", DEFAULT_BASE_URL.to_owned())?,
            model: parse_or("LLM_MODEL", DEFAULT_MODEL.to_owned())?,
            max_tokens: parse_or("LLM_MAX_TOKENS", DEFAULT_MAX_TOKENS)?,
            timeout: Duration::from_secs(parse_or("LLM_TIMEOUT_SECS", DEFAULT_TIMEOUT_SECS)?),
            max_attempts: parse_or("LLM_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS)?,
            retry_backoff: Duration::from_millis(parse_or(
                "LLM_RETRY_BACKOFF_MS",
                DEFAULT_RETRY_BACKOFF_MS,
            )?),
            retry_backoff_max: Duration::from_millis(parse_or(
                "LLM_RETRY_BACKOFF_MAX_MS",
                DEFAULT_RETRY_BACKOFF_MAX_MS,
            )?),
            retry_after_cap: Duration::from_secs(parse_or(
                "LLM_RETRY_AFTER_CAP_SECS",
                DEFAULT_RETRY_AFTER_CAP_SECS,
            )?),
            breaker_failure_threshold: parse_or(
                "LLM_BREAKER_FAILURE_THRESHOLD",
                DEFAULT_BREAKER_FAILURE_THRESHOLD,
            )?,
            breaker_open_cooldown: Duration::from_secs(parse_or(
                "LLM_BREAKER_OPEN_SECS",
                DEFAULT_BREAKER_OPEN_SECS,
            )?),
            admission: AdmissionConfig {
                max_in_flight: parse_or("LLM_MAX_IN_FLIGHT", DEFAULT_MAX_IN_FLIGHT)?,
                spend_ceiling: parse_or("LLM_SPEND_CEILING_TOKENS", 0_u64)?,
                spend_window: Duration::from_secs(parse_or("LLM_SPEND_WINDOW_SECS", 3_600_u64)?),
            },
            cache_capacity: parse_or("LLM_CACHE_CAPACITY", DEFAULT_CACHE_CAPACITY)?,
            cache_ttl: Duration::from_secs(parse_or("LLM_CACHE_TTL_SECS", DEFAULT_CACHE_TTL_SECS)?),
            effort,
            fallbacks: parse_or("LLM_FALLBACKS", true)?,
        })
    }

    /// The endpoint one completion is POSTed to. Tolerates a trailing slash on
    /// the configured base — a `//v1/messages` 404 is a silly way to fail a
    /// boot smoke call.
    pub fn messages_url(&self) -> String {
        format!("{}/v1/messages", self.base_url.trim_end_matches('/'))
    }

    /// A config for tests and for a local stub server: everything defaulted
    /// except the base URL, with retries and timeouts wound down so a test
    /// asserting the retry path takes milliseconds, not a minute.
    #[cfg(any(test, feature = "test-util"))]
    pub fn for_test(base_url: impl Into<String>) -> Self {
        Self {
            api_key: "test-key".into(),
            base_url: base_url.into(),
            model: DEFAULT_MODEL.to_owned(),
            max_tokens: 1_024,
            timeout: Duration::from_secs(5),
            max_attempts: 2,
            retry_backoff: Duration::from_millis(1),
            retry_backoff_max: Duration::from_millis(2),
            retry_after_cap: Duration::from_secs(30),
            breaker_failure_threshold: 5,
            breaker_open_cooldown: Duration::from_millis(10),
            admission: AdmissionConfig {
                max_in_flight: 4,
                spend_ceiling: 0,
                spend_window: Duration::from_secs(3_600),
            },
            cache_capacity: 0,
            cache_ttl: Duration::from_secs(60),
            effort: None,
            fallbacks: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn the_url_survives_a_trailing_slash() {
        let mut config = LlmConfig::for_test("https://api.anthropic.com/");
        assert_eq!(
            config.messages_url(),
            "https://api.anthropic.com/v1/messages"
        );
        config.base_url = "http://127.0.0.1:8080".into();
        assert_eq!(config.messages_url(), "http://127.0.0.1:8080/v1/messages");
    }

    /// The point of `SecretString`: a config dumped into a boot log must not
    /// carry the key with it.
    #[test]
    fn debug_redacts_the_api_key() {
        let config = LlmConfig::for_test(DEFAULT_BASE_URL);
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("test-key"), "{rendered}");
        assert_eq!(config.api_key.expose_secret(), "test-key");
    }

    /// A garbage effort level fails the boot that set it, naming the variable
    /// — not the first completion three hours later.
    #[test]
    fn an_unparseable_effort_is_a_boot_failure() {
        std::env::set_var("ANTHROPIC_API_KEY", "k");
        std::env::set_var("LLM_EFFORT", "enormous");
        let err = LlmConfig::from_env().expect_err("must reject");
        assert!(format!("{err:#}").contains("LLM_EFFORT"), "{err:#}");
        std::env::remove_var("LLM_EFFORT");
        std::env::remove_var("ANTHROPIC_API_KEY");
    }
}
