//! The shared in-memory [`LlmClient`] double, behind the `test-util` feature
//! (`llm = { workspace = true, features = ["test-util"] }`).
//!
//! The seam's whole point, expressed as a type: the copilot's interesting
//! logic — grounding every claim in event ids, compiling a drafted rule
//! through the rule engine's parse boundary, flipping a draft's approval state
//! — is testable against a scripted answer, with no network, no API key, and
//! no cost. That matters more here than for most doubles: the alternative is a
//! test suite that is nondeterministic *and* bills.
//!
//! ```
//! # use llm::{CompletionRequest, LlmClient};
//! # use llm::test_util::StubClient;
//! let client = StubClient::answering("the narrative");
//! let runtime = tokio::runtime::Builder::new_current_thread().build()?;
//!
//! let completion =
//!     runtime.block_on(client.complete(&CompletionRequest::new("test", "draft")))?;
//!
//! assert_eq!(completion.text, "the narrative");
//! assert_eq!(client.requests().len(), 1);
//! # Ok::<_, Box<dyn std::error::Error>>(())
//! ```

use std::sync::{Arc, Mutex};

use crate::client::{Completion, CompletionRequest, LlmClient, LlmError, StopReason, TokenUsage};
use crate::config::DEFAULT_MODEL;

/// One scripted outcome.
///
/// A failure is a *closure* rather than a stored value because [`LlmError`]
/// is deliberately not `Clone` (it carries a boxed cause), and because a
/// retry test wants a fresh error per attempt anyway.
#[derive(Clone)]
enum Reply {
    Answer(Box<Completion>),
    Fail(Arc<dyn Fn() -> LlmError + Send + Sync>),
}

/// An [`LlmClient`] that answers from a script and records what it was asked.
///
/// The script is consumed in order; once it runs out, the **last** entry
/// repeats forever. So the common cases stay one-liners
/// ([`StubClient::answering`] answers the same thing every time) while a
/// multi-step interaction is still expressible ([`StubClient::sequence`]).
pub struct StubClient {
    model: String,
    script: Vec<Reply>,
    calls: Mutex<Vec<CompletionRequest>>,
}

impl std::fmt::Debug for StubClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StubClient")
            .field("model", &self.model)
            .field("scripted_replies", &self.script.len())
            .field(
                "calls",
                &self.calls.lock().map(|c| c.len()).unwrap_or_default(),
            )
            .finish()
    }
}

impl StubClient {
    fn new(script: Vec<Reply>) -> Self {
        Self {
            model: DEFAULT_MODEL.to_owned(),
            script,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Always answer `text`, `end_turn`, no token usage.
    pub fn answering(text: impl Into<String>) -> Self {
        Self::new(vec![Reply::Answer(Box::new(Completion {
            text: text.into(),
            stop_reason: StopReason::EndTurn,
            model: DEFAULT_MODEL.to_owned(),
            usage: TokenUsage::default(),
        }))])
    }

    /// Always fail with a freshly-built error — the retry/classification path.
    pub fn failing(make_error: impl Fn() -> LlmError + Send + Sync + 'static) -> Self {
        Self::new(vec![Reply::Fail(Arc::new(make_error))])
    }

    /// Answer each [`Completion`] in turn, then repeat the last one.
    pub fn sequence(completions: Vec<Completion>) -> Self {
        assert!(
            !completions.is_empty(),
            "a scripted StubClient needs at least one completion"
        );
        Self::new(
            completions
                .into_iter()
                .map(|c| Reply::Answer(Box::new(c)))
                .collect(),
        )
    }

    /// Fail the first `failures` calls, then answer `text` from then on — the
    /// shape a "recovers after a blip" test needs.
    pub fn failing_then_answering(
        failures: usize,
        make_error: impl Fn() -> LlmError + Send + Sync + 'static,
        text: impl Into<String>,
    ) -> Self {
        let make_error = Arc::new(make_error);
        let mut script: Vec<Reply> = (0..failures)
            .map(|_| Reply::Fail(make_error.clone()))
            .collect();
        script.push(Reply::Answer(Box::new(Completion {
            text: text.into(),
            stop_reason: StopReason::EndTurn,
            model: DEFAULT_MODEL.to_owned(),
            usage: TokenUsage::default(),
        })));
        Self::new(script)
    }

    /// Attach token usage to every scripted answer — what the metering
    /// decorator's tests bill against.
    pub fn with_usage(mut self, usage: TokenUsage) -> Self {
        for reply in &mut self.script {
            if let Reply::Answer(completion) = reply {
                completion.usage = usage;
            }
        }
        self
    }

    /// Make every scripted answer stop for `stop_reason` — a truncation or a
    /// refusal, the two outcomes a caller must not treat as an answer.
    pub fn with_stop_reason(mut self, stop_reason: StopReason) -> Self {
        for reply in &mut self.script {
            if let Reply::Answer(completion) = reply {
                completion.stop_reason = stop_reason.clone();
            }
        }
        self
    }

    /// Report a different model than the default — e.g. to stand in for a
    /// refusal rescued by a server-side fallback, where the model that
    /// answered is not the one that was asked.
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        for reply in &mut self.script {
            if let Reply::Answer(completion) = reply {
                completion.model = self.model.clone();
            }
        }
        self
    }

    /// Every request this client was given, in order — so a test can assert on
    /// the *prompt* (that the audit stream was rendered into it, that the
    /// schema was attached, that the customer was named) and not only on what
    /// came back.
    pub fn requests(&self) -> Vec<CompletionRequest> {
        self.calls.lock().expect("stub lock").clone()
    }

    /// How many completions have been asked for.
    pub fn call_count(&self) -> usize {
        self.calls.lock().expect("stub lock").len()
    }
}

#[async_trait::async_trait]
impl LlmClient for StubClient {
    fn model(&self) -> &str {
        &self.model
    }

    async fn complete(&self, request: &CompletionRequest) -> Result<Completion, LlmError> {
        let index = {
            let mut calls = self.calls.lock().expect("stub lock");
            calls.push(request.clone());
            calls.len() - 1
        };
        // Past the end of the script, the last entry stands.
        match &self.script[index.min(self.script.len() - 1)] {
            Reply::Answer(completion) => Ok((**completion).clone()),
            Reply::Fail(make_error) => Err(make_error()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_script_runs_out_into_its_last_entry() {
        let client = StubClient::failing_then_answering(
            2,
            || LlmError::RateLimited { retry_after: None },
            "eventually",
        );
        let request = CompletionRequest::new("test", "go");

        assert!(client.complete(&request).await.is_err());
        assert!(client.complete(&request).await.is_err());
        assert_eq!(client.complete(&request).await.unwrap().text, "eventually");
        assert_eq!(client.complete(&request).await.unwrap().text, "eventually");
        assert_eq!(client.call_count(), 4);
    }

    #[tokio::test]
    async fn requests_are_recorded_for_prompt_assertions() {
        let client = StubClient::answering("ok");
        client
            .complete(&CompletionRequest::new(
                "incident_narrative",
                "event 7 happened",
            ))
            .await
            .unwrap();

        let requests = client.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].purpose, "incident_narrative");
        assert_eq!(requests[0].messages[0].content, "event 7 happened");
    }
}
