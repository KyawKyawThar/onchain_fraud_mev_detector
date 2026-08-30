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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::batch::{
    BatchClient, BatchCounts, BatchId, BatchItem, BatchItemOutcome, BatchOutcome, BatchState,
    BatchStatus, BatchSubmission,
};
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

// ── The Batch API double ──────────────────────────────────────────────────

/// An in-memory [`BatchClient`] whose whole 24-hour lifecycle runs in
/// microseconds.
///
/// The backfill's interesting logic is the *lifecycle*: submit, survive a
/// restart, poll, land each item by `custom_id`, and never fetch a batch's
/// results twice. None of that is testable against a real provider inside a
/// test suite — the fastest real batch still takes minutes — so this double is
/// the only way that code is covered at all.
///
/// By default every submitted item answers with the same text once the batch
/// is polled [`ready_after`](StubBatchClient::ready_after) times; individual
/// `custom_id`s can be scripted to any other outcome
/// ([`with_outcome`](StubBatchClient::with_outcome)).
pub struct StubBatchClient {
    model: String,
    answer: String,
    usage: TokenUsage,
    /// Polls a batch reports `in_progress` before it ends — how a test drives
    /// "the backfill waited, then landed".
    ready_after: usize,
    scripted: Mutex<HashMap<String, BatchItemOutcome>>,
    batches: Mutex<Vec<StubBatch>>,
    /// Every `results` fetch, by batch id — a test asserts a batch is read
    /// exactly once, because a second read would re-meter tokens.
    fetches: Mutex<Vec<BatchId>>,
    /// `custom_id`s this client leaves *out* of its results stream — the
    /// provider returning fewer results than were submitted, which is the
    /// shape that used to wedge a caller polling until every item was
    /// accounted for.
    omitted: Mutex<Vec<String>>,
    fail_submit: Mutex<Option<Arc<dyn Fn() -> LlmError + Send + Sync>>>,
}

struct StubBatch {
    id: BatchId,
    items: Vec<String>,
    polls: usize,
    canceled: bool,
}

impl std::fmt::Debug for StubBatchClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StubBatchClient")
            .field("model", &self.model)
            .field(
                "batches",
                &self.batches.lock().map(|b| b.len()).unwrap_or_default(),
            )
            .finish_non_exhaustive()
    }
}

impl Default for StubBatchClient {
    fn default() -> Self {
        Self::answering("a backfilled narrative")
    }
}

impl StubBatchClient {
    /// Every item answers `text`, ending as soon as it is first polled.
    pub fn answering(text: impl Into<String>) -> Self {
        Self {
            model: DEFAULT_MODEL.to_owned(),
            answer: text.into(),
            usage: TokenUsage::default(),
            ready_after: 0,
            scripted: Mutex::new(HashMap::new()),
            batches: Mutex::new(Vec::new()),
            fetches: Mutex::new(Vec::new()),
            omitted: Mutex::new(Vec::new()),
            fail_submit: Mutex::new(None),
        }
    }

    /// Report `in_progress` for this many polls before ending.
    pub fn ready_after(mut self, polls: usize) -> Self {
        self.ready_after = polls;
        self
    }

    /// Attach token usage to every answered item — what the batch metering
    /// decorator bills against.
    pub fn with_usage(mut self, usage: TokenUsage) -> Self {
        self.usage = usage;
        self
    }

    /// Script one `custom_id` to a specific outcome (a refusal, an expiry, a
    /// validation error).
    pub fn with_outcome(self, custom_id: impl Into<String>, outcome: BatchItemOutcome) -> Self {
        self.scripted
            .lock()
            .expect("stub lock")
            .insert(custom_id.into(), outcome);
        self
    }

    /// Return results that do not mention this `custom_id`.
    ///
    /// A real provider does this when a result line is malformed, when an item
    /// is dropped, or when a `custom_id` comes back that the caller cannot
    /// parse. The caller has to notice and reconcile — it cannot wait for an
    /// item that is never coming.
    pub fn omitting(self, custom_id: impl Into<String>) -> Self {
        self.omitted
            .lock()
            .expect("stub lock")
            .push(custom_id.into());
        self
    }

    /// Fail every submit — the "the provider was down when the backfill ran"
    /// path.
    pub fn failing_submit(self, make_error: impl Fn() -> LlmError + Send + Sync + 'static) -> Self {
        *self.fail_submit.lock().expect("stub lock") = Some(Arc::new(make_error));
        self
    }

    /// How many batches have been submitted.
    pub fn submitted_batches(&self) -> usize {
        self.batches.lock().expect("stub lock").len()
    }

    /// The `custom_id`s of one submitted batch, in submission order.
    pub fn items_of(&self, index: usize) -> Vec<String> {
        self.batches.lock().expect("stub lock")[index].items.clone()
    }

    /// Every `results` fetch, in order.
    pub fn fetches(&self) -> Vec<BatchId> {
        self.fetches.lock().expect("stub lock").clone()
    }

    fn answer_for(&self, custom_id: &str) -> BatchItemOutcome {
        if let Some(scripted) = self.scripted.lock().expect("stub lock").get(custom_id) {
            return scripted.clone();
        }
        BatchItemOutcome::Answered(Box::new(Completion {
            text: self.answer.clone(),
            stop_reason: StopReason::EndTurn,
            model: self.model.clone(),
            usage: self.usage,
        }))
    }
}

#[async_trait::async_trait]
impl BatchClient for StubBatchClient {
    fn model(&self) -> &str {
        &self.model
    }

    async fn submit(&self, items: &[BatchItem]) -> Result<BatchSubmission, LlmError> {
        if let Some(make_error) = self.fail_submit.lock().expect("stub lock").clone() {
            return Err(make_error());
        }
        let mut batches = self.batches.lock().expect("stub lock");
        let id = BatchId(format!("msgbatch_stub_{}", batches.len()));
        batches.push(StubBatch {
            id: id.clone(),
            items: items.iter().map(|item| item.custom_id.clone()).collect(),
            polls: 0,
            canceled: false,
        });
        Ok(BatchSubmission {
            batch_id: id,
            submitted: items.len(),
        })
    }

    async fn status(&self, batch_id: &BatchId) -> Result<BatchStatus, LlmError> {
        let mut batches = self.batches.lock().expect("stub lock");
        let Some(batch) = batches.iter_mut().find(|batch| &batch.id == batch_id) else {
            return Err(LlmError::Invalid {
                status: 404,
                reason: format!("no batch {batch_id}"),
            });
        };
        let polls = batch.polls;
        batch.polls += 1;
        let ended = polls >= self.ready_after;
        Ok(BatchStatus {
            batch_id: batch_id.clone(),
            state: if batch.canceled {
                BatchState::Canceling
            } else if ended {
                BatchState::Ended
            } else {
                BatchState::InProgress
            },
            counts: BatchCounts {
                processing: if ended { 0 } else { batch.items.len() as u64 },
                succeeded: if ended { batch.items.len() as u64 } else { 0 },
                ..BatchCounts::default()
            },
        })
    }

    async fn results(&self, batch_id: &BatchId) -> Result<Vec<BatchOutcome>, LlmError> {
        self.fetches
            .lock()
            .expect("stub lock")
            .push(batch_id.clone());
        let items = {
            let batches = self.batches.lock().expect("stub lock");
            let Some(batch) = batches.iter().find(|batch| &batch.id == batch_id) else {
                return Err(LlmError::Invalid {
                    status: 404,
                    reason: format!("no batch {batch_id}"),
                });
            };
            batch.items.clone()
        };
        let omitted = self.omitted.lock().expect("stub lock").clone();
        Ok(items
            .into_iter()
            .filter(|custom_id| !omitted.contains(custom_id))
            .map(|custom_id| BatchOutcome {
                outcome: self.answer_for(&custom_id),
                custom_id,
            })
            .collect())
    }

    async fn cancel(&self, batch_id: &BatchId) -> Result<BatchStatus, LlmError> {
        {
            let mut batches = self.batches.lock().expect("stub lock");
            if let Some(batch) = batches.iter_mut().find(|batch| &batch.id == batch_id) {
                batch.canceled = true;
            }
        }
        self.status(batch_id).await
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
