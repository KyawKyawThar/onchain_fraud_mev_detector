//! The historical narrative backfill (§20.4) — every incident in the archive,
//! drafted through the Batch API at **half price**.
//!
//! # Why this is not the worker pool with a bigger queue
//!
//! Drafting the archive is the same work as drafting a live incident and a
//! completely different *job*: thousands of long-context completions, none of
//! which anyone is waiting for. §20.4 says so explicitly — "narrative
//! generation is never latency-critical" — and the Batch API prices exactly
//! that trade at 50%. Running the backfill through the synchronous pool would
//! pay double for a result nobody reads sooner, while spending the org-wide
//! rate limit that live incidents share.
//!
//! So a backfill draft is marked `backfill` at enqueue, the worker pool cannot
//! claim it ([`crate::store::DraftWorkQueue::claim_batch`] is live-only), and
//! this runner drains it on the other side of that split.
//!
//! # The lifecycle, and the one thing that must survive a restart
//!
//! ```text
//!   event-store /v1/replay ──▶ enqueue (idempotent, per incident)
//!                                    │
//!                        claim + render + begin_attempt
//!                                    │
//!                             submit ──▶ batch_id written to every row
//!                                    │        ▲
//!                                 poll ───────┘  (a restart resumes from here)
//!                                    │
//!                         results ──▶ land each item by custom_id
//! ```
//!
//! The `batch_id` write immediately after a submit is the load-bearing step. A
//! batch is a server-side job that outlives this process: without that column
//! a restart would forget a job it has **already paid for** and submit the
//! same thousand drafts again. With it, [`BackfillRunner::resume`] finds every
//! outstanding batch before submitting anything new.
//!
//! # Results are landed by `custom_id`, never by position
//!
//! Batch results come back in arbitrary order. The `custom_id` is the draft
//! id, so each answer lands on the draft it belongs to; a positional match
//! would file narratives against the wrong incidents — the quietest possible
//! catastrophe in a compliance system.
//!
//! # Fetch once
//!
//! A batch's results are fetched exactly once and landed durably in the same
//! pass, because [`llm::MeteredBatchClient`] meters tokens on the fetch. A
//! second fetch would re-bill the same answers into the §13 stream.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use event_bus::Transience;
use events::primitives::IncidentId;
use llm::batch::{BatchClient, BatchId, BatchItem};
use llm::cache::CacheKey;
use tokio_util::sync::CancellationToken;

use crate::audit::{AuditSource, IncidentSource};
use crate::draft::DraftGenerator;
use crate::metrics;
use crate::model::{DraftId, DraftJob, DraftKind};
use crate::store::{DraftBatchQueue, DraftOutcome, DraftQueue};

/// Incidents read from event-store per page.
pub const DEFAULT_PAGE_SIZE: u64 = 500;

/// Drafts submitted in one batch. Well under the API's 100k ceiling on
/// purpose: a batch is atomic in its *deadline*, so a huge one risks the whole
/// job expiring at 24 hours with items unfinished, and a smaller one starts
/// landing answers sooner.
pub const DEFAULT_BATCH_SIZE: usize = 200;

/// How the backfill is paced.
#[derive(Debug, Clone, Copy)]
pub struct BackfillConfig {
    pub batch_size: usize,
    /// How long a claimed backfill draft is leased. Must outlast the batch's
    /// own 24-hour deadline plus the poll that lands it — a lease that expires
    /// while the server is still working would let a second run claim the
    /// draft and submit it again, paying twice for one narrative.
    pub lease: Duration,
    /// Gap between status polls. Minutes, not seconds: a batch takes an hour
    /// or more, and polling it every second is a rate limit spent on nothing.
    pub poll_interval: Duration,
    pub max_attempts: i32,
    pub max_audit_events: usize,
    pub page_size: u64,
}

impl Default for BackfillConfig {
    fn default() -> Self {
        Self {
            batch_size: DEFAULT_BATCH_SIZE,
            // 25 hours: the API's deadline is 24, and a lease that expires the
            // minute the deadline does leaves no room to land the results.
            lease: Duration::from_secs(25 * 60 * 60),
            poll_interval: Duration::from_secs(60),
            max_attempts: 3,
            max_audit_events: crate::audit::DEFAULT_MAX_EVENTS,
            page_size: DEFAULT_PAGE_SIZE,
        }
    }
}

/// What one backfill run did — the operator's report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BackfillReport {
    /// Incidents seen in the window.
    pub scanned: usize,
    /// Drafts newly enqueued (the rest already had one).
    pub enqueued: usize,
    /// Drafts handed to a batch.
    pub submitted: usize,
    /// Items landed onto their drafts.
    pub landed: usize,
    /// Batches submitted.
    pub batches: usize,
}

/// Runs the §20.4 historical backfill.
pub struct BackfillRunner {
    queue: Arc<dyn DraftQueue>,
    store: Arc<dyn DraftBatchQueue>,
    incidents: Arc<dyn IncidentSource>,
    audit: Arc<dyn AuditSource>,
    generator: Arc<dyn DraftGenerator>,
    batch: Arc<dyn BatchClient>,
    config: BackfillConfig,
}

impl std::fmt::Debug for BackfillRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackfillRunner")
            .field("config", &self.config)
            .field("generator", &self.generator)
            .finish_non_exhaustive()
    }
}

impl BackfillRunner {
    pub fn new(
        queue: Arc<dyn DraftQueue>,
        store: Arc<dyn DraftBatchQueue>,
        incidents: Arc<dyn IncidentSource>,
        audit: Arc<dyn AuditSource>,
        generator: Arc<dyn DraftGenerator>,
        batch: Arc<dyn BatchClient>,
        config: BackfillConfig,
    ) -> Self {
        Self {
            queue,
            store,
            incidents,
            audit,
            generator,
            batch,
            config,
        }
    }

    /// The whole run: resume outstanding batches, enqueue the window, then
    /// submit and drain until nothing is left or `shutdown` fires.
    ///
    /// Interruptible at every step, and safe to re-run: the enqueue is
    /// idempotent per incident, and an outstanding batch is resumed rather
    /// than re-submitted.
    pub async fn run(
        &self,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        shutdown: &CancellationToken,
    ) -> anyhow::Result<BackfillReport> {
        let mut report = BackfillReport::default();

        // Before anything is submitted: land what a previous run already paid
        // for. Doing this first also frees those drafts' lease slots.
        report.landed += self.resume(shutdown).await?;

        let enqueued = self.enqueue_window(from, to, shutdown).await?;
        report.scanned += enqueued.scanned;
        report.enqueued += enqueued.enqueued;

        while !shutdown.is_cancelled() {
            let submitted = self.submit_next(shutdown).await?;
            if submitted == 0 {
                break;
            }
            report.submitted += submitted;
            report.batches += 1;
        }

        // Then wait out the batches this run created.
        report.landed += self.drain(shutdown).await?;
        Ok(report)
    }

    /// Enqueue a draft for every incident in the window.
    ///
    /// Idempotent per incident (`ON CONFLICT (kind, subject_id) DO NOTHING`),
    /// so overlapping windows are cheap and a re-run after a partial pass
    /// costs nothing but the read.
    pub async fn enqueue_window(
        &self,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        shutdown: &CancellationToken,
    ) -> anyhow::Result<BackfillReport> {
        let mut report = BackfillReport::default();
        let mut cursor: Option<String> = None;

        loop {
            if shutdown.is_cancelled() {
                break;
            }
            let page = self
                .incidents
                .incidents(from, to, cursor.as_deref(), self.config.page_size)
                .await?;
            for (incident_id, chain) in &page.incidents {
                report.scanned += 1;
                let job = DraftJob::backfilled_narrative(*incident_id, *chain);
                match self.queue.enqueue(&job, Utc::now()).await {
                    Ok(outcome) => {
                        if outcome.is_new() {
                            report.enqueued += 1;
                            metrics::record_backfill_enqueued("queued");
                        } else {
                            // Already drafted (or already queued) — the live
                            // consumer may have got there first, which is
                            // exactly what makes a re-run safe.
                            metrics::record_backfill_enqueued("duplicate");
                        }
                    }
                    Err(err) => {
                        tracing::error!(%incident_id, error = %err, "enqueueing a backfill draft failed");
                    }
                }
            }
            match page.next_cursor {
                Some(next) if !page.incidents.is_empty() => cursor = Some(next),
                _ => break,
            }
        }
        Ok(report)
    }

    /// Claim, render and submit one batch. Returns how many drafts it carried
    /// (`0` when the queue is empty).
    pub async fn submit_next(&self, shutdown: &CancellationToken) -> anyhow::Result<usize> {
        let claimed = self
            .store
            .claim_for_batch(
                self.config.batch_size,
                self.config.lease,
                self.config.max_attempts,
                Utc::now(),
            )
            .await?;
        if claimed.is_empty() {
            return Ok(0);
        }

        let mut items: Vec<BatchItem> = Vec::with_capacity(claimed.len());
        let mut ids: Vec<DraftId> = Vec::with_capacity(claimed.len());

        for job in &claimed {
            if shutdown.is_cancelled() {
                break;
            }
            let draft_id = job.job.draft_id;
            // Read the grounding, render the request, record the digest and
            // the window — the same three steps the worker takes, because a
            // backfilled draft must be the same draft, produced the same way,
            // and checkable by the same rule.
            let audit = match self
                .audit
                .audit_stream(IncidentId(job.job.subject_id), self.config.max_audit_events)
                .await
            {
                Ok(audit) => audit,
                Err(err) => {
                    self.give_back(draft_id, &err, err.is_transient()).await;
                    continue;
                }
            };
            let request = match self.generator.build_request(job, &audit) {
                Ok(request) => request,
                Err(err) => {
                    // Permanent by construction (no grounding, wrong kind) —
                    // failing it here saves the batch a slot it would waste.
                    self.give_back(draft_id, &err, false).await;
                    continue;
                }
            };
            let key = CacheKey::new(self.batch.model(), &request);
            // The same `begin_attempt` the worker makes, through the shared
            // `DraftAttempt` supertrait: the digest gives the answer a row to
            // land on, and the window is what the citation check narrows.
            if let Err(err) = self
                .store
                .begin_attempt(
                    draft_id,
                    &key,
                    request.prompt,
                    &audit.event_ids(),
                    Utc::now(),
                )
                .await
            {
                self.give_back(draft_id, &err, err.is_transient()).await;
                continue;
            }
            items.push(BatchItem::new(draft_id.to_string(), request));
            ids.push(draft_id);
        }

        if items.is_empty() {
            return Ok(0);
        }

        let submission = match self.batch.submit(&items).await {
            Ok(submission) => submission,
            Err(err) => {
                // Nothing was accepted, so every claim goes back to the queue
                // on its own clock rather than sitting leased for 25 hours.
                let transient = err.is_transient();
                for draft_id in &ids {
                    self.give_back(*draft_id, &err, transient).await;
                }
                return Err(err.into());
            }
        };

        // The write that makes a restart survivable (module docs). If it
        // fails, the batch is running and unattributed — loud, because there
        // is nothing else that can recover it.
        if let Err(err) = self
            .store
            .attach_batch(&ids, &submission.batch_id, Utc::now())
            .await
        {
            tracing::error!(
                batch_id = %submission.batch_id,
                error = %err,
                drafts = ids.len(),
                "submitted a batch but could not record its id — it will not be resumed; \
                 cancel it at the provider to avoid paying for an unlandable job"
            );
            return Err(err.into());
        }

        tracing::info!(
            batch_id = %submission.batch_id,
            drafts = submission.submitted,
            "backfill batch submitted"
        );
        Ok(submission.submitted)
    }

    /// Land whatever is already finished, without waiting. Called first in a
    /// run so a restart collects answers a previous process paid for.
    pub async fn resume(&self, shutdown: &CancellationToken) -> anyhow::Result<usize> {
        let mut landed = 0usize;
        for batch_id in self.store.open_batches().await? {
            if shutdown.is_cancelled() {
                break;
            }
            let status = self.batch.status(&batch_id).await?;
            if status.state.is_ended() {
                landed += self.settle(&batch_id).await?;
            } else {
                tracing::info!(
                    batch_id = %batch_id,
                    processing = status.counts.processing,
                    "batch still running; leaving it for the drain"
                );
            }
        }
        Ok(landed)
    }

    /// Poll every outstanding batch until each has ended and been settled.
    ///
    /// # Why this terminates
    ///
    /// Because [`Self::settle`] **closes** every batch it touches, whatever
    /// the results contained. An earlier shape polled `open_batches` and
    /// relied on the drafts moving out of `in_flight` to shrink the set — so a
    /// batch whose results were short by one item (an unparseable JSONL line,
    /// a `custom_id` that is not a draft id, an item the provider never
    /// returned) stayed open forever, was re-fetched on every lap, and,
    /// because the metering decorator bills on `results`, re-billed its whole
    /// token usage each time. A hot loop that also corrupts the invoice.
    ///
    /// Now each pass either ends a batch or finds it still running, so the
    /// open set strictly shrinks and the sleep only guards the "still running"
    /// case.
    pub async fn drain(&self, shutdown: &CancellationToken) -> anyhow::Result<usize> {
        let mut landed = 0usize;
        loop {
            let open = self.store.open_batches().await?;
            if open.is_empty() || shutdown.is_cancelled() {
                break;
            }
            let mut settled = 0usize;
            let mut waiting = 0usize;
            for batch_id in open {
                if shutdown.is_cancelled() {
                    break;
                }
                if self.batch.status(&batch_id).await?.state.is_ended() {
                    landed += self.settle(&batch_id).await?;
                    settled += 1;
                } else {
                    waiting += 1;
                }
            }
            if settled == 0 && waiting == 0 {
                break;
            }
            if settled > 0 {
                // Progress: the open set is strictly smaller, so go straight
                // back round rather than sleeping on work that is ready.
                continue;
            }
            tracing::info!(batches = waiting, "waiting on batches");
            tokio::select! {
                () = shutdown.cancelled() => break,
                () = tokio::time::sleep(self.config.poll_interval) => {}
            }
        }
        Ok(landed)
    }

    /// Consume one ended batch: fetch its results (at most once, ever), land
    /// each onto its draft, release whatever the results did not account for,
    /// and close the batch.
    ///
    /// Closing is unconditional and that is the point — a batch this build
    /// cannot fully account for must still stop being polled, or the drain
    /// above cannot terminate.
    async fn settle(&self, batch_id: &BatchId) -> anyhow::Result<usize> {
        let landed = if self.store.claim_results_fetch(batch_id, Utc::now()).await? {
            self.land(batch_id).await?
        } else {
            // Another process (or an earlier run) already consumed them.
            // Re-fetching would re-meter every answered item into the §13
            // stream, so the only correct move is to leave them and reconcile
            // whatever is still in flight below.
            tracing::info!(
                batch_id = %batch_id,
                "batch results were already consumed; reconciling without re-fetching"
            );
            0
        };

        let stragglers = self
            .store
            .release_batch_stragglers(
                batch_id,
                &format!("batch {batch_id} ended without a result for this draft"),
                Utc::now(),
            )
            .await?;
        let reason = if stragglers == 0 {
            "landed"
        } else {
            "released"
        };
        if stragglers > 0 {
            // Alert on this: it means the provider returned a results stream
            // this build could not match to the drafts it submitted.
            tracing::error!(
                batch_id = %batch_id,
                stragglers,
                "batch ended with drafts it never accounted for; released back to the queue"
            );
            metrics::record_backfill_stragglers(stragglers);
        }
        self.store.close_batch(batch_id, reason, Utc::now()).await?;
        Ok(landed)
    }

    /// Fetch one ended batch's results and land each onto its draft.
    ///
    /// Called only through [`Self::settle`], which holds the fetch claim —
    /// results are read exactly once per batch, because that read is where
    /// `MeteredBatchClient` bills the tokens.
    async fn land(&self, batch_id: &BatchId) -> anyhow::Result<usize> {
        let outcomes = self.batch.results(batch_id).await?;
        let mut landed = 0usize;
        for outcome in outcomes {
            let Ok(draft_id) = outcome.custom_id.parse::<uuid::Uuid>() else {
                tracing::error!(
                    custom_id = %outcome.custom_id,
                    "batch result carries a custom_id that is not a draft id"
                );
                metrics::record_backfill_landed("orphaned");
                continue;
            };
            let label = outcome.outcome.as_wire_str();
            match self
                .store
                .land_batch_outcome(DraftId(draft_id), batch_id, outcome.outcome, Utc::now())
                .await
            {
                // `false` means the row moved on — released, re-submitted, or
                // already reviewed. Counted, not an error: the batch's answer
                // is simply no longer this draft's.
                Ok(true) => {
                    metrics::record_backfill_landed(label);
                    landed += 1;
                }
                Ok(false) => metrics::record_backfill_landed("orphaned"),
                Err(err) => {
                    tracing::error!(%draft_id, error = %err, "landing a batch result failed");
                    metrics::record_backfill_landed("unrecorded");
                }
            }
        }
        tracing::info!(batch_id = %batch_id, landed, "backfill batch landed");
        Ok(landed)
    }

    /// Hand a claimed draft back — released for a transient fault, failed for
    /// a permanent one. Never propagates: one bad draft must not abort a
    /// batch of two hundred.
    async fn give_back(&self, draft_id: DraftId, err: &dyn std::fmt::Display, transient: bool) {
        if transient {
            tracing::warn!(%draft_id, error = %err, "backfill draft deferred");
        } else {
            tracing::error!(%draft_id, error = %err, "backfill draft failed");
        }
        // Transient → back to the queue on its own clock; permanent → failed.
        // The two-clocks split the worker already draws, one level over.
        let outcome = if transient {
            self.store.release(draft_id, Utc::now()).await
        } else {
            self.store
                .finish(
                    draft_id,
                    DraftOutcome::failed(format!("backfill: {err}"), true),
                    Utc::now(),
                )
                .await
                .map(|_| ())
        };
        if let Err(err) = outcome {
            tracing::error!(%draft_id, error = %err, "releasing a backfill claim failed; the lease will expire");
        }
    }
}

/// The kind this runner drafts. Narratives only: a rule draft is a customer's
/// request with a person waiting on it, which is the opposite of what the
/// Batch API is for.
pub const BACKFILL_KIND: DraftKind = DraftKind::IncidentNarrative;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{VecAuditSource, VecIncidentSource};
    use crate::draft::NarrativeDrafter;
    use crate::model::{DraftSource, DraftStatus};
    use crate::store::{DraftFilter, DraftReview};
    use crate::test_util::{envelope, InMemoryDraftStore};
    use events::primitives::Chain;
    use llm::batch::BatchItemOutcome;
    use llm::test_util::StubBatchClient;
    use std::collections::BTreeMap;

    /// The one event every fixture incident's audit stream contains — and the
    /// id a passing narrative has to cite.
    fn grounding_event() -> events::EventEnvelope {
        envelope(0)
    }

    fn answer(event_id: uuid::Uuid) -> String {
        format!(
            "The attacker's transaction preceded the victim's swap in the same block [{event_id}]."
        )
    }

    /// A runner over the in-memory store, with `count` archived incidents.
    fn runner(
        store: &Arc<InMemoryDraftStore>,
        incidents: &[IncidentId],
        client: Arc<StubBatchClient>,
        config: BackfillConfig,
    ) -> BackfillRunner {
        let audit = incidents
            .iter()
            .fold(VecAuditSource::default(), |audit, incident| {
                audit.with_stream(*incident, vec![grounding_event()])
            });
        BackfillRunner::new(
            store.clone(),
            store.clone(),
            Arc::new(VecIncidentSource::new(
                incidents.iter().map(|id| (*id, Chain::ETHEREUM)).collect(),
            )),
            Arc::new(audit),
            Arc::new(NarrativeDrafter::new()),
            client,
            config,
        )
    }

    fn incidents(count: usize) -> Vec<IncidentId> {
        (0..count).map(|_| IncidentId::new()).collect()
    }

    fn config(batch_size: usize) -> BackfillConfig {
        BackfillConfig {
            batch_size,
            page_size: 2,
            poll_interval: Duration::from_millis(1),
            ..BackfillConfig::default()
        }
    }

    /// The whole lifecycle over the doubles: every archived incident ends up
    /// with a ready, grounded draft produced through the batch path.
    #[tokio::test]
    async fn the_archive_is_drafted_through_batches_and_landed_by_custom_id() {
        let shutdown = CancellationToken::new();
        let store = Arc::new(InMemoryDraftStore::default());
        let ids = incidents(3);
        let event_id = grounding_event().event_id;
        let client = Arc::new(StubBatchClient::answering(answer(event_id)));
        let runner = runner(&store, &ids, client.clone(), config(2));

        let report = runner.run(None, None, &shutdown).await.expect("runs");
        assert_eq!((report.scanned, report.enqueued), (3, 3));
        assert_eq!(report.submitted, 3);
        assert_eq!(report.batches, 2, "batch_size 2 over 3 drafts");
        assert_eq!(report.landed, 3);

        let drafts = store.list(&DraftFilter::with_limit(10)).await.unwrap();
        assert_eq!(drafts.len(), 3);
        for draft in &drafts {
            assert_eq!(draft.status, DraftStatus::Ready, "{:?}", draft.last_error);
            assert_eq!(draft.source, DraftSource::Backfill);
            assert_eq!(
                draft.grounded_event_ids,
                vec![event_id],
                "a landed batch answer is narrowed to what it cites, exactly as the \
                 synchronous path is"
            );
            assert!(draft.batch_id.is_some(), "the batch id is durable state");
        }

        // Each batch's results are fetched exactly once: a second fetch would
        // re-bill every answer into the §13 metering stream.
        let mut fetches = client.fetches();
        let before = fetches.len();
        fetches.sort();
        fetches.dedup();
        assert_eq!(fetches.len(), before, "a batch's results are fetched once");
    }

    /// A re-run over the same window enqueues nothing and submits nothing — the
    /// property that makes an interrupted backfill safe to simply run again.
    #[tokio::test]
    async fn a_second_run_over_the_same_window_is_a_no_op() {
        let shutdown = CancellationToken::new();
        let store = Arc::new(InMemoryDraftStore::default());
        let ids = incidents(2);
        let client = Arc::new(StubBatchClient::answering(answer(
            grounding_event().event_id,
        )));
        let runner = runner(&store, &ids, client.clone(), config(10));

        let first = runner.run(None, None, &shutdown).await.unwrap();
        assert_eq!((first.enqueued, first.submitted), (2, 2));

        let second = runner.run(None, None, &shutdown).await.unwrap();
        assert_eq!(second.scanned, 2, "the window is re-read");
        assert_eq!(
            (second.enqueued, second.submitted, second.batches),
            (0, 0, 0),
            "a re-run must not re-draft — or re-bill — what is already drafted"
        );
        assert_eq!(client.submitted_batches(), 1);
    }

    /// An expired item is queued again rather than failed (the deadline says
    /// nothing about the request); a validation error fails outright.
    #[tokio::test]
    async fn an_expired_item_returns_to_the_queue_and_a_rejected_one_fails() {
        let shutdown = CancellationToken::new();
        let store = Arc::new(InMemoryDraftStore::default());
        let ids = incidents(2);
        let event_id = grounding_event().event_id;

        // Enqueue first so the draft ids exist, then script outcomes for them.
        let seed = runner(
            &store,
            &ids,
            Arc::new(StubBatchClient::default()),
            config(10),
        );
        seed.enqueue_window(None, None, &shutdown)
            .await
            .expect("enqueues");
        let drafts = store.list(&DraftFilter::with_limit(10)).await.unwrap();
        let (expired, rejected) = (drafts[0].draft_id, drafts[1].draft_id);

        let client = Arc::new(
            StubBatchClient::answering(answer(event_id))
                .with_outcome(expired.to_string(), BatchItemOutcome::Expired)
                .with_outcome(
                    rejected.to_string(),
                    BatchItemOutcome::Errored {
                        kind: "invalid_request".into(),
                        message: "max_tokens too large".into(),
                        permanent: true,
                    },
                ),
        );
        // The drafts are already queued, so the incident source is empty —
        // but the audit streams must still resolve, or the runner would fail
        // them for want of grounding before any batch outcome was reached.
        let runner = BackfillRunner::new(
            store.clone(),
            store.clone(),
            Arc::new(VecIncidentSource::new(Vec::new())),
            Arc::new(
                ids.iter()
                    .fold(VecAuditSource::default(), |audit, incident| {
                        audit.with_stream(*incident, vec![grounding_event()])
                    }),
            ),
            Arc::new(NarrativeDrafter::new()),
            client,
            config(10),
        );
        runner.run(None, None, &shutdown).await.unwrap();

        let by_id: BTreeMap<_, _> = store
            .list(&DraftFilter::with_limit(10))
            .await
            .unwrap()
            .into_iter()
            .map(|draft| (draft.draft_id, draft))
            .collect();
        assert_eq!(by_id[&expired].status, DraftStatus::Queued);
        assert!(
            by_id[&expired].batch_id.is_none(),
            "a re-runnable draft must not stay attached to a dead batch"
        );
        assert_eq!(by_id[&rejected].status, DraftStatus::Failed);
        assert!(by_id[&rejected]
            .last_error
            .as_ref()
            .is_some_and(|error| error.contains("invalid_request")));
    }

    /// The restart story: a batch submitted by a process that then died is
    /// resumed from the store, never submitted (and paid for) twice.
    #[tokio::test]
    async fn an_outstanding_batch_is_resumed_rather_than_resubmitted() {
        let shutdown = CancellationToken::new();
        let store = Arc::new(InMemoryDraftStore::default());
        let ids = incidents(1);
        let client =
            Arc::new(StubBatchClient::answering(answer(grounding_event().event_id)).ready_after(1));
        let runner = runner(&store, &ids, client.clone(), config(10));

        // Pass 1: enqueue and submit, then "die" before draining.
        runner
            .enqueue_window(None, None, &shutdown)
            .await
            .expect("enqueues");
        assert_eq!(runner.submit_next(&shutdown).await.unwrap(), 1);
        assert_eq!(client.submitted_batches(), 1);

        // Pass 2: a fresh run finds the outstanding batch before submitting.
        let report = runner.run(None, None, &shutdown).await.unwrap();
        assert_eq!(
            client.submitted_batches(),
            1,
            "the batch already paid for must not be submitted again"
        );
        assert_eq!(report.landed, 1);
        assert_eq!(
            store.list(&DraftFilter::with_limit(5)).await.unwrap()[0].status,
            DraftStatus::Ready
        );
    }

    /// The drain must terminate even when a batch never accounts for one of
    /// its drafts.
    ///
    /// This is a regression test for a livelock: `open_batches` used to be
    /// derived from drafts still `in_flight`, so a batch whose results were
    /// short by one item stayed open forever — polled, re-fetched and
    /// (because the metering decorator bills on `results`) **re-billed** on
    /// every lap, with no sleep between them. The timeout is the assertion:
    /// a regression hangs, and a hang that fails in 10s is a test result
    /// rather than a wedged CI job.
    #[tokio::test]
    async fn a_batch_that_never_accounts_for_a_draft_still_terminates() {
        let shutdown = CancellationToken::new();
        let store = Arc::new(InMemoryDraftStore::default());
        let ids = incidents(2);
        let event_id = grounding_event().event_id;

        // Enqueue first so the draft ids exist, then omit one from the results.
        let seed = runner(
            &store,
            &ids,
            Arc::new(StubBatchClient::default()),
            config(10),
        );
        seed.enqueue_window(None, None, &shutdown)
            .await
            .expect("enqueues");
        let drafts = store.list(&DraftFilter::with_limit(10)).await.unwrap();
        let abandoned = drafts[0].draft_id;

        // Audit streams for both incidents, but no incident source: the drafts
        // are already queued, and this run's job is to submit and settle them.
        let client =
            Arc::new(StubBatchClient::answering(answer(event_id)).omitting(abandoned.to_string()));
        let runner = BackfillRunner::new(
            store.clone(),
            store.clone(),
            Arc::new(VecIncidentSource::new(Vec::new())),
            Arc::new(
                ids.iter()
                    .fold(VecAuditSource::default(), |audit, incident| {
                        audit.with_stream(*incident, vec![grounding_event()])
                    }),
            ),
            Arc::new(NarrativeDrafter::new()),
            client.clone(),
            config(10),
        );

        let report = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            runner.run(None, None, &shutdown),
        )
        .await
        .expect("the drain must terminate, not spin on a batch it cannot finish")
        .expect("runs");
        assert_eq!(report.landed, 1, "the item that did come back landed");

        // The one that never came back is queued again, detached from the dead
        // batch, so the next run re-submits it.
        let draft = store.get(abandoned).await.unwrap().unwrap();
        assert_eq!(draft.status, DraftStatus::Queued);
        assert!(draft.batch_id.is_none());
        assert!(draft
            .last_error
            .as_ref()
            .is_some_and(|error| error.contains("without a result")));

        // …and the results were read exactly once, so the answered item's
        // tokens were metered once.
        let fetches = client.fetches();
        assert_eq!(
            fetches.len(),
            1,
            "a short results stream must not be re-read"
        );
    }

    /// The grounding boundary applies to backfilled drafts too: a batched
    /// answer with a fabricated citation is blocked, not filed as ready.
    #[tokio::test]
    async fn a_batched_answer_is_held_to_the_same_citation_check() {
        let shutdown = CancellationToken::new();
        let store = Arc::new(InMemoryDraftStore::default());
        let ids = incidents(1);
        let invented = uuid::Uuid::from_u128(0xDEAD);
        let client = Arc::new(StubBatchClient::answering(answer(invented)));
        let runner = runner(&store, &ids, client, config(10));

        runner.run(None, None, &shutdown).await.unwrap();

        let draft = &store.list(&DraftFilter::with_limit(5)).await.unwrap()[0];
        assert_eq!(draft.status, DraftStatus::Blocked);
        assert!(
            draft
                .last_error
                .as_ref()
                .is_some_and(|error| error.contains("not in its audit window")),
            "{:?}",
            draft.last_error
        );
    }
}
