//! The worker pool — the slow half of §7's slow path.
//!
//! The consumer records a job and commits; this drains the queue out of band,
//! on its own clock, with no Kafka partition riding on how long a completion
//! takes. Losing that coupling is the entire point of the split.
//!
//! # The loop
//!
//! 1. Lease up to *available concurrency* jobs (`FOR UPDATE SKIP LOCKED`, so
//!    every pod runs the same query and they do not collide).
//! 2. Per job: read the incident's audit stream, render the request, record
//!    the request digest, call the seam, write the outcome.
//! 3. Sleep until the poll interval elapses or the consumer wakes us.
//!
//! The wake is a latency hint only. Polling is the mechanism, because the
//! jobs this pod must eventually run include ones *another* pod enqueued and
//! ones whose lease expired when a pod died — neither of which any local
//! notification can announce.
//!
//! # What a worker never decides
//!
//! It never retries. A transient fault releases the job back to the queue and
//! the *outer* clock re-runs it; a permanent one fails the draft outright.
//! That is the two-clocks split the LLM seam already draws between
//! `Transience::is_transient` ("should the queue above re-run this later?")
//! and `LlmError::retry_now` ("would trying again in 200ms help?"), and
//! holding a lease through a backoff is exactly what it forbids.
//!
//! # Leases and long calls
//!
//! A lease must outlast the longest call a worker can make — the LLM seam's
//! own bounded retry budget times its per-request timeout — or a second pod
//! reclaims a job that is still running and both pay. There is no lease
//! heartbeat: the config check in [`crate::config`] enforces the margin at
//! boot instead, where an operator can see it.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use event_bus::Transience;
use events::primitives::IncidentId;
use llm::cache::CacheKey;
use llm::{LlmClient, LlmError};
use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::audit::{AuditSource, AuditStream};
use crate::capability::{index, DraftCapability, Grounding, RegistryError};
use crate::draft::DraftError;
use crate::metrics;
use crate::model::{ClaimedJob, DraftKind, DraftStatus};
use crate::store::{DraftOutcome, DraftWorkQueue, StoreError};

/// How the pool is sized and paced.
#[derive(Debug, Clone, Copy)]
pub struct PoolConfig {
    /// Jobs this pod runs at once. Small by §20's own guidance — LLM calls
    /// are I/O-bound and the provider's limit is org-wide, so concurrency
    /// here multiplies by the replica count before it reaches the provider.
    pub concurrency: usize,
    /// Backstop poll interval. Covers other pods' enqueues and expired
    /// leases; the consumer's wake covers this pod's own.
    pub poll_interval: Duration,
    /// How long a claim holds a job. Must exceed the longest possible call
    /// (see the module docs).
    pub lease: Duration,
    /// Claims per draft before it is failed rather than re-leased.
    pub max_attempts: i32,
    /// Ceiling on one incident's audit stream (see [`crate::audit`]).
    pub max_audit_events: usize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            concurrency: 2,
            poll_interval: Duration::from_secs(5),
            lease: Duration::from_secs(900),
            max_attempts: 3,
            max_audit_events: crate::audit::DEFAULT_MAX_EVENTS,
        }
    }
}

/// The generators this process serves, resolved once at boot.
///
/// Link-or-fail, like `llm::PromptRegistry` and detection's `DetectionPlan`:
/// two generators claiming the same [`DraftKind`] is a wiring bug that must
/// fail the rollout, not a last-one-wins that shows up as drafts written by
/// whichever `Arc` happened to be second in a `Vec`.
///
/// Its real job is [`kinds`](Self::kinds), which the pool passes to every
/// claim. That is what stops a pod from taking a durable lease on work it has
/// no way to finish.
#[derive(Debug, Default)]
pub struct GeneratorRegistry {
    by_kind: BTreeMap<DraftKind, Arc<dyn DraftCapability>>,
}

impl GeneratorRegistry {
    /// Link the roster this pod serves. A **subset** of the kinds, unlike
    /// `CheckRegistry`, which must cover all of them: what a pod may *run* and
    /// what it must be able to *land* are different questions, and collapsing
    /// them would either let a pod claim work it cannot finish or stop it
    /// landing an answer it already paid for.
    ///
    /// An empty roster is refused: a pod with no generators polls forever and
    /// drains nothing, which reads as a healthy deployment and a growing
    /// backlog.
    pub fn link(capabilities: Vec<Arc<dyn DraftCapability>>) -> Result<Self, RegistryError> {
        Ok(Self {
            by_kind: index(capabilities)?,
        })
    }

    /// The capability for `kind`, if this pod serves it.
    pub fn get(&self, kind: DraftKind) -> Option<&Arc<dyn DraftCapability>> {
        self.by_kind.get(&kind)
    }

    /// What this pod may claim. Sorted and stable (a `BTreeMap`), so the
    /// claim query's parameter does not churn between polls.
    pub fn kinds(&self) -> Vec<DraftKind> {
        self.by_kind.keys().copied().collect()
    }
}

/// Everything a worker needs, shared across the pool by cheap `Arc` clones.
///
/// The store is a [`DraftWorkQueue`], not the whole `DraftStore`: a worker
/// leases, attempts and reports, and has no business enqueueing or approving
/// anything.
#[derive(Clone)]
pub struct DraftWorkerPool {
    store: Arc<dyn DraftWorkQueue>,
    audit: Arc<dyn AuditSource>,
    client: Arc<dyn LlmClient>,
    generators: Arc<GeneratorRegistry>,
    kinds: Vec<DraftKind>,
    config: PoolConfig,
}

impl std::fmt::Debug for DraftWorkerPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DraftWorkerPool")
            .field("config", &self.config)
            .field("kinds", &self.kinds)
            .finish_non_exhaustive()
    }
}

impl DraftWorkerPool {
    pub fn new(
        store: Arc<dyn DraftWorkQueue>,
        audit: Arc<dyn AuditSource>,
        client: Arc<dyn LlmClient>,
        generators: Arc<GeneratorRegistry>,
        config: PoolConfig,
    ) -> Self {
        // Resolved once: the claim filter is the registry's key set, and
        // re-deriving it every poll would be the same answer at a cost.
        let kinds = generators.kinds();
        Self {
            store,
            audit,
            client,
            generators,
            kinds,
            config,
        }
    }

    /// Drain the queue until `shutdown` fires.
    ///
    /// On shutdown the loop stops claiming and waits for in-flight jobs: a
    /// call already paid for is worth the drain window, and a job abandoned
    /// mid-call would be re-run — and re-billed — by whoever reclaims the
    /// lease.
    pub async fn run(self, wake: Arc<Notify>, shutdown: CancellationToken) {
        let permits = Arc::new(Semaphore::new(self.config.concurrency.max(1)));
        let mut tasks = tokio::task::JoinSet::new();

        while !shutdown.is_cancelled() {
            // Take the permits *first*, then claim at most that many. The
            // order is the point: a claim is a durable lease, so claiming
            // before holding a slot means a job is leased by a pod that
            // cannot start it, and the lease then has to expire before anyone
            // else may. Reserving capacity up front makes "every claimed job
            // has a slot to run in" a fact about the code rather than an
            // arithmetic coincidence a later edit can quietly break.
            let mut reserved = Vec::new();
            while let Ok(permit) = Arc::clone(&permits).try_acquire_owned() {
                reserved.push(permit);
            }

            if !reserved.is_empty() {
                match self
                    .store
                    .claim_batch(
                        &self.kinds,
                        reserved.len(),
                        self.config.lease,
                        self.config.max_attempts,
                        Utc::now(),
                    )
                    .await
                {
                    Ok(jobs) => {
                        for job in jobs {
                            // Counted per job rather than per batch: the queue
                            // is kind-agnostic, so a batch is not one kind.
                            metrics::record_claimed(job.job.kind.as_wire_str(), 1);
                            let permit = reserved.pop().expect("a permit per claimed job");
                            let worker = self.clone();
                            tasks.spawn(async move {
                                let _permit = permit;
                                worker.run_one(job).await;
                            });
                        }
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "claiming draft jobs failed; retrying after the poll interval")
                    }
                }
                // Unclaimed capacity goes straight back; holding it would
                // shrink the pool for the rest of the process's life.
                drop(reserved);
            }

            // Reap finished tasks so the set doesn't grow, and keep the
            // in-flight gauge honest.
            while let Some(finished) = tasks.try_join_next() {
                if let Err(err) = finished {
                    tracing::error!(error = %err, "draft worker task panicked");
                }
            }
            metrics::set_in_flight(self.config.concurrency.max(1) - permits.available_permits());

            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                () = wake.notified() => {}
                () = tokio::time::sleep(self.config.poll_interval) => {}
            }
        }

        tracing::info!(
            in_flight = self.config.concurrency.max(1) - permits.available_permits(),
            "draft pool draining"
        );
        while let Some(finished) = tasks.join_next().await {
            if let Err(err) = finished {
                tracing::error!(error = %err, "draft worker task panicked during drain");
            }
        }
        metrics::set_in_flight(0);
    }

    /// One job, timed. The §14 timed-wrapper split: this records the metric
    /// and the outcome, [`Self::draft`] does the work.
    async fn run_one(&self, job: ClaimedJob) {
        let started = Instant::now();
        let draft_id = job.job.draft_id;
        let kind = job.job.kind.as_wire_str();

        // Belt to the claim filter's braces. `claim_batch` is asked only for
        // kinds this pod serves, so reaching here means the store handed back
        // something else — a real defect, and one worth a counter rather than
        // a panic. Releasing (not failing) is still the right answer: nothing
        // is wrong with the draft.
        let Some(generator) = self.generators.get(job.job.kind) else {
            tracing::error!(
                %draft_id,
                kind,
                served = ?self.kinds,
                "claimed a draft kind this pod has no generator for; releasing"
            );
            metrics::record_unservable(kind);
            if let Err(err) = self.store.release(draft_id, Utc::now()).await {
                tracing::error!(%draft_id, error = %err, "releasing the lease failed; it will expire");
            }
            metrics::record_finished(kind, "unservable", started);
            return;
        };

        let outcome = match self.draft(&job, generator.as_ref()).await {
            Ok(outcome) => outcome,
            Err(err) => {
                if err.is_transient() {
                    // Hand it back rather than burning the drain window: a
                    // released job is claimable immediately by any pod.
                    tracing::warn!(%draft_id, error = %err, "draft attempt failed transiently; releasing");
                    if let Err(release_err) = self.store.release(draft_id, Utc::now()).await {
                        tracing::error!(%draft_id, error = %release_err, "releasing the lease failed; it will expire");
                    }
                    metrics::record_finished(kind, "released", started);
                    return;
                }
                DraftOutcome::failed(err.to_string(), true)
            }
        };

        // Note what is *not* checked here: the shutdown token. An answer that
        // came back is already paid for, so it is written even mid-drain —
        // dropping it would buy it again on restart.
        match self.store.finish(draft_id, outcome, Utc::now()).await {
            Ok(status) => {
                if status == DraftStatus::Blocked {
                    tracing::warn!(%draft_id, "draft blocked: the model answered but the answer is unusable");
                }
                metrics::record_finished(kind, status.as_wire_str(), started);
            }
            Err(err) => {
                // The lease expires and another pod reclaims the job — where
                // the cross-pod cache serves the answer this attempt already
                // paid for, instead of buying it twice.
                tracing::error!(%draft_id, error = %err, "recording the draft outcome failed; the lease will expire");
                metrics::record_finished(kind, "unrecorded", started);
            }
        }
    }

    /// Read the grounding, render the request, call the seam.
    async fn draft(
        &self,
        job: &ClaimedJob,
        generator: &dyn DraftCapability,
    ) -> Result<DraftOutcome, WorkerError> {
        // Fetch what *this* generator declared it needs, not what the first
        // one happened to. A rule draft's whole input is the customer's
        // sentence, already on the row: reading an "incident" stream for it
        // would be an HTTP round trip for an id that is not an incident,
        // answered empty, and then a permanently failed job.
        let audit = match generator.grounding() {
            Grounding::IncidentAuditStream => {
                self.audit
                    .audit_stream(IncidentId(job.job.subject_id), self.config.max_audit_events)
                    .await?
            }
            Grounding::SourceText => AuditStream::default(),
        };
        let grounded = audit.event_ids();

        let request = generator.build_request(job, &audit)?;
        let key = CacheKey::new(self.client.model(), &request);

        // Written *before* the call: the completion needs a row to land on
        // even if this worker dies between the provider's answer and its own
        // bookkeeping (see `crate::cache`).
        self.store
            .begin_attempt(
                job.job.draft_id,
                &key,
                request.prompt,
                &grounded,
                Utc::now(),
            )
            .await?;

        match self.client.complete(&request).await {
            // Including a refusal or a truncation: those are successful,
            // billed calls, and the store decides they land as `blocked`.
            Ok(completion) => Ok(DraftOutcome::Completed(Box::new(completion))),
            Err(err) => {
                let permanent = !err.is_transient();
                Ok(DraftOutcome::failed(failure_reason(&err), permanent))
            }
        }
    }
}

/// Why one attempt could not produce an outcome.
///
/// Distinct from [`DraftOutcome::Failed`]: this is a failure *before* the
/// model was reached, so it decides whether the job goes back to the queue,
/// while an `LlmError` has already been classified by the seam.
#[derive(Debug, thiserror::Error)]
enum WorkerError {
    #[error(transparent)]
    Audit(#[from] crate::audit::AuditError),
    #[error(transparent)]
    Draft(#[from] DraftError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl Transience for WorkerError {
    fn is_transient(&self) -> bool {
        match self {
            WorkerError::Audit(err) => err.is_transient(),
            WorkerError::Draft(err) => err.is_transient(),
            WorkerError::Store(err) => err.is_transient(),
        }
    }
}

/// The wall-clock a single claimed job can occupy, in the parts an operator
/// actually configures.
///
/// The subtlety this type exists to stop someone from re-introducing: the LLM
/// seam's retry **sleeps between attempts, outside the per-request timeout**
/// (`RetryingClient` awaits `Backoff::decide`'s delay after a failed attempt).
/// So `attempts x timeout` is *not* the worst case — it under-counts by the
/// backoff budget, and a lease sized from it can expire while the job is still
/// running. That is the one failure mode here that produces no error at all:
/// a second pod reclaims the job, both call the provider, and the platform
/// pays twice for two versions of one regulatory document.
#[derive(Debug, Clone, Copy)]
pub struct CallBudget {
    /// Reading the grounding before the model is reached — the audit stream's
    /// per-request timeout times the pages a full read can take.
    pub audit: Duration,
    /// Attempts the seam will make (`LLM_MAX_ATTEMPTS`).
    pub attempts: u32,
    /// Per-request ceiling (`LLM_TIMEOUT_SECS`).
    pub timeout: Duration,
    /// The longest sleep *between* two attempts: the jittered backoff is
    /// bounded by its own max, and a server-directed `retry-after` is bounded
    /// by the cap past which the seam gives up rather than parking a worker.
    pub gap: Duration,
}

impl CallBudget {
    /// Everything, end to end, in the worst case.
    pub fn worst_case(&self) -> Duration {
        let attempts = self.attempts.max(1);
        self.audit
            .saturating_add(self.timeout.saturating_mul(attempts))
            .saturating_add(self.gap.saturating_mul(attempts - 1))
    }
}

/// Whether a lease outlasts the worst-case job (see [`CallBudget`]). Asserted
/// at boot, because there is no lease heartbeat and the failure is silent.
pub fn lease_covers_call(lease: Duration, budget: CallBudget) -> bool {
    lease >= budget.worst_case()
}

/// The reason string a failed draft records — the seam's own low-cardinality
/// `reason()` plus the message, so a stored failure and its metric label say
/// the same thing rather than drifting into two vocabularies.
fn failure_reason(err: &LlmError) -> String {
    format!("{}: {err}", err.reason())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::VecAuditSource;
    use crate::draft::NarrativeDrafter;
    use crate::model::{DraftJob, DraftKind};
    use crate::store::{DraftQueue, DraftReview};
    use crate::test_util::{envelope, InMemoryDraftStore};
    use events::primitives::Chain;
    use llm::test_util::StubClient;
    use llm::{Completion, StopReason, TokenUsage};

    fn narrative_only() -> Arc<GeneratorRegistry> {
        Arc::new(
            GeneratorRegistry::link(vec![
                Arc::new(NarrativeDrafter::new()) as Arc<dyn DraftCapability>
            ])
            .expect("one generator links"),
        )
    }

    fn pool(
        store: Arc<InMemoryDraftStore>,
        audit: Arc<dyn AuditSource>,
        client: Arc<dyn LlmClient>,
    ) -> DraftWorkerPool {
        DraftWorkerPool::new(
            store,
            audit,
            client,
            narrative_only(),
            PoolConfig {
                concurrency: 2,
                poll_interval: Duration::from_millis(20),
                lease: Duration::from_secs(60),
                max_attempts: 3,
                max_audit_events: 100,
            },
        )
    }

    async fn queued(store: &InMemoryDraftStore, incident: IncidentId) -> ClaimedJob {
        store
            .enqueue(&DraftJob::narrative(incident, Chain::ETHEREUM), Utc::now())
            .await
            .unwrap();
        store
            .claim_batch(DraftKind::ALL, 1, Duration::from_secs(60), 3, Utc::now())
            .await
            .unwrap()
            .remove(0)
    }

    #[tokio::test]
    async fn a_completed_call_lands_as_a_ready_draft_with_its_provenance() {
        let store = Arc::new(InMemoryDraftStore::default());
        let incident = IncidentId::new();
        let audit = Arc::new(VecAuditSource::new(
            incident,
            vec![envelope(0), envelope(1)],
        ));
        // The narrative has to cite the events it was shown, or the §20.4
        // citation check blocks it — which is the point of that check and is
        // asserted on its own below.
        let cited = envelope(0).event_id;
        let narrative = format!("The attacker's transaction preceded the victim's swap [{cited}].");
        let client = Arc::new(StubClient::answering(narrative.clone()).with_model("claude-opus-5"));
        let job = queued(&store, incident).await;

        pool(store.clone(), audit, client)
            .run_one(job.clone())
            .await;

        let draft = store.get(job.job.draft_id).await.unwrap().unwrap();
        assert_eq!(draft.status, DraftStatus::Ready, "{:?}", draft.last_error);
        assert_eq!(draft.body(), Some(narrative.as_str()));
        assert_eq!(
            draft.model(),
            Some("claude-opus-5"),
            "provenance comes from the response, not the request"
        );
        assert_eq!(
            draft.provenance.as_ref().map(|p| p.prompt_id.as_str()),
            Some("incident_narrative@v2")
        );
        assert_eq!(
            draft.grounded_event_ids,
            vec![cited],
            "the window the model was shown (2 events) narrows to the one the \
             narrative actually cites"
        );
    }

    #[tokio::test]
    async fn a_refusal_is_blocked_and_not_retried() {
        let store = Arc::new(InMemoryDraftStore::default());
        let incident = IncidentId::new();
        let audit = Arc::new(VecAuditSource::new(incident, vec![envelope(0)]));
        let client = Arc::new(
            StubClient::answering("").with_stop_reason(StopReason::Refusal {
                category: Some("financial_crime".into()),
            }),
        );
        let job = queued(&store, incident).await;

        pool(store.clone(), audit, client)
            .run_one(job.clone())
            .await;

        let draft = store.get(job.job.draft_id).await.unwrap().unwrap();
        assert_eq!(
            draft.status,
            DraftStatus::Blocked,
            "a decline refuses again; re-running it buys a second identical refusal"
        );
        assert!(!draft.status.is_runnable());
    }

    #[tokio::test]
    async fn a_transient_llm_fault_releases_the_job_for_the_outer_clock() {
        let store = Arc::new(InMemoryDraftStore::default());
        let incident = IncidentId::new();
        let audit = Arc::new(VecAuditSource::new(incident, vec![envelope(0)]));
        let client = Arc::new(StubClient::failing(|| LlmError::RateLimited {
            retry_after: None,
        }));
        let job = queued(&store, incident).await;

        pool(store.clone(), audit, client)
            .run_one(job.clone())
            .await;

        // The seam already exhausted its in-process budget; the *queue* owns
        // the next attempt, so the draft is queued again rather than failed.
        let draft = store.get(job.job.draft_id).await.unwrap().unwrap();
        assert_eq!(draft.status, DraftStatus::Queued);
        assert!(draft.last_error.is_some());
    }

    #[tokio::test]
    async fn a_permanent_llm_fault_fails_the_draft_outright() {
        let store = Arc::new(InMemoryDraftStore::default());
        let incident = IncidentId::new();
        let audit = Arc::new(VecAuditSource::new(incident, vec![envelope(0)]));
        let client = Arc::new(StubClient::failing(|| LlmError::Auth {
            reason: "invalid x-api-key".into(),
        }));
        let job = queued(&store, incident).await;

        pool(store.clone(), audit, client)
            .run_one(job.clone())
            .await;

        let draft = store.get(job.job.draft_id).await.unwrap().unwrap();
        assert_eq!(draft.status, DraftStatus::Failed);
    }

    #[tokio::test]
    async fn an_incident_with_no_audit_stream_fails_rather_than_looping() {
        let store = Arc::new(InMemoryDraftStore::default());
        let incident = IncidentId::new();
        let job = queued(&store, incident).await;

        pool(
            store.clone(),
            Arc::new(VecAuditSource::default()),
            Arc::new(StubClient::answering("unused")),
        )
        .run_one(job.clone())
        .await;

        let draft = store.get(job.job.draft_id).await.unwrap().unwrap();
        assert_eq!(draft.status, DraftStatus::Failed);
    }

    #[tokio::test]
    async fn a_transient_audit_read_never_reaches_the_model() {
        let store = Arc::new(InMemoryDraftStore::default());
        let incident = IncidentId::new();
        let job = queued(&store, incident).await;
        let client = Arc::new(StubClient::answering("must not be called"));

        pool(
            store.clone(),
            Arc::new(crate::test_util::FailingAuditSource::transient()),
            client.clone(),
        )
        .run_one(job.clone())
        .await;

        assert_eq!(client.call_count(), 0, "no grounding, no billed call");
        let draft = store.get(job.job.draft_id).await.unwrap().unwrap();
        assert_eq!(draft.status, DraftStatus::Queued);
    }

    #[tokio::test]
    async fn a_kind_this_pod_cannot_serve_is_released_not_failed() {
        // Nothing is wrong with the draft — this replica just doesn't carry
        // the generator. Failing it would retire a perfectly good job because
        // it landed on the wrong pod.
        let store = Arc::new(InMemoryDraftStore::default());
        let incident = IncidentId::new();
        store
            .enqueue(
                &DraftJob {
                    kind: DraftKind::RuleDraft,
                    ..DraftJob::narrative(incident, Chain::ETHEREUM)
                },
                Utc::now(),
            )
            .await
            .unwrap();
        let job = store
            .claim_batch(DraftKind::ALL, 1, Duration::from_secs(60), 3, Utc::now())
            .await
            .unwrap()
            .remove(0);
        let client = Arc::new(StubClient::answering("must not be called"));

        pool(
            store.clone(),
            Arc::new(VecAuditSource::new(incident, vec![envelope(0)])),
            client.clone(),
        )
        .run_one(job.clone())
        .await;

        assert_eq!(client.call_count(), 0, "the wrong pod never bills");
        let draft = store.get(job.job.draft_id).await.unwrap().unwrap();
        assert_eq!(draft.status, DraftStatus::Queued, "left for a pod that can");
    }

    #[tokio::test]
    async fn a_pod_only_claims_the_kinds_it_serves() {
        // The structural fix: a narrative-only pod does not lease a rule
        // draft at all, so it never has to release one. `run_one`'s registry
        // miss is the belt to this braces.
        let store = Arc::new(InMemoryDraftStore::default());
        store
            .enqueue(
                &DraftJob {
                    kind: DraftKind::RuleDraft,
                    ..DraftJob::narrative(IncidentId::new(), Chain::ETHEREUM)
                },
                Utc::now(),
            )
            .await
            .unwrap();

        let claimed = store
            .claim_batch(
                &narrative_only().kinds(),
                10,
                Duration::from_secs(60),
                3,
                Utc::now(),
            )
            .await
            .unwrap();
        assert!(
            claimed.is_empty(),
            "a durable lease on work this pod cannot finish blocks every pod that can"
        );
    }

    #[test]
    fn a_roster_that_could_never_drain_anything_is_a_refused_boot() {
        assert!(matches!(
            GeneratorRegistry::link(Vec::new()),
            Err(RegistryError::Empty)
        ));
        let twice = vec![
            Arc::new(NarrativeDrafter::new()) as Arc<dyn DraftCapability>,
            Arc::new(NarrativeDrafter::new()) as Arc<dyn DraftCapability>,
        ];
        assert!(matches!(
            GeneratorRegistry::link(twice),
            Err(RegistryError::Duplicate { .. })
        ));
    }

    #[tokio::test]
    async fn the_pool_drains_the_queue_and_stops_on_shutdown() {
        let store = Arc::new(InMemoryDraftStore::default());
        let incident = IncidentId::new();
        store
            .enqueue(&DraftJob::narrative(incident, Chain::ETHEREUM), Utc::now())
            .await
            .unwrap();
        let audit = Arc::new(VecAuditSource::new(incident, vec![envelope(0)]));
        let client: Arc<dyn LlmClient> = Arc::new(StubClient::sequence(vec![Completion {
            text: format!(
                "The block was drained by the attacker [{}].",
                envelope(0).event_id
            ),
            stop_reason: StopReason::EndTurn,
            model: "claude-opus-5".into(),
            usage: TokenUsage::default(),
        }]));

        let shutdown = CancellationToken::new();
        let wake = Arc::new(Notify::new());
        let handle =
            tokio::spawn(pool(store.clone(), audit, client).run(wake.clone(), shutdown.clone()));

        // The wake is the latency hint; the assertion is on the drain.
        wake.notify_one();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let done = store
                .drafts()
                .iter()
                .all(|d| d.status == DraftStatus::Ready);
            if done && !store.drafts().is_empty() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the pool never drained the queue"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("the pool stops on shutdown")
            .expect("no panic");
    }

    fn budget() -> CallBudget {
        // The shipped defaults.
        CallBudget {
            audit: Duration::from_secs(60),
            attempts: 3,
            timeout: Duration::from_secs(300),
            gap: Duration::from_secs(30),
        }
    }

    #[test]
    fn the_worst_case_counts_the_sleeps_between_attempts() {
        // The bug this pins: `attempts x timeout` is 900s, and the real
        // worst case is 1020s. A 900s lease sized from the naive formula
        // expires while the job is still running — and two pods then pay for
        // the same narrative, with nothing in any log saying so.
        assert_eq!(budget().worst_case(), Duration::from_secs(60 + 900 + 60));
        assert!(!lease_covers_call(Duration::from_secs(900), budget()));
        assert!(lease_covers_call(Duration::from_secs(1200), budget()));
    }

    #[test]
    fn a_single_attempt_has_no_gap_to_count() {
        let budget = CallBudget {
            attempts: 1,
            gap: Duration::from_secs(999),
            ..budget()
        };
        assert_eq!(budget.worst_case(), Duration::from_secs(60 + 300));
    }
}
