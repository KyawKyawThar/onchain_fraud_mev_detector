//! The [`DraftStore`] contract, exercised twice: against the in-memory double
//! (every `cargo test` run) and against real Postgres via testcontainers
//! (`#[ignore]`, run by `just test-integration`).
//!
//! Running one body against both backends is the point. The parts most likely
//! to be wrong here — the `SKIP LOCKED` claim, the lease expiry, the
//! digest-keyed cache write landing on in-flight rows — are exactly the parts
//! a hand-written double is most tempted to fake, and the ones whose failure
//! mode is a doubled bill rather than an error. Mirrors
//! `notification/tests/store_contract.rs`.

use chrono::{DateTime, Utc};
use copilot::model::{DraftJob, DraftStatus, Review};
use copilot::store::{DraftOutcome, DraftStore, PgDraftStore};
use copilot::test_util::InMemoryDraftStore;
use copilot::DraftKind as Kind;
use events::primitives::{Chain, IncidentId};
use llm::cache::CacheKey;
use llm::{Completion, CompletionRequest, StopReason, TokenUsage};
use std::time::Duration;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

fn at(secs: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(secs, 0).expect("valid timestamp")
}

fn job(incident: IncidentId) -> DraftJob {
    DraftJob::narrative(incident, Chain::ETHEREUM)
}

fn request(seed: &str) -> CompletionRequest {
    CompletionRequest::new("incident_narrative", seed)
}

fn answer(text: &str) -> Completion {
    Completion {
        text: text.to_owned(),
        stop_reason: StopReason::EndTurn,
        model: "claude-opus-5".to_owned(),
        usage: TokenUsage {
            input_tokens: 10,
            output_tokens: 20,
            cache_creation_input_tokens: 30,
            cache_read_input_tokens: 40,
        },
    }
}

// ── The contract, backend-agnostic ───────────────────────────────

/// A redelivered `IncidentCreated` resolves to the draft that already exists.
/// A second row would be a second billed narrative of the same incident.
async fn contract_enqueue_is_idempotent_per_subject(store: &dyn DraftStore) {
    let incident = IncidentId::new();
    let first = store.enqueue(&job(incident), at(1)).await.expect("enqueue");
    assert!(first.is_new());

    // A *different* draft id for the same subject — what a redelivery
    // actually looks like, since the consumer mints an id before it asks.
    let second = store.enqueue(&job(incident), at(2)).await.expect("enqueue");
    assert!(!second.is_new());
    assert_eq!(second.draft_id(), first.draft_id());
}

/// A claim leases the row, bumps `attempts`, and hides it from the next
/// claim — the property that lets every pod run the same query.
async fn contract_a_claimed_job_is_not_claimed_twice(store: &dyn DraftStore) {
    let enqueued = store
        .enqueue(&job(IncidentId::new()), at(1))
        .await
        .expect("enqueue");

    let first = store
        .claim_batch(Kind::ALL, 10, Duration::from_secs(600), 3, at(2))
        .await
        .expect("claim");
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].job.draft_id, enqueued.draft_id());
    assert_eq!(first[0].attempts, 1);

    let second = store
        .claim_batch(Kind::ALL, 10, Duration::from_secs(600), 3, at(3))
        .await
        .expect("claim");
    assert!(second.is_empty(), "a leased job is invisible to other pods");
}

/// A pod that dies mid-call leaves a lease that expires; the job is reclaimed
/// rather than lost. Without this, a killed worker silently drops a draft
/// whose Kafka offset already said it was handled.
async fn contract_an_expired_lease_is_reclaimed(store: &dyn DraftStore) {
    store
        .enqueue(&job(IncidentId::new()), at(1))
        .await
        .expect("enqueue");
    store
        .claim_batch(Kind::ALL, 10, Duration::from_secs(60), 5, at(2))
        .await
        .expect("claim");

    let reclaimed = store
        .claim_batch(Kind::ALL, 10, Duration::from_secs(60), 5, at(1_000))
        .await
        .expect("claim");
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(reclaimed[0].attempts, 2, "the attempt counter survives");
}

/// A draft that keeps failing is retired instead of circulating forever.
async fn contract_attempts_are_bounded(store: &dyn DraftStore) {
    let enqueued = store
        .enqueue(&job(IncidentId::new()), at(1))
        .await
        .expect("enqueue");

    for tick in 0..2 {
        let claimed = store
            .claim_batch(
                Kind::ALL,
                10,
                Duration::from_secs(1),
                2,
                at(100 * (tick + 1)),
            )
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1, "attempt {tick} should claim");
    }

    let exhausted = store
        .claim_batch(Kind::ALL, 10, Duration::from_secs(1), 2, at(10_000))
        .await
        .expect("claim");
    assert!(
        exhausted.is_empty(),
        "the attempt ceiling retires the draft"
    );
    let draft = store
        .get(enqueued.draft_id())
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(draft.status, DraftStatus::Failed);
}

/// The row is the cache: a completion filed under `(model, request)` is
/// readable by any pod, and lands on the in-flight draft that was waiting for
/// it. This is what makes a rebalance cost nothing instead of a second billed
/// document.
async fn contract_the_row_is_the_cross_pod_cache(store: &dyn DraftStore) {
    let enqueued = store
        .enqueue(&job(IncidentId::new()), at(1))
        .await
        .expect("enqueue");
    store
        .claim_batch(Kind::ALL, 10, Duration::from_secs(600), 3, at(2))
        .await
        .expect("claim");

    let key = CacheKey::new("claude-opus-5", &request("incident-a"));
    store
        .begin_attempt(
            enqueued.draft_id(),
            &key,
            Some(copilot::prompts::incident_narrative()),
            &[uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2)],
            at(3),
        )
        .await
        .expect("begin");

    assert!(
        store.cached_completion(&key).await.expect("read").is_none(),
        "nothing has been paid for yet"
    );

    let landed = store
        .store_completion(&key, &answer("a narrative"), at(4))
        .await
        .expect("cache write");
    assert_eq!(landed, 1, "the answer lands on the waiting draft");

    let hit = store
        .cached_completion(&key)
        .await
        .expect("read")
        .expect("a hit");
    assert_eq!(hit.text, "a narrative");
    assert_eq!(
        hit.usage.cache_read_input_tokens, 40,
        "all four SKUs survive"
    );

    let draft = store
        .get(enqueued.draft_id())
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(draft.status, DraftStatus::Ready);
    assert_eq!(
        draft.provenance.as_ref().map(|p| p.prompt_id.as_str()),
        Some("incident_narrative@v1")
    );
    assert_eq!(draft.grounded_event_ids.len(), 2);

    // A different question is a different key — the property whose absence
    // would be a cross-tenant leak rather than a stale read.
    let other = CacheKey::new("claude-opus-5", &request("incident-b"));
    assert!(store
        .cached_completion(&other)
        .await
        .expect("read")
        .is_none());
}

/// A refusal is cached (it will refuse again) but never presented as an
/// answer; a failure is neither.
async fn contract_a_refusal_is_blocked_and_a_failure_is_not_cached(store: &dyn DraftStore) {
    let refused = store
        .enqueue(&job(IncidentId::new()), at(1))
        .await
        .expect("enqueue");
    store
        .claim_batch(Kind::ALL, 10, Duration::from_secs(600), 3, at(2))
        .await
        .expect("claim");
    let key = CacheKey::new("claude-opus-5", &request("refusing"));
    store
        .begin_attempt(refused.draft_id(), &key, None, &[], at(3))
        .await
        .expect("begin");

    let status = store
        .finish(
            refused.draft_id(),
            DraftOutcome::Completed(Box::new(Completion {
                text: String::new(),
                stop_reason: StopReason::Refusal { category: None },
                model: "claude-opus-5".to_owned(),
                usage: TokenUsage::default(),
            })),
            at(4),
        )
        .await
        .expect("finish");
    assert_eq!(status, DraftStatus::Blocked);

    let hit = store.cached_completion(&key).await.expect("read");
    assert!(
        hit.is_some_and(|c| matches!(c.stop_reason, StopReason::Refusal { .. })),
        "a cached decline is what stops a redelivery loop paying for it again"
    );

    // A failure, by contrast, is the one case where trying again might work.
    let failed = store
        .enqueue(&job(IncidentId::new()), at(5))
        .await
        .expect("enqueue");
    store
        .claim_batch(Kind::ALL, 10, Duration::from_secs(600), 3, at(6))
        .await
        .expect("claim");
    let failed_key = CacheKey::new("claude-opus-5", &request("failing"));
    store
        .begin_attempt(failed.draft_id(), &failed_key, None, &[], at(7))
        .await
        .expect("begin");
    store
        .finish(
            failed.draft_id(),
            DraftOutcome::failed("upstream 500", true),
            at(8),
        )
        .await
        .expect("finish");
    assert!(
        store
            .cached_completion(&failed_key)
            .await
            .expect("read")
            .is_none(),
        "a fault is never a cache entry"
    );
}

/// The two writers must agree. `finish` (the worker's own bookkeeping) and
/// `store_completion` (the cache's write-behind, which covers a worker that
/// died between the provider's answer and its bookkeeping) both land a
/// completion on a row — two separate `UPDATE`s that must produce the same
/// row, or a draft's recorded state would depend on *which* path happened to
/// win. Nothing but this test holds them together.
async fn contract_both_completion_writers_agree(store: &dyn DraftStore) {
    let completion = answer("identical text");

    // Path A: the worker's own write.
    let by_worker = store
        .enqueue(&job(IncidentId::new()), at(1))
        .await
        .expect("enqueue");
    store
        .claim_batch(Kind::ALL, 10, Duration::from_secs(600), 3, at(2))
        .await
        .expect("claim");
    let key_a = CacheKey::new("claude-opus-5", &request("worker-path"));
    store
        .begin_attempt(by_worker.draft_id(), &key_a, None, &[], at(3))
        .await
        .expect("begin");
    store
        .finish(
            by_worker.draft_id(),
            DraftOutcome::Completed(Box::new(completion.clone())),
            at(4),
        )
        .await
        .expect("finish");

    // Path B: the cache's write, keyed only by the digest.
    let by_cache = store
        .enqueue(&job(IncidentId::new()), at(5))
        .await
        .expect("enqueue");
    store
        .claim_batch(Kind::ALL, 10, Duration::from_secs(600), 3, at(6))
        .await
        .expect("claim");
    let key_b = CacheKey::new("claude-opus-5", &request("cache-path"));
    store
        .begin_attempt(by_cache.draft_id(), &key_b, None, &[], at(7))
        .await
        .expect("begin");
    store
        .store_completion(&key_b, &completion, at(4))
        .await
        .expect("cache write");

    let a = store.get(by_worker.draft_id()).await.unwrap().unwrap();
    let b = store.get(by_cache.draft_id()).await.unwrap().unwrap();
    assert_eq!(a.status, b.status);
    assert_eq!(a.body(), b.body());
    assert_eq!(a.model(), b.model());
    assert_eq!(
        a.answer.as_ref().map(|x| &x.stop_reason),
        b.answer.as_ref().map(|x| &x.stop_reason)
    );
    assert_eq!(
        a.answer.as_ref().map(|x| x.completed_at),
        b.answer.as_ref().map(|x| x.completed_at)
    );

    // And both are readable as cache hits, with the four SKUs intact.
    for key in [&key_a, &key_b] {
        let hit = store.cached_completion(key).await.unwrap().expect("a hit");
        assert_eq!(hit.text, completion.text);
        assert_eq!(hit.usage, completion.usage);
        assert_eq!(hit.stop_reason, completion.stop_reason);
    }
}

/// A transient failure returns the draft to the queue; a release does the
/// same without consuming the outcome. Neither is a retry *inside* the worker.
async fn contract_a_transient_failure_requeues(store: &dyn DraftStore) {
    let enqueued = store
        .enqueue(&job(IncidentId::new()), at(1))
        .await
        .expect("enqueue");
    store
        .claim_batch(Kind::ALL, 10, Duration::from_secs(600), 3, at(2))
        .await
        .expect("claim");
    let status = store
        .finish(
            enqueued.draft_id(),
            DraftOutcome::failed("rate limited", false),
            at(3),
        )
        .await
        .expect("finish");
    assert_eq!(status, DraftStatus::Queued);

    let reclaimed = store
        .claim_batch(Kind::ALL, 10, Duration::from_secs(600), 3, at(4))
        .await
        .expect("claim");
    assert_eq!(
        reclaimed.len(),
        1,
        "requeued immediately, not after the lease"
    );

    store
        .release(enqueued.draft_id(), at(5))
        .await
        .expect("release");
    let after_release = store
        .claim_batch(Kind::ALL, 10, Duration::from_secs(600), 3, at(6))
        .await
        .expect("claim");
    assert_eq!(after_release.len(), 1);
}

/// A draft that keeps failing *transiently* is retired too. It goes back as
/// `queued` with its attempts intact, so a claim filter alone would leave it
/// runnable-but-never-claimed: present in the backlog, invisible in the
/// failures, and stuck forever.
async fn contract_repeated_transient_failures_are_retired(store: &dyn DraftStore) {
    let enqueued = store
        .enqueue(&job(IncidentId::new()), at(1))
        .await
        .expect("enqueue");

    for tick in 0..2i64 {
        let claimed = store
            .claim_batch(Kind::ALL, 10, Duration::from_secs(600), 2, at(10 + tick))
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1, "attempt {tick} should claim");
        store
            .finish(
                enqueued.draft_id(),
                DraftOutcome::failed("rate limited", false),
                at(20 + tick),
            )
            .await
            .expect("finish");
    }

    let after = store
        .claim_batch(Kind::ALL, 10, Duration::from_secs(600), 2, at(100))
        .await
        .expect("claim");
    assert!(after.is_empty());
    let draft = store
        .get(enqueued.draft_id())
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(draft.status, DraftStatus::Failed);
}

/// §20.4's validating boundary: only a draft with an answer can be approved,
/// and the verdict is recorded with who made it.
async fn contract_only_a_ready_draft_is_reviewable(store: &dyn DraftStore) {
    let enqueued = store
        .enqueue(&job(IncidentId::new()), at(1))
        .await
        .expect("enqueue");

    let err = store
        .review(
            enqueued.draft_id(),
            Review::Approve,
            "analyst@example.com",
            None,
            at(2),
        )
        .await
        .expect_err("a queued draft has no answer to approve");
    assert!(err.to_string().contains("cannot be reviewed"), "{err}");

    store
        .claim_batch(Kind::ALL, 10, Duration::from_secs(600), 3, at(3))
        .await
        .expect("claim");
    store
        .finish(
            enqueued.draft_id(),
            DraftOutcome::Completed(Box::new(answer("a narrative"))),
            at(4),
        )
        .await
        .expect("finish");

    let status = store
        .review(
            enqueued.draft_id(),
            Review::Approve,
            "analyst@example.com",
            Some("checked against the store"),
            at(5),
        )
        .await
        .expect("approve");
    assert_eq!(status, DraftStatus::Approved);

    let draft = store
        .get(enqueued.draft_id())
        .await
        .expect("get")
        .expect("exists");
    let review = draft.review.as_ref().expect("a verdict is recorded");
    assert_eq!(review.by, "analyst@example.com");
    assert_eq!(review.at, at(5));

    // Re-approving is refused rather than silently re-stamped: a second
    // approval of an already-approved regulatory draft is a fact about a
    // process going wrong.
    assert!(store
        .review(
            enqueued.draft_id(),
            Review::Reject,
            "someone-else",
            None,
            at(6)
        )
        .await
        .is_err());
}

/// A draft `kind` the queue does not distinguish would let t4's rule drafts
/// collide with t3's narratives for the same subject id.
async fn contract_kind_is_part_of_the_subject_key(store: &dyn DraftStore) {
    let subject = uuid::Uuid::new_v4();
    let narrative = DraftJob {
        draft_id: copilot::DraftId::new(),
        kind: Kind::IncidentNarrative,
        subject_id: subject,
        customer_id: None,
        chain: Chain::ETHEREUM,
    };
    let rule = DraftJob {
        draft_id: copilot::DraftId::new(),
        kind: Kind::RuleDraft,
        ..narrative.clone()
    };

    assert!(store
        .enqueue(&narrative, at(1))
        .await
        .expect("enqueue")
        .is_new());
    assert!(store.enqueue(&rule, at(2)).await.expect("enqueue").is_new());
}

// ── In-memory double (runs on every `cargo test`) ────────────────

macro_rules! double_tests {
    ($($name:ident => $contract:ident,)*) => {
        $(
            #[tokio::test]
            async fn $name() {
                $contract(&InMemoryDraftStore::default()).await;
            }
        )*
    };
}

double_tests! {
    double_enqueue_is_idempotent_per_subject => contract_enqueue_is_idempotent_per_subject,
    double_a_claimed_job_is_not_claimed_twice => contract_a_claimed_job_is_not_claimed_twice,
    double_an_expired_lease_is_reclaimed => contract_an_expired_lease_is_reclaimed,
    double_attempts_are_bounded => contract_attempts_are_bounded,
    double_the_row_is_the_cross_pod_cache => contract_the_row_is_the_cross_pod_cache,
    double_a_refusal_is_blocked_and_a_failure_is_not_cached =>
        contract_a_refusal_is_blocked_and_a_failure_is_not_cached,
    double_both_completion_writers_agree => contract_both_completion_writers_agree,
    double_a_transient_failure_requeues => contract_a_transient_failure_requeues,
    double_repeated_transient_failures_are_retired =>
        contract_repeated_transient_failures_are_retired,
    double_only_a_ready_draft_is_reviewable => contract_only_a_ready_draft_is_reviewable,
    double_kind_is_part_of_the_subject_key => contract_kind_is_part_of_the_subject_key,
}

// ── Real Postgres (`just test-integration`) ──────────────────────

async fn pg_store() -> (PgDraftStore, testcontainers::ContainerAsync<Postgres>) {
    let container = Postgres::default()
        .start()
        .await
        .expect("start Postgres container");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("Postgres port");
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");

    let pool = db::connect(&url).await.expect("connect");
    sqlx::migrate!("../db/migrations")
        .run(&pool)
        .await
        .expect("apply migrations");
    (PgDraftStore::new(pool), container)
}

macro_rules! pg_tests {
    ($($name:ident => $contract:ident,)*) => {
        $(
            #[tokio::test]
            #[ignore = "requires Docker (testcontainers Postgres)"]
            async fn $name() {
                let (store, _pg) = pg_store().await;
                store.ping().await.expect("schema applied");
                $contract(&store).await;
            }
        )*
    };
}

pg_tests! {
    pg_enqueue_is_idempotent_per_subject => contract_enqueue_is_idempotent_per_subject,
    pg_a_claimed_job_is_not_claimed_twice => contract_a_claimed_job_is_not_claimed_twice,
    pg_an_expired_lease_is_reclaimed => contract_an_expired_lease_is_reclaimed,
    pg_attempts_are_bounded => contract_attempts_are_bounded,
    pg_the_row_is_the_cross_pod_cache => contract_the_row_is_the_cross_pod_cache,
    pg_a_refusal_is_blocked_and_a_failure_is_not_cached =>
        contract_a_refusal_is_blocked_and_a_failure_is_not_cached,
    pg_both_completion_writers_agree => contract_both_completion_writers_agree,
    pg_a_transient_failure_requeues => contract_a_transient_failure_requeues,
    pg_repeated_transient_failures_are_retired =>
        contract_repeated_transient_failures_are_retired,
    pg_only_a_ready_draft_is_reviewable => contract_only_a_ready_draft_is_reviewable,
    pg_kind_is_part_of_the_subject_key => contract_kind_is_part_of_the_subject_key,
}
