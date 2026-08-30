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
use copilot::model::{DraftJob, DraftSource, DraftStatus, Review};
use copilot::store::{DraftFilter, DraftOutcome, DraftStore, PgDraftStore};
use copilot::test_util::InMemoryDraftStore;
use copilot::DraftKind as Kind;
use events::primitives::{Chain, IncidentId};
use events::{DomainEvent, EventEnvelope};
use llm::batch::{BatchId, BatchItemOutcome};
use llm::cache::CacheKey;
use llm::{Completion, CompletionRequest, StopReason, TokenUsage};
use std::time::Duration;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;
use uuid::Uuid;

fn at(secs: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(secs, 0).expect("valid timestamp")
}

fn job(incident: IncidentId) -> DraftJob {
    DraftJob::narrative(incident, Chain::ETHEREUM)
}

/// The audit window every attempt below declares — the ids a narrative is
/// allowed to cite. Landing applies the §20.4 citation check against exactly
/// this list, so a contract test that skipped it would be testing a path
/// production never takes.
fn window() -> Vec<Uuid> {
    vec![Uuid::from_u128(1), Uuid::from_u128(2)]
}

fn request(seed: &str) -> CompletionRequest {
    CompletionRequest::new("incident_narrative", seed)
}

/// A *grounded* narrative: the citation check is part of every landing, so a
/// completion a contract test expects to reach `ready` has to cite the window.
fn answer(text: &str) -> Completion {
    let ids = window();
    Completion {
        text: format!(
            "The audit stream records that {text} [{}, {}].",
            ids[0], ids[1]
        ),
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
            &window(),
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
    assert_eq!(hit.text, answer("a narrative").text);
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
        Some("incident_narrative@v2")
    );
    assert_eq!(
        draft.grounded_event_ids,
        window(),
        "the landed draft's ids are the ones its narrative cites"
    );

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
        .begin_attempt(refused.draft_id(), &key, None, &window(), at(3))
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
        .begin_attempt(failed.draft_id(), &failed_key, None, &window(), at(7))
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
        .begin_attempt(by_worker.draft_id(), &key_a, None, &window(), at(3))
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
        .begin_attempt(by_cache.draft_id(), &key_b, None, &window(), at(7))
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
    // The attempt declares its window before the call, exactly as the worker
    // does — without it the landing has nothing to check the narrative's
    // citations against, and a grounded answer would read as a fabricated one.
    store
        .begin_attempt(
            enqueued.draft_id(),
            &CacheKey::new("claude-opus-5", &request("reviewable")),
            Some(copilot::prompts::incident_narrative()),
            &window(),
            at(3),
        )
        .await
        .expect("begin");
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
        source: DraftSource::Live,
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

/// §20.4's citation boundary, at the store: a landing narrows
/// `grounded_event_ids` to what the narrative cites, and a narrative citing an
/// event it was never shown is `blocked` rather than handed to a reviewer.
///
/// This lives in the *contract* rather than only in `grounding`'s unit tests
/// because the narrowing is a write: if the store landed the window instead of
/// the cited subset, every downstream reader — the review API, the drafting
/// event, t5's grounding audit — would be checking claims against a list the
/// draft never made.
async fn contract_landing_narrows_ids_and_blocks_a_fabricated_citation(store: &dyn DraftStore) {
    let grounded = store
        .enqueue(&job(IncidentId::new()), at(1))
        .await
        .expect("enqueue");
    store
        .claim_batch(Kind::ALL, 10, Duration::from_secs(600), 3, at(2))
        .await
        .expect("claim");
    // Shown three events; the narrative will cite one of them.
    let shown = vec![Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3)];
    store
        .begin_attempt(
            grounded.draft_id(),
            &CacheKey::new("claude-opus-5", &request("grounded")),
            None,
            &shown,
            at(3),
        )
        .await
        .expect("begin");
    let status = store
        .finish(
            grounded.draft_id(),
            DraftOutcome::Completed(Box::new(Completion {
                text: format!(
                    "The attacker's transaction preceded the victim's swap [{}].",
                    shown[1]
                ),
                stop_reason: StopReason::EndTurn,
                model: "claude-opus-5".to_owned(),
                usage: TokenUsage::default(),
            })),
            at(4),
        )
        .await
        .expect("finish");
    assert_eq!(status, DraftStatus::Ready);

    let draft = store.get(grounded.draft_id()).await.unwrap().unwrap();
    assert_eq!(
        draft.grounded_event_ids,
        vec![shown[1]],
        "the window narrows to the cited ids"
    );
    let summary = draft.grounding.as_ref().expect("the check ran");
    assert_eq!((summary.claims, summary.cited_claims), (1, 1));

    // And the dangerous case: a citation that resolves to nothing.
    let invented = store
        .enqueue(&job(IncidentId::new()), at(5))
        .await
        .expect("enqueue");
    store
        .claim_batch(Kind::ALL, 10, Duration::from_secs(600), 3, at(6))
        .await
        .expect("claim");
    store
        .begin_attempt(
            invented.draft_id(),
            &CacheKey::new("claude-opus-5", &request("invented")),
            None,
            &shown,
            at(7),
        )
        .await
        .expect("begin");
    let status = store
        .finish(
            invented.draft_id(),
            DraftOutcome::Completed(Box::new(Completion {
                text: format!(
                    "The attacker was funded by a sanctioned entity [{}].",
                    Uuid::from_u128(0xDEAD)
                ),
                stop_reason: StopReason::EndTurn,
                model: "claude-opus-5".to_owned(),
                usage: TokenUsage::default(),
            })),
            at(8),
        )
        .await
        .expect("finish");
    assert_eq!(
        status,
        DraftStatus::Blocked,
        "a fabricated citation must never reach a reviewer as `ready`"
    );
    let draft = store.get(invented.draft_id()).await.unwrap().unwrap();
    assert!(draft
        .last_error
        .as_ref()
        .is_some_and(|error| error.contains("not in its audit window")));
    assert!(!draft
        .grounding
        .as_ref()
        .expect("the check ran")
        .unknown_event_ids
        .is_empty());
}

/// The announcement is written **with** the draft, in the same transaction:
/// a narrative reaching `ready` and the audit trail hearing about it are one
/// fact. Publishing afterwards would leave a window where a narrative exists
/// that nothing recorded; stamping the draft first would lose the event on a
/// crash. The outbox row is how both are avoided.
async fn contract_a_landing_files_its_announcement(store: &dyn DraftStore) {
    let enqueued = store
        .enqueue(&job(IncidentId::new()), at(1))
        .await
        .expect("enqueue");
    store
        .claim_batch(Kind::ALL, 10, Duration::from_secs(600), 3, at(2))
        .await
        .expect("claim");
    store
        .begin_attempt(
            enqueued.draft_id(),
            &CacheKey::new("claude-opus-5", &request("announce")),
            Some(copilot::prompts::incident_narrative()),
            &window(),
            at(3),
        )
        .await
        .expect("begin");

    assert!(store
        .pending_announcements(10)
        .await
        .expect("read")
        .is_empty());

    store
        .finish(
            enqueued.draft_id(),
            DraftOutcome::Completed(Box::new(answer("the swap was sandwiched"))),
            at(4),
        )
        .await
        .expect("finish");

    let pending = store.pending_announcements(10).await.expect("read");
    assert_eq!(pending.len(), 1, "the landing filed its announcement");
    assert_eq!(store.pending_announcement_count().await.unwrap(), 1);

    // The envelope is the wire form, ready to publish verbatim — and carries a
    // reference, never the prose.
    let envelope: EventEnvelope =
        serde_json::from_value(pending[0].envelope.clone()).expect("a decodable envelope");
    let DomainEvent::IncidentNarrativeDrafted(event) = &envelope.payload else {
        panic!(
            "expected IncidentNarrativeDrafted, got {:?}",
            envelope.payload
        );
    };
    assert_eq!(event.draft_id, enqueued.draft_id().0);
    assert_eq!(event.grounded_event_ids, window());
    assert_eq!(event.prompt_version, "v2");
    assert!(!pending[0].envelope.to_string().contains("a narrative"));

    // Stamped once published, so the flusher does not re-send it every tick.
    store
        .mark_announced(pending[0].id, at(5))
        .await
        .expect("stamp");
    assert_eq!(store.pending_announcement_count().await.unwrap(), 0);
}

/// A blocked draft has no narrative for anyone to read, so nothing is
/// announced for it: the audit trail must not claim a narrative was drafted
/// for an incident where none was.
async fn contract_a_blocked_landing_announces_nothing(store: &dyn DraftStore) {
    let enqueued = store
        .enqueue(&job(IncidentId::new()), at(1))
        .await
        .expect("enqueue");
    store
        .claim_batch(Kind::ALL, 10, Duration::from_secs(600), 3, at(2))
        .await
        .expect("claim");
    store
        .begin_attempt(
            enqueued.draft_id(),
            &CacheKey::new("claude-opus-5", &request("blocked")),
            Some(copilot::prompts::incident_narrative()),
            &window(),
            at(3),
        )
        .await
        .expect("begin");

    // Confident, wholly uncited prose: the citation check blocks it.
    let status = store
        .finish(
            enqueued.draft_id(),
            DraftOutcome::Completed(Box::new(Completion {
                text: "The attacker laundered the proceeds through a mixing service.".into(),
                stop_reason: StopReason::EndTurn,
                model: "claude-opus-5".to_owned(),
                usage: TokenUsage::default(),
            })),
            at(4),
        )
        .await
        .expect("finish");
    assert_eq!(status, DraftStatus::Blocked);
    assert!(store
        .pending_announcements(10)
        .await
        .expect("read")
        .is_empty());
}

/// Two landings racing one draft — a worker write and the cross-pod cache
/// write, the ordinary consequence of a rebalance — announce it **once**.
async fn contract_a_racing_landing_announces_once(store: &dyn DraftStore) {
    let enqueued = store
        .enqueue(&job(IncidentId::new()), at(1))
        .await
        .expect("enqueue");
    store
        .claim_batch(Kind::ALL, 10, Duration::from_secs(600), 3, at(2))
        .await
        .expect("claim");
    let key = CacheKey::new("claude-opus-5", &request("raced"));
    store
        .begin_attempt(
            enqueued.draft_id(),
            &key,
            Some(copilot::prompts::incident_narrative()),
            &window(),
            at(3),
        )
        .await
        .expect("begin");

    // The cache write lands it first…
    store
        .store_completion(&key, &answer("raced"), at(4))
        .await
        .expect("cache write");
    // …and the worker's own write arrives after.
    store
        .finish(
            enqueued.draft_id(),
            DraftOutcome::Completed(Box::new(answer("raced"))),
            at(5),
        )
        .await
        .expect("finish");

    assert_eq!(
        store.pending_announcement_count().await.unwrap(),
        1,
        "one draft, one announcement — whichever path landed it"
    );
}

/// A batch's results are consumed **once**, ever. The Batch API reports token
/// usage in the results stream, so a second fetch bills the same tokens again
/// — the claim is what makes that impossible rather than merely discouraged.
async fn contract_a_batch_result_fetch_is_claimed_once(store: &dyn DraftStore) {
    let enqueued = store
        .enqueue(
            &DraftJob::backfilled_narrative(IncidentId::new(), Chain::ETHEREUM),
            at(1),
        )
        .await
        .expect("enqueue");
    store
        .claim_for_batch(10, Duration::from_secs(600), 3, at(2))
        .await
        .expect("claim");

    let batch = BatchId("msgbatch_fetch_once".to_owned());
    store
        .attach_batch(&[enqueued.draft_id()], &batch, at(3))
        .await
        .expect("attach");

    assert!(store
        .claim_results_fetch(&batch, at(4))
        .await
        .expect("claim"));
    assert!(
        !store
            .claim_results_fetch(&batch, at(5))
            .await
            .expect("claim"),
        "a second reader must not re-fetch (and re-bill) the same results"
    );
}

/// The drain's terminating condition. A batch can end with drafts it never
/// accounted for — an unparseable result line, a `custom_id` that is not a
/// draft id, an item the provider never returned. They are released back to
/// the queue and the batch is closed, so the poll loop that keeps finding open
/// batches actually finishes.
async fn contract_an_unaccounted_draft_is_released_and_the_batch_closes(store: &dyn DraftStore) {
    let enqueued = store
        .enqueue(
            &DraftJob::backfilled_narrative(IncidentId::new(), Chain::ETHEREUM),
            at(1),
        )
        .await
        .expect("enqueue");
    store
        .claim_for_batch(10, Duration::from_secs(600), 3, at(2))
        .await
        .expect("claim");
    let batch = BatchId("msgbatch_short".to_owned());
    store
        .attach_batch(&[enqueued.draft_id()], &batch, at(3))
        .await
        .expect("attach");
    assert_eq!(
        store.open_batches().await.expect("open"),
        vec![batch.clone()]
    );

    // The results came back without this draft's item.
    let released = store
        .release_batch_stragglers(&batch, "batch ended without a result", at(4))
        .await
        .expect("release");
    assert_eq!(released, 1);

    let draft = store
        .get(enqueued.draft_id())
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(draft.status, DraftStatus::Queued, "re-submittable");
    assert!(
        draft.batch_id.is_none(),
        "a released draft must not stay attached to a finished batch"
    );

    store
        .close_batch(&batch, "released", at(5))
        .await
        .expect("close");
    assert!(
        store.open_batches().await.expect("open").is_empty(),
        "a closed batch is never polled again — this is what bounds the drain"
    );
}

/// The source split: a backfill draft belongs to the Batch API's lifecycle, so
/// the synchronous worker pool must not be able to claim it. If it could, a
/// historical narrative would be drafted at full price on a path nobody is
/// waiting on — §20.4's reason for using batches at all.
async fn contract_a_worker_cannot_claim_a_backfill_draft(store: &dyn DraftStore) {
    let backfilled = DraftJob::backfilled_narrative(IncidentId::new(), Chain::ETHEREUM);
    let enqueued = store.enqueue(&backfilled, at(1)).await.expect("enqueue");

    let by_worker = store
        .claim_batch(Kind::ALL, 10, Duration::from_secs(600), 3, at(2))
        .await
        .expect("claim");
    assert!(
        by_worker.is_empty(),
        "the worker pool must not pay full price for backfill work"
    );

    let by_backfill = store
        .claim_for_batch(10, Duration::from_secs(600), 3, at(3))
        .await
        .expect("claim");
    assert_eq!(by_backfill.len(), 1);
    assert_eq!(by_backfill[0].job.draft_id, enqueued.draft_id());
    assert_eq!(by_backfill[0].job.source, DraftSource::Backfill);

    // …and the reverse: the batch claim leaves live drafts alone.
    store
        .enqueue(&job(IncidentId::new()), at(4))
        .await
        .expect("enqueue");
    let again = store
        .claim_for_batch(10, Duration::from_secs(600), 3, at(5))
        .await
        .expect("claim");
    assert!(again.is_empty(), "a live draft is the worker pool's");
}

/// The batch lifecycle: the id is durable, outstanding batches are
/// discoverable after a restart, and a result lands only on a draft that is
/// still in that batch.
async fn contract_the_batch_id_survives_and_scopes_the_landing(store: &dyn DraftStore) {
    let enqueued = store
        .enqueue(
            &DraftJob::backfilled_narrative(IncidentId::new(), Chain::ETHEREUM),
            at(1),
        )
        .await
        .expect("enqueue");
    let claimed = store
        .claim_for_batch(10, Duration::from_secs(600), 3, at(2))
        .await
        .expect("claim");
    let draft_id = claimed[0].job.draft_id;
    store
        .begin_attempt(
            draft_id,
            &CacheKey::new("claude-opus-5", &request("batched")),
            Some(copilot::prompts::incident_narrative()),
            &window(),
            at(3),
        )
        .await
        .expect("begin");

    let batch = BatchId("msgbatch_contract".to_owned());
    store
        .attach_batch(&[draft_id], &batch, at(4))
        .await
        .expect("attach");
    assert_eq!(
        store.open_batches().await.expect("open"),
        vec![batch.clone()],
        "a restarted backfill finds the job it already paid for"
    );

    // A result from a *different* batch must not touch this row.
    let stray = BatchId("msgbatch_other".to_owned());
    assert!(!store
        .land_batch_outcome(
            draft_id,
            &stray,
            BatchItemOutcome::Answered(Box::new(answer("from another batch"))),
            at(5)
        )
        .await
        .expect("land"));
    assert_eq!(
        store.get(draft_id).await.unwrap().unwrap().status,
        DraftStatus::InFlight
    );

    assert!(store
        .land_batch_outcome(
            draft_id,
            &batch,
            BatchItemOutcome::Answered(Box::new(answer("the swap was sandwiched"))),
            at(6)
        )
        .await
        .expect("land"));

    let draft = store.get(draft_id).await.unwrap().unwrap();
    assert_eq!(draft.status, DraftStatus::Ready);
    assert_eq!(
        draft.grounded_event_ids,
        window(),
        "a batched answer is held to the same citation check as a live one"
    );
    assert_eq!(draft.batch_id.as_deref(), Some("msgbatch_contract"));
    assert_eq!(draft.draft_id, enqueued.draft_id());

    // Landing an item does *not* close the batch: a batch is open until
    // somebody has accounted for all of it. That is deliberate — the drain
    // closes it after reconciling, which is what stops a batch whose results
    // came back short from being polled forever.
    assert_eq!(
        store.open_batches().await.expect("open"),
        vec![batch.clone()],
        "landing an item does not decide whether the batch is finished"
    );
    store
        .close_batch(&batch, "landed", at(7))
        .await
        .expect("close");
    assert!(
        store.open_batches().await.expect("open").is_empty(),
        "a closed batch is never polled again"
    );
}

/// The review queue's filters. Narrow reads are the difference between a
/// reviewer's working list and a table scan of every narrative ever drafted.
async fn contract_the_review_queue_filters(store: &dyn DraftStore) {
    let incident = IncidentId::new();
    store.enqueue(&job(incident), at(1)).await.expect("enqueue");
    store
        .enqueue(
            &DraftJob::backfilled_narrative(IncidentId::new(), Chain::ETHEREUM),
            at(2),
        )
        .await
        .expect("enqueue");

    let all = store
        .list(&DraftFilter::with_limit(10))
        .await
        .expect("list");
    assert_eq!(all.len(), 2);
    assert!(
        all[0].created_at >= all[1].created_at,
        "newest first: {all:#?}"
    );

    let live = store
        .list(&DraftFilter {
            source: Some(DraftSource::Live),
            ..DraftFilter::with_limit(10)
        })
        .await
        .expect("list");
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].subject_id, incident.0);

    let by_subject = store
        .list(&DraftFilter {
            subject_id: Some(incident.0),
            status: Some(DraftStatus::Queued),
            kind: Some(Kind::IncidentNarrative),
            ..DraftFilter::with_limit(10)
        })
        .await
        .expect("list");
    assert_eq!(by_subject.len(), 1);

    assert!(store
        .list(&DraftFilter {
            status: Some(DraftStatus::Approved),
            ..DraftFilter::with_limit(10)
        })
        .await
        .expect("list")
        .is_empty());
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
    double_landing_narrows_ids_and_blocks_a_fabricated_citation =>
        contract_landing_narrows_ids_and_blocks_a_fabricated_citation,
    double_a_landing_files_its_announcement => contract_a_landing_files_its_announcement,
    double_a_blocked_landing_announces_nothing => contract_a_blocked_landing_announces_nothing,
    double_a_racing_landing_announces_once => contract_a_racing_landing_announces_once,
    double_a_batch_result_fetch_is_claimed_once =>
        contract_a_batch_result_fetch_is_claimed_once,
    double_an_unaccounted_draft_is_released_and_the_batch_closes =>
        contract_an_unaccounted_draft_is_released_and_the_batch_closes,
    double_a_worker_cannot_claim_a_backfill_draft =>
        contract_a_worker_cannot_claim_a_backfill_draft,
    double_the_batch_id_survives_and_scopes_the_landing =>
        contract_the_batch_id_survives_and_scopes_the_landing,
    double_the_review_queue_filters => contract_the_review_queue_filters,
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
    pg_landing_narrows_ids_and_blocks_a_fabricated_citation =>
        contract_landing_narrows_ids_and_blocks_a_fabricated_citation,
    pg_a_landing_files_its_announcement => contract_a_landing_files_its_announcement,
    pg_a_blocked_landing_announces_nothing => contract_a_blocked_landing_announces_nothing,
    pg_a_racing_landing_announces_once => contract_a_racing_landing_announces_once,
    pg_a_batch_result_fetch_is_claimed_once =>
        contract_a_batch_result_fetch_is_claimed_once,
    pg_an_unaccounted_draft_is_released_and_the_batch_closes =>
        contract_an_unaccounted_draft_is_released_and_the_batch_closes,
    pg_a_worker_cannot_claim_a_backfill_draft =>
        contract_a_worker_cannot_claim_a_backfill_draft,
    pg_the_batch_id_survives_and_scopes_the_landing =>
        contract_the_batch_id_survives_and_scopes_the_landing,
    pg_the_review_queue_filters => contract_the_review_queue_filters,
}
