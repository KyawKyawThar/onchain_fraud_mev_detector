//! The drafts table as `llm::CompletionCache` — the cross-pod half of §20.4's
//! "at-least-once must not mean twice-billed".
//!
//! # What the in-process cache cannot do
//!
//! `llm::InMemoryCache` survives a redelivery to *the same pod* and nothing
//! else. The redeliveries that actually happen here are the ones it cannot
//! help with: a rolling update, a consumer-group rebalance, a worker killed
//! between the provider's answer and its own bookkeeping. Each of those hands
//! the job to a *different* process, which — with a process-local cache —
//! pays again and produces a second narrative that disagrees in wording with
//! the first. For a regulatory document that is not a wasted write; it is two
//! versions of the same filing with no record of which one a reviewer read.
//!
//! # Why the cache and the draft are one row
//!
//! A cached completion is an answer somebody was billed for. Filing it
//! anywhere other than the draft it answers would leave the platform holding
//! a paid-for regulatory text that no audit trail accounts for. So `get` is a
//! read of the newest usable draft under this `(model, request)` pair, and
//! `put` lands the answer on every in-flight draft waiting for it (see
//! [`crate::store::DraftCache::store_completion`] for why matching on the
//! digest rather than a draft id is the point).
//!
//! # A cache may never fail a call
//!
//! Every store fault here is logged and swallowed. `get` degrades to a miss
//! (worst case: a second call, which is the behaviour without a cache at
//! all); `put` degrades to a lost entry, and the worker's own `finish` write
//! still records the draft. Propagating a cache error would fail a call that
//! already succeeded and was already paid for.
//!
//! # This is an adapter, and it holds no logic
//!
//! Everything below is `llm`'s vocabulary translated into the store's and
//! back. The decisions — which statuses are cacheable, what a refusal lands
//! as, which rows a digest-keyed write may touch — all live in
//! [`crate::store`], because they are facts about drafts rather than facts
//! about caching. An adapter that started deciding things would be a second
//! place to look when the two disagreed.

use std::sync::Arc;

use chrono::Utc;
use llm::cache::{CacheKey, CompletionCache};
use llm::Completion;

use crate::store::DraftCache;

/// The drafts table, exposed as the LLM seam's cache.
///
/// Depends on [`DraftCache`] and not the whole store: this adapter can read a
/// completion and land one, and has no way to enqueue, claim, or approve
/// anything. Interface segregation as a blast radius, not as an aesthetic —
/// the type that a third-party seam holds an `Arc` to should be able to do as
/// little as possible.
#[derive(Clone)]
pub struct PgCompletionCache {
    store: Arc<dyn DraftCache>,
}

impl std::fmt::Debug for PgCompletionCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgCompletionCache").finish_non_exhaustive()
    }
}

impl PgCompletionCache {
    pub fn new(store: Arc<dyn DraftCache>) -> Self {
        Self { store }
    }
}

#[async_trait::async_trait]
impl CompletionCache for PgCompletionCache {
    async fn get(&self, key: &CacheKey) -> Option<Completion> {
        match self.store.cached_completion(key).await {
            Ok(hit) => hit,
            Err(err) => {
                // A miss, not a failure: the call proceeds and pays. Worth a
                // warning, because a persistently unreadable cache means the
                // fleet is quietly re-billing every redelivery.
                tracing::warn!(error = %err, "draft cache read failed; treating as a miss");
                None
            }
        }
    }

    async fn put(&self, key: CacheKey, completion: &Completion) {
        match self
            .store
            .store_completion(&key, completion, Utc::now())
            .await
        {
            Ok(0) => {
                // The answer arrived with no in-flight draft to land on — a
                // lease expired mid-call and another pod took over, or the
                // call came from somewhere that never wrote a draft row (a
                // boot smoke call). The worker's own `finish` still records
                // its draft; nothing is lost that this write owned.
                tracing::debug!("completion landed on no in-flight draft");
            }
            Ok(rows) => tracing::debug!(rows, "completion cached onto in-flight drafts"),
            Err(err) => {
                tracing::warn!(error = %err, "draft cache write failed; the answer is still recorded by the worker")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DraftJob, DraftKind, DraftStatus};
    use crate::store::{DraftQueue, DraftReview, DraftWorkQueue};
    use crate::test_util::{completion, request, InMemoryDraftStore};
    use events::primitives::{Chain, IncidentId};

    /// Enqueue one narrative, claim it, and declare the request it is about
    /// to make — the state a completion needs to land on.
    async fn in_flight(store: &InMemoryDraftStore, key: &CacheKey) -> crate::model::DraftId {
        let job = DraftJob::narrative(IncidentId::new(), Chain::ETHEREUM);
        let enqueued = store.enqueue(&job, Utc::now()).await.unwrap();
        let claimed = store
            .claim_batch(
                DraftKind::ALL,
                10,
                std::time::Duration::from_secs(60),
                3,
                Utc::now(),
            )
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1);
        store
            .begin_attempt(enqueued.draft_id(), key, None, &[], Utc::now())
            .await
            .unwrap();
        enqueued.draft_id()
    }

    #[tokio::test]
    async fn a_second_pod_reads_the_answer_the_first_one_paid_for() {
        let store = Arc::new(InMemoryDraftStore::default());
        let cache = PgCompletionCache::new(store.clone());

        let request = request();
        let key = CacheKey::new("claude-opus-5", &request);
        let draft_id = in_flight(&store, &key).await;

        assert!(cache.get(&key).await.is_none(), "nothing paid for yet");
        cache.put(key, &completion("a narrative")).await;

        // The write landed on the draft — the cache entry and the audit
        // record are the same row.
        let draft = store.get(draft_id).await.unwrap().unwrap();
        assert_eq!(draft.status, DraftStatus::Ready);
        assert_eq!(draft.body(), Some("a narrative"));
        assert_eq!(draft.kind, DraftKind::IncidentNarrative);

        let hit = cache
            .get(&CacheKey::new("claude-opus-5", &request))
            .await
            .expect("a redelivery on any pod reads the first answer");
        assert_eq!(hit.text, "a narrative");
    }

    #[tokio::test]
    async fn a_different_model_is_a_different_key() {
        let store = Arc::new(InMemoryDraftStore::default());
        let cache = PgCompletionCache::new(store.clone());
        let request = request();
        let key = CacheKey::new("claude-opus-5", &request);
        in_flight(&store, &key).await;
        cache.put(key, &completion("a narrative")).await;

        assert!(
            cache
                .get(&CacheKey::new("some-other-model", &request))
                .await
                .is_none(),
            "the same question asked of a different model is a different answer"
        );
    }

    /// A cache is never allowed to fail a call that already succeeded and was
    /// already paid for — so a store that is down reads as a miss and writes
    /// as a no-op, and the caller never learns.
    #[tokio::test]
    async fn a_store_fault_degrades_instead_of_propagating() {
        let store = Arc::new(InMemoryDraftStore::default().failing_transiently());
        let cache = PgCompletionCache::new(store);
        let key = CacheKey::new("claude-opus-5", &request());

        assert!(cache.get(&key).await.is_none());
        cache.put(key, &completion("swallowed")).await;
    }
}
