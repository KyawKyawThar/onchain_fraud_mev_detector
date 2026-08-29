//! Response caching — the layer that makes at-least-once delivery affordable.
//!
//! # Why this is a correctness feature, not an optimisation
//!
//! §7 requires every consumer to dedup replayed events from day one. For a
//! projection, a duplicate costs a wasted write. Here it costs **money and a
//! different answer**: the model is not deterministic, so redelivering one
//! `IncidentCreated` produces a second narrative that disagrees in wording
//! with the first — and if the first was already shown to a compliance
//! reviewer, the system now has two versions of a regulatory document with no
//! record of which was read.
//!
//! Redelivery is not exotic here. It is the *normal* consequence of a rolling
//! update, a consumer-group rebalance, or a worker that died between calling
//! the provider and committing its work. So the cache is what turns
//! at-least-once into effectively-once for the expensive part.
//!
//! # The key is the request digest, and it includes the tenant
//!
//! [`CompletionRequest::digest`] folds in the customer id, the prompt
//! artifact's *content hash*, every message, and every generation parameter.
//! Two consequences worth stating:
//!
//! * **an edit to a live prompt busts the cache**, even if nobody bumped its
//!   version — the digest is over the bytes;
//! * **two tenants cannot share an entry.** A cache key that collided across
//!   customers would not be a stale read, it would be one customer's incident
//!   data served to another. That is why the digest is SHA-256 with
//!   length-prefixed fields rather than a convenience hash.
//!
//! The model id is part of the key too: the same question asked of a different
//! model is a different answer, and with server-side fallbacks in play the
//! configured model can change under a deployment.
//!
//! # What is cached
//!
//! Every *returned* completion, including refusals and truncations. A refusal
//! will refuse again — caching it is what stops a redelivery loop from paying
//! for the same decline repeatedly. A truncation is safe to cache because the
//! fix (raising `max_tokens`) changes the digest, so the retry is a different
//! key by construction. Failures are never cached: they are the case where
//! trying again genuinely might work.
//!
//! # Where the real cache lives
//!
//! [`InMemoryCache`] is process-local, so it survives a redelivery to *the
//! same pod* and nothing else — which is the common case for an immediate
//! retry, and useless for a rolling update. Like [`crate::CallAdmission`],
//! this is a seam: a deployment that wants cross-pod effectively-once supplies
//! a Postgres- or Redis-backed implementation from the service crate, where
//! the store edge is allowed. For the copilot specifically the natural home is
//! the drafts table it needs anyway — a draft keyed by request digest *is* the
//! cache.

use std::sync::{Arc, Mutex};

use bounded_map::BoundedFifoMap;

use crate::client::{Completion, CompletionRequest, LlmClient, LlmError};
use crate::digest::ContentDigest;
use crate::metrics::record_cache;

/// What a cached completion is filed under: the request digest plus the model
/// that would answer it.
///
/// Two digests rather than a digest and a `String`, so the key is `Copy` and
/// fits [`BoundedFifoMap`] — and, incidentally, so the key is fixed-size no
/// matter how long a model id gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CacheKey {
    model: ContentDigest,
    request: ContentDigest,
}

impl CacheKey {
    pub fn new(model: &str, request: &CompletionRequest) -> Self {
        Self {
            model: ContentDigest::of(model.as_bytes()),
            request: request.digest(),
        }
    }

    /// The request half of the key — the same digest a draft event is stamped
    /// with, so a stored draft and its cache entry are trivially joinable.
    pub fn request_digest(&self) -> ContentDigest {
        self.request
    }

    /// The model half. A digest, not the id: this is an identity component,
    /// and the readable model name is already on every completion and span.
    pub fn model_digest(&self) -> ContentDigest {
        self.model
    }
}

impl std::fmt::Display for CacheKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.model, self.request)
    }
}

/// The cache seam.
///
/// **Async, for the implementation that isn't in this crate.** The in-process
/// map below needs no `await` and pays one boxed future per call for the
/// privilege; the cross-pod cache the copilot supplies is a database round
/// trip, and a synchronous trait would force it to block a runtime worker on
/// that I/O — `block_in_place` + `Handle::block_on`, a spawned replacement
/// thread per call, and a hard requirement on the multi-threaded scheduler.
/// Sizing a seam for the cheap implementation and taxing the expensive one is
/// exactly backwards when the expensive one is the one that runs in
/// production.
#[async_trait::async_trait]
pub trait CompletionCache: Send + Sync + std::fmt::Debug {
    /// A previously stored completion for this exact request, if any.
    async fn get(&self, key: &CacheKey) -> Option<Completion>;

    /// Store a completion. Best-effort: an implementation that cannot store
    /// (full, store down) must return normally — a cache is never allowed to
    /// fail a call that already succeeded and was already paid for.
    async fn put(&self, key: CacheKey, completion: &Completion);
}

/// A cache that never hits — the default when caching is switched off, so the
/// stack shape stays the same either way rather than growing an `Option`.
#[derive(Debug, Default)]
pub struct NoCache;

#[async_trait::async_trait]
impl CompletionCache for NoCache {
    async fn get(&self, _key: &CacheKey) -> Option<Completion> {
        None
    }

    async fn put(&self, _key: CacheKey, _completion: &Completion) {}
}

/// Process-local cache over the workspace's bounded FIFO map.
///
/// [`BoundedFifoMap`] rather than a hand-rolled `HashMap` + eviction: an
/// unbounded map keyed by request digest is a memory leak with a backfill's
/// name on it, and this is the crate that already exists for exactly that
/// discipline.
#[derive(Debug)]
pub struct InMemoryCache {
    entries: Mutex<BoundedFifoMap<CacheKey, Entry>>,
    ttl: std::time::Duration,
}

#[derive(Debug, Clone)]
struct Entry {
    completion: Completion,
    stored_at: std::time::Instant,
}

impl InMemoryCache {
    /// `capacity` distinct requests; the oldest is evicted on overflow.
    /// `ttl` bounds staleness — a prompt's *inputs* can change without its
    /// digest changing (an incident's audit stream grows), so an entry that
    /// lives forever eventually answers a question nobody asked.
    pub fn new(capacity: usize, ttl: std::time::Duration) -> Self {
        Self {
            entries: Mutex::new(BoundedFifoMap::new(capacity.max(1), "llm completion cache")),
            ttl,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BoundedFifoMap<CacheKey, Entry>> {
        self.entries.lock().expect("llm cache mutex poisoned")
    }

    /// Entries currently held — for a gauge and for tests.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait::async_trait]
impl CompletionCache for InMemoryCache {
    /// No `await` inside, and none wanted: the lock is never held across a
    /// suspension point, so this stays a plain map lookup wearing an async
    /// signature.
    async fn get(&self, key: &CacheKey) -> Option<Completion> {
        let entries = self.lock();
        let entry = entries.get(key)?;
        (entry.stored_at.elapsed() < self.ttl).then(|| entry.completion.clone())
    }

    async fn put(&self, key: CacheKey, completion: &Completion) {
        self.lock().put(
            key,
            Entry {
                completion: completion.clone(),
                stored_at: std::time::Instant::now(),
            },
        );
    }
}

/// Wraps any [`LlmClient`] in a [`CompletionCache`].
///
/// Sits **outermost** in the stack, and that placement is the whole design: a
/// hit must cost nothing at all — no admission permit, no breaker signal, no
/// provider call, and no token bill. Putting the cache below the metering
/// decorator instead would bill a hit as a zero-token call and make the call
/// rate — the number the provider's rate limit is actually spent against —
/// wrong.
///
/// A hit therefore never appears in `llm_calls_total`; it appears in
/// `llm_cache_total{outcome="hit"}`, which is the same split
/// `intelligence_similarity_neighbor_cache_total` already uses.
#[derive(Debug)]
pub struct CachingClient<C> {
    inner: C,
    cache: Arc<dyn CompletionCache>,
}

impl<C: LlmClient> CachingClient<C> {
    pub fn new(inner: C, cache: Arc<dyn CompletionCache>) -> Self {
        Self { inner, cache }
    }

    pub fn inner(&self) -> &C {
        &self.inner
    }
}

#[async_trait::async_trait]
impl<C: LlmClient> LlmClient for CachingClient<C> {
    fn model(&self) -> &str {
        self.inner.model()
    }

    async fn complete(&self, request: &CompletionRequest) -> Result<Completion, LlmError> {
        let key = CacheKey::new(self.inner.model(), request);
        if let Some(hit) = self.cache.get(&key).await {
            record_cache(request.purpose, "hit");
            tracing::debug!(
                purpose = request.purpose,
                request = %key.request_digest(),
                "llm completion served from cache"
            );
            return Ok(hit);
        }
        record_cache(request.purpose, "miss");

        let outcome = self.inner.complete(request).await;
        // Store anything the provider *returned*, refusals and truncations
        // included (see the module docs); never store a failure, which is the
        // one case where trying again might genuinely differ.
        if let Ok(completion) = &outcome {
            self.cache.put(key, completion).await;
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{StopReason, TokenUsage};
    use crate::prompt::PromptDescriptor;
    use events::primitives::CustomerId;
    use std::time::Duration;

    fn completion(text: &str) -> Completion {
        Completion {
            text: text.to_owned(),
            stop_reason: StopReason::EndTurn,
            model: "claude-opus-5".into(),
            usage: TokenUsage::default(),
        }
    }

    #[tokio::test]
    async fn a_stored_completion_comes_back_for_the_same_request() {
        let cache = InMemoryCache::new(8, Duration::from_secs(60));
        let request = CompletionRequest::new("narrative", "incident 7");
        let key = CacheKey::new("claude-opus-5", &request);

        assert!(cache.get(&key).await.is_none());
        cache.put(key, &completion("a draft")).await;
        assert_eq!(cache.get(&key).await.unwrap().text, "a draft");
    }

    /// The tenant-isolation property. Identical questions, different
    /// customers: a shared entry here would serve one customer's incident
    /// analysis to another.
    #[tokio::test]
    async fn two_customers_asking_the_same_question_do_not_share_an_entry() {
        let cache = InMemoryCache::new(8, Duration::from_secs(60));
        let a = CompletionRequest::new("narrative", "incident 7").for_customer(CustomerId::new());
        let b = CompletionRequest::new("narrative", "incident 7").for_customer(CustomerId::new());

        let key_a = CacheKey::new("claude-opus-5", &a);
        let key_b = CacheKey::new("claude-opus-5", &b);
        assert_ne!(key_a, key_b);

        cache.put(key_a, &completion("customer A's draft")).await;
        assert!(cache.get(&key_b).await.is_none(), "cross-tenant hit");
    }

    /// An untracked edit to a live prompt must not be served from cache under
    /// the old answer.
    #[test]
    fn editing_a_prompt_under_its_version_busts_the_key() {
        static V1: std::sync::LazyLock<PromptDescriptor> =
            std::sync::LazyLock::new(|| PromptDescriptor::new("narrative", "v1", "be careful"));
        static V1_EDITED: std::sync::LazyLock<PromptDescriptor> =
            std::sync::LazyLock::new(|| PromptDescriptor::new("narrative", "v1", "be careful."));

        let before = CacheKey::new("m", &CompletionRequest::for_prompt(&V1, "incident 7"));
        let after = CacheKey::new(
            "m",
            &CompletionRequest::for_prompt(&V1_EDITED, "incident 7"),
        );
        assert_ne!(before, after);
    }

    #[test]
    fn the_same_question_of_a_different_model_is_a_different_key() {
        let request = CompletionRequest::new("narrative", "incident 7");
        assert_ne!(
            CacheKey::new("claude-opus-5", &request),
            CacheKey::new("claude-sonnet-5", &request)
        );
    }

    #[tokio::test]
    async fn an_expired_entry_is_a_miss() {
        let cache = InMemoryCache::new(8, Duration::from_millis(1));
        let request = CompletionRequest::new("narrative", "incident 7");
        let key = CacheKey::new("m", &request);
        cache.put(key, &completion("stale")).await;
        std::thread::sleep(Duration::from_millis(5));
        assert!(cache.get(&key).await.is_none());
    }

    /// A backfill must not be able to grow this without bound.
    #[tokio::test]
    async fn capacity_is_bounded_and_evicts_the_oldest() {
        let cache = InMemoryCache::new(2, Duration::from_secs(60));
        let keys: Vec<CacheKey> = (0..3)
            .map(|i| {
                CacheKey::new(
                    "m",
                    &CompletionRequest::new("narrative", format!("incident {i}")),
                )
            })
            .collect();
        for key in &keys {
            cache.put(*key, &completion("draft")).await;
        }
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&keys[0]).await.is_none(), "oldest evicted");
        assert!(cache.get(&keys[2]).await.is_some());
    }

    #[tokio::test]
    async fn the_null_cache_never_hits() {
        let request = CompletionRequest::new("narrative", "x");
        let key = CacheKey::new("m", &request);
        NoCache.put(key, &completion("ignored")).await;
        assert!(NoCache.get(&key).await.is_none());
    }
}
