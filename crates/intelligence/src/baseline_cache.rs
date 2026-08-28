//! A process-wide, periodically refreshed snapshot of the population baseline
//! (§20.3) — the read path's answer to "this datum is shared by every request,
//! so stop fetching it per request".
//!
//! # Why this is a snapshot and not a cache
//!
//! A [`BehaviorBaseline`] is keyed by `(chain, embedding_version)` — **not** by
//! address. Every similarity search on a chain standardizes against the same
//! ~264 bytes (two vectors of [`INDEXED_DIMENSION`](super::INDEXED_DIMENSION)
//! floats), and the baseline job rewrites it on the order of once a day. Read
//! per request it costs a ClickHouse round trip, a connection, and a failure
//! mode, all to re-read a value that did not change. That is not a cache miss
//! problem; it is the wrong shape.
//!
//! So it is loaded once, refreshed on a timer, and served from memory. There is
//! no per-key eviction, no TTL race with a writer, and no invalidation stream —
//! the staleness bound is simply [`refresh_interval`](BaselineCacheConfig).
//!
//! # `RwLock`, deliberately, over an `ArcSwap`
//!
//! A read takes the lock only long enough to clone an `Arc` — tens of
//! nanoseconds — and uncontended readers never block one another. Writes happen
//! a handful of times a day. `arc-swap` would shave that to a single atomic
//! load, which is not worth a new dependency in a workspace with a
//! supply-chain policy (§14) for a lock this cold. If profiling ever shows read
//! contention here, the seam is one type wide and swapping it is mechanical.
//!
//! # Staleness is measured, not assumed
//!
//! The failure this exists to make visible: if the `embedding-baseline` run
//! mode dies, nothing breaks. Searches keep returning confident rankings
//! against a population that is drifting away from reality — the worst kind of
//! outage, because it looks exactly like success. So the snapshot records how
//! old its value is, exports it as a gauge, and **refuses** a baseline past
//! [`max_age`](BaselineCacheConfig): a refused search is recoverable, a
//! silently wrong ranking is not.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use events::primitives::Chain;

use crate::embedding::baseline::BehaviorBaseline;
use crate::embedding_store::{EmbeddingStore, EmbeddingStoreError};

/// Age of the served population baseline, in seconds, labelled by chain and
/// embedding version. A gauge rather than a counter because the question ops
/// asks is "how stale is it *now*" — alert above roughly two refresh
/// intervals, and hard-alert as it approaches `max_age`.
pub const BASELINE_AGE_SECONDS: &str = "intelligence_similarity_baseline_age_seconds";
/// Refresh attempts, labelled `outcome` = `loaded` | `missing` | `error`. A
/// sustained `error` rate with a rising [`BASELINE_AGE_SECONDS`] is the
/// signature of "ClickHouse is up but the baseline table is not readable".
pub const BASELINE_REFRESH_TOTAL: &str = "intelligence_similarity_baseline_refresh_total";

/// Bounds for the snapshot.
#[derive(Debug, Clone, Copy)]
pub struct BaselineCacheConfig {
    /// How often to re-read the baseline from the store. Well below `max_age`,
    /// so a couple of consecutive failed refreshes do not take the endpoint
    /// down.
    pub refresh_interval: Duration,
    /// Past this age a baseline is refused rather than served. The population
    /// it describes has moved on, and ranking against it would be confident
    /// and wrong — the one output this subsystem must never produce.
    pub max_age: Duration,
}

impl Default for BaselineCacheConfig {
    fn default() -> Self {
        Self {
            // The baseline job runs on a far slower cadence than this; the
            // interval is short because the read is cheap and picking up a
            // re-derived baseline promptly is what keeps rankings consistent
            // across replicas.
            refresh_interval: Duration::from_secs(300),
            // Seven refresh intervals of slack before an operator-visible
            // failure becomes a caller-visible one.
            max_age: Duration::from_secs(7 * 24 * 60 * 60),
        }
    }
}

/// What the snapshot currently holds.
#[derive(Clone)]
struct Snapshot {
    baseline: Option<Arc<BehaviorBaseline>>,
    /// When the *baseline itself* was computed — not when we last read it. The
    /// distinction is the whole point: a successful refresh of an ancient
    /// baseline is still an ancient baseline.
    computed_at: Option<DateTime<Utc>>,
}

/// A periodically refreshed population baseline for one
/// `(chain, embedding_version)`.
pub struct BaselineSnapshot {
    chain: Chain,
    embedding_version: String,
    config: BaselineCacheConfig,
    current: RwLock<Snapshot>,
}

impl BaselineSnapshot {
    /// Build an empty snapshot. Empty is a legitimate state — the baseline job
    /// may genuinely not have run yet — and reads report it as
    /// [`Unavailable::NoBaseline`](super::Unavailable::NoBaseline) rather than
    /// as an error.
    pub fn new(chain: Chain, embedding_version: String, config: BaselineCacheConfig) -> Self {
        Self {
            chain,
            embedding_version,
            config,
            current: RwLock::new(Snapshot {
                baseline: None,
                computed_at: None,
            }),
        }
    }

    /// The current baseline, or `None` when none has been loaded *or* the
    /// loaded one is past [`BaselineCacheConfig::max_age`].
    ///
    /// Takes `now` explicitly rather than reading the clock, so the staleness
    /// rule is testable without sleeping — the same `as_of` discipline the
    /// embedding kernel follows.
    pub fn get(&self, now: DateTime<Utc>) -> Option<Arc<BehaviorBaseline>> {
        let snapshot = self.current.read().ok()?.clone();
        let baseline = snapshot.baseline?;
        let computed_at = snapshot.computed_at?;

        let age = now.signed_duration_since(computed_at);
        // A negative age (a writer's clock ahead of ours) is not stale.
        if age.num_seconds() > self.config.max_age.as_secs() as i64 {
            return None;
        }
        Some(baseline)
    }

    /// Age of the held baseline as of `now`, if one is held.
    pub fn age(&self, now: DateTime<Utc>) -> Option<Duration> {
        let computed_at = self.current.read().ok()?.computed_at?;
        let secs = now.signed_duration_since(computed_at).num_seconds();
        Some(Duration::from_secs(secs.max(0) as u64))
    }

    /// Re-read the baseline from the store and publish it.
    ///
    /// A miss leaves whatever is held in place rather than clearing it: the
    /// baseline table not answering is not evidence that the baseline is gone,
    /// and dropping a good value on a transient read would turn a blip into an
    /// outage. `max_age` is what eventually retires a stale value — one rule
    /// for going stale, not two.
    pub async fn refresh(
        &self,
        store: &dyn EmbeddingStore,
        now: DateTime<Utc>,
    ) -> Result<(), EmbeddingStoreError> {
        let outcome = store
            .latest_baseline(self.chain, &self.embedding_version)
            .await;

        match outcome {
            Ok(Some(baseline)) => {
                let computed_at = baseline.computed_at;
                if let Ok(mut guard) = self.current.write() {
                    *guard = Snapshot {
                        baseline: Some(Arc::new(baseline)),
                        computed_at: Some(computed_at),
                    };
                }
                metrics::counter!(BASELINE_REFRESH_TOTAL, "outcome" => "loaded").increment(1);
                self.report_age(now);
                Ok(())
            }
            Ok(None) => {
                metrics::counter!(BASELINE_REFRESH_TOTAL, "outcome" => "missing").increment(1);
                self.report_age(now);
                Ok(())
            }
            Err(err) => {
                metrics::counter!(BASELINE_REFRESH_TOTAL, "outcome" => "error").increment(1);
                self.report_age(now);
                Err(err)
            }
        }
    }

    /// Publish the age gauge. Called after every refresh so the value tracks
    /// wall time even while the baseline itself does not change.
    fn report_age(&self, now: DateTime<Utc>) {
        if let Some(age) = self.age(now) {
            metrics::gauge!(
                BASELINE_AGE_SECONDS,
                "chain" => self.chain.id().to_string(),
                "embedding_version" => self.embedding_version.clone(),
            )
            .set(age.as_secs_f64());
        }
    }

    pub fn refresh_interval(&self) -> Duration {
        self.config.refresh_interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embedding::v1;
    use crate::test_util::RecordingEmbeddingStore;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    fn baseline(computed_at: DateTime<Utc>) -> BehaviorBaseline {
        let schema = &*v1::SCHEMA;
        BehaviorBaseline {
            embedding_version: schema.version().to_owned(),
            schema_hash: schema.content_hash().to_owned(),
            centre: vec![0.0; schema.dimension()],
            spread: vec![1.0; schema.dimension()],
            sample_count: crate::embedding::baseline::MIN_SAMPLES,
            computed_at,
        }
    }

    fn snapshot(config: BaselineCacheConfig) -> BaselineSnapshot {
        BaselineSnapshot::new(Chain::ETHEREUM, v1::VERSION.to_owned(), config)
    }

    /// An empty snapshot is a legitimate state, not an error: the baseline job
    /// may simply not have run yet.
    #[tokio::test]
    async fn an_unloaded_snapshot_is_empty_rather_than_erroring() {
        let cache = snapshot(BaselineCacheConfig::default());
        assert!(cache.get(at(0)).is_none());
        assert!(cache.age(at(0)).is_none());
    }

    #[tokio::test]
    async fn a_refresh_publishes_the_stored_baseline_and_its_age() {
        let store = RecordingEmbeddingStore::new();
        store
            .put_baseline(Chain::ETHEREUM, &baseline(at(1_000)))
            .await
            .unwrap();

        let cache = snapshot(BaselineCacheConfig::default());
        cache.refresh(&store, at(1_000)).await.unwrap();

        assert!(cache.get(at(1_000)).is_some());
        assert_eq!(cache.age(at(1_600)), Some(Duration::from_secs(600)));
    }

    /// The whole reason the snapshot measures age: a baseline whose population
    /// has moved on must be refused, not served. A confident ranking against a
    /// dead baseline is the one output this subsystem must never produce.
    #[tokio::test]
    async fn a_baseline_past_max_age_is_refused_rather_than_served() {
        let store = RecordingEmbeddingStore::new();
        store
            .put_baseline(Chain::ETHEREUM, &baseline(at(0)))
            .await
            .unwrap();

        let cache = snapshot(BaselineCacheConfig {
            refresh_interval: Duration::from_secs(60),
            max_age: Duration::from_secs(3_600),
        });
        cache.refresh(&store, at(0)).await.unwrap();

        assert!(cache.get(at(3_000)).is_some(), "inside max_age");
        assert!(cache.get(at(3_601)).is_none(), "past max_age");
    }

    /// A read failure must not discard a good value — the table not answering
    /// is not evidence the baseline is gone, and dropping it would turn a blip
    /// into an outage. `max_age` is the single rule that retires a value.
    #[tokio::test]
    async fn a_failed_refresh_keeps_the_previous_baseline() {
        let store = RecordingEmbeddingStore::new();
        store
            .put_baseline(Chain::ETHEREUM, &baseline(at(1_000)))
            .await
            .unwrap();
        let cache = snapshot(BaselineCacheConfig::default());
        cache.refresh(&store, at(1_000)).await.unwrap();

        store.fail_next();
        let _ = cache.refresh(&store, at(1_100)).await;

        assert!(
            cache.get(at(1_100)).is_some(),
            "a transient read failure must not clear a good baseline"
        );
    }

    /// Likewise for a genuine miss: the store answering "none" while we hold a
    /// good value is not a reason to forget it.
    #[tokio::test]
    async fn a_missing_baseline_does_not_clear_a_held_one() {
        let store = RecordingEmbeddingStore::new();
        store
            .put_baseline(Chain::ETHEREUM, &baseline(at(1_000)))
            .await
            .unwrap();
        let cache = snapshot(BaselineCacheConfig::default());
        cache.refresh(&store, at(1_000)).await.unwrap();

        let empty = RecordingEmbeddingStore::new();
        cache.refresh(&empty, at(1_100)).await.unwrap();

        assert!(cache.get(at(1_100)).is_some());
    }

    /// A writer whose clock runs ahead of ours yields a negative age; that is
    /// not staleness and must not refuse the search.
    #[tokio::test]
    async fn a_future_dated_baseline_is_not_stale() {
        let store = RecordingEmbeddingStore::new();
        store
            .put_baseline(Chain::ETHEREUM, &baseline(at(10_000)))
            .await
            .unwrap();
        let cache = snapshot(BaselineCacheConfig::default());
        cache.refresh(&store, at(0)).await.unwrap();

        assert!(cache.get(at(0)).is_some());
        assert_eq!(cache.age(at(0)), Some(Duration::from_secs(0)));
    }
}
