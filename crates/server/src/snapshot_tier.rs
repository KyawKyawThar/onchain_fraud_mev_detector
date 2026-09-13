//! A per-pod memory tier in front of the Redis snapshot store (§11 graceful
//! degradation, readiness Epic D).
//!
//! **A second failure domain, not only a faster read.** Redis already carries
//! intelligence's hot cache and this service's rate limiter. A Redis incident is
//! therefore likely to coincide with a degraded intelligence — the one moment
//! the snapshots are needed. The L1 tier keeps the most recently screened
//! addresses in the pod itself, so the fallback still answers for the traffic
//! that is actually arriving when Redis is gone.
//!
//! **Fewer writes.** Most screening calls re-screen an address whose facts have
//! not changed. Writing the same bytes to Redis on every call is pure load, so a
//! write whose facts digest matches the last one *written to L2* is skipped —
//! until `rewrite_after` has passed, after which it is rewritten so the shared
//! copy's `observed_at` (what another pod's age check reads) never lags reality
//! by more than that.
//!
//! **Bounded, FIFO, counted.** The tier holds at most `capacity` addresses and
//! evicts the oldest-inserted; every eviction is a counter increment, never a
//! log line — at production volume a per-eviction warning is a log flood (why
//! this does not reuse `bounded_map::BoundedFifoMap`, which warns per eviction
//! because its call sites treat eviction as an anomaly).

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::primitives::AccountAddress;
use prost::Message;

use crate::degrade::{FactsSnapshot, SnapshotError, SnapshotStore};

/// Counter: snapshot reads, by `tier` (`l1` | `l2`) and `result` (`hit` |
/// `miss`).
pub const TIER_READS_TOTAL: &str = "screening_snapshot_tier_reads_total";
/// Counter: snapshot writes not sent to Redis because the facts were unchanged.
pub const WRITES_SKIPPED_TOTAL: &str = "screening_snapshot_writes_skipped_total";
/// Counter: addresses evicted from the memory tier to stay within capacity.
pub const L1_EVICTIONS_TOTAL: &str = "screening_snapshot_l1_evictions_total";

struct Entry {
    snapshot: FactsSnapshot,
    digest: u64,
    /// `observed_at` of the copy L2 last accepted for this address, if any.
    l2_written: Option<(u64, DateTime<Utc>)>,
}

struct L1 {
    capacity: usize,
    entries: HashMap<AccountAddress, Entry>,
    order: VecDeque<AccountAddress>,
}

impl L1 {
    fn insert(&mut self, address: AccountAddress, snapshot: FactsSnapshot, digest: u64) {
        if let Some(entry) = self.entries.get_mut(&address) {
            entry.snapshot = snapshot;
            entry.digest = digest;
            return;
        }
        while self.entries.len() >= self.capacity {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if self.entries.remove(&oldest).is_some() {
                metrics::counter!(L1_EVICTIONS_TOTAL).increment(1);
            }
        }
        self.order.push_back(address);
        self.entries.insert(
            address,
            Entry {
                snapshot,
                digest,
                l2_written: None,
            },
        );
    }
}

/// [`SnapshotStore`] with a bounded memory tier over a shared one.
pub struct TieredSnapshotStore {
    l1: Mutex<L1>,
    l2: Arc<dyn SnapshotStore>,
    rewrite_after: Duration,
}

impl TieredSnapshotStore {
    /// `capacity` must be at least 1 — a deployment without a memory tier uses
    /// the L2 store directly rather than wrapping it in an empty one.
    pub fn new(l2: Arc<dyn SnapshotStore>, capacity: usize, rewrite_after: Duration) -> Self {
        assert!(
            capacity > 0,
            "an L1 tier needs capacity; use the L2 store directly"
        );
        Self {
            l1: Mutex::new(L1 {
                capacity,
                entries: HashMap::new(),
                order: VecDeque::new(),
            }),
            l2,
            rewrite_after,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, L1> {
        // Every mutation leaves the map consistent between statements, so a
        // poisoned lock is recovered rather than latched (§15).
        self.l1
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// A digest of the facts alone — not `observed_at`, which changes on every
/// fresh read even when nothing else does.
fn digest(snapshot: &FactsSnapshot) -> u64 {
    let mut hasher = DefaultHasher::new();
    snapshot.facts.encode_to_vec().hash(&mut hasher);
    hasher.finish()
}

#[async_trait]
impl SnapshotStore for TieredSnapshotStore {
    async fn get(&self, address: &AccountAddress) -> Result<Option<FactsSnapshot>, SnapshotError> {
        if let Some(entry) = self.lock().entries.get(address) {
            metrics::counter!(TIER_READS_TOTAL, "tier" => "l1", "result" => "hit").increment(1);
            return Ok(Some(entry.snapshot.clone()));
        }
        metrics::counter!(TIER_READS_TOTAL, "tier" => "l1", "result" => "miss").increment(1);

        let found = self.l2.get(address).await?;
        let result = if found.is_some() { "hit" } else { "miss" };
        metrics::counter!(TIER_READS_TOTAL, "tier" => "l2", "result" => result).increment(1);
        if let Some(snapshot) = &found {
            let digest = digest(snapshot);
            let mut l1 = self.lock();
            // A concurrent fresh write may have landed while L2 was read; the
            // newer observation wins.
            let newer_present = l1
                .entries
                .get(address)
                .is_some_and(|e| e.snapshot.observed_at >= snapshot.observed_at);
            if !newer_present {
                l1.insert(*address, snapshot.clone(), digest);
                if let Some(entry) = l1.entries.get_mut(address) {
                    entry.l2_written = Some((digest, snapshot.observed_at));
                }
            }
        }
        Ok(found)
    }

    async fn put_many(
        &self,
        snapshots: Vec<(AccountAddress, FactsSnapshot)>,
    ) -> Result<(), SnapshotError> {
        let mut to_l2 = Vec::new();
        let mut written = Vec::new();
        {
            let mut l1 = self.lock();
            for (address, snapshot) in snapshots {
                let digest = digest(&snapshot);
                let unchanged_and_recent = l1
                    .entries
                    .get(&address)
                    .and_then(|entry| entry.l2_written)
                    .is_some_and(|(written_digest, written_at)| {
                        written_digest == digest
                            && (snapshot.observed_at - written_at)
                                .to_std()
                                .is_ok_and(|age| age < self.rewrite_after)
                    });
                l1.insert(address, snapshot.clone(), digest);
                if unchanged_and_recent {
                    metrics::counter!(WRITES_SKIPPED_TOTAL).increment(1);
                } else {
                    written.push((address, digest, snapshot.observed_at));
                    to_l2.push((address, snapshot));
                }
            }
        }
        if to_l2.is_empty() {
            return Ok(());
        }
        // Only an accepted write moves `l2_written`: a failed batch must be
        // retried by the next observation, not skipped as if it had landed.
        self.l2.put_many(to_l2).await?;
        let mut l1 = self.lock();
        for (address, digest, observed_at) in written {
            if let Some(entry) = l1.entries.get_mut(&address) {
                entry.l2_written = Some((digest, observed_at));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::degrade::test_util::InMemorySnapshotStore;
    use intelligence::pb::ScreeningFactsReply;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// An L2 that counts what reaches it and can be switched to failing.
    #[derive(Default)]
    struct CountingL2 {
        inner: InMemorySnapshotStore,
        writes: AtomicUsize,
        reads: AtomicUsize,
        down: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl SnapshotStore for CountingL2 {
        async fn get(
            &self,
            address: &AccountAddress,
        ) -> Result<Option<FactsSnapshot>, SnapshotError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if self.down.load(Ordering::SeqCst) {
                return Err(SnapshotError::Corrupt("redis down"));
            }
            self.inner.get(address).await
        }

        async fn put_many(
            &self,
            snapshots: Vec<(AccountAddress, FactsSnapshot)>,
        ) -> Result<(), SnapshotError> {
            if self.down.load(Ordering::SeqCst) {
                return Err(SnapshotError::Corrupt("redis down"));
            }
            self.writes.fetch_add(snapshots.len(), Ordering::SeqCst);
            self.inner.put_many(snapshots).await
        }
    }

    fn addr(byte: u8) -> AccountAddress {
        alloy_primitives::Address::repeat_byte(byte)
    }

    fn snap(score: u32, at: DateTime<Utc>) -> FactsSnapshot {
        FactsSnapshot {
            facts: ScreeningFactsReply {
                score,
                ..Default::default()
            },
            observed_at: at,
        }
    }

    fn tiered(l2: &Arc<CountingL2>, capacity: usize) -> TieredSnapshotStore {
        TieredSnapshotStore::new(l2.clone(), capacity, Duration::from_secs(60))
    }

    #[tokio::test]
    async fn unchanged_facts_are_not_rewritten_until_the_rewrite_interval() {
        let l2 = Arc::new(CountingL2::default());
        let store = tiered(&l2, 10);
        let t0 = Utc::now();

        store.put_many(vec![(addr(1), snap(5, t0))]).await.unwrap();
        store
            .put_many(vec![(addr(1), snap(5, t0 + chrono::Duration::seconds(10)))])
            .await
            .unwrap();
        assert_eq!(
            l2.writes.load(Ordering::SeqCst),
            1,
            "same facts, recently written"
        );

        store
            .put_many(vec![(addr(1), snap(6, t0 + chrono::Duration::seconds(11)))])
            .await
            .unwrap();
        assert_eq!(
            l2.writes.load(Ordering::SeqCst),
            2,
            "changed facts are always written"
        );

        store
            .put_many(vec![(addr(1), snap(6, t0 + chrono::Duration::seconds(80)))])
            .await
            .unwrap();
        assert_eq!(
            l2.writes.load(Ordering::SeqCst),
            3,
            "unchanged but past the interval: refreshed so other pods see a current observed_at"
        );
    }

    #[tokio::test]
    async fn the_memory_tier_answers_when_redis_is_down() {
        let l2 = Arc::new(CountingL2::default());
        let store = tiered(&l2, 10);
        store
            .put_many(vec![(addr(1), snap(5, Utc::now()))])
            .await
            .unwrap();

        l2.down.store(true, Ordering::SeqCst);
        let found = store.get(&addr(1)).await.unwrap().expect("served from L1");
        assert_eq!(found.facts.score, 5);
        assert!(
            store.get(&addr(2)).await.is_err(),
            "an L1 miss still surfaces the L2 fault"
        );
    }

    #[tokio::test]
    async fn an_l2_hit_warms_the_memory_tier() {
        let l2 = Arc::new(CountingL2::default());
        l2.inner.insert(addr(1), snap(9, Utc::now()));
        let store = tiered(&l2, 10);

        assert_eq!(store.get(&addr(1)).await.unwrap().unwrap().facts.score, 9);
        assert_eq!(store.get(&addr(1)).await.unwrap().unwrap().facts.score, 9);
        assert_eq!(
            l2.reads.load(Ordering::SeqCst),
            1,
            "the second read never left the pod"
        );
    }

    /// A failed write must not be recorded as landed, or the next identical
    /// observation would be skipped and Redis would never get it.
    #[tokio::test]
    async fn a_failed_l2_write_is_retried_by_the_next_observation() {
        let l2 = Arc::new(CountingL2::default());
        let store = tiered(&l2, 10);
        let t0 = Utc::now();

        l2.down.store(true, Ordering::SeqCst);
        assert!(store.put_many(vec![(addr(1), snap(5, t0))]).await.is_err());
        l2.down.store(false, Ordering::SeqCst);

        store
            .put_many(vec![(addr(1), snap(5, t0 + chrono::Duration::seconds(1)))])
            .await
            .unwrap();
        assert_eq!(l2.writes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn the_memory_tier_is_bounded_and_evicts_the_oldest() {
        let l2 = Arc::new(CountingL2::default());
        let store = tiered(&l2, 2);
        let t = Utc::now();
        store
            .put_many(vec![
                (addr(1), snap(1, t)),
                (addr(2), snap(2, t)),
                (addr(3), snap(3, t)),
            ])
            .await
            .unwrap();

        l2.down.store(true, Ordering::SeqCst);
        assert!(
            store.get(&addr(1)).await.is_err(),
            "evicted from L1, and L2 is down"
        );
        assert!(store.get(&addr(3)).await.unwrap().is_some());
        assert_eq!(store.lock().entries.len(), 2);
    }
}
