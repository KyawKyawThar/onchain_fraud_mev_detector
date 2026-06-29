//! Result memoization keyed by `(block, tx_set)` (§7 hardening) — the
//! [`CachingSimulator`] decorator.
//!
//! ## Why a decorator, not engine state
//!
//! [`crate::simulator::RevmSimulator`] is a *pure function* of its input — that is
//! what makes it deterministically testable with no I/O. Memoization is a stateful
//! concern, so it lives in a wrapper that also implements [`Simulator`]: the worker
//! holds `Arc<dyn Simulator>` either way, and the binary stacks
//! `CachingSimulator<RevmSimulator>` to get both. The engine stays pure; the cache
//! stays a separable, separately-tested layer.
//!
//! ## What `(block, tx_set)` keys, and why a hit is safe
//!
//! A `SimulationJob` is a self-contained `(block, tx_set)` unit (§7 "ordering &
//! idempotency"), and a deterministic resolver turns the *same* `(block, tx_set)`
//! into the *same* executable scenario — so the EVM result (profit, victim loss,
//! confirm decision, severity) is a function of the key alone. A redelivered job
//! (RabbitMQ is at-least-once) or the same bundle re-hit during a backtest replay is
//! therefore a cache hit, not duplicate revm work — exactly the idempotency §7 leans
//! on so the work queue can redeliver freely.
//!
//! The cached value is the *financial* verdict. The result's **identity** —
//! `alert_id`, `kind`, `txs` — is re-stamped from the requesting scenario on every
//! hit, so two alerts that implicate the same `(block, tx_set)` each get a result
//! carrying their own `alert_id` (the downstream dedup key) over the shared compute.
//!
//! ## Bounded on purpose
//!
//! The cache is FIFO-bounded to `capacity` entries. An unbounded map would itself be
//! a memory-exhaustion vector — an attacker flooding unique bundles (each a distinct
//! key) could grow it without limit, which is the opposite of treating the input as
//! hostile. FIFO eviction is dependency-free and good enough for a replay-scoped /
//! redelivery-window working set, where re-hits cluster in time.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use revm::primitives::B256;

use crate::simulator::{SimError, SimulationOutcome, SimulationRequest, Simulator};

/// The memoization key: the block and the *set* of implicated tx hashes (§7). The
/// hashes are sorted on construction so the key is order-independent — the same
/// bundle presented in a different order is the same scenario, hence the same key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    block: u64,
    txs: Vec<B256>,
}

impl CacheKey {
    fn of(req: &SimulationRequest) -> Self {
        let mut txs = req.txs.clone();
        txs.sort_unstable();
        Self {
            block: req.block.number,
            txs,
        }
    }
}

/// A [`Simulator`] that memoizes the inner engine's outcomes by `(block, tx_set)`.
/// Generic over the inner simulator so the production stack
/// (`CachingSimulator<RevmSimulator>`) is static-dispatched; the worker still erases
/// it to `Arc<dyn Simulator>`.
pub struct CachingSimulator<S> {
    inner: S,
    capacity: usize,
    cache: Mutex<CacheInner>,
}

/// The cache map plus a FIFO queue of keys for bounded eviction. Behind one `Mutex`
/// so an insert's map-write and eviction stay atomic.
#[derive(Default)]
struct CacheInner {
    map: HashMap<CacheKey, SimulationOutcome>,
    /// Insertion order, oldest at the front — the eviction order when at capacity.
    order: VecDeque<CacheKey>,
}

impl<S: Simulator> CachingSimulator<S> {
    /// Wrap `inner`, holding up to `capacity` memoized outcomes. A `capacity` of 0
    /// disables caching (every call delegates) — a valid "off" switch, not an error.
    pub fn new(inner: S, capacity: usize) -> Self {
        Self {
            inner,
            capacity,
            cache: Mutex::new(CacheInner::default()),
        }
    }

    /// Re-stamp a cached outcome's identity fields from the requesting scenario, so a
    /// hit carries *this* alert's id/kind/txs over the shared financial verdict.
    fn rebind(mut cached: SimulationOutcome, req: &SimulationRequest) -> SimulationOutcome {
        cached.alert_id = req.alert_id;
        cached.kind = req.kind;
        cached.txs = req.txs.clone();
        cached
    }
}

impl<S: Simulator> Simulator for CachingSimulator<S> {
    fn simulate(&self, req: &SimulationRequest) -> Result<SimulationOutcome, SimError> {
        if self.capacity == 0 {
            return self.inner.simulate(req);
        }

        let key = CacheKey::of(req);

        // Fast path: a hit returns the cached verdict re-stamped with this request's
        // identity, without touching revm.
        if let Some(cached) = self.cache.lock().unwrap().map.get(&key).cloned() {
            return Ok(Self::rebind(cached, req));
        }

        // Miss: run the real engine. Only a *successful* outcome is cached — an error
        // (transient blip or poison) is never memoized, so a transient fault can still
        // succeed on redelivery rather than being pinned as a permanent failure.
        let outcome = self.inner.simulate(req)?;
        self.insert(key, outcome.clone());
        Ok(outcome)
    }
}

impl<S: Simulator> CachingSimulator<S> {
    /// Insert under the lock, evicting the oldest entry first when at capacity. A key
    /// already present (a race where two threads missed the same key) is overwritten
    /// in place without growing the FIFO queue.
    fn insert(&self, key: CacheKey, outcome: SimulationOutcome) {
        use std::collections::hash_map::Entry;

        let mut inner = self.cache.lock().unwrap();
        if let Entry::Occupied(mut e) = inner.map.entry(key.clone()) {
            e.insert(outcome);
            return;
        }
        while inner.map.len() >= self.capacity {
            match inner.order.pop_front() {
                Some(oldest) => {
                    inner.map.remove(&oldest);
                }
                None => break, // queue empty but map full shouldn't happen; bail safe
            }
        }
        inner.order.push_back(key.clone());
        inner.map.insert(key, outcome);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use events::primitives::{AlertId, AlertKind, Severity};
    use revm::primitives::Address;

    use super::*;
    use crate::simulator::BlockParams;

    /// A `Simulator` double that counts how many times the real engine ran and returns
    /// a deterministic outcome derived from the request — so a test can prove a hit
    /// skipped the engine and that identity is re-stamped per request.
    #[derive(Default)]
    struct CountingSimulator {
        calls: AtomicUsize,
    }

    impl CountingSimulator {
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Simulator for CountingSimulator {
        fn simulate(&self, req: &SimulationRequest) -> Result<SimulationOutcome, SimError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(SimulationOutcome {
                alert_id: req.alert_id,
                kind: req.kind,
                // Profit encodes the block so different keys are distinguishable.
                profit: req.block.number as f64,
                victim_loss: 0.0,
                confirmed: true,
                severity: Severity::Medium,
                txs: req.txs.clone(),
            })
        }
    }

    fn request(block: u64, txs: Vec<B256>) -> SimulationRequest {
        SimulationRequest {
            alert_id: AlertId::new(),
            kind: AlertKind::Sandwich,
            block: BlockParams {
                number: block,
                ..BlockParams::default()
            },
            accounts: vec![],
            bundle: vec![],
            attacker: Address::ZERO,
            victim: None,
            txs,
        }
    }

    #[test]
    fn second_identical_request_is_a_hit_that_skips_the_engine() {
        let inner = Arc::new(CountingSimulator::default());
        let sim = CachingSimulator::new(inner.clone(), 8);
        let req = request(100, vec![B256::repeat_byte(0x01)]);

        let first = sim.simulate(&req).unwrap();
        let second = sim.simulate(&req).unwrap();

        assert_eq!(
            inner.calls(),
            1,
            "the engine ran once; the second was a hit"
        );
        assert_eq!(first, second);
        assert_eq!(first.profit, 100.0);
    }

    #[test]
    fn different_block_or_tx_set_misses() {
        let inner = Arc::new(CountingSimulator::default());
        let sim = CachingSimulator::new(inner.clone(), 8);

        sim.simulate(&request(100, vec![B256::repeat_byte(0x01)]))
            .unwrap();
        // Different block, same txs → miss.
        sim.simulate(&request(101, vec![B256::repeat_byte(0x01)]))
            .unwrap();
        // Same block, different txs → miss.
        sim.simulate(&request(100, vec![B256::repeat_byte(0x02)]))
            .unwrap();

        assert_eq!(inner.calls(), 3, "each distinct (block, tx_set) recomputes");
    }

    #[test]
    fn tx_set_order_does_not_affect_the_key() {
        let inner = Arc::new(CountingSimulator::default());
        let sim = CachingSimulator::new(inner.clone(), 8);
        let a = B256::repeat_byte(0x01);
        let b = B256::repeat_byte(0x02);

        sim.simulate(&request(100, vec![a, b])).unwrap();
        // Same set, reversed order — still a hit.
        sim.simulate(&request(100, vec![b, a])).unwrap();

        assert_eq!(inner.calls(), 1, "tx order is irrelevant to the set key");
    }

    #[test]
    fn a_hit_rebinds_identity_to_the_requesting_alert() {
        let inner = Arc::new(CountingSimulator::default());
        let sim = CachingSimulator::new(inner.clone(), 8);
        let txs = vec![B256::repeat_byte(0x01)];

        let first = sim.simulate(&request(100, txs.clone())).unwrap();
        // A second alert over the same (block, tx_set) — distinct alert_id.
        let second_req = request(100, txs);
        let second = sim.simulate(&second_req).unwrap();

        assert_eq!(inner.calls(), 1, "the compute was shared");
        assert_ne!(first.alert_id, second.alert_id, "distinct alerts");
        assert_eq!(
            second.alert_id, second_req.alert_id,
            "the hit carries the requesting alert's id, not the cached one"
        );
        assert_eq!(second.profit, first.profit, "over the same verdict");
    }

    #[test]
    fn capacity_evicts_oldest_first() {
        let inner = Arc::new(CountingSimulator::default());
        let sim = CachingSimulator::new(inner.clone(), 2);
        let r1 = request(1, vec![B256::repeat_byte(0x01)]);
        let r2 = request(2, vec![B256::repeat_byte(0x02)]);
        let r3 = request(3, vec![B256::repeat_byte(0x03)]);

        sim.simulate(&r1).unwrap(); // [1]
        sim.simulate(&r2).unwrap(); // [1, 2]
        sim.simulate(&r3).unwrap(); // evict 1 (oldest) → [2, 3]
        assert_eq!(inner.calls(), 3);

        // The two survivors are still hits; the evicted oldest is a miss.
        sim.simulate(&r2).unwrap();
        sim.simulate(&r3).unwrap();
        assert_eq!(inner.calls(), 3, "r2 and r3 survived eviction");
        sim.simulate(&r1).unwrap();
        assert_eq!(inner.calls(), 4, "r1 was evicted as the oldest → recompute");
    }

    #[test]
    fn zero_capacity_disables_caching() {
        let inner = Arc::new(CountingSimulator::default());
        let sim = CachingSimulator::new(inner.clone(), 0);
        let req = request(100, vec![B256::repeat_byte(0x01)]);

        sim.simulate(&req).unwrap();
        sim.simulate(&req).unwrap();
        assert_eq!(inner.calls(), 2, "capacity 0 delegates every call");
    }

    #[test]
    fn an_error_is_not_cached() {
        struct AlwaysTransient(AtomicUsize);
        impl Simulator for AlwaysTransient {
            fn simulate(&self, _req: &SimulationRequest) -> Result<SimulationOutcome, SimError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(SimError::Transient("blip".into()))
            }
        }
        let inner = Arc::new(AlwaysTransient(AtomicUsize::new(0)));
        let sim = CachingSimulator::new(inner.clone(), 8);
        let req = request(100, vec![B256::repeat_byte(0x01)]);

        assert!(sim.simulate(&req).is_err());
        assert!(sim.simulate(&req).is_err());
        assert_eq!(
            inner.0.load(Ordering::SeqCst),
            2,
            "a transient error is never memoized; the retry re-runs the engine"
        );
    }
}
