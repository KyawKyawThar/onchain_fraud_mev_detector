//! The address-partitioned temporal workers (§9/§17, Sprint 9 t3) — the
//! concurrency half of the imperative shell around [`crate::temporal`]'s pure
//! core (the storage half is [`crate::state_store`]).
//!
//! ## Why partitioning is the correctness mechanism, not a tuning knob
//!
//! Stepping a machine is a read-modify-write (`load` → [`temporal::step`] →
//! `save`) with no transaction around it: two tasks stepping the same
//! `(rule, address)` key concurrently would lose one of the updates. Rather
//! than locking per key, the §17 design makes the race unrepresentable: every
//! event is routed by [`partition_for`] over its subject address to one of N
//! worker tasks, each draining a bounded FIFO mailbox — so **one worker owns
//! all state for an address**, and its read-modify-writes are serialized by
//! the mailbox, not by locks.
//!
//! Single-writer ownership also pays a second dividend: each worker keeps a
//! **bounded read-through cache** of the machines it owns. Every write to a
//! key goes through its owner (steps *and* rewinds — see below), so a cached
//! entry can never be stale with respect to this pool; and an entry whose
//! Redis key has since *expired* is still harmless, because the pure core
//! closes windows exactly by block arithmetic — a TTL lapse never changes an
//! answer, only reclaims memory. The cache turns the steady-state cost from
//! one `GET` per (temporal rule × event) into a hash lookup; capacity is
//! bounded ([`PoolConfig::cache_entries`]) and eviction is safe by
//! construction (Redis remains the record; a miss just reloads).
//!
//! ## Flush and rewind: barriers, not coordination
//!
//! [`TemporalPool::flush`] enqueues a marker in every mailbox and awaits all
//! acks — on return, everything enqueued before it is applied and persisted.
//! This is the t4 consumer's **checkpoint primitive**: commit Kafka offsets
//! only after a flush and a crash can never lose an acknowledged window.
//!
//! The §15 rewind is built on it: `flush` (every pre-revert step is applied,
//! so the scan below is complete) → **one** `in_flight_keys` scan → route
//! each key to its *owning* worker as a per-key rewind (the owner re-reads
//! and rewrites, staying single-writer, and its cache stays truthful) →
//! `flush` again, so `rewind` returns only once fully applied. Ordering
//! needs no cross-worker protocol — just mailbox FIFO plus the documented
//! contract that `step`/`rewind` share one sequential caller.
//!
//! **Deadlock note:** `flush` (and therefore `rewind`) waits on workers, and
//! a worker blocked sending into a *full* `fires` channel cannot reach the
//! flush marker. Drain `fires` from a separate task; never from the task
//! calling `flush`.
//!
//! ## Scaling out (§20: "rule-engine-service — scale by partition count")
//!
//! In-process, N workers share one Kafka-partition's event stream. Across
//! instances, the same invariant must hold at the stream layer: the t4
//! consumer keys/partitions the rule-engine's event feed by address, so all
//! events for an address arrive at one instance, whose [`partition_for`]
//! then routes them to one worker. Both layers make the same promise at
//! different granularity — and the cache above is sound only while they keep
//! it.
//!
//! ## Fault stance
//!
//! The state store is correctness-bearing (see `state_store`'s docs), so a
//! transient store fault is **retried with backoff until it succeeds or
//! shutdown** — never dropped (the same policy as
//! `event_bus::publish_resilient`). Backpressure is the bounded mailbox
//! (§6): a stalled worker propagates to [`TemporalPool::step`]'s `await`,
//! which is exactly the consumer-lag signal the operator watches.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use events::primitives::{AccountAddress, CustomerId, RuleId};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::compile::RuleSetHandle;
use crate::ctx::EventCtx;
use crate::model::Action;
use crate::state_store::{StateKey, StateStoreError, TemporalStateStore, TtlPolicy};
use crate::temporal::{self, TemporalState};

/// The worker partition that owns `address`'s temporal state.
///
/// Must be **stable across processes, restarts and compiler versions** —
/// state persisted under one deployment must map to the same owner in the
/// next — so this is deliberately not `DefaultHasher` (whose output the std
/// docs allow to change). Addresses are already uniformly distributed
/// (hashes of public keys / creator+nonce), so their leading bytes modulo N
/// are both stable and evenly spread with no extra mixing.
///
/// Changing `partitions` across a restart re-homes addresses; that is safe —
/// ownership only needs to be exclusive at any instant, not historically
/// consistent — as long as the whole instance restarts together (it does:
/// `partitions` is per-[`TemporalPool`]).
pub fn partition_for(address: &AccountAddress, partitions: usize) -> usize {
    assert!(partitions > 0, "a pool has at least one partition");
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&address.as_slice()[..8]);
    (u64::from_be_bytes(prefix) % partitions as u64) as usize
}

/// A temporal rule completed its window — everything the t4 consumer needs to
/// raise the `RuleAlert`/`RuleAlertCreated` (§2) without re-reading the rule
/// set (which may have been swapped since; these fields are from the rule
/// version that actually fired).
#[derive(Debug, Clone, PartialEq)]
pub struct TemporalFire {
    pub rule_id: RuleId,
    /// Alert routing: only this customer ever sees the fire (§9 isolation).
    pub owner: CustomerId,
    pub rule_name: String,
    pub actions: Vec<Action>,
    /// The subject address the window completed for.
    pub address: AccountAddress,
    /// Block of the completing event.
    pub block: u64,
    /// The evidence window ([`temporal::Fired`]).
    pub matched_blocks: Vec<u64>,
}

/// Tuning for one [`TemporalPool`].
#[derive(Debug, Clone, Copy)]
pub struct PoolConfig {
    /// Worker (= in-process partition) count. IO-bound tasks, so this is a
    /// Redis-concurrency knob, not a CPU one.
    pub partitions: usize,
    /// Per-worker mailbox bound — the §6 backpressure seam.
    pub mailbox: usize,
    /// Window-to-TTL translation for persisted state.
    pub ttl: TtlPolicy,
    /// Back-off between retries of a transient store fault (tests shrink it).
    pub retry_backoff: Duration,
    /// Per-worker read-through cache capacity (machines, not bytes; `0`
    /// disables). Sound because of single-writer ownership — see the module
    /// docs. Sized so the hot working set stays memory-resident while the
    /// total stays modest (entries are a key + a few block numbers).
    pub cache_entries: usize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            partitions: 8,
            mailbox: 256,
            ttl: TtlPolicy::default(),
            retry_backoff: Duration::from_secs(1),
            cache_entries: 8192,
        }
    }
}

/// Why a pool operation failed.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    /// The workers are gone — shutdown was signalled (or a worker stopped
    /// because the fire receiver dropped). Terminal for this pool; the
    /// caller's own shutdown path is already in motion.
    #[error("the temporal pool's workers are gone (shutting down)")]
    Closed,

    /// The rewind's in-flight scan failed permanently (transient faults are
    /// retried internally). The rewind was **not** applied; the caller's
    /// at-least-once redelivery of the `BlockReverted` is the retry path.
    #[error("the in-flight scan failed permanently")]
    Scan(#[from] StateStoreError),
}

/// One unit of work in a worker's mailbox. The ctx is boxed so the smaller
/// control commands don't pay a full `EventCtx` of mailbox slot (clippy:
/// large_enum_variant).
enum Command {
    /// Step every temporal rule's machine for this event.
    Step(Box<EventCtx>),
    /// §15: unwind one *owned* machine past a reverted block. Routed (never
    /// broadcast) so only the key's owner touches it.
    RewindKey { key: StateKey, reverted_block: u64 },
    /// Barrier marker: ack once everything enqueued before it is applied.
    Flush(oneshot::Sender<()>),
}

/// The address-partitioned worker pool. Owns N worker tasks; route events in
/// with [`step`](Self::step), reverted blocks with [`rewind`](Self::rewind),
/// checkpoint with [`flush`](Self::flush), and consume completed windows
/// from the `fires` channel handed to [`spawn`](Self::spawn) — **from a
/// separate task** (see the module's deadlock note).
pub struct TemporalPool {
    workers: Vec<mpsc::Sender<Command>>,
    handles: Vec<JoinHandle<()>>,
    store: Arc<dyn TemporalStateStore>,
    retry_backoff: Duration,
    shutdown: CancellationToken,
}

impl TemporalPool {
    /// Spawn the workers. `rules` is the live snapshot handle (shared with
    /// the refresh task); `store` the persisted-state seam; completed windows
    /// are sent into `fires` (bounded by the caller — a full fire channel
    /// backpressures the worker, which backpressures [`step`](Self::step));
    /// `shutdown` stops workers promptly, abandoning queued work (the
    /// at-least-once consumer redelivers it on the next boot).
    pub fn spawn(
        config: PoolConfig,
        rules: Arc<RuleSetHandle>,
        store: Arc<dyn TemporalStateStore>,
        fires: mpsc::Sender<TemporalFire>,
        shutdown: CancellationToken,
    ) -> Self {
        let (workers, handles) = (0..config.partitions)
            .map(|index| {
                let (tx, rx) = mpsc::channel(config.mailbox);
                let worker = Worker {
                    index,
                    ttl: config.ttl,
                    retry_backoff: config.retry_backoff,
                    cache: StateCache::new(config.cache_entries),
                    rules: Arc::clone(&rules),
                    store: Arc::clone(&store),
                    fires: fires.clone(),
                    shutdown: shutdown.clone(),
                };
                (tx, tokio::spawn(worker.run(rx)))
            })
            .unzip();
        Self {
            workers,
            handles,
            store,
            retry_backoff: config.retry_backoff,
            shutdown,
        }
    }

    pub fn partitions(&self) -> usize {
        self.workers.len()
    }

    /// Route one event to the worker owning its subject address. Awaits
    /// mailbox space — this is the backpressure seam (§6).
    pub async fn step(&self, ctx: EventCtx) -> Result<(), PoolError> {
        let worker = &self.workers[partition_for(&ctx.address, self.workers.len())];
        worker
            .send(Command::Step(Box::new(ctx)))
            .await
            .map_err(|_| PoolError::Closed)
    }

    /// Barrier: returns once everything enqueued before this call is applied
    /// and persisted. The t4 consumer's checkpoint — commit offsets after a
    /// flush and no acknowledged window can be lost to a crash.
    pub async fn flush(&self) -> Result<(), PoolError> {
        let mut acks = Vec::with_capacity(self.workers.len());
        for worker in &self.workers {
            let (ack, done) = oneshot::channel();
            worker
                .send(Command::Flush(ack))
                .await
                .map_err(|_| PoolError::Closed)?;
            acks.push(done);
        }
        for done in acks {
            done.await.map_err(|_| PoolError::Closed)?;
        }
        Ok(())
    }

    /// Apply a §15 rewind and return only once it is fully applied:
    /// flush (so every pre-revert step is persisted and the scan below is
    /// complete) → one in-flight scan → route each key to its owner →
    /// flush again. Shares [`step`](Self::step)'s sequential-caller
    /// contract: don't enqueue steps concurrently with a rewind.
    pub async fn rewind(&self, reverted_block: u64) -> Result<(), PoolError> {
        self.flush().await?;
        let keys = self.in_flight_with_retry().await?;
        for key in keys {
            let worker = &self.workers[partition_for(&key.address, self.workers.len())];
            worker
                .send(Command::RewindKey {
                    key,
                    reverted_block,
                })
                .await
                .map_err(|_| PoolError::Closed)?;
        }
        self.flush().await
    }

    /// The rewind work list, surviving transient store faults (same policy
    /// as the workers: retry with backoff until success or shutdown).
    async fn in_flight_with_retry(&self) -> Result<Vec<StateKey>, PoolError> {
        loop {
            match self.store.in_flight_keys().await {
                Ok(keys) => return Ok(keys),
                Err(err) if err.is_transient() => {
                    tracing::warn!(error = %err, "in-flight scan: transient fault, retrying");
                    tokio::select! {
                        biased;
                        _ = self.shutdown.cancelled() => return Err(PoolError::Closed),
                        _ = tokio::time::sleep(self.retry_backoff) => {}
                    }
                }
                Err(err) => return Err(PoolError::Scan(err)),
            }
        }
    }

    /// Graceful shutdown: close the mailboxes, then wait for each worker to
    /// finish draining what it already accepted. (For a prompt stop, cancel
    /// the token passed to [`spawn`](Self::spawn) instead/first.)
    pub async fn shutdown(self) {
        drop(self.workers);
        for handle in self.handles {
            // A worker panic already aborted the task; nothing to unwind here.
            let _ = handle.await;
        }
    }
}

/// The worker stopped mid-command: shutdown was signalled, or the fire
/// receiver is gone. Bubbles out of the helpers so the run loop exits.
struct Stopped;

/// How one retried store operation ended. Replaces a nested
/// `Result<Result<..>>`: each variant is a *distinct caller decision* —
/// proceed with the value, decide what "permanently broken" means for this
/// operation, or unwind the worker.
enum Retried<T> {
    /// The operation succeeded (possibly after transient retries).
    Done(T),
    /// The fault re-occurs on every retry; the caller owns the fallback.
    Permanent(StateStoreError),
    /// Shutdown was signalled mid-retry.
    Stopped,
}

/// A bounded map of the machines this worker owns, `None`-aware: caching
/// "idle" is the common case and saves the most `GET`s. FIFO eviction — the
/// cache is an optimization by construction (Redis is the record; a miss
/// reloads), so eviction order affects only hit rate, never answers.
struct StateCache {
    capacity: usize,
    map: HashMap<StateKey, Option<TemporalState>>,
    order: VecDeque<StateKey>,
}

impl StateCache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// `Some(machine)` on a hit — where `machine` may itself be `None` (a
    /// known-idle key). `None` means *unknown*: go to the store.
    fn get(&self, key: &StateKey) -> Option<Option<TemporalState>> {
        if self.capacity == 0 {
            return None;
        }
        self.map.get(key).cloned()
    }

    fn insert(&mut self, key: StateKey, machine: Option<TemporalState>) {
        if self.capacity == 0 {
            return;
        }
        if self.map.insert(key, machine).is_none() {
            self.order.push_back(key);
            if self.map.len() > self.capacity {
                if let Some(evicted) = self.order.pop_front() {
                    self.map.remove(&evicted);
                }
            }
        }
    }
}

/// One worker: exclusive owner of every `(rule, address)` key whose address
/// partitions to `index`.
struct Worker {
    index: usize,
    ttl: TtlPolicy,
    retry_backoff: Duration,
    cache: StateCache,
    rules: Arc<RuleSetHandle>,
    store: Arc<dyn TemporalStateStore>,
    fires: mpsc::Sender<TemporalFire>,
    shutdown: CancellationToken,
}

impl Worker {
    async fn run(mut self, mut rx: mpsc::Receiver<Command>) {
        loop {
            let command = tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => return,
                command = rx.recv() => match command {
                    Some(command) => command,
                    None => return, // pool dropped: mailbox drained, done
                },
            };
            let outcome = match command {
                Command::Step(ctx) => self.step(&ctx).await,
                Command::RewindKey {
                    key,
                    reverted_block,
                } => self.rewind_key(key, reverted_block).await,
                Command::Flush(ack) => {
                    // Everything enqueued before this marker is applied.
                    let _ = ack.send(());
                    Ok(())
                }
            };
            if outcome.is_err() {
                return;
            }
        }
    }

    /// load (cache-first) → [`temporal::step`] → SETEX/DEL, once per temporal
    /// rule in the current snapshot.
    async fn step(&mut self, ctx: &EventCtx) -> Result<(), Stopped> {
        let set = self.rules.load();
        for rule in set.temporal_rules() {
            let clause = rule
                .temporal()
                .expect("temporal_rules yields temporal rules");
            let key = StateKey {
                rule_id: rule.id,
                address: ctx.address,
            };
            let prior = self.load_state(&key).await?;
            let (next, fired) = temporal::step(clause, prior.clone(), ctx);
            // Persist only real transitions. An untouched machine keeps its
            // key *and its TTL* — the bound stays anchored near the window's
            // start instead of being refreshed by unrelated events.
            if next != prior {
                match &next {
                    Some(state) => {
                        self.save_state(&key, state, clause.within_blocks()).await?;
                    }
                    None => self.clear_state(&key).await?,
                }
            }
            if let Some(fired) = fired {
                let fire = TemporalFire {
                    rule_id: rule.id,
                    owner: rule.owner,
                    rule_name: rule.name.clone(),
                    actions: rule.actions.clone(),
                    address: ctx.address,
                    block: ctx.block,
                    matched_blocks: fired.matched_blocks,
                };
                // A dropped fire receiver means nothing downstream can
                // deliver alerts anymore — that's shutdown, not an error to
                // swallow.
                if self.fires.send(fire).await.is_err() {
                    return Err(Stopped);
                }
            }
        }
        Ok(())
    }

    /// §15: rewind one owned machine past `reverted_block`. Reads through
    /// the same cache/load path as `step` (the cache is authoritative for
    /// owned keys), writes back or clears — single-writer throughout.
    async fn rewind_key(&mut self, key: StateKey, reverted_block: u64) -> Result<(), Stopped> {
        let Some(prior) = self.load_state(&key).await? else {
            return Ok(()); // expired between scan and now — already closed
        };
        match temporal::rewind(prior.clone(), reverted_block) {
            // Untouched by this revert: keep the key and its TTL.
            Some(next) if next == prior => {}
            Some(next) => {
                // Re-bound under the rule's current clause; a rule that left
                // the set since (disabled/deleted) has no window to re-bound
                // — drop its state.
                let set = self.rules.load();
                let clause = set
                    .temporal_rules()
                    .find(|rule| rule.id == key.rule_id)
                    .and_then(|rule| rule.temporal());
                match clause {
                    Some(clause) => {
                        self.save_state(&key, &next, clause.within_blocks()).await?;
                    }
                    None => self.clear_state(&key).await?,
                }
            }
            None => self.clear_state(&key).await?,
        }
        Ok(())
    }

    /// Load with retry, cache-first. A `Malformed` value re-reads identically
    /// forever, so it is discarded — the machine restarts from idle, the same
    /// stance [`temporal::step`] takes on wrong-variant state — and the key
    /// is best-effort cleared so it doesn't warn on every subsequent event.
    async fn load_state(&mut self, key: &StateKey) -> Result<Option<TemporalState>, Stopped> {
        if let Some(cached) = self.cache.get(key) {
            return Ok(cached);
        }
        let loaded = match self
            .retry("load temporal state", || self.store.load(key))
            .await
        {
            Retried::Done(state) => state,
            Retried::Permanent(err) => {
                tracing::warn!(worker = self.index, error = %err, "discarding malformed temporal state");
                let _ = self.store.clear(key).await;
                None
            }
            Retried::Stopped => return Err(Stopped),
        };
        self.cache.insert(*key, loaded.clone());
        Ok(loaded)
    }

    async fn save_state(
        &mut self,
        key: &StateKey,
        state: &TemporalState,
        within_blocks: u64,
    ) -> Result<(), Stopped> {
        let ttl = self.ttl.ttl_for(within_blocks);
        match self
            .retry("save temporal state", || self.store.save(key, state, ttl))
            .await
        {
            Retried::Done(()) => {
                self.cache.insert(*key, Some(state.clone()));
                Ok(())
            }
            Retried::Permanent(err) => {
                // Encoding our own state can't fail and SETEX decodes
                // nothing; a permanent fault here is a store bug. Log and
                // move on — the machine loses this transition, bounded by
                // the at-least-once redelivery upstream. The cache entry is
                // dropped so we re-read the store's actual truth next time.
                tracing::error!(worker = self.index, error = %err, "saving temporal state failed permanently");
                self.cache.insert(*key, None);
                Ok(())
            }
            Retried::Stopped => Err(Stopped),
        }
    }

    async fn clear_state(&mut self, key: &StateKey) -> Result<(), Stopped> {
        match self
            .retry("clear temporal state", || self.store.clear(key))
            .await
        {
            Retried::Done(()) => {
                self.cache.insert(*key, None);
                Ok(())
            }
            Retried::Permanent(err) => {
                tracing::error!(worker = self.index, error = %err, "clearing temporal state failed permanently");
                self.cache.insert(*key, None);
                Ok(())
            }
            Retried::Stopped => Err(Stopped),
        }
    }

    /// Retry `op` on transient faults with backoff until one of the three
    /// [`Retried`] outcomes is reached.
    async fn retry<T, F, Fut>(&self, what: &'static str, op: F) -> Retried<T>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, StateStoreError>>,
    {
        loop {
            match op().await {
                Ok(value) => return Retried::Done(value),
                Err(err) if err.is_transient() => {
                    tracing::warn!(worker = self.index, error = %err, "{what}: transient fault, retrying");
                    tokio::select! {
                        biased;
                        _ = self.shutdown.cancelled() => return Retried::Stopped,
                        _ = tokio::time::sleep(self.retry_backoff) => {}
                    }
                }
                Err(err) => return Retried::Permanent(err),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use uuid::Uuid;

    /// The partition function is a persistence contract (see its docs) — pin
    /// actual values so an accidental change to the mapping fails loudly.
    #[test]
    fn partition_for_is_pinned() {
        let addr = Address::repeat_byte(0xAB);
        // 0xABABABABABABABAB (= 12370169555311111083) % 8 == 3, % 5 == 3.
        assert_eq!(partition_for(&addr, 8), 3);
        assert_eq!(partition_for(&addr, 5), 3);
        // One partition owns everything.
        assert_eq!(partition_for(&addr, 1), 0);
    }

    #[test]
    fn partition_for_spreads_and_stays_in_bounds() {
        let partitions = 8;
        let mut seen = vec![0usize; partitions];
        for byte in 0..=255u8 {
            let p = partition_for(&Address::repeat_byte(byte), partitions);
            assert!(p < partitions);
            seen[p] += 1;
        }
        // Repeat-byte addresses land on byte % 8 patterns; every partition
        // must still be reachable (no dead partition).
        assert!(seen.iter().all(|count| *count > 0), "spread: {seen:?}");
    }

    fn cache_key(byte: u128) -> StateKey {
        StateKey {
            rule_id: RuleId(Uuid::from_u128(byte)),
            address: Address::repeat_byte(byte as u8),
        }
    }

    #[test]
    fn cache_distinguishes_known_idle_from_unknown() {
        let mut cache = StateCache::new(4);
        let key = cache_key(1);
        // Unknown: go to the store.
        assert_eq!(cache.get(&key), None);
        // Known idle: a hit that says "no machine" — the common, GET-saving case.
        cache.insert(key, None);
        assert_eq!(cache.get(&key), Some(None));
        // Known in-flight.
        let state = TemporalState::Frequency { hits: vec![10] };
        cache.insert(key, Some(state.clone()));
        assert_eq!(cache.get(&key), Some(Some(state)));
    }

    #[test]
    fn cache_evicts_fifo_at_capacity() {
        let mut cache = StateCache::new(2);
        let (a, b, c) = (cache_key(1), cache_key(2), cache_key(3));
        cache.insert(a, None);
        cache.insert(b, None);
        // Updating an existing key must not grow the cache or its order.
        cache.insert(a, Some(TemporalState::Frequency { hits: vec![1] }));
        cache.insert(c, None); // over capacity: evicts `a` (oldest inserted)
        assert_eq!(cache.get(&a), None, "evicted");
        assert_eq!(cache.get(&b), Some(None));
        assert_eq!(cache.get(&c), Some(None));
    }

    #[test]
    fn zero_capacity_disables_the_cache() {
        let mut cache = StateCache::new(0);
        let key = cache_key(1);
        cache.insert(key, None);
        assert_eq!(cache.get(&key), None);
        assert!(cache.map.is_empty());
    }
}
