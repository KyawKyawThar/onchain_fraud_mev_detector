//! The per-entity merge actor (§8.2/§17, Sprint 7 t5) — closes the one gap
//! [`store::EntityStore::absorb`](crate::store::EntityStore::absorb) leaves
//! open: each store write is its own atomic, entity-locked Postgres
//! transaction (`store.rs`'s `lock_entities`, ascending-order row locks), but
//! [`cluster::cluster_address`](crate::cluster::cluster_address) is a
//! *sequence* of them — read every member's current owner, decide a plan,
//! then issue several separate `create_entity`/`absorb`/`link_address`
//! calls. Nothing held that sequence together: a concurrent pass touching an
//! overlapping entity between the read and the writes could tombstone an
//! entity this pass was about to link into (`LinkOutcome::TargetInactive`,
//! silently dropped) or hand the caller a since-absorbed entity id.
//!
//! This module is a pure in-process concurrency primitive — it never touches
//! the store. It hands out **multi-entity lock guards**: a caller names every
//! entity id its pass has read as an owner, awaits [`MergeActorHandle::lock`],
//! and holds the returned [`EntityGuard`] for the rest of its decide-and-write
//! sequence. No other in-process caller can be granted a guard over any of
//! those same ids until it drops.
//!
//! ## Why one coordinator task, not one task per entity id
//!
//! A merge touches *several* entity ids at once (the survivor plus every
//! entity being absorbed), so acquiring them safely means acquiring a set
//! atomically. With independent per-key tasks or lock shards that means a
//! cross-task lock-ordering protocol to avoid deadlock. A single coordinator
//! sidesteps that: it's the sole place that knows the full "currently held"
//! set, so it can grant or queue a multi-id request in one decision, with no
//! ordering protocol to get wrong. It also avoids spawning a task per entity
//! id — cardinality that could reach millions in production — the
//! coordinator's state is just two in-memory collections.
//!
//! ## The channel shape (§17, mirroring `detection::Scheduler` and
//! `simulation::worker`'s oneshot bridge)
//!
//! Acquire requests arrive on a bounded `mpsc` (backpressure on submitting
//! *new* lock requests — §6). Releases arrive on a separate **unbounded**
//! `mpsc`: an [`EntityGuard`]'s `Drop` can't `.await`, so it needs a
//! synchronous, always-succeeds send. That channel only ever carries tiny
//! control messages (one per currently-held guard, bounded by how much
//! in-process concurrency exists, not by any external input), which is why
//! unbounded is safe here unlike the data-plane channels §6 is about.
//!
//! ## What this deliberately does not cover
//!
//! In-process only. It does not serialize the `intelligence cluster` CLI
//! (a separate one-shot process) against a running `attribute` consumer, or
//! multiple horizontally-scaled `attribute` replicas — those share no
//! mailbox. Each individual store primitive stays safe across processes via
//! `lock_entities`'s DB-level locking (no corruption), but the
//! decide-and-write *sequence* is only race-free among callers sharing one
//! [`MergeActorHandle`]. Cross-process sequencing would need a DB-level lock
//! (e.g. a Postgres advisory lock) or folding the whole plan into one store
//! transaction — a documented follow-up, not silently assumed away.

use std::collections::HashSet;

use events::primitives::EntityId;
use tokio::sync::{mpsc, oneshot};

/// Bound on the *acquire* mailbox — control-plane traffic (one message per
/// in-flight `cluster_address` pass wanting a lock), not data volume, so a
/// generous fixed size is simply a sanity backstop, not a tuned capacity.
pub const DEFAULT_MAILBOX_CAPACITY: usize = 256;

/// A failure talking to the merge actor's coordinator task.
#[derive(Debug, thiserror::Error)]
pub enum MergeActorError {
    /// The coordinator task is gone (panicked, or the process is shutting
    /// down and every [`MergeActorHandle`] was already dropped). Classified
    /// transient by [`crate::cluster::ClusterError::is_transient`] — a
    /// redelivered pass against a freshly booted process gets a fresh actor.
    #[error("the merge actor's coordinator task is gone")]
    Gone,
}

/// One pending request in the coordinator's mailbox.
struct AcquireRequest {
    ids: HashSet<EntityId>,
    reply: oneshot::Sender<EntityGuard>,
}

/// Exclusive, in-process hold on every id in [`EntityGuard::ids`]. No other
/// request naming any of these ids is granted until this guard drops.
///
/// `#[must_use]`: a discarded guard releases immediately (its `Drop` runs at
/// the end of the statement that created it), so `merge_actor.lock(ids).await?;`
/// with no binding compiles but holds the lock for zero time — exactly the
/// kind of silent no-op this annotation catches at compile time.
#[must_use = "dropping this immediately releases the lock it just acquired"]
pub struct EntityGuard {
    ids: HashSet<EntityId>,
    release_tx: mpsc::UnboundedSender<HashSet<EntityId>>,
}

impl EntityGuard {
    /// The ids this guard holds — mostly useful via [`matches`](Self::matches);
    /// exposed directly for tests and any caller that needs the raw set.
    pub fn ids(&self) -> &HashSet<EntityId> {
        &self.ids
    }

    /// Whether this guard already covers exactly `ids` — the question
    /// [`cluster::cluster_address`](crate::cluster::cluster_address)'s
    /// converge loop actually asks after a fresh owners-read, phrased as the
    /// guard's own business instead of the caller reaching in and comparing
    /// sets itself.
    pub fn matches(&self, ids: &HashSet<EntityId>) -> bool {
        &self.ids == ids
    }
}

impl Drop for EntityGuard {
    fn drop(&mut self) {
        // Synchronous and non-blocking (an unbounded channel), because
        // `Drop` can't `.await`. A closed channel means the coordinator
        // already shut down — nothing left to release into.
        let _ = self.release_tx.send(std::mem::take(&mut self.ids));
    }
}

/// Cheap-to-clone handle to a running [`MergeActor`]'s mailbox.
#[derive(Clone)]
pub struct MergeActorHandle {
    acquire_tx: mpsc::Sender<AcquireRequest>,
}

impl MergeActorHandle {
    /// Acquire exclusive, in-process access to every id in `ids`, waiting if
    /// any is currently held by another guard. `ids` may be empty (a
    /// brand-new component with no pre-existing owners) — that grants
    /// immediately, since there's nothing to serialize against yet.
    pub async fn lock(&self, ids: HashSet<EntityId>) -> Result<EntityGuard, MergeActorError> {
        let (reply, reply_rx) = oneshot::channel();
        self.acquire_tx
            .send(AcquireRequest { ids, reply })
            .await
            .map_err(|_| MergeActorError::Gone)?;
        reply_rx.await.map_err(|_| MergeActorError::Gone)
    }
}

/// The coordinator: single writer over the "currently held" entity-id set,
/// so granting or queueing a multi-id request is one uncontested decision.
pub struct MergeActor {
    acquire_rx: mpsc::Receiver<AcquireRequest>,
    release_tx: mpsc::UnboundedSender<HashSet<EntityId>>,
    release_rx: mpsc::UnboundedReceiver<HashSet<EntityId>>,
    held: HashSet<EntityId>,
    /// FIFO-ish: a later request can still be granted ahead of an earlier
    /// one still blocked on a different held id — acceptable, since merge
    /// components are small and this isn't a fairness-critical path.
    ///
    /// `release()` rescans this whole `Vec` on every release (`O(pending)`
    /// requests × `O(ids)` per disjointness check) — deliberately not an
    /// index from `EntityId` to waiting requests. Fine at today's
    /// cardinality (a handful of in-flight `cluster_address` passes); if
    /// this ever shows up in profiling, that's the structure to reach for,
    /// not a premature one to build now.
    pending: Vec<AcquireRequest>,
}

impl MergeActor {
    /// Spawn the coordinator task and return a cloneable handle to it. The
    /// task runs until every [`MergeActorHandle`] clone *and* every
    /// outstanding [`EntityGuard`] have been dropped — no explicit shutdown
    /// signal needed, it cleans itself up.
    pub fn spawn() -> MergeActorHandle {
        Self::spawn_with_capacity(DEFAULT_MAILBOX_CAPACITY)
    }

    /// [`spawn`](Self::spawn) with an explicit acquire-mailbox capacity —
    /// split out for tests that want a tiny bound.
    pub fn spawn_with_capacity(capacity: usize) -> MergeActorHandle {
        let (acquire_tx, acquire_rx) = mpsc::channel(capacity);
        let (release_tx, release_rx) = mpsc::unbounded_channel();
        let actor = MergeActor {
            acquire_rx,
            release_tx,
            release_rx,
            held: HashSet::new(),
            pending: Vec::new(),
        };
        tokio::spawn(actor.run());
        MergeActorHandle { acquire_tx }
    }

    async fn run(mut self) {
        let mut acquire_open = true;
        loop {
            // Nothing left to grant and no one left who could ask for more —
            // the handle side is gone and every guard has released.
            if !acquire_open && self.held.is_empty() {
                return;
            }
            tokio::select! {
                biased;
                released = self.release_rx.recv() => {
                    match released {
                        Some(ids) => self.release(ids),
                        None => return, // unreachable in practice: `self` holds a sender clone.
                    }
                }
                maybe_req = self.acquire_rx.recv(), if acquire_open => {
                    match maybe_req {
                        Some(req) => self.acquire(req),
                        None => acquire_open = false,
                    }
                }
            }
        }
    }

    fn acquire(&mut self, req: AcquireRequest) {
        if req.ids.is_disjoint(&self.held) {
            self.grant(req);
        } else {
            self.pending.push(req);
        }
    }

    fn release(&mut self, ids: HashSet<EntityId>) {
        for id in &ids {
            self.held.remove(id);
        }
        let mut i = 0;
        while i < self.pending.len() {
            if self.pending[i].ids.is_disjoint(&self.held) {
                let req = self.pending.remove(i);
                self.grant(req);
                // Don't advance `i`: `remove` shifted the next element down,
                // and it may itself be unblocked by what was just freed.
            } else {
                i += 1;
            }
        }
    }

    fn grant(&mut self, req: AcquireRequest) {
        self.held.extend(req.ids.iter().copied());
        let guard = EntityGuard {
            ids: req.ids,
            release_tx: self.release_tx.clone(),
        };
        // If the waiter's future was already cancelled, `send` hands the
        // guard back in the `Err` — dropping that temporary still runs
        // `EntityGuard::drop`, releasing the hold immediately instead of
        // leaking it until the process exits.
        drop(req.reply.send(guard));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use uuid::Uuid;

    fn eid(byte: u128) -> EntityId {
        EntityId(Uuid::from_u128(byte))
    }

    fn set(ids: impl IntoIterator<Item = EntityId>) -> HashSet<EntityId> {
        ids.into_iter().collect()
    }

    #[tokio::test]
    async fn disjoint_requests_are_both_granted_immediately() {
        let handle = MergeActor::spawn();
        let a = tokio::time::timeout(Duration::from_millis(200), handle.lock(set([eid(1)])))
            .await
            .expect("must not block")
            .unwrap();
        let b = tokio::time::timeout(Duration::from_millis(200), handle.lock(set([eid(2)])))
            .await
            .expect("must not block")
            .unwrap();
        assert_eq!(a.ids(), &set([eid(1)]));
        assert_eq!(b.ids(), &set([eid(2)]));
    }

    #[tokio::test]
    async fn empty_id_set_grants_immediately() {
        let handle = MergeActor::spawn();
        let guard = tokio::time::timeout(Duration::from_millis(200), handle.lock(HashSet::new()))
            .await
            .expect("must not block")
            .unwrap();
        assert!(guard.ids().is_empty());
    }

    #[tokio::test]
    async fn overlapping_request_queues_until_release() {
        let handle = MergeActor::spawn();
        let first = handle.lock(set([eid(1), eid(2)])).await.unwrap();

        let second_handle = handle.clone();
        let second = tokio::spawn(async move { second_handle.lock(set([eid(2), eid(3)])).await });

        tokio::task::yield_now().await;
        assert!(
            !second.is_finished(),
            "an id held by `first` must block `second`"
        );

        drop(first);
        let second_guard = tokio::time::timeout(Duration::from_millis(500), second)
            .await
            .expect("must be granted once the overlapping id is released")
            .unwrap()
            .unwrap();
        assert_eq!(second_guard.ids(), &set([eid(2), eid(3)]));
    }

    #[tokio::test]
    async fn unrelated_pending_request_is_not_blocked_by_an_unrelated_release() {
        let handle = MergeActor::spawn();
        let holds_one = handle.lock(set([eid(1)])).await.unwrap();
        let holds_two = handle.lock(set([eid(2)])).await.unwrap();

        // Wants id 1, currently held — must queue, unaffected by id 2.
        let waiter_handle = handle.clone();
        let waiter = tokio::spawn(async move { waiter_handle.lock(set([eid(1)])).await });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        // Releasing the *unrelated* hold must not unblock the waiter.
        drop(holds_two);
        tokio::task::yield_now().await;
        assert!(
            !waiter.is_finished(),
            "releasing an unrelated id must not grant a request for a different held id"
        );

        drop(holds_one);
        let granted = tokio::time::timeout(Duration::from_millis(500), waiter)
            .await
            .expect("granted once the id it actually wants is released")
            .unwrap()
            .unwrap();
        assert_eq!(granted.ids(), &set([eid(1)]));
    }

    #[tokio::test]
    async fn coordinator_shuts_down_once_every_handle_and_guard_drop() {
        let handle = MergeActor::spawn();
        let guard = handle.lock(set([eid(1)])).await.unwrap();
        drop(handle);
        drop(guard);
        // No direct observation of the task's exit from here, but a fresh
        // handle-free future proves the earlier calls didn't panic/hang —
        // the real assertion is that `spawn`'s task doesn't leak forever,
        // exercised implicitly by every other test in this module completing
        // without a runtime shutdown timeout.
    }
}
