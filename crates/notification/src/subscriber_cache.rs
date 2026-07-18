//! The subscriber snapshot cache (§11/§17) — mirrors
//! `rule_engine::compile::RuleSetHandle` exactly, for the same reason: every
//! consumed event needs "who is a fan-out candidate" cheaply and often (once
//! per event, on the Kafka consume hot path), so a Postgres round-trip per
//! event doesn't scale past a trivial event rate. [`SubscriberSetHandle`]
//! holds the last-loaded snapshot behind an `RwLock<Arc<_>>` — [`load`](SubscriberSetHandle::load)
//! is one `Arc` clone, safe to call from the hot path; [`refresh_subscribers`]
//! publishes a fresh one and is what a periodic backstop task (the binary's
//! wiring) calls.
//!
//! **Consistency tradeoff, deliberate.** Unlike rule-engine's `RuleCreated`-
//! triggered *immediate* refresh, there is no `SubscriberCreated`/
//! `SubscriberUpdated` domain event yet — this crate has no subscriber-
//! management HTTP API in this pass (see the crate's module docs). So the
//! cache is refreshed **periodically only**: a newly seeded subscriber starts
//! routing within one refresh interval, not instantly. Correctness is
//! unaffected by this — dedup/receipts (`claim_delivery`/`record_outcome`)
//! always read/write Postgres directly, never the cache; only "who is a
//! *routing candidate*" is eventually consistent. When a subscriber-
//! management API lands, it should call [`refresh_subscribers`] immediately
//! on create/update, the same way `rule_engine`'s `POST /v1/rules` handler
//! triggers an immediate `refresh_rules` — the periodic task then becomes the
//! backstop for updates with no event of their own (disable/delete), exactly
//! mirroring rule-engine's own split.

use std::sync::{Arc, RwLock};

use crate::model::Subscriber;
use crate::store::{NotificationStore, StoreError};

/// Counter (labeled by `outcome`: `ok` | `error`): subscriber-set refreshes —
/// an `error` rate means the cache is serving an increasingly stale snapshot
/// because the store is unreachable, not a silent gap.
pub const SUBSCRIBER_REFRESH_TOTAL: &str = "notification_subscriber_refresh_total";

/// The live subscriber snapshot the routing path reads and a refresh swaps —
/// same snapshot semantics as `rule_engine::compile::RuleSetHandle`:
/// [`load`](Self::load) hands back an `Arc` a caller routes against for as
/// long as it likes (a concurrent swap can't tear it), and [`swap`](Self::swap)
/// publishes a freshly loaded set atomically. The lock is held only for the
/// pointer clone/replace, never across routing.
pub struct SubscriberSetHandle {
    inner: RwLock<Arc<Vec<Subscriber>>>,
}

impl SubscriberSetHandle {
    pub fn new(subscribers: Vec<Subscriber>) -> Self {
        Self {
            inner: RwLock::new(Arc::new(subscribers)),
        }
    }

    /// The current snapshot. Cheap (one `Arc` clone) — call per event.
    pub fn load(&self) -> Arc<Vec<Subscriber>> {
        self.inner.read().expect("subscriber-set lock").clone()
    }

    /// Publish a new snapshot. In-flight routing against the old `Arc`
    /// finishes undisturbed; the next [`load`](Self::load) sees the new set.
    pub fn swap(&self, subscribers: Vec<Subscriber>) {
        *self.inner.write().expect("subscriber-set lock") = Arc::new(subscribers);
    }
}

/// Reload every enabled subscriber from the store and publish it as the live
/// snapshot. Shared by the binary's boot (initial load, link-or-fail — an
/// unreachable store at boot should fail loudly, not start with an empty
/// cache) and its periodic backstop refresh (which logs and keeps the old
/// snapshot on error rather than propagating, since one transient store blip
/// must not crash a long-running consumer — see the call sites in `main.rs`).
pub async fn refresh_subscribers(
    store: &dyn NotificationStore,
    handle: &SubscriberSetHandle,
) -> Result<usize, StoreError> {
    match store.subscribers_for(None).await {
        Ok(subscribers) => {
            let len = subscribers.len();
            handle.swap(subscribers);
            metrics::counter!(SUBSCRIBER_REFRESH_TOTAL, "outcome" => "ok").increment(1);
            tracing::info!(subscribers = len, "subscriber set refreshed");
            Ok(len)
        }
        Err(err) => {
            metrics::counter!(SUBSCRIBER_REFRESH_TOTAL, "outcome" => "error").increment(1);
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Channel, SubscriberId, SubscriptionFilter};
    use events::primitives::CustomerId;

    fn a_subscriber() -> Subscriber {
        Subscriber {
            id: SubscriberId::new(),
            owner: CustomerId::new(),
            channels: vec![Channel::Webhook {
                url: "https://example.com/hook".into(),
            }],
            filter: SubscriptionFilter::default(),
            enabled: true,
        }
    }

    #[test]
    fn load_reflects_the_last_swap() {
        let handle = SubscriberSetHandle::new(vec![]);
        assert!(handle.load().is_empty());

        let sub = a_subscriber();
        handle.swap(vec![sub.clone()]);
        let snapshot = handle.load();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].id, sub.id);
    }

    #[test]
    fn an_in_flight_snapshot_is_undisturbed_by_a_concurrent_swap() {
        let first = a_subscriber();
        let handle = SubscriberSetHandle::new(vec![first.clone()]);
        let held = handle.load();

        handle.swap(vec![a_subscriber(), a_subscriber()]);

        assert_eq!(held.len(), 1, "the held Arc still sees the old snapshot");
        assert_eq!(held[0].id, first.id);
        assert_eq!(handle.load().len(), 2, "a fresh load sees the new one");
    }

    #[tokio::test]
    async fn refresh_publishes_the_stores_current_enabled_set() {
        let store = crate::test_util::InMemoryNotificationStore::new();
        let sub = a_subscriber();
        store.seed(sub.clone());

        let handle = SubscriberSetHandle::new(vec![]);
        let count = refresh_subscribers(&store, &handle).await.expect("refresh");
        assert_eq!(count, 1);
        assert_eq!(handle.load()[0].id, sub.id);
    }
}
