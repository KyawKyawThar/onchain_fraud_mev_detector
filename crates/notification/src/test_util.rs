//! Shared test doubles (`test-util` feature): [`InMemoryNotificationStore`]
//! (the [`NotificationStore`] double) and [`RecordingChannelSink`] (the
//! [`ChannelSink`] double) — mirrors `rule_engine::test_util`'s
//! `InMemoryRuleStore`/`RecordingActionSink` shape exactly, including the
//! claim/dedup semantics `store::PgNotificationStore` implements for real.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::primitives::{AlertId, CustomerId, IncidentId};
use uuid::Uuid;

use crate::delivery::{ChannelSink, DeliveryError};
use crate::model::{
    Channel, ChannelKind, DeliveryStatus, LifecycleStage, Subscriber, SubscriberId,
};
use crate::notice::Notice;
use crate::store::{ClaimOutcome, DeliveryOutcome, NotificationStore, StoreError};

/// One claimed delivery slot, keyed exactly like the real
/// `notice_deliveries` unique index.
#[derive(Clone)]
struct DeliveryRow {
    id: Uuid,
    status: DeliveryStatus,
}

type DeliveryKey = (SubscriberId, String, LifecycleStage, ChannelKind);

/// The in-memory [`NotificationStore`] double — same claim-or-resume-or-dedup
/// semantics as [`crate::store::PgNotificationStore`], so a test proves the
/// same contract the real store honours.
#[derive(Default)]
pub struct InMemoryNotificationStore {
    subscribers: Mutex<HashMap<SubscriberId, Subscriber>>,
    deliveries: Mutex<HashMap<DeliveryKey, DeliveryRow>>,
    incident_alerts: Mutex<HashMap<IncidentId, AlertId>>,
}

impl InMemoryNotificationStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Test convenience: seed a subscriber directly, bypassing
    /// `create_subscriber`'s idempotency dance.
    pub fn seed(&self, subscriber: Subscriber) {
        self.subscribers
            .lock()
            .expect("subscribers lock")
            .insert(subscriber.id, subscriber);
    }
}

#[async_trait]
impl NotificationStore for InMemoryNotificationStore {
    async fn create_subscriber(
        &self,
        subscriber: &Subscriber,
        _at: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        let mut subscribers = self.subscribers.lock().expect("subscribers lock");
        if subscribers.contains_key(&subscriber.id) {
            return Ok(false);
        }
        subscribers.insert(subscriber.id, subscriber.clone());
        Ok(true)
    }

    async fn subscribers_for(
        &self,
        owner: Option<CustomerId>,
    ) -> Result<Vec<Subscriber>, StoreError> {
        let subscribers = self.subscribers.lock().expect("subscribers lock");
        Ok(subscribers
            .values()
            .filter(|s| s.enabled)
            .filter(|s| owner.is_none_or(|o| s.owner == o))
            .cloned()
            .collect())
    }

    async fn claim_delivery(
        &self,
        subscriber_id: SubscriberId,
        dedup_key: &str,
        stage: LifecycleStage,
        channel: ChannelKind,
        _at: DateTime<Utc>,
    ) -> Result<ClaimOutcome, StoreError> {
        let mut deliveries = self.deliveries.lock().expect("deliveries lock");
        let key = (subscriber_id, dedup_key.to_owned(), stage, channel);
        if let Some(existing) = deliveries.get(&key) {
            return Ok(if existing.status == DeliveryStatus::Delivered {
                ClaimOutcome::AlreadyDelivered
            } else {
                ClaimOutcome::Proceed(existing.id)
            });
        }
        let id = Uuid::new_v4();
        deliveries.insert(
            key,
            DeliveryRow {
                id,
                status: DeliveryStatus::Pending,
            },
        );
        Ok(ClaimOutcome::Proceed(id))
    }

    async fn record_outcome(
        &self,
        delivery_id: Uuid,
        outcome: DeliveryOutcome,
        _at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let mut deliveries = self.deliveries.lock().expect("deliveries lock");
        let status = match outcome {
            DeliveryOutcome::Delivered => DeliveryStatus::Delivered,
            DeliveryOutcome::Rejected(_) => DeliveryStatus::Rejected,
            DeliveryOutcome::Failed(_) => DeliveryStatus::Failed,
        };
        if let Some(row) = deliveries.values_mut().find(|r| r.id == delivery_id) {
            row.status = status;
        }
        Ok(())
    }

    async fn delivered_targets_for(
        &self,
        dedup_key: &str,
    ) -> Result<Vec<(SubscriberId, CustomerId, Channel)>, StoreError> {
        let deliveries = self.deliveries.lock().expect("deliveries lock");
        let subscribers = self.subscribers.lock().expect("subscribers lock");
        let mut seen = std::collections::HashSet::new();
        let mut targets = Vec::new();
        for ((subscriber_id, key, _stage, channel_kind), row) in deliveries.iter() {
            if key != dedup_key || row.status != DeliveryStatus::Delivered {
                continue;
            }
            if !seen.insert((*subscriber_id, *channel_kind)) {
                continue;
            }
            let Some(subscriber) = subscribers.get(subscriber_id) else {
                continue;
            };
            if let Some(channel) = subscriber
                .channels
                .iter()
                .find(|c| c.kind() == *channel_kind)
            {
                targets.push((*subscriber_id, subscriber.owner, channel.clone()));
            }
        }
        Ok(targets)
    }

    async fn record_incident_alert(
        &self,
        incident_id: IncidentId,
        alert_id: AlertId,
        _at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        self.incident_alerts
            .lock()
            .expect("incident_alerts lock")
            .entry(incident_id)
            .or_insert(alert_id);
        Ok(())
    }

    async fn alert_for_incident(
        &self,
        incident_id: IncidentId,
    ) -> Result<Option<AlertId>, StoreError> {
        Ok(self
            .incident_alerts
            .lock()
            .expect("incident_alerts lock")
            .get(&incident_id)
            .copied())
    }

    async fn finalize(&self, dedup_key: &str, _at: DateTime<Utc>) -> Result<(), StoreError> {
        // Test double: nothing observes `finalized_at`, so this is a no-op
        // proving only that the call doesn't error.
        let _ = dedup_key;
        Ok(())
    }
}

/// The [`ChannelSink`] double: records every `(notice, channel)` handed to
/// it and, unless a canned failure is queued (per [`ChannelKind`]), succeeds
/// — mirrors `rule_engine::test_util::RecordingActionSink`.
#[derive(Default)]
pub struct RecordingChannelSink {
    deliveries: Mutex<Vec<(Notice, Channel)>>,
    #[allow(clippy::type_complexity)]
    queued_failures: Mutex<HashMap<ChannelKind, Vec<DeliveryError>>>,
}

impl RecordingChannelSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn deliveries(&self) -> Vec<(Notice, Channel)> {
        self.deliveries.lock().expect("deliveries lock").clone()
    }

    /// Queue `error` to be returned on the next `deliver()` call for
    /// `channel`'s kind (FIFO); later calls succeed once the queue drains.
    pub fn queue_failure(&self, channel: ChannelKind, error: DeliveryError) {
        self.queued_failures
            .lock()
            .expect("queued_failures lock")
            .entry(channel)
            .or_default()
            .push(error);
    }
}

#[async_trait]
impl ChannelSink for RecordingChannelSink {
    async fn deliver(&self, notice: &Notice, channel: &Channel) -> Result<(), DeliveryError> {
        if let Some(queue) = self
            .queued_failures
            .lock()
            .expect("queued_failures lock")
            .get_mut(&channel.kind())
        {
            if !queue.is_empty() {
                return Err(queue.remove(0));
            }
        }
        self.deliveries
            .lock()
            .expect("deliveries lock")
            .push((notice.clone(), channel.clone()));
        Ok(())
    }
}
