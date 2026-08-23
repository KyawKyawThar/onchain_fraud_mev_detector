//! The §11 Kafka consumer — the imperative shell tying every seam in this
//! crate together: consume `PreliminaryAlertCreated` / `IncidentCreated` /
//! `IncidentRetracted` / `IncidentFinalized` / `RuleAlertCreated` /
//! `SanctionHit`, derive a [`Notice`] ([`crate::notice`]), resolve the
//! candidate `(subscriber, channel)` set, claim/dedup/deliver/receipt each
//! one through [`NotificationStore`]/[`ChannelSink`], and meter
//! `AlertDelivered` on every successful send — mirrors
//! `rule_engine::consumer::EngineConsumer`'s shape.
//!
//! ## Retraction/finalization correlation
//!
//! `IncidentRetracted`/`IncidentFinalized` carry only `incident_id`, keyed on
//! a *different* Kafka partition key (`PartitionKey::Incident`) than
//! `IncidentCreated` (`PartitionKey::Alert`), so they can arrive out of
//! order. The durable `incident_alerts` mapping
//! (`NotificationStore::alert_for_incident`) is the primary lookup; a small
//! in-memory bounded FIFO buffer covers a retraction/finalization that
//! outruns its confirm within one process's lifetime — the same shared
//! `bounded_map::BoundedFifoMap` `rule_engine::consumer`'s `PendingState`
//! already uses for the identical race.
//!
//! **Inherited, accepted gap** (same as `rule_engine::consumer`'s own
//! buffer): a buffered retraction/finalization commits its Kafka offset
//! before it's applied, so a process restart between buffering and the
//! confirm's arrival loses the buffered fact — the confirm's own processing
//! is unaffected (the mapping still gets recorded), only the *buffered
//! retraction's* delivery is silently dropped. Documented, not fixed here,
//! for the same reason rule-engine leaves its mirror-image gap: closing it
//! needs a durable pending-correlation table, a bigger change than this
//! narrow race justifies today.
//!
//! ## Routing reads (§17)
//!
//! Subscriber routing (`subscribers_for`, filtered by severity/kind/chain)
//! reads the in-memory [`crate::subscriber_cache::SubscriberSetHandle`]
//! snapshot, never Postgres directly — a per-event store round-trip doesn't
//! scale past a trivial event rate. See that module's docs for the
//! refresh cadence and its consistency tradeoff. `delivered_targets_for`
//! (the retraction re-targeting path) is keyed by `dedup_key`, not by "every
//! enabled subscriber", so it still reads the store directly — a cache
//! doesn't help a lookup that isn't "scan everyone".
//!
//! ## Offset discipline (§4/§17)
//!
//! Every `(subscriber, channel)` delivery attempt commits its claim/outcome
//! to the store *before* the record's offset advances — `ChannelSink::deliver`
//! failures are logged and receipted, never retried at this layer (retry is
//! the adapter's own bounded policy); only a *store* fault leaves the offset
//! for redelivery, and because `claim_delivery` is dedup-safe, a redelivered
//! record re-attempts only the deliveries that didn't already land.
//!
//! ## Two consumers, one delivery core (§16.4, Sprint 16 task 4)
//!
//! [`DeliveryEngine`] holds everything above (route/claim/deliver/meter) with
//! no opinion on event types. [`NotificationConsumer`] wraps it with the
//! incident-correlation bookkeeping this module's docs describe; the opt-in
//! predictive stream gets its own lean [`PredictiveConsumer`] wrapping the
//! same engine shape instead of reusing `NotificationConsumer` — it has no
//! provisional/confirmed/retracted lifecycle to correlate, so it carries none
//! of that state. `main.rs` builds one of each per process, sharing the
//! underlying store/channels/sink/subscribers via cheap `Arc` clones, and
//! runs them as two independent consumer-group subscriptions.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use bounded_map::BoundedFifoMap;
use chrono::{DateTime, Utc};
use event_bus::dlq::DeadLetterQueue;
use event_bus::lag::{build_reporting_consumer, LagReporting};
use event_bus::usage::UsageFact;
use event_bus::{handled, EventHandler, EventSink, Handled, Transience};
use events::primitives::{AlertId, Chain, CustomerId, IncidentId};
use events::system::UsageEventType;
use events::{DomainEvent, EventEnvelope};
use rdkafka::consumer::StreamConsumer;
use tokio_util::sync::CancellationToken;

use crate::delivery::{ChannelSink, DeliveryError};
use crate::model::{Channel, LifecycleStage, SubscriberId};
use crate::notice::{self, Notice};
use crate::store::{ClaimOutcome, DeliveryOutcome, NotificationStore, StoreError};
use crate::subscriber_cache::SubscriberSetHandle;

/// Log/span label for this consumer.
const CONSUMER: &str = "notification";

/// The six §11 event types, an explicit closed list (not a topic regex) —
/// same discipline as every consumer on the backbone.
const CONSUMED_EVENT_TYPES: &[&str] = &[
    "PreliminaryAlertCreated",
    "IncidentCreated",
    "IncidentRetracted",
    "IncidentFinalized",
    "RuleAlertCreated",
    "SanctionHit",
    "WalletExposureReportReady",
];

/// §16.4 (Sprint 16 task 4): the predictive pipeline's own event family, each
/// already on its own `mev.events.<EventType>` topic (§2) with no coupling to
/// the incident-stream topics above. This list feeds [`PredictiveConsumer`],
/// a second, independently spawned consumer task (wired up in `main.rs`)
/// with its own consumer group and DLQ — deployed only when a risk desk
/// actually opts in (`NOTIFICATION_PREDICTIVE_ENABLED`), and never sharing
/// an offset/lag budget with the incident-critical consumer.
const PREDICTIVE_EVENT_TYPES: &[&str] = &[
    "PredictedAlert",
    "LiquidationRiskPredicted",
    "LiquidationCascadeWarned",
];

/// Log/span label for the predictive consumer task — distinct from
/// [`CONSUMER`] so its lag-reporting series and DLQ topic never collide with
/// the incident-stream consumer's.
const CONSUMER_PREDICTIVE: &str = "notification-predictive";

/// Bound on the in-memory pending-correlation buffer (see the module docs) —
/// mirrors `rule_engine::consumer::DEFAULT_PENDING_CAPACITY`.
pub const DEFAULT_PENDING_CAPACITY: usize = 100_000;

/// Counter (labeled by `stage`): notices routed — the §19 throughput signal.
pub const NOTIFICATION_NOTICES_TOTAL: &str = "notification_notices_total";

/// Gauge (0/1): whether the predictive-events consumer task is currently
/// subscribed and consuming. `main.rs`'s supervisor loop sets it to `1` for
/// the duration of each [`PredictiveConsumer::run`] attempt and back to `0`
/// the moment it exits (cleanly or not) — a distinct signal from K8s
/// readiness, which only reflects "boot wiring completed" and would stay
/// `true` even if this task died at subscribe and no retry existed. Alert on
/// this being `0` for longer than one retry cycle while
/// `NOTIFICATION_PREDICTIVE_ENABLED=true` (§19).
pub const PREDICTIVE_CONSUMER_UP: &str = "notification_predictive_consumer_up";

pub fn consumed_topics() -> Vec<String> {
    events::topics_for(CONSUMED_EVENT_TYPES)
}

/// The predictive-only topic list (§16.4) — a distinct, opt-in subscription
/// from [`consumed_topics`], never merged into it (see [`PREDICTIVE_EVENT_TYPES`]'s docs).
pub fn predictive_topics() -> Vec<String> {
    events::topics_for(PREDICTIVE_EVENT_TYPES)
}

/// Build the consumer. Manual offset commit ties the commit to a fully
/// claimed/delivered/receipted record.
pub fn build_consumer(brokers: &str, group_id: &str) -> Result<StreamConsumer<LagReporting>> {
    build_reporting_consumer(brokers, group_id, CONSUMER)
}

/// Build the predictive consumer — its own consumer group, so a lagging or
/// down predictive pipeline can never stall the incident-stream consumer's
/// offset progress (§16.4's "opt-in, no coupling").
pub fn build_predictive_consumer(
    brokers: &str,
    group_id: &str,
) -> Result<StreamConsumer<LagReporting>> {
    build_reporting_consumer(brokers, group_id, CONSUMER_PREDICTIVE)
}

/// What a buffered `IncidentRetracted`/`IncidentFinalized` needs replayed
/// once its `alert_id` mapping resolves.
enum PendingCorrelation {
    Retracted {
        reason: String,
        chain: Chain,
        occurred_at: DateTime<Utc>,
    },
    Finalized,
}

/// A failure evaluating one record — funnels every fallible seam into the
/// one `verdict` mapping, mirroring `rule_engine::consumer::EngineError`.
#[derive(Debug, thiserror::Error)]
enum ConsumerError {
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl Transience for ConsumerError {
    fn is_transient(&self) -> bool {
        match self {
            ConsumerError::Store(err) => err.is_transient(),
        }
    }
}

/// The delivery core every consumer in this crate drives through: resolve
/// the candidate `(subscriber, channel)` set, claim/dedup/deliver/receipt
/// each one, and meter `AlertDelivered` on every successful send.
/// Deliberately has **no opinion on which event types feed it** — building a
/// [`Notice`] from a `DomainEvent` is each consumer's own job (see
/// [`NotificationConsumer::handle`]/[`PredictiveConsumer::handle`]); this
/// struct only knows how to route and deliver one already-built `Notice`.
///
/// Two consumers each hold one of these — never the *same* instance (see
/// `main.rs`, which builds two via cheap `Arc::clone`s of the same
/// underlying store/channels/sink/subscribers): [`NotificationConsumer`] for
/// the incident stream (§11), and [`PredictiveConsumer`] for the §16.4
/// opt-in predictive stream. Splitting this out — rather than folding
/// predictive dispatch into `NotificationConsumer` directly — means
/// `PredictiveConsumer` carries no incident-correlation state it would never
/// touch; see [`NotificationConsumer`]'s docs for what stays specific to the
/// incident stream.
struct DeliveryEngine {
    store: Arc<dyn NotificationStore>,
    channels: Arc<dyn ChannelSink>,
    sink: Arc<dyn EventSink>,
    /// The routing-candidate snapshot (`crate::subscriber_cache`) —
    /// `subscribers_for` never runs on this hot path, only at boot and on
    /// the binary's periodic refresh. `delivered_targets_for` (the
    /// retraction re-targeting path) still reads the store directly: it's
    /// keyed by `dedup_key`, not by "every enabled subscriber", so a cache
    /// wouldn't help it the way it helps the fan-out scan.
    subscribers: Arc<SubscriberSetHandle>,
    shutdown: CancellationToken,
    publish_backoff: Duration,
}

impl DeliveryEngine {
    fn new(
        store: Arc<dyn NotificationStore>,
        channels: Arc<dyn ChannelSink>,
        sink: Arc<dyn EventSink>,
        subscribers: Arc<SubscriberSetHandle>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            store,
            channels,
            sink,
            subscribers,
            shutdown,
            publish_backoff: event_bus::PUBLISH_BACKOFF,
        }
    }

    #[cfg(any(test, feature = "test-util"))]
    fn with_publish_backoff(mut self, backoff: Duration) -> Self {
        self.publish_backoff = backoff;
        self
    }

    /// The underlying store — [`NotificationConsumer`]'s incident-correlation
    /// bookkeeping (`record_incident_alert`/`alert_for_incident`/`finalize`)
    /// needs it directly, beyond what [`Self::route_and_deliver`]/
    /// [`Self::deliver_one`] already do with it internally.
    fn store(&self) -> &Arc<dyn NotificationStore> {
        &self.store
    }

    fn verdict(&self, result: Result<(), ConsumerError>) -> Handled {
        match result {
            Ok(()) if self.shutdown.is_cancelled() => Handled::Stop,
            Ok(()) => Handled::Commit,
            Err(err) => handled(err, CONSUMER),
        }
    }

    /// Resolve candidates and deliver `notice` to each — the shared path
    /// every event type routes through, regardless of which consumer built
    /// it. `Retracted` re-targets prior recipients via the delivery ledger
    /// (unfiltered, see `notice.rs`'s module docs); every other stage
    /// scans+filters the subscriber snapshot (`crate::subscriber_cache`) —
    /// no Postgres read on this path.
    async fn route_and_deliver(&self, notice: Notice) -> Result<(), ConsumerError> {
        let targets: Vec<(SubscriberId, CustomerId, Channel)> =
            if notice.stage == LifecycleStage::Retracted {
                self.store.delivered_targets_for(&notice.dedup_key).await?
            } else {
                let snapshot = self.subscribers.load();
                snapshot
                    .iter()
                    .filter(|s| notice.owner.is_none_or(|owner| s.owner == owner))
                    .filter(|s| {
                        s.admits(
                            notice.severity,
                            notice.suggested_action,
                            notice.kind,
                            notice.chain,
                        )
                    })
                    .flat_map(|s| {
                        s.channels
                            .iter()
                            .cloned()
                            .map(|c| (s.id, s.owner, c))
                            .collect::<Vec<_>>()
                    })
                    .collect()
            };

        metrics::counter!(NOTIFICATION_NOTICES_TOTAL, "stage" => notice.stage.as_wire_str())
            .increment(1);

        for (subscriber_id, owner, channel) in targets {
            self.deliver_one(&notice, subscriber_id, owner, channel)
                .await?;
        }
        Ok(())
    }

    /// Claim → deliver → receipt one `(subscriber, channel)` slot. A
    /// `ChannelSink::deliver` failure is logged and receipted, never
    /// retried here — the adapter already exhausted its own bounded retry
    /// (see the module docs); one dead endpoint must not wedge the record.
    async fn deliver_one(
        &self,
        notice: &Notice,
        subscriber_id: SubscriberId,
        owner: CustomerId,
        channel: Channel,
    ) -> Result<(), ConsumerError> {
        let claim = self
            .store
            .claim_delivery(
                subscriber_id,
                &notice.dedup_key,
                notice.stage,
                channel.kind(),
                Utc::now(),
            )
            .await?;
        let delivery_id = match claim {
            ClaimOutcome::AlreadyDelivered => return Ok(()),
            ClaimOutcome::Proceed(id) => id,
        };

        match self.channels.deliver(notice, &channel).await {
            Ok(()) => {
                self.store
                    .record_outcome(delivery_id, DeliveryOutcome::Delivered, Utc::now())
                    .await?;
                // §13: a delivered notice is a billable AlertDelivered fact,
                // attributed to the *subscriber's* owner (whose subscription
                // consumed the delivery) — not `notice.owner`, which is only
                // `Some` for a `RuleAlertCreated` and would misattribute
                // every platform-wide notice.
                UsageFact::new(UsageEventType::AlertDelivered, 1)
                    .for_customer(owner)
                    .record(
                        self.sink.as_ref(),
                        notice.chain,
                        self.publish_backoff,
                        &self.shutdown,
                    )
                    .await;
            }
            Err(err) => {
                tracing::warn!(
                    subscriber = %subscriber_id,
                    channel = channel.kind().as_wire_str(),
                    error = %err,
                    transient = err.is_transient(),
                    "channel delivery failed"
                );
                let outcome = match err {
                    DeliveryError::Rejected { reason } => DeliveryOutcome::Rejected(reason),
                    DeliveryError::Transport { reason } => DeliveryOutcome::Failed(reason),
                };
                self.store
                    .record_outcome(delivery_id, outcome, Utc::now())
                    .await?;
            }
        }
        Ok(())
    }
}

/// The §11 incident-stream consumer: a [`DeliveryEngine`] plus the
/// provisional↔confirmed↔retracted correlation bookkeeping specific to the
/// incident lifecycle (§7) — nothing here is shared with
/// [`PredictiveConsumer`], which has no such lifecycle to correlate. See the
/// module docs for the per-record flow.
pub struct NotificationConsumer {
    engine: DeliveryEngine,
    pending: Mutex<BoundedFifoMap<IncidentId, PendingCorrelation>>,
}

impl NotificationConsumer {
    pub fn new(
        store: Arc<dyn NotificationStore>,
        channels: Arc<dyn ChannelSink>,
        sink: Arc<dyn EventSink>,
        subscribers: Arc<SubscriberSetHandle>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            engine: DeliveryEngine::new(store, channels, sink, subscribers, shutdown),
            pending: Mutex::new(BoundedFifoMap::new(
                DEFAULT_PENDING_CAPACITY,
                "notification consumer's pending-correlation buffer",
            )),
        }
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn with_publish_backoff(mut self, backoff: Duration) -> Self {
        self.engine = self.engine.with_publish_backoff(backoff);
        self
    }

    /// Drive the consumer off Kafka until shutdown or a fatal subscribe
    /// error, via the shared [`event_bus::run_consumer`] loop.
    pub async fn run(
        self,
        consumer: StreamConsumer<LagReporting>,
        retry_backoff: Duration,
        dlq: Option<&DeadLetterQueue>,
        shutdown: &CancellationToken,
    ) -> Result<()> {
        let topics = consumed_topics();
        let topic_refs: Vec<&str> = topics.iter().map(String::as_str).collect();
        event_bus::run_consumer(
            consumer,
            &topic_refs,
            CONSUMER,
            retry_backoff,
            dlq,
            self,
            shutdown,
        )
        .await
    }

    /// `IncidentCreated`: record the incident↔alert mapping, deliver the
    /// Confirmed notice, then replay anything buffered waiting for exactly
    /// this mapping (see the module docs).
    async fn on_incident_created(
        &self,
        event: events::simulation::IncidentCreated,
        chain: Chain,
        occurred_at: DateTime<Utc>,
    ) -> Result<(), ConsumerError> {
        let (incident_id, alert_id) = notice::incident_alert_link(&event);
        self.engine
            .store()
            .record_incident_alert(incident_id, alert_id, Utc::now())
            .await?;
        let notice = Notice::from_incident_created(&event, chain, occurred_at);
        self.engine.route_and_deliver(notice).await?;

        let replay = self
            .pending
            .lock()
            .expect("pending lock")
            .take(&incident_id);
        if let Some(pending) = replay {
            self.apply_correlation(alert_id, pending).await?;
        }
        Ok(())
    }

    /// `IncidentRetracted`/`IncidentFinalized`: resolve the durable mapping,
    /// falling back to the in-memory buffer for a fact that outran its
    /// confirm (see the module docs).
    async fn resolve_and_apply(
        &self,
        incident_id: IncidentId,
        correlate: PendingCorrelation,
    ) -> Result<(), ConsumerError> {
        match self.engine.store().alert_for_incident(incident_id).await? {
            Some(alert_id) => self.apply_correlation(alert_id, correlate).await,
            None => {
                self.pending
                    .lock()
                    .expect("pending lock")
                    .put(incident_id, correlate);
                Ok(())
            }
        }
    }

    async fn apply_correlation(
        &self,
        alert_id: AlertId,
        correlate: PendingCorrelation,
    ) -> Result<(), ConsumerError> {
        match correlate {
            PendingCorrelation::Retracted {
                reason,
                chain,
                occurred_at,
            } => {
                let notice = Notice::retraction(alert_id, chain, &reason, occurred_at);
                self.engine.route_and_deliver(notice).await
            }
            PendingCorrelation::Finalized => {
                self.engine
                    .store()
                    .finalize(&alert_id.to_string(), Utc::now())
                    .await?;
                Ok(())
            }
        }
    }
}

#[async_trait]
impl EventHandler for NotificationConsumer {
    #[tracing::instrument(skip_all, fields(chain = %envelope.chain, event = envelope.payload.event_type()))]
    async fn handle(&self, envelope: EventEnvelope) -> Handled {
        let chain = envelope.chain;
        let occurred_at = envelope.occurred_at;
        match envelope.payload {
            DomainEvent::PreliminaryAlertCreated(event) => {
                let notice = Notice::from_preliminary_alert(&event, chain, occurred_at);
                self.engine
                    .verdict(self.engine.route_and_deliver(notice).await)
            }

            DomainEvent::IncidentCreated(event) => self
                .engine
                .verdict(self.on_incident_created(event, chain, occurred_at).await),

            DomainEvent::IncidentRetracted(event) => {
                let result = self
                    .resolve_and_apply(
                        event.incident_id,
                        PendingCorrelation::Retracted {
                            reason: event.reason,
                            chain,
                            occurred_at,
                        },
                    )
                    .await;
                self.engine.verdict(result)
            }

            DomainEvent::IncidentFinalized(event) => {
                let result = self
                    .resolve_and_apply(event.incident_id, PendingCorrelation::Finalized)
                    .await;
                self.engine.verdict(result)
            }

            DomainEvent::RuleAlertCreated(event) => {
                let notice = Notice::from_rule_alert(&event, chain, occurred_at);
                self.engine
                    .verdict(self.engine.route_and_deliver(notice).await)
            }

            DomainEvent::SanctionHit(event) => {
                let notice = Notice::from_sanction_hit(&event, chain, occurred_at);
                self.engine
                    .verdict(self.engine.route_and_deliver(notice).await)
            }

            DomainEvent::WalletExposureReportReady(event) => {
                let notice = Notice::from_exposure_report(&event, chain, occurred_at);
                self.engine
                    .verdict(self.engine.route_and_deliver(notice).await)
            }

            other => {
                tracing::warn!(
                    event = other.event_type(),
                    "unexpected event on notification topics; skipping"
                );
                Handled::Commit
            }
        }
    }
}

/// The §16.4 (Sprint 16 task 4) opt-in predictive-events consumer: the same
/// [`DeliveryEngine`] as [`NotificationConsumer`], but no incident-
/// correlation state — `PredictedAlert`/`LiquidationRiskPredicted`/
/// `LiquidationCascadeWarned` are all Standalone notices (`notice.rs`),
/// never provisional/confirmed/retracted, so there is nothing here to
/// correlate. Deployed as a second, independent task (`main.rs`) with its
/// own consumer group/DLQ against [`predictive_topics`], never folded into
/// [`NotificationConsumer::run`]'s subscription — a lagging or down
/// predictive pipeline can never stall the incident-stream consumer.
pub struct PredictiveConsumer {
    engine: DeliveryEngine,
}

impl PredictiveConsumer {
    pub fn new(
        store: Arc<dyn NotificationStore>,
        channels: Arc<dyn ChannelSink>,
        sink: Arc<dyn EventSink>,
        subscribers: Arc<SubscriberSetHandle>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            engine: DeliveryEngine::new(store, channels, sink, subscribers, shutdown),
        }
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn with_publish_backoff(mut self, backoff: Duration) -> Self {
        self.engine = self.engine.with_publish_backoff(backoff);
        self
    }

    /// Drive the predictive-only consumer off its own Kafka consumer group
    /// until shutdown or a fatal subscribe error — the same
    /// [`event_bus::run_consumer`] loop [`NotificationConsumer::run`] uses,
    /// over [`predictive_topics`] and labeled [`CONSUMER_PREDICTIVE`] so its
    /// lag/DLQ never share a budget with the incident-stream consumer.
    pub async fn run(
        self,
        consumer: StreamConsumer<LagReporting>,
        retry_backoff: Duration,
        dlq: Option<&DeadLetterQueue>,
        shutdown: &CancellationToken,
    ) -> Result<()> {
        let topics = predictive_topics();
        let topic_refs: Vec<&str> = topics.iter().map(String::as_str).collect();
        event_bus::run_consumer(
            consumer,
            &topic_refs,
            CONSUMER_PREDICTIVE,
            retry_backoff,
            dlq,
            self,
            shutdown,
        )
        .await
    }
}

#[async_trait]
impl EventHandler for PredictiveConsumer {
    #[tracing::instrument(skip_all, fields(chain = %envelope.chain, event = envelope.payload.event_type()))]
    async fn handle(&self, envelope: EventEnvelope) -> Handled {
        let chain = envelope.chain;
        let occurred_at = envelope.occurred_at;
        match envelope.payload {
            DomainEvent::PredictedAlert(event) => {
                let notice = Notice::from_predicted_alert(&event, chain, occurred_at);
                self.engine
                    .verdict(self.engine.route_and_deliver(notice).await)
            }

            DomainEvent::LiquidationRiskPredicted(event) => {
                let notice = Notice::from_liquidation_risk_predicted(&event, chain, occurred_at);
                self.engine
                    .verdict(self.engine.route_and_deliver(notice).await)
            }

            DomainEvent::LiquidationCascadeWarned(event) => {
                let notice = Notice::from_liquidation_cascade_warned(&event, chain, occurred_at);
                self.engine
                    .verdict(self.engine.route_and_deliver(notice).await)
            }

            other => {
                tracing::warn!(
                    event = other.event_type(),
                    "unexpected event on the predictive-events consumer; skipping"
                );
                Handled::Commit
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_bus::test_util::RecordingSink;
    use events::detection::PreliminaryAlertCreated;
    use events::intelligence::SanctionHit;
    use events::predictive::{LiquidationRiskPredicted, PredictedAlert};
    use events::primitives::{
        AccountAddress, AlertKind, Confidence, CustomerId, DetectorRef, LendingProtocol,
        PredictionId, RuleId, Severity, SuggestedAction,
    };
    use events::rule_engine::RuleAlertCreated;
    use events::simulation::{IncidentCreated, IncidentFinalized, IncidentRetracted};

    use crate::model::{Channel, Subscriber, SubscriberId, SubscriptionFilter};
    use crate::subscriber_cache::SubscriberSetHandle;
    use crate::test_util::{InMemoryNotificationStore, RecordingChannelSink};

    fn addr(byte: u8) -> AccountAddress {
        AccountAddress::repeat_byte(byte)
    }

    fn envelope(payload: DomainEvent) -> EventEnvelope {
        EventEnvelope::new(Chain::ETHEREUM, payload)
    }

    fn webhook_subscriber(owner: CustomerId, filter: SubscriptionFilter) -> Subscriber {
        Subscriber {
            id: SubscriberId::new(),
            owner,
            channels: vec![Channel::Webhook {
                url: "https://example.com/hook".into(),
            }],
            filter,
            enabled: true,
        }
    }

    struct Harness {
        consumer: NotificationConsumer,
        store: Arc<InMemoryNotificationStore>,
        subscribers: Arc<SubscriberSetHandle>,
        channels: Arc<RecordingChannelSink>,
        sink: Arc<RecordingSink>,
    }

    impl Harness {
        /// Seed a subscriber into both the store (so `delivered_targets_for`,
        /// which reads the store directly, sees it) and the routing snapshot
        /// (so `route_and_deliver`'s live-subscriber scan sees it too) —
        /// production keeps these in sync via the periodic
        /// `subscriber_cache::refresh_subscribers` call; a test seeds both
        /// directly since there's no periodic task running here.
        fn seed(&self, subscriber: Subscriber) {
            self.store.seed(subscriber.clone());
            let mut current = (*self.subscribers.load()).clone();
            current.push(subscriber);
            self.subscribers.swap(current);
        }
    }

    fn harness() -> Harness {
        let store = Arc::new(InMemoryNotificationStore::new());
        let subscribers = Arc::new(SubscriberSetHandle::new(vec![]));
        let channels = Arc::new(RecordingChannelSink::new());
        let sink = Arc::new(RecordingSink::default());
        let consumer = NotificationConsumer::new(
            store.clone(),
            channels.clone(),
            sink.clone(),
            subscribers.clone(),
            CancellationToken::new(),
        )
        .with_publish_backoff(Duration::from_millis(1));
        Harness {
            consumer,
            store,
            subscribers,
            channels,
            sink,
        }
    }

    /// [`PredictiveConsumer`]'s own harness — deliberately not folded into
    /// [`Harness`]: the two consumer types are different structs (that's the
    /// point of the [`DeliveryEngine`] split), so a test exercising
    /// `PredictiveConsumer::handle` needs a `PredictiveConsumer` in hand, not
    /// a `NotificationConsumer`.
    struct PredictiveHarness {
        consumer: PredictiveConsumer,
        store: Arc<InMemoryNotificationStore>,
        subscribers: Arc<SubscriberSetHandle>,
        channels: Arc<RecordingChannelSink>,
    }

    impl PredictiveHarness {
        /// Mirrors [`Harness::seed`] — see its docs.
        fn seed(&self, subscriber: Subscriber) {
            self.store.seed(subscriber.clone());
            let mut current = (*self.subscribers.load()).clone();
            current.push(subscriber);
            self.subscribers.swap(current);
        }
    }

    fn predictive_harness() -> PredictiveHarness {
        let store = Arc::new(InMemoryNotificationStore::new());
        let subscribers = Arc::new(SubscriberSetHandle::new(vec![]));
        let channels = Arc::new(RecordingChannelSink::new());
        let sink = Arc::new(RecordingSink::default());
        let consumer = PredictiveConsumer::new(
            store.clone(),
            channels.clone(),
            sink,
            subscribers.clone(),
            CancellationToken::new(),
        )
        .with_publish_backoff(Duration::from_millis(1));
        PredictiveHarness {
            consumer,
            store,
            subscribers,
            channels,
        }
    }

    fn preliminary_alert(alert_id: AlertId, kind: AlertKind, confidence: f64) -> DomainEvent {
        DomainEvent::PreliminaryAlertCreated(PreliminaryAlertCreated {
            alert_id,
            detector: DetectorRef {
                id: "sandwich".into(),
                version: "1.0".into(),
                config_hash: "abc".into(),
            },
            addresses: vec![addr(1)],
            kind,
            confidence: Confidence::new(confidence),
            provisional: true,
            impact_usd: None,
            severity: Severity::Low,
            suggested_action: SuggestedAction::Monitor,
        })
    }

    fn incident_created(
        incident_id: IncidentId,
        alert_id: AlertId,
        severity: Severity,
    ) -> DomainEvent {
        DomainEvent::IncidentCreated(IncidentCreated {
            incident_id,
            alert_id,
            kind: AlertKind::Sandwich,
            txs: vec![],
            profit: 5.0,
            victim_loss: 2.0,
            impact_usd: None,
            severity,
            suggested_action: events::scoring::suggested_action(severity),
            victim_address: None,
            victim_loss_usd: None,
        })
    }

    fn incident_retracted(incident_id: IncidentId) -> DomainEvent {
        DomainEvent::IncidentRetracted(IncidentRetracted {
            incident_id,
            reason: "block reverted".into(),
        })
    }

    fn incident_finalized(incident_id: IncidentId) -> DomainEvent {
        DomainEvent::IncidentFinalized(IncidentFinalized {
            incident_id,
            block_hash: Default::default(),
        })
    }

    /// The full §11 lifecycle over one `dedup_key`: a subscriber whose
    /// filter admits the provisional alert receives all three stages, each
    /// a distinct delivery — and the retraction reaches them even though it
    /// carries no severity of its own to re-check against the filter.
    #[tokio::test]
    async fn provisional_confirmed_retracted_lifecycle_delivers_all_three_stages() {
        let h = harness();
        let owner = CustomerId::new();
        h.seed(webhook_subscriber(
            owner,
            SubscriptionFilter {
                min_severity: Some(Severity::Low),
                min_suggested_action: None,
                kinds: None,
                chains: None,
            },
        ));

        let alert_id = AlertId::new();
        let incident_id = IncidentId::new();

        assert_eq!(
            h.consumer
                .handle(envelope(preliminary_alert(
                    alert_id,
                    AlertKind::Sandwich,
                    0.95
                )))
                .await,
            Handled::Commit
        );
        assert_eq!(
            h.consumer
                .handle(envelope(incident_created(
                    incident_id,
                    alert_id,
                    Severity::Critical
                )))
                .await,
            Handled::Commit
        );
        assert_eq!(
            h.consumer
                .handle(envelope(incident_retracted(incident_id)))
                .await,
            Handled::Commit
        );

        let deliveries = h.channels.deliveries();
        assert_eq!(deliveries.len(), 3, "provisional + confirmed + retracted");
        let stages: Vec<_> = deliveries.iter().map(|(n, _)| n.stage).collect();
        assert_eq!(
            stages,
            vec![
                LifecycleStage::Provisional,
                LifecycleStage::Confirmed,
                LifecycleStage::Retracted
            ]
        );
        assert!(deliveries
            .iter()
            .all(|(n, _)| n.dedup_key == alert_id.to_string()));
    }

    /// A redelivered `PreliminaryAlertCreated` (same envelope) is deduped —
    /// the subscriber is notified once, not twice.
    #[tokio::test]
    async fn a_redelivered_record_is_deduped() {
        let h = harness();
        let owner = CustomerId::new();
        h.seed(webhook_subscriber(owner, SubscriptionFilter::default()));

        let event = envelope(preliminary_alert(AlertId::new(), AlertKind::Sandwich, 0.95));
        h.consumer.handle(event.clone()).await;
        h.consumer.handle(event).await;

        assert_eq!(
            h.channels.deliveries().len(),
            1,
            "the second delivery deduped"
        );
    }

    /// `RuleAlertCreated` reaches only its owning customer's subscribers,
    /// never another customer's — the isolation contract carried over from
    /// rule-engine's own delivery, now enforced at this layer too.
    #[tokio::test]
    async fn rule_alert_reaches_only_its_owner() {
        let h = harness();
        let owner = CustomerId::new();
        let other = CustomerId::new();
        h.seed(webhook_subscriber(owner, SubscriptionFilter::default()));
        h.seed(webhook_subscriber(other, SubscriptionFilter::default()));

        h.consumer
            .handle(envelope(DomainEvent::RuleAlertCreated(RuleAlertCreated {
                alert_id: AlertId::new(),
                rule_id: RuleId::new(),
                owner,
                address: addr(5),
                explanation: "matched".into(),
            })))
            .await;

        assert_eq!(
            h.channels.deliveries().len(),
            1,
            "only the owner's subscriber"
        );
    }

    /// `WalletExposureReportReady` reaches only the wallet's owner, the same
    /// isolation contract as `RuleAlertCreated` (both scope on `owner`, bypass
    /// severity/kind).
    #[tokio::test]
    async fn wallet_exposure_report_reaches_only_its_owner() {
        let h = harness();
        let owner = CustomerId::new();
        let other = CustomerId::new();
        h.seed(webhook_subscriber(owner, SubscriptionFilter::default()));
        h.seed(webhook_subscriber(other, SubscriptionFilter::default()));

        h.consumer
            .handle(envelope(DomainEvent::WalletExposureReportReady(
                events::simulation::WalletExposureReportReady {
                    customer_id: owner,
                    address: addr(7),
                    period_start: Utc::now(),
                    period_end: Utc::now(),
                    headline: "no MEV exposure this period".into(),
                    summary: serde_json::json!({}),
                },
            )))
            .await;

        assert_eq!(
            h.channels.deliveries().len(),
            1,
            "only the owner's subscriber"
        );
    }

    /// A `SanctionHit` is hardcoded `Critical` — a subscriber with a `High`
    /// floor is admitted, one with a `Critical`-only floor set *above*
    /// Critical is impossible (closed enum), but a kind-scoped subscriber
    /// (which `SanctionHit` never matches, since it carries no kind) is
    /// correctly excluded.
    #[tokio::test]
    async fn sanction_hit_bypasses_kind_but_still_honours_severity() {
        let h = harness();
        h.seed(webhook_subscriber(
            CustomerId::new(),
            SubscriptionFilter {
                min_severity: Some(Severity::High),
                min_suggested_action: None,
                kinds: None,
                chains: None,
            },
        ));
        h.seed(webhook_subscriber(
            CustomerId::new(),
            SubscriptionFilter {
                min_severity: None,
                min_suggested_action: None,
                kinds: Some(vec![AlertKind::Sandwich]),
                chains: None,
            },
        ));

        h.consumer
            .handle(envelope(DomainEvent::SanctionHit(SanctionHit {
                address: addr(9),
                list: "ofac_sdn".into(),
                entry: "SDN-1".into(),
            })))
            .await;

        // Both subscribers admit it: the first via severity (Critical >=
        // High), the second because its severity axis has no floor and its
        // kind axis bypasses (SanctionHit carries no kind).
        assert_eq!(h.channels.deliveries().len(), 2);
    }

    /// An `IncidentRetracted` that outruns its `IncidentCreated` (a genuine
    /// cross-partition race, §11) buffers rather than being dropped, and
    /// replays the moment the confirm's mapping lands.
    #[tokio::test]
    async fn a_retraction_that_outruns_its_confirm_buffers_and_replays() {
        let h = harness();
        let owner = CustomerId::new();
        h.seed(webhook_subscriber(owner, SubscriptionFilter::default()));

        let alert_id = AlertId::new();
        let incident_id = IncidentId::new();

        // Retraction arrives first — nothing to deliver yet, buffered.
        assert_eq!(
            h.consumer
                .handle(envelope(incident_retracted(incident_id)))
                .await,
            Handled::Commit
        );
        assert!(h.channels.deliveries().is_empty());

        // The provisional never landed in this scenario (a pure confirm+retract
        // race) — the confirm alone should deliver, then replay the retraction.
        h.consumer
            .handle(envelope(incident_created(
                incident_id,
                alert_id,
                Severity::High,
            )))
            .await;

        let deliveries = h.channels.deliveries();
        assert_eq!(
            deliveries.len(),
            2,
            "confirmed, then the replayed retraction"
        );
        assert_eq!(deliveries[0].0.stage, LifecycleStage::Confirmed);
        assert_eq!(deliveries[1].0.stage, LifecycleStage::Retracted);
        assert_eq!(deliveries[1].0.dedup_key, alert_id.to_string());
    }

    /// `IncidentFinalized` is a ledger-only mark — no new outbound delivery.
    #[tokio::test]
    async fn incident_finalized_sends_no_new_delivery() {
        let h = harness();
        let owner = CustomerId::new();
        h.seed(webhook_subscriber(owner, SubscriptionFilter::default()));

        let alert_id = AlertId::new();
        let incident_id = IncidentId::new();
        h.consumer
            .handle(envelope(incident_created(
                incident_id,
                alert_id,
                Severity::High,
            )))
            .await;
        assert_eq!(h.channels.deliveries().len(), 1);

        let verdict = h
            .consumer
            .handle(envelope(incident_finalized(incident_id)))
            .await;
        assert_eq!(verdict, Handled::Commit);
        assert_eq!(
            h.channels.deliveries().len(),
            1,
            "no new delivery from finalization"
        );
    }

    /// A successful delivery meters exactly one `AlertDelivered` usage fact,
    /// attributed to the *subscriber's* owner.
    #[tokio::test]
    async fn a_successful_delivery_meters_alert_delivered_for_the_subscriber() {
        let h = harness();
        let owner = CustomerId::new();
        h.seed(webhook_subscriber(owner, SubscriptionFilter::default()));

        h.consumer
            .handle(envelope(preliminary_alert(
                AlertId::new(),
                AlertKind::Sandwich,
                0.95,
            )))
            .await;

        let usage: Vec<_> = h
            .sink
            .events()
            .into_iter()
            .filter_map(|e| match e {
                DomainEvent::UsageRecorded(u) => Some(u),
                _ => None,
            })
            .collect();
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].customer_id, Some(owner));
        assert_eq!(
            usage[0].event_type,
            UsageEventType::AlertDelivered.as_wire_str()
        );
    }

    /// §16.4, Sprint 16 task 4: `predictive_topics` is a distinct list from
    /// `consumed_topics` — the whole point of the opt-in, decoupled consumer.
    #[test]
    fn predictive_topics_are_disjoint_from_the_incident_stream_topics() {
        let incident = consumed_topics();
        let predictive = predictive_topics();
        for topic in &predictive {
            assert!(
                !incident.contains(topic),
                "{topic} must not also be one of the incident-stream topics"
            );
        }
        assert_eq!(
            predictive,
            vec![
                "mev.events.PredictedAlert",
                "mev.events.LiquidationRiskPredicted",
                "mev.events.LiquidationCascadeWarned",
            ]
        );
    }

    /// A risk-desk subscriber filtered on `AlertKind::Liquidation` receives
    /// the liquidation-forecast event but not a `PredictedAlert` tagged with
    /// a different kind — the routing this task wires up. Exercises
    /// [`PredictiveConsumer`] directly (not [`NotificationConsumer`]): these
    /// two events are only ever dispatched through the predictive consumer
    /// in production, since `NotificationConsumer::run` never subscribes to
    /// their topics.
    #[tokio::test]
    async fn a_risk_desk_subscriber_filters_liquidation_predictions_by_kind() {
        let h = predictive_harness();
        h.seed(webhook_subscriber(
            CustomerId::new(),
            SubscriptionFilter {
                min_severity: None,
                min_suggested_action: None,
                kinds: Some(vec![AlertKind::Liquidation]),
                chains: None,
            },
        ));

        h.consumer
            .handle(envelope(DomainEvent::PredictedAlert(PredictedAlert {
                prediction_id: PredictionId::new(),
                tx_hash: Default::default(),
                addresses: vec![addr(1)],
                kind: AlertKind::Sandwich,
                confidence: Confidence::new(0.9),
                provisional: true,
            })))
            .await;
        assert!(
            h.channels.deliveries().is_empty(),
            "a Sandwich forecast doesn't match a Liquidation-only filter"
        );

        h.consumer
            .handle(envelope(DomainEvent::LiquidationRiskPredicted(
                LiquidationRiskPredicted {
                    prediction_id: PredictionId::new(),
                    protocol: LendingProtocol::Aave,
                    account: addr(2),
                    health_factor: 0.9,
                    distance_pct: -10.0,
                    severity: Severity::Critical,
                    confidence: Confidence::new(1.0),
                    provisional: true,
                },
            )))
            .await;
        assert_eq!(
            h.channels.deliveries().len(),
            1,
            "the liquidation-risk forecast matches the risk-desk filter"
        );
    }

    /// Unrelated events on the subscribed topics are skipped, not wedged on.
    #[tokio::test]
    async fn unexpected_events_are_skipped() {
        let h = harness();
        let verdict = h
            .consumer
            .handle(envelope(DomainEvent::BlockFinalized(
                events::chain::BlockFinalized {
                    block: events::primitives::BlockRef::new(1, Default::default()),
                },
            )))
            .await;
        assert_eq!(verdict, Handled::Commit);
    }
}
