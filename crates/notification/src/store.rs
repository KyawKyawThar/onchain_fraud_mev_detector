//! The Postgres store (§11, §14): subscribers, the delivery/dedup ledger,
//! and the incident↔alert correlation index — behind the object-safe
//! [`NotificationStore`] seam so `crate::consumer` is tested against the
//! in-memory double (`crate::test_util`) with no database, mirroring
//! `rule_engine::store`.
//!
//! **Dedup is `claim_delivery`'s contract, not the caller's care.** See its
//! doc comment for the exact claim-or-retry-or-skip semantics the
//! `notice_deliveries` unique index backs.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::primitives::{AlertId, AlertKind, CustomerId, IncidentId, Severity};
use sqlx::types::Uuid;
use sqlx::PgPool;

use crate::model::{
    Channel, ChannelKind, DeliveryStatus, LifecycleStage, Subscriber, SubscriberId,
    SubscriptionFilter,
};

/// A failure reading or writing the notification store. Carries the
/// retry/skip *decision* via [`event_bus::Transience`] — the same contract
/// every other store in this system exposes.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A Postgres round-trip failed. Usually transient (connection/pool/
    /// server), but an encoding/schema fault is a bug that fails identically
    /// on every retry (classified via [`db::is_permanent`]).
    #[error("postgres round-trip failed")]
    Postgres(#[from] sqlx::Error),
    /// A stored JSONB column no longer parses into its domain type. Permanent:
    /// the row itself is bad, retrying re-reads the same bytes.
    #[error("stored value is malformed: {what}")]
    Malformed { what: String },
}

impl StoreError {
    fn malformed(what: impl Into<String>) -> Self {
        StoreError::Malformed { what: what.into() }
    }
}

impl event_bus::Transience for StoreError {
    fn is_transient(&self) -> bool {
        match self {
            StoreError::Malformed { .. } => false,
            StoreError::Postgres(err) => !db::is_permanent(err),
        }
    }
}

/// What [`NotificationStore::claim_delivery`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// No delivered row exists yet for this `(subscriber, dedup_key, stage,
    /// channel)` — proceed with a delivery attempt against this row id
    /// (freshly inserted, or a `pending`/`failed` row from a prior crashed
    /// attempt: either way, not yet delivered).
    Proceed(Uuid),
    /// A row for this exact key already carries `status = delivered` — a
    /// redelivered Kafka record's true dedup case. Nothing to do.
    AlreadyDelivered,
}

/// What a delivery attempt did, for [`NotificationStore::record_outcome`] to
/// persist. Speaks the domain (mirrors `DeliveryError`) so the consumer
/// never hand-writes a status string.
#[derive(Debug, Clone)]
pub enum DeliveryOutcome {
    Delivered,
    Rejected(String),
    Failed(String),
}

/// Subscribers, delivery receipts, and the incident↔alert correlation index
/// (§11, §14) — this service's tables alone (no cross-service joins).
#[async_trait]
pub trait NotificationStore: Send + Sync {
    /// Insert a subscriber, keyed by its `id` — a redelivered/retried create
    /// (same id) is an idempotent no-op. Returns `false` when the id already
    /// existed.
    async fn create_subscriber(
        &self,
        subscriber: &Subscriber,
        at: DateTime<Utc>,
    ) -> Result<bool, StoreError>;

    /// Every enabled subscriber that is a fan-out *candidate* for `owner`:
    /// `Some(_)` scopes to that customer's own subscribers only (a
    /// `RuleAlertCreated`); `None` returns every enabled subscriber
    /// platform-wide (a detection/simulation/sanctions fact has no customer
    /// in scope). Severity/kind/chain filtering happens after this call, via
    /// [`Subscriber::admits`](crate::model::Subscriber::admits) — the store
    /// only answers "who is even in scope", not "who matches the filter".
    async fn subscribers_for(
        &self,
        owner: Option<CustomerId>,
    ) -> Result<Vec<Subscriber>, StoreError>;

    /// Claim (or resume) one `(subscriber, dedup_key, stage, channel)`
    /// delivery slot — see [`ClaimOutcome`]'s docs for the exact semantics.
    /// `at` stamps `created_at`/`updated_at` on a fresh claim.
    async fn claim_delivery(
        &self,
        subscriber_id: SubscriberId,
        dedup_key: &str,
        stage: LifecycleStage,
        channel: ChannelKind,
        at: DateTime<Utc>,
    ) -> Result<ClaimOutcome, StoreError>;

    /// Persist one delivery attempt's outcome against the row `claim_delivery`
    /// returned. `at` stamps `delivered_at` only on [`DeliveryOutcome::Delivered`].
    async fn record_outcome(
        &self,
        delivery_id: Uuid,
        outcome: DeliveryOutcome,
        at: DateTime<Utc>,
    ) -> Result<(), StoreError>;

    /// Every `(subscriber, owner, channel)` triple that already received a
    /// *delivered* notice for `dedup_key`, across every stage — the
    /// retraction/finalization re-targeting path (see `notice.rs`'s module
    /// docs: a retraction is not filtered, it re-targets prior recipients
    /// exactly). `owner` rides along so a retraction delivery meters
    /// `AlertDelivered` the same as every other stage.
    async fn delivered_targets_for(
        &self,
        dedup_key: &str,
    ) -> Result<Vec<(SubscriberId, CustomerId, Channel)>, StoreError>;

    /// Record what `IncidentCreated` teaches: this incident's `alert_id`, so
    /// a later `IncidentRetracted`/`IncidentFinalized` (keyed only on
    /// `incident_id`) can resolve back to the provisional/confirmed
    /// delivery's `dedup_key`. Idempotent on `incident_id`.
    async fn record_incident_alert(
        &self,
        incident_id: IncidentId,
        alert_id: AlertId,
        at: DateTime<Utc>,
    ) -> Result<(), StoreError>;

    /// The durable half of the incident↔alert correlation lookup (see
    /// [`Self::record_incident_alert`]). `None` when not yet recorded —
    /// `crate::consumer` falls back to its in-memory buffer for a retraction
    /// that outran its confirm within one process lifetime.
    async fn alert_for_incident(
        &self,
        incident_id: IncidentId,
    ) -> Result<Option<AlertId>, StoreError>;

    /// Mark every *delivered* row for `dedup_key` finalized — a ledger-only
    /// update, no new outbound send (see `notice.rs`'s module docs on
    /// `IncidentFinalized`).
    async fn finalize(&self, dedup_key: &str, at: DateTime<Utc>) -> Result<(), StoreError>;
}

/// Postgres-backed [`NotificationStore`]. Cheap to clone (the pool is an
/// `Arc` internally).
#[derive(Clone)]
pub struct PgNotificationStore {
    pool: PgPool,
}

impl PgNotificationStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Liveness probe for boot-time fail-fast.
    pub async fn ping(&self) -> Result<(), StoreError> {
        sqlx::query!("SELECT 1 AS one FROM subscribers LIMIT 1")
            .fetch_optional(&self.pool)
            .await?;
        Ok(())
    }
}

// ── Raw row types ────────────────────────────────────────────────
// The single boundary where stored JSONB becomes the validated domain type
// ("parse, don't validate"), mirroring `rule_engine::store::RuleRow`.

struct SubscriberRow {
    subscriber_id: Uuid,
    owner: Uuid,
    channels: serde_json::Value,
    min_severity: Option<serde_json::Value>,
    kinds: Option<serde_json::Value>,
    chains: Option<serde_json::Value>,
    enabled: bool,
}

impl TryFrom<SubscriberRow> for Subscriber {
    type Error = StoreError;

    fn try_from(row: SubscriberRow) -> Result<Self, StoreError> {
        let channels: Vec<Channel> = serde_json::from_value(row.channels)
            .map_err(|err| StoreError::malformed(format!("stored channels: {err}")))?;
        let min_severity: Option<Severity> = row
            .min_severity
            .map(serde_json::from_value)
            .transpose()
            .map_err(|err| StoreError::malformed(format!("stored min_severity: {err}")))?;
        let kinds: Option<Vec<AlertKind>> = row
            .kinds
            .map(serde_json::from_value)
            .transpose()
            .map_err(|err| StoreError::malformed(format!("stored kinds: {err}")))?;
        let chains = row
            .chains
            .map(serde_json::from_value)
            .transpose()
            .map_err(|err| StoreError::malformed(format!("stored chains: {err}")))?;
        Ok(Subscriber {
            id: SubscriberId(row.subscriber_id),
            owner: CustomerId(row.owner),
            channels,
            filter: SubscriptionFilter {
                min_severity,
                kinds,
                chains,
            },
            enabled: row.enabled,
        })
    }
}

#[async_trait]
impl NotificationStore for PgNotificationStore {
    async fn create_subscriber(
        &self,
        subscriber: &Subscriber,
        at: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        let channels = serde_json::to_value(&subscriber.channels)
            .map_err(|err| StoreError::malformed(format!("encoding channels: {err}")))?;
        let min_severity = subscriber
            .filter
            .min_severity
            .map(serde_json::to_value)
            .transpose()
            .map_err(|err| StoreError::malformed(format!("encoding min_severity: {err}")))?;
        let kinds = subscriber
            .filter
            .kinds
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|err| StoreError::malformed(format!("encoding kinds: {err}")))?;
        let chains = subscriber
            .filter
            .chains
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|err| StoreError::malformed(format!("encoding chains: {err}")))?;

        let result = sqlx::query!(
            "INSERT INTO subscribers (subscriber_id, owner, channels, min_severity, kinds, chains, enabled, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
             ON CONFLICT (subscriber_id) DO NOTHING",
            subscriber.id.0,
            subscriber.owner.0,
            channels,
            min_severity,
            kinds,
            chains,
            subscriber.enabled,
            at,
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn subscribers_for(
        &self,
        owner: Option<CustomerId>,
    ) -> Result<Vec<Subscriber>, StoreError> {
        let rows = match owner {
            Some(owner) => {
                sqlx::query_as!(
                    SubscriberRow,
                    r#"SELECT subscriber_id, owner,
                              channels AS "channels: serde_json::Value",
                              min_severity AS "min_severity: serde_json::Value",
                              kinds AS "kinds: serde_json::Value",
                              chains AS "chains: serde_json::Value",
                              enabled
                       FROM subscribers
                       WHERE owner = $1 AND enabled AND deleted_at IS NULL"#,
                    owner.0,
                )
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as!(
                    SubscriberRow,
                    r#"SELECT subscriber_id, owner,
                              channels AS "channels: serde_json::Value",
                              min_severity AS "min_severity: serde_json::Value",
                              kinds AS "kinds: serde_json::Value",
                              chains AS "chains: serde_json::Value",
                              enabled
                       FROM subscribers
                       WHERE enabled AND deleted_at IS NULL"#,
                )
                .fetch_all(&self.pool)
                .await?
            }
        };
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn claim_delivery(
        &self,
        subscriber_id: SubscriberId,
        dedup_key: &str,
        stage: LifecycleStage,
        channel: ChannelKind,
        at: DateTime<Utc>,
    ) -> Result<ClaimOutcome, StoreError> {
        let fresh_id = Uuid::new_v4();
        let inserted = sqlx::query!(
            "INSERT INTO notice_deliveries
                (id, subscriber_id, dedup_key, stage, channel, status, attempts, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, 0, $7, $7)
             ON CONFLICT (subscriber_id, dedup_key, stage, channel) DO NOTHING
             RETURNING id",
            fresh_id,
            subscriber_id.0,
            dedup_key,
            stage.as_wire_str(),
            channel.as_wire_str(),
            DeliveryStatus::Pending.as_wire_str(),
            at,
        )
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = inserted {
            return Ok(ClaimOutcome::Proceed(row.id));
        }

        // Conflict: a row already claims this key. Re-read it — `delivered`
        // is true dedup (skip); anything else (a crash mid-attempt left it
        // `pending`/`failed`) resumes the same row rather than dropping it.
        let existing = sqlx::query!(
            "SELECT id, status FROM notice_deliveries
             WHERE subscriber_id = $1 AND dedup_key = $2 AND stage = $3 AND channel = $4",
            subscriber_id.0,
            dedup_key,
            stage.as_wire_str(),
            channel.as_wire_str(),
        )
        .fetch_one(&self.pool)
        .await?;

        if existing.status == DeliveryStatus::Delivered.as_wire_str() {
            Ok(ClaimOutcome::AlreadyDelivered)
        } else {
            Ok(ClaimOutcome::Proceed(existing.id))
        }
    }

    async fn record_outcome(
        &self,
        delivery_id: Uuid,
        outcome: DeliveryOutcome,
        at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let (status, error, delivered): (&str, Option<String>, bool) = match outcome {
            DeliveryOutcome::Delivered => (DeliveryStatus::Delivered.as_wire_str(), None, true),
            DeliveryOutcome::Rejected(reason) => {
                (DeliveryStatus::Rejected.as_wire_str(), Some(reason), false)
            }
            DeliveryOutcome::Failed(reason) => {
                (DeliveryStatus::Failed.as_wire_str(), Some(reason), false)
            }
        };
        sqlx::query!(
            "UPDATE notice_deliveries
             SET status = $2, attempts = attempts + 1, last_error = $3, updated_at = $4,
                 delivered_at = CASE WHEN $5 THEN $4 ELSE delivered_at END
             WHERE id = $1",
            delivery_id,
            status,
            error,
            at,
            delivered,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delivered_targets_for(
        &self,
        dedup_key: &str,
    ) -> Result<Vec<(SubscriberId, CustomerId, Channel)>, StoreError> {
        struct TargetRow {
            subscriber_id: Uuid,
            owner: Uuid,
            channel: String,
            channels: serde_json::Value,
        }
        let rows = sqlx::query_as!(
            TargetRow,
            r#"SELECT DISTINCT nd.subscriber_id, s.owner, nd.channel, s.channels AS "channels: serde_json::Value"
               FROM notice_deliveries nd
               JOIN subscribers s ON s.subscriber_id = nd.subscriber_id
               WHERE nd.dedup_key = $1 AND nd.status = 'delivered'"#,
            dedup_key,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut targets = Vec::with_capacity(rows.len());
        for row in rows {
            let channels: Vec<Channel> = serde_json::from_value(row.channels)
                .map_err(|err| StoreError::malformed(format!("stored channels: {err}")))?;
            let Some(channel) = channels
                .into_iter()
                .find(|c| c.kind().as_wire_str() == row.channel)
            else {
                // The subscriber edited/removed this channel since delivery —
                // nothing to retract it on; skip rather than fail the batch.
                continue;
            };
            targets.push((
                SubscriberId(row.subscriber_id),
                CustomerId(row.owner),
                channel,
            ));
        }
        Ok(targets)
    }

    async fn record_incident_alert(
        &self,
        incident_id: IncidentId,
        alert_id: AlertId,
        at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        sqlx::query!(
            "INSERT INTO incident_alerts (incident_id, alert_id, recorded_at)
             VALUES ($1, $2, $3)
             ON CONFLICT (incident_id) DO NOTHING",
            incident_id.0,
            alert_id.0,
            at,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn alert_for_incident(
        &self,
        incident_id: IncidentId,
    ) -> Result<Option<AlertId>, StoreError> {
        let row = sqlx::query!(
            "SELECT alert_id FROM incident_alerts WHERE incident_id = $1",
            incident_id.0,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| AlertId(r.alert_id)))
    }

    async fn finalize(&self, dedup_key: &str, at: DateTime<Utc>) -> Result<(), StoreError> {
        sqlx::query!(
            "UPDATE notice_deliveries SET finalized_at = $2
             WHERE dedup_key = $1 AND status = 'delivered'",
            dedup_key,
            at,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
