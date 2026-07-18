//! The storage core: writes consumed [`UsageRecorded`] envelopes to the
//! ClickHouse `usage_events` table as one typed row each — the §13 raw usage
//! record, trimmed to the Sprint-12 scope (analytics/capacity/abuse, no
//! billing aggregates).
//!
//! Unlike the event store, which persists the payload JSON verbatim to
//! reconstruct envelopes byte-for-byte, this sink is a *projection*: the §13
//! `UsageEvent` fields are lifted into columns and nothing else is kept,
//! because its consumers are aggregation queries, not replay. The event store
//! (which also drains this topic) remains the system of record; `event_id` is
//! the reconciliation key between the two.

use chrono::{DateTime, Utc};
use clickhouse::Client;
use events::system::UsageRecorded;
use events::{DomainEvent, EventEnvelope};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::ClickhouseConfig;

/// The stored stand-in for [`UsageRecorded::customer_id`](events::system::UsageRecorded)
/// being `None` — see [`UsageRow::customer_id`] for why a sentinel, not a
/// nullable column. A real customer id can never collide with this: the API
/// service's JWT gate (`server::auth::require_jwt`) rejects a nil-UUID `sub`
/// outright, the one place a `CustomerId` is minted from user input.
pub const NIL_CUSTOMER: Uuid = Uuid::nil();

/// A failure mapping or writing a usage row. The variant decides whether
/// retrying the *same* input could ever succeed — the Kafka consumer uses the
/// [`event_bus::Transience`] impl to choose between "back off and redeliver"
/// and "this will never work, skip it".
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The envelope on the topic is not a `UsageRecorded` — a misrouted
    /// message that will never map, no matter how often it is redelivered.
    #[error("not a UsageRecorded event: {event_type}")]
    NotUsage { event_type: &'static str },

    /// The ClickHouse round-trip failed (unreachable, timeout, server error).
    /// Typically transient.
    #[error("clickhouse request failed")]
    Clickhouse(#[from] clickhouse::error::Error),
}

impl event_bus::Transience for StoreError {
    fn is_transient(&self) -> bool {
        matches!(self, StoreError::Clickhouse(_))
    }
}

/// Build the ClickHouse client from config. Does no I/O — the first real
/// connection happens on the first query. Kept separate from [`UsageStore`] so
/// the migration runner can use the same client without depending on the store.
pub fn build_client(cfg: &ClickhouseConfig) -> Client {
    Client::default()
        .with_url(&cfg.url)
        .with_user(&cfg.user)
        .with_password(cfg.password.expose_secret())
        .with_database(&cfg.database)
}

/// The append-only raw usage store, backed by ClickHouse.
#[derive(Clone)]
pub struct UsageStore {
    client: Client,
}

impl UsageStore {
    /// Wrap a ClickHouse client (see [`build_client`]) as the usage store.
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// The underlying client, for the analytics/read side (integration tests
    /// today). Writes must go through [`UsageStore::insert`] to preserve the
    /// append-only invariant — this is not a general SQL escape hatch.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Liveness/readiness probe: a trivial query that proves ClickHouse is
    /// reachable and answering.
    pub async fn ping(&self) -> Result<(), StoreError> {
        let _: u8 = self.client.query("SELECT 1").fetch_one().await?;
        Ok(())
    }

    /// Insert a batch of usage rows in one RowBinary insert — one ClickHouse
    /// *part* per batch, not per row (the parts economics the batching consume
    /// loop exists for). Append-only: no update, no delete (§14). An empty
    /// batch is a no-op.
    ///
    /// At-least-once by design — the consumer commits its offsets only *after*
    /// this returns, so a crash mid-insert re-delivers the whole batch; the
    /// redelivered duplicates carry the same `event_id`s and converge away
    /// under the table's ReplacingMergeTree key (see the 0001 migration).
    pub async fn insert_batch(&self, rows: &[UsageRow]) -> Result<(), StoreError> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut insert = self.client.insert::<UsageRow>("usage_events").await?;
        for row in rows {
            insert.write(row).await?;
        }
        insert.end().await?;
        Ok(())
    }
}

/// One row of `usage_events` — the §13 `UsageEvent` fields plus the envelope
/// identity. Field names are the ClickHouse column names; `ingested_at` is
/// intentionally absent (it has a `DEFAULT`, so omitting it lets ClickHouse
/// fill the ingest time).
#[derive(Debug, Clone, PartialEq, Eq, clickhouse::Row, Serialize, Deserialize)]
pub struct UsageRow {
    /// Envelope identity — the dedup key under redelivery and the
    /// reconciliation key against the event store's copy of the stream.
    #[serde(with = "clickhouse::serde::uuid")]
    pub event_id: Uuid,
    /// [`NIL_CUSTOMER`] (the all-zero UUID) for system-/chain-wide usage with
    /// no customer in scope (`UsageRecorded.customer_id: None` — see
    /// [`events::system::UsageRecorded`]) rather than a `Nullable(UUID)`
    /// column: ClickHouse's own guidance is against nullable columns in a
    /// `MergeTree` `ORDER BY` key (worse compression, no min/max index skip),
    /// and this table's whole query shape leans on `ORDER BY (customer_id,
    /// …)`. A real customer id can never collide with the sentinel — v4/v7
    /// UUIDs practically never land on all-zero bits, and application code
    /// never mints one. Filter system rows out with `WHERE customer_id !=
    /// '00000000-0000-0000-0000-000000000000'`.
    #[serde(with = "clickhouse::serde::uuid")]
    pub customer_id: Uuid,
    /// The §13 vocabulary in its snake_case wire form (`api_call_made`, …),
    /// stored as-is: an older sink must store a newer producer's variant, not
    /// reject it (forward compatibility, §2).
    pub event_type: String,
    pub quantity: u64,
    /// Envelope chain stamp (`Chain(u64)`) — partition placement today,
    /// per-chain capacity analytics once multi-chain lands (§13/Sprint 13).
    pub chain: u64,
    /// The metered moment: the `UsageRecorded` payload's own timestamp (§13's
    /// `UsageEvent.timestamp`), not the envelope's `occurred_at` — the two are
    /// stamped microseconds apart by the producer, but the payload field is
    /// the domain fact.
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    pub occurred_at: DateTime<Utc>,
}

impl TryFrom<&EventEnvelope> for UsageRow {
    type Error = StoreError;

    /// Lift a `UsageRecorded` envelope into its stored row. The only failure
    /// is a non-usage payload — permanent, so the consumer skips it rather
    /// than wedging the stream on a misrouted message.
    fn try_from(env: &EventEnvelope) -> Result<Self, Self::Error> {
        let DomainEvent::UsageRecorded(UsageRecorded {
            customer_id,
            event_type,
            quantity,
            timestamp,
        }) = &env.payload
        else {
            return Err(StoreError::NotUsage {
                event_type: env.event_type(),
            });
        };
        Ok(Self {
            event_id: env.event_id,
            customer_id: customer_id.map_or(NIL_CUSTOMER, |c| c.0),
            event_type: event_type.clone(),
            quantity: *quantity,
            chain: env.chain.id(),
            occurred_at: *timestamp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_bus::Transience;
    use events::primitives::{Chain, CustomerId};
    use events::system::UsageEventType;

    fn usage_envelope() -> EventEnvelope {
        EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::UsageRecorded(UsageRecorded {
                customer_id: Some(CustomerId(Uuid::from_u128(7))),
                event_type: UsageEventType::ApiCallMade.as_wire_str().to_owned(),
                quantity: 3,
                timestamp: DateTime::<Utc>::from_timestamp_millis(1_700_000_000_123).unwrap(),
            }),
        )
    }

    #[test]
    fn row_maps_every_usage_field() {
        let env = usage_envelope();
        let row = UsageRow::try_from(&env).expect("map");

        assert_eq!(row.event_id, env.event_id);
        assert_eq!(row.customer_id, Uuid::from_u128(7));
        assert_eq!(row.event_type, "api_call_made");
        assert_eq!(row.quantity, 3);
        assert_eq!(row.chain, Chain::ETHEREUM.id());
        // The payload's own timestamp, not the envelope's occurred_at.
        assert_eq!(
            row.occurred_at,
            DateTime::<Utc>::from_timestamp_millis(1_700_000_000_123).unwrap()
        );
    }

    #[test]
    fn a_system_fact_with_no_customer_stores_as_the_nil_sentinel() {
        // `EventProcessed`, `DetectorRun`, … have no customer in scope
        // (§13) — the row still lands, keyed by the well-known sentinel
        // rather than a nullable column (see `UsageRow::customer_id`).
        let mut env = usage_envelope();
        if let DomainEvent::UsageRecorded(ref mut usage) = env.payload {
            usage.customer_id = None;
            usage.event_type = UsageEventType::EventProcessed.as_wire_str().to_owned();
        }
        let row = UsageRow::try_from(&env).expect("map");
        assert_eq!(row.customer_id, NIL_CUSTOMER);
        assert_eq!(row.event_type, "event_processed");
    }

    #[test]
    fn a_forward_compat_event_type_is_stored_as_is() {
        // A newer producer's variant this sink has never heard of must land,
        // not bounce (§2 forward compatibility — the wire field is a String).
        let mut env = usage_envelope();
        if let DomainEvent::UsageRecorded(ref mut usage) = env.payload {
            usage.event_type = "teleport_call".to_owned();
        }
        let row = UsageRow::try_from(&env).expect("map");
        assert_eq!(row.event_type, "teleport_call");
    }

    #[test]
    fn a_non_usage_event_is_a_permanent_fault() {
        use events::intelligence::SanctionHit;
        use events::primitives::AccountAddress;

        let env = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::SanctionHit(SanctionHit {
                address: AccountAddress::repeat_byte(0x42),
                list: "OFAC".into(),
                entry: "SDN-1".into(),
            }),
        );
        let err = UsageRow::try_from(&env).expect_err("must not map");
        // Permanent: redelivering a misrouted message can never help, so the
        // consumer must skip-and-commit, not retry forever.
        assert!(!err.is_transient());
        assert!(err.to_string().contains("SanctionHit"), "{err}");
    }
}
