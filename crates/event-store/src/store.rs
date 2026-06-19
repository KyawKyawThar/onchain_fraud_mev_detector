//! The storage core: appends [`EventEnvelope`]s to the ClickHouse `events`
//! table. Ingress-agnostic — both the HTTP API and the Kafka consumer drive the
//! same [`EventStore::append_batch`], so there is exactly one write path.

use chrono::{DateTime, Utc};
use clickhouse::Client;
use events::primitives::Chain;
use events::{DomainEvent, EventEnvelope};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::ClickhouseConfig;

/// A failure appending to (or probing) the store. The variant decides whether
/// retrying the *same* input could ever succeed — the Kafka consumer uses
/// [`StoreError::is_transient`] to choose between "back off and redeliver" and
/// "this will never work, skip it".
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Encoding an event to its stored form failed. A data/logic bug, not a
    /// blip — retrying won't help.
    #[error("encoding event payload")]
    Encode(#[from] serde_json::Error),

    /// The ClickHouse round-trip failed (unreachable, timeout, server error).
    /// Typically transient.
    #[error("clickhouse request failed")]
    Clickhouse(#[from] clickhouse::error::Error),
}

impl StoreError {
    /// Whether retrying the same operation could plausibly succeed later.
    pub fn is_transient(&self) -> bool {
        matches!(self, StoreError::Clickhouse(_))
    }
}

/// Build the ClickHouse client from config. Does no I/O — the first real
/// connection happens on the first query. Kept separate from [`EventStore`] so
/// the migration runner can use the same client without depending on the store.
pub fn build_client(cfg: &ClickhouseConfig) -> Client {
    Client::default()
        .with_url(&cfg.url)
        .with_user(&cfg.user)
        .with_password(cfg.password.expose_secret())
        .with_database(&cfg.database)
}

/// The append-only event store, backed by ClickHouse.
#[derive(Clone)]
pub struct EventStore {
    client: Client,
}

impl EventStore {
    /// Wrap a ClickHouse client (see [`build_client`]) as the event store.
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// The underlying client, for the read/query path (the integration tests and
    /// the Sprint-1 task-3 query API). Writes must go through
    /// [`EventStore::append_batch`] to preserve the append-only invariant — this
    /// is not a general SQL escape hatch.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Liveness/readiness probe: a trivial query that proves ClickHouse is
    /// reachable and answering.
    pub async fn ping(&self) -> Result<(), StoreError> {
        let _: u8 = self.client.query("SELECT 1").fetch_one().await?;
        Ok(())
    }

    /// Append a batch of envelopes in one RowBinary insert. Append-only: no
    /// update, no delete (§4). An empty batch is a no-op.
    ///
    /// At-least-once by design — callers commit their source offset only *after*
    /// this returns, so a crash mid-append re-delivers rather than loses (§4).
    pub async fn append_batch(&self, envelopes: &[EventEnvelope]) -> Result<(), StoreError> {
        if envelopes.is_empty() {
            return Ok(());
        }

        let mut insert = self.client.insert::<EventRow>("events").await?;
        for envelope in envelopes {
            // Encode failures are permanent (`StoreError::Encode`); I/O failures
            // from `write`/`end` are transient (`StoreError::Clickhouse`).
            insert.write(&EventRow::try_from(envelope)?).await?;
        }
        insert.end().await?;
        Ok(())
    }
}

/// One stored row. The envelope metadata (§2) is lifted into typed columns; the
/// `DomainEvent` itself is the exact schema-locked JSON in `payload`, so a read
/// reconstructs the original envelope via [`EventRow::into_envelope`].
///
/// Field names are the ClickHouse column names. `appended_at` is intentionally
/// absent: it has a `DEFAULT`, so omitting it lets ClickHouse fill the ingest
/// time.
#[derive(Debug, Clone, clickhouse::Row, Serialize, Deserialize)]
#[non_exhaustive]
pub struct EventRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub event_id: Uuid,
    pub schema_version: u16,
    /// Chain id (`Chain(u64)`) — the high-order partition key.
    pub chain: u64,
    pub event_type: String,
    pub event_family: String,
    /// The event's occurrence time. The serde helper maps it to/from the
    /// `DateTime64(3,'UTC')` column (millisecond precision), so the stored value
    /// is type-checked against the column rather than smuggled through as an
    /// integer.
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    pub occurred_at: DateTime<Utc>,
    /// The `DomainEvent` as adjacently-tagged JSON (the locked wire format).
    pub payload: String,
}

impl TryFrom<&EventEnvelope> for EventRow {
    /// The only fallible step is encoding the payload to JSON.
    type Error = serde_json::Error;

    fn try_from(env: &EventEnvelope) -> Result<Self, Self::Error> {
        Ok(Self {
            event_id: env.event_id,
            schema_version: env.schema_version,
            chain: env.chain.id(),
            event_type: env.event_type().to_owned(),
            event_family: env.payload.family().as_str().to_owned(),
            occurred_at: env.occurred_at,
            payload: serde_json::to_string(&env.payload)?,
        })
    }
}

impl TryFrom<EventRow> for EventEnvelope {
    /// The only fallible step is decoding the stored payload JSON.
    type Error = serde_json::Error;

    /// Reconstruct the original envelope from a stored row. Uses the
    /// identity-preserving [`EventEnvelope::with_metadata`] so replay reproduces
    /// the event's `event_id`/`occurred_at` exactly (§18).
    fn try_from(row: EventRow) -> Result<Self, Self::Error> {
        let payload: DomainEvent = serde_json::from_str(&row.payload)?;
        Ok(EventEnvelope::with_metadata(
            row.event_id,
            row.occurred_at,
            Chain(row.chain),
            payload,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use events::chain::BlockAssembled;
    use events::primitives::BlockRef;

    fn sample_envelope() -> EventEnvelope {
        EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::BlockAssembled(BlockAssembled {
                block: BlockRef::new(19_800_000, B256::repeat_byte(0xab)),
                tx_count: 142,
                trace_available: true,
            }),
        )
    }

    #[test]
    fn row_maps_every_envelope_field() {
        let env = sample_envelope();
        let row = EventRow::try_from(&env).expect("map");

        assert_eq!(row.event_id, env.event_id);
        assert_eq!(row.schema_version, env.schema_version);
        assert_eq!(row.chain, Chain::ETHEREUM.id());
        assert_eq!(row.event_type, "BlockAssembled");
        assert_eq!(row.event_family, "chain");
        assert_eq!(row.occurred_at, env.occurred_at);
        // payload is exactly the DomainEvent wire form, nothing more.
        assert_eq!(row.payload, serde_json::to_string(&env.payload).unwrap());
    }

    #[test]
    fn row_round_trips_back_to_the_original_envelope() {
        // Build with a millisecond-precise timestamp: the DateTime64(3) column
        // stores only milliseconds, so an arbitrary `now()` (sub-ms precision)
        // would not survive the round trip. Replay timestamps are millisecond
        // values anyway.
        let when = DateTime::<Utc>::from_timestamp_millis(1_700_000_000_123).unwrap();
        let env = EventEnvelope::with_metadata(
            Uuid::nil(),
            when,
            Chain::ETHEREUM,
            sample_envelope().payload,
        );

        let row = EventRow::try_from(&env).expect("map");
        let back = EventEnvelope::try_from(row).expect("reconstruct");
        assert_eq!(back, env);
    }
}
