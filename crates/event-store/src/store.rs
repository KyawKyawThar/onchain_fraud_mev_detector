//! The storage core: appends [`EventEnvelope`]s to the ClickHouse `events`
//! table. Ingress-agnostic — both the HTTP API and the Kafka consumer drive the
//! same [`EventStore::append_batch`], so there is exactly one write path.

use chrono::{DateTime, Utc};
use clickhouse::Client;
use events::primitives::{AccountAddress, Chain};
use events::{DomainEvent, EventEnvelope};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::ClickhouseConfig;

/// A failure appending to (or probing) the store. The variant decides whether
/// retrying the *same* input could ever succeed — the Kafka consumer uses
/// [`StoreError`]'s [`event_bus::Transience`] impl to choose between "back off and redeliver" and
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

impl event_bus::Transience for StoreError {
    /// Whether retrying the same operation could plausibly succeed later.
    fn is_transient(&self) -> bool {
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
    /// The encode step runs first and whole: an envelope that cannot be encoded
    /// fails the call before any row is sent.
    pub async fn append_batch(&self, envelopes: &[EventEnvelope]) -> Result<(), StoreError> {
        let rows = match envelopes
            .iter()
            .map(EventRow::try_from)
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(rows) => rows,
            Err(err) => {
                let err = StoreError::Encode(err);
                crate::metrics::record_append_error(std::time::Duration::ZERO, &err);
                return Err(err);
            }
        };
        self.append_rows(&rows).await
    }

    /// Append already-encoded rows — **the one write path**. The HTTP API goes
    /// through [`Self::append_batch`], and the Kafka ingest encodes per record
    /// (so one bad envelope is dead-lettered alone) and flushes here.
    ///
    /// Idempotent under retry, in two layers. The insert carries an
    /// `insert_deduplication_token` derived from the batch's event ids
    /// ([`dedup_token`]), so an exact retry of a batch — the batch loop's
    /// transient-failure path, a redelivery of the same batch — is refused at
    /// insert time. A redelivery that forms a *different* batch still lands its
    /// duplicates, and those collapse under the table's `ReplacingMergeTree`
    /// key; reads dedupe by `event_id` meanwhile (`query`).
    #[tracing::instrument(skip_all, fields(rows = rows.len()))]
    pub async fn append_rows(&self, rows: &[EventRow]) -> Result<(), StoreError> {
        if rows.is_empty() {
            return Ok(());
        }
        let started = std::time::Instant::now();
        let result = self.insert_rows(rows).await;
        match &result {
            Ok(()) => crate::metrics::record_append_success(started.elapsed(), rows),
            Err(err) => crate::metrics::record_append_error(started.elapsed(), err),
        }
        result
    }

    async fn insert_rows(&self, rows: &[EventRow]) -> Result<(), StoreError> {
        let mut insert = self
            .client
            .insert::<EventRow>(TABLE)
            .await?
            .with_setting(DEDUP_TOKEN_SETTING, dedup_token(rows));
        for row in rows {
            // I/O failures from `write`/`end` are transient (`StoreError::Clickhouse`).
            insert.write(row).await?;
        }
        insert.end().await?;
        Ok(())
    }
}

/// The table every write lands in. Named once: the repartition, tiering and
/// retention modules all address it.
pub const TABLE: &str = "events";

/// The ClickHouse setting that makes an insert idempotent within the table's
/// `non_replicated_deduplication_window` (`replicated_deduplication_window` on a
/// replicated table).
const DEDUP_TOKEN_SETTING: &str = "insert_deduplication_token";

/// The deduplication token for one insert: SHA-256 over the batch's event ids,
/// **sorted**, so the same set of events is the same token however a retry or a
/// redelivery happened to order it.
///
/// SHA-256 rather than a `std` hasher because the token must be identical
/// across processes and builds — a retry after a deploy is exactly the case it
/// exists for, and `DefaultHasher` makes no stability promise across versions.
pub fn dedup_token(rows: &[EventRow]) -> String {
    let mut ids: Vec<[u8; 16]> = rows.iter().map(|row| *row.event_id.as_bytes()).collect();
    ids.sort_unstable();
    let mut hasher = Sha256::new();
    for id in &ids {
        hasher.update(id);
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Canonical stored form of an on-chain address: lowercase `0x`-hex. The write
/// path (the `addresses` index column) and the by-address query both normalize
/// through this one function, so a lookup can never silently miss because the
/// two sides disagreed on casing.
pub(crate) fn normalized_address(address: &AccountAddress) -> String {
    format!("{address:#x}")
}

/// Shared reconstruction: decode the stored `payload` JSON and rewrap it with its
/// original identity via [`EventEnvelope::with_metadata`], so replay reproduces
/// the event's `event_id`/`occurred_at` exactly (§18). Used by every read path.
fn envelope_from_stored(
    event_id: Uuid,
    occurred_at: DateTime<Utc>,
    chain: u64,
    payload: &str,
) -> Result<EventEnvelope, serde_json::Error> {
    let payload: DomainEvent = serde_json::from_str(payload)?;
    Ok(EventEnvelope::with_metadata(
        event_id,
        occurred_at,
        Chain(chain),
        payload,
    ))
}

/// One row to *insert*. The envelope metadata (§2) is lifted into typed columns;
/// the `DomainEvent` itself is the exact schema-locked JSON in `payload`. Reads
/// don't use this type — they select only the canonical columns into
/// [`StoredEvent`] (the denormalized index columns never feed reconstruction).
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
    /// Denormalized business key for the §4 audit-by-incident query: the
    /// incident this event references, or `NULL` if it names none. Derived from
    /// `payload` via [`DomainEvent::incident_id`]; an index accelerator only,
    /// never read back when reconstructing the envelope. Maps to the
    /// `Nullable(UUID)` column.
    #[serde(with = "clickhouse::serde::uuid::option")]
    pub incident_id: Option<Uuid>,
    /// Denormalized business key for the §4 by-address query: every on-chain
    /// address this event references, lowercase `0x…` hex. Derived from `payload`
    /// via [`DomainEvent::addresses`]; maps to the `Array(String)` column.
    pub addresses: Vec<String>,
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
            incident_id: env.payload.incident_id().map(|id| id.0),
            addresses: {
                // One event can name the same address twice (e.g. a
                // PreliminaryAlertCreated listing it as both a victim and a
                // beneficiary); dedupe so the indexed array stays tight.
                let mut addrs: Vec<String> = env
                    .payload
                    .addresses()
                    .iter()
                    .map(normalized_address)
                    .collect();
                addrs.sort_unstable();
                addrs.dedup();
                addrs
            },
        })
    }
}

/// The canonical columns a read needs to rebuild an [`EventEnvelope`]: identity,
/// chain, occurrence time, and the payload that is the source of truth. The
/// denormalized `incident_id`/`addresses` index columns are deliberately *not*
/// selected — they only accelerate lookups, never feed reconstruction, so a
/// query that returns rows doesn't pay to ship them.
#[derive(Debug, clickhouse::Row, Deserialize)]
pub struct StoredEvent {
    #[serde(with = "clickhouse::serde::uuid")]
    pub event_id: Uuid,
    pub chain: u64,
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    pub occurred_at: DateTime<Utc>,
    pub payload: String,
}

/// The `SELECT` projection for [`StoredEvent`], in field order (RowBinary maps by
/// position). The single source of the read column list, shared by every query.
pub const STORED_EVENT_COLUMNS: &str = "event_id, chain, occurred_at, payload";

impl TryFrom<StoredEvent> for EventEnvelope {
    /// The only fallible step is decoding the stored payload JSON.
    type Error = serde_json::Error;

    fn try_from(row: StoredEvent) -> Result<Self, Self::Error> {
        envelope_from_stored(row.event_id, row.occurred_at, row.chain, &row.payload)
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

    /// A retry that reorders the batch must still be recognised as the same
    /// insert, and a batch with one different event must not be.
    #[test]
    fn the_dedup_token_is_order_independent_and_set_sensitive() {
        let a = EventRow::try_from(&sample_envelope()).unwrap();
        let b = EventRow::try_from(&sample_envelope()).unwrap();
        let c = EventRow::try_from(&sample_envelope()).unwrap();
        let forward = dedup_token(&[a.clone(), b.clone()]);
        let backward = dedup_token(&[b.clone(), a.clone()]);
        assert_eq!(forward, backward);
        assert_ne!(forward, dedup_token(&[a, c]));
        assert_eq!(forward.len(), 64, "hex SHA-256");
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
        // A chain event names no business key, so both accelerator columns are empty.
        assert_eq!(row.incident_id, None);
        assert!(row.addresses.is_empty());
    }

    #[test]
    fn row_denormalizes_business_keys_for_indexed_lookup() {
        use events::intelligence::SanctionHit;
        use events::primitives::AccountAddress;

        let address = AccountAddress::repeat_byte(0x42);
        let env = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::SanctionHit(SanctionHit {
                address,
                list: "OFAC".into(),
                entry: "SDN-1".into(),
            }),
        );
        let row = EventRow::try_from(&env).expect("map");

        // SanctionHit carries an address but no incident.
        assert_eq!(row.incident_id, None);
        // Stored lowercase so it matches the by-address query's normalized input.
        assert_eq!(row.addresses, vec![format!("{address:#x}")]);
        assert_eq!(row.addresses[0], row.addresses[0].to_lowercase());
    }

    #[test]
    fn write_then_canonical_read_round_trips_to_the_original() {
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

        // What the write path stores, then what a read selects back (the
        // canonical columns only) — the pair must reconstruct the original.
        let row = EventRow::try_from(&env).expect("map");
        let stored = StoredEvent {
            event_id: row.event_id,
            chain: row.chain,
            occurred_at: row.occurred_at,
            payload: row.payload,
        };
        let back = EventEnvelope::try_from(stored).expect("reconstruct");
        assert_eq!(back, env);
    }
}
