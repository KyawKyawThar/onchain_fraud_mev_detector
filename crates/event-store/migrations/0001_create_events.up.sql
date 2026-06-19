-- Event store: the immutable, append-only system of record (§4).
--
-- One row per domain event. The envelope metadata (§2) is lifted into columns
-- for partitioning and (Sprint-1 task 3) query-by-business-key; the DomainEvent
-- itself rides in `payload` as the exact, schema-locked JSON the producer wrote
-- (the `crates/events` golden wire format), so a read reconstructs the envelope
-- byte-for-byte via `EventEnvelope::with_metadata`.
--
-- DateTime64(3,'UTC') columns are an Int64 of milliseconds in RowBinary, which
-- is why the inserting Rust struct carries `occurred_at` as an `i64`.
--
-- One statement per migration file (the boot-time runner executes each file as a
-- single query — see `src/migrate.rs`).
CREATE TABLE IF NOT EXISTS events
(
    event_id        UUID,
    schema_version  UInt16,
    chain           UInt64,
    event_type      String,
    event_family    String,
    occurred_at     DateTime64(3, 'UTC'),
    payload         String CODEC(ZSTD(3)),
    -- Server-side ingest timestamp; defaulted so inserts never set it.
    appended_at     DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC')
)
ENGINE = MergeTree
-- §4: partitioned by (chain, event_type, date). `date` is derived from the
-- event's own occurrence time, not ingest time.
PARTITION BY (chain, event_type, toDate(occurred_at))
-- Orders within a partition for the §4 query patterns (by type, over a time
-- window); event_id is the tie-breaker that keeps the key unique.
ORDER BY (chain, event_type, occurred_at, event_id);
