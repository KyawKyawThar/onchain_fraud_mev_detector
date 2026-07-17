-- Raw usage events: the append-only metering record (§13, §14 — trimmed to the
-- Sprint-12 scope: analytics/capacity/abuse only, no billing aggregates).
--
-- One row per consumed `UsageRecorded` envelope. The §13 `UsageEvent` fields
-- are lifted into typed columns (customer, metered type, quantity, chain,
-- occurrence time); `event_id` is the envelope's identity and the
-- reconciliation key against the event store's copy of the same stream.
--
-- ReplacingMergeTree, not plain MergeTree: the Kafka ingest is at-least-once,
-- so a crash between insert and offset commit re-delivers the same envelope.
-- Re-inserting it produces an identical ORDER BY key (event_id is in the key),
-- and background merges converge the duplicates away. Merges are eventual, so
-- an *exact* count still uses count(DISTINCT event_id) or FINAL; the engine
-- keeps the table from accumulating redelivery noise, it is not the
-- correctness mechanism. Still append-only: this service never updates or
-- deletes a row.
--
-- One statement per migration file (the shared ch-migrate runner executes each
-- file as a single query), and no literal question marks anywhere in this file
-- (the clickhouse client would parse one as a bind placeholder).
CREATE TABLE IF NOT EXISTS usage_events
(
    event_id     UUID,
    customer_id  UUID,
    -- The §13 vocabulary in its snake_case wire form (`api_call_made`, ...).
    -- Kept a plain String, mirroring the wire: an older sink must store a
    -- newer producer's variant, not reject it (forward compatibility, §2).
    event_type   String,
    quantity     UInt64,
    -- Envelope chain stamp (`Chain(u64)`). Usage is aggregated by customer,
    -- not chain (§13) - today producers stamp a fixed chain for partition
    -- placement - but the column keeps per-chain capacity analytics possible
    -- once multi-chain lands (§13/Sprint 13).
    chain        UInt64,
    -- The metered moment: the `UsageRecorded` payload's own timestamp.
    occurred_at  DateTime64(3, 'UTC'),
    -- Server-side ingest timestamp; defaulted so inserts never set it.
    ingested_at  DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(ingested_at)
-- Monthly partitions: usage volume is orders of magnitude below the event
-- firehose, and the analytics queries scan time windows, so date-grained
-- partitions would only multiply parts.
PARTITION BY toYYYYMM(occurred_at)
-- Orders for the §13 query patterns (one customer's usage of one metered type
-- over a window); event_id is the tie-breaker that makes the key unique and
-- the ReplacingMergeTree dedup key precise.
ORDER BY (customer_id, event_type, occurred_at, event_id);
