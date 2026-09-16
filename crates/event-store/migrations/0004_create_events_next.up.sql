-- Readiness Epic D capacity plan: the replacement definition of `events`.
--
-- DDL only. The table is created under the staged name `events__next`
-- (ch_migrate::swap) and put in place by the service, never by copying data
-- inside a migration: boot swaps it in when the live table is empty (a fresh
-- deployment, a CI container), and a store with data moves through the
-- resumable `event-store repartition run` Job (docs/runbooks/capacity-plan.md).
--
-- Why a new definition at all. The original key, PARTITION BY (chain,
-- event_type, toDate(occurred_at)), is one partition per chain x event type x
-- day. Held for the 2192-day evidence window that is about 176 thousand
-- partitions, each at least one part, and ClickHouse refuses every insert once
-- a table passes max_parts_in_total (100000): the store would have stopped
-- accepting evidence on day 1258. A bulk insert block (a backup restore) may
-- also touch at most 100 partitions, which the daily key exceeds on any real
-- archive. `crates/capacity` gates both.
--
-- What changes:
--
-- * PARTITION BY toYYYYMM(occurred_at): 74 partitions across the window,
--   whatever the number of chains or event types. Chain and event type stay
--   the leading ORDER BY columns, so by-type and by-window reads still prune
--   through the primary index.
-- * ReplacingMergeTree. Ingest is at-least-once: a crash between the insert and
--   the Kafka commit redelivers the batch. The sorting key ends in event_id, so
--   a redelivered event is a duplicate row with an identical key, and merges
--   collapse it. Reads also dedupe (LIMIT 1 BY event_id), because merges are
--   eventual. An event is immutable, so which copy survives does not matter.
-- * non_replicated_deduplication_window: the insert path sends an
--   insert_deduplication_token per batch, so an exact retry of the same batch
--   is refused at insert time instead of waiting for a merge.
-- * ttl_only_drop_parts: expiry drops whole parts instead of rewriting them. A
--   merged monthly part is dropped once its newest row expires, so evidence is
--   over-retained by up to a month — the safe direction for a floor.
--
-- The TTL is the migration floor, as in 0003; boot reconciliation raises it.
-- Column order is identical to the table 0001 + 0002 produce. One statement,
-- and no literal question mark (the ch-migrate runner binds every one).
CREATE TABLE IF NOT EXISTS events__next
(
    event_id        UUID,
    schema_version  UInt16,
    chain           UInt64,
    event_type      String,
    event_family    String,
    occurred_at     DateTime64(3, 'UTC'),
    payload         String CODEC(ZSTD(3)),
    appended_at     DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC'),
    incident_id     Nullable(UUID),
    addresses       Array(String),
    INDEX idx_incident_id incident_id TYPE bloom_filter GRANULARITY 1,
    INDEX idx_addresses addresses TYPE bloom_filter GRANULARITY 1
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (chain, event_type, occurred_at, event_id)
TTL toDateTime(occurred_at) + toIntervalDay(2192) DELETE
SETTINGS ttl_only_drop_parts = 1, non_replicated_deduplication_window = 1000
