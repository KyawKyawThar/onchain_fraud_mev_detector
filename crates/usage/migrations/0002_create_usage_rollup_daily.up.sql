-- Daily usage rollup: the query surface for §13 analytics/capacity/abuse
-- dashboards, so they scan thousands of pre-aggregated rows instead of the
-- raw billions. Fed automatically by the materialized view in 0003; nothing
-- inserts here directly.
--
-- SummingMergeTree keeps one row per ORDER BY key per part and sums the
-- numeric columns on merge. Merges are eventual, so readers MUST aggregate:
--   SELECT customer_id, event_type, day, sum(total_quantity), sum(events)
--   FROM usage_rollup_daily GROUP BY customer_id, event_type, day
-- (a bare SELECT sees partial sums across unmerged parts).
--
-- Accuracy posture, stated honestly: the feeding view fires on raw INSERTs,
-- so a crash-redelivered duplicate batch double-counts here - the raw table's
-- ReplacingMergeTree dedup does NOT propagate to this rollup. The rollup is
-- for trends and dashboards; anything that must be exact (a §13
-- reconciliation) reads the raw usage_events with count(DISTINCT event_id).
-- The batching consumer commits offsets only after a successful flush, so the
-- duplicate window is a crash between flush and commit - rare, and bounded to
-- one batch.
--
-- One statement per migration file, and no literal question marks anywhere
-- (the clickhouse client would parse one as a bind placeholder).
CREATE TABLE IF NOT EXISTS usage_rollup_daily
(
    day             Date,
    customer_id     UUID,
    event_type      String,
    chain           UInt64,
    total_quantity  UInt64,
    events          UInt64
)
ENGINE = SummingMergeTree((total_quantity, events))
PARTITION BY toYYYYMM(day)
ORDER BY (customer_id, event_type, day, chain);
