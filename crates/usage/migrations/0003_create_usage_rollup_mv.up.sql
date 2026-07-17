-- The feed for 0002's usage_rollup_daily: a materialized view is ClickHouse's
-- insert trigger - every block inserted into usage_events is aggregated and
-- appended to the rollup in the same write. GROUP BY here collapses within
-- one inserted block; SummingMergeTree collapses across blocks on merge -
-- which is why readers aggregate again (see 0002's header).
--
-- See 0002 for the accuracy posture: fires on raw inserts, so exact numbers
-- come from the raw table, this rollup is the dashboard surface.
CREATE MATERIALIZED VIEW IF NOT EXISTS usage_rollup_daily_mv
TO usage_rollup_daily
AS SELECT
    toDate(occurred_at) AS day,
    customer_id,
    event_type,
    chain,
    sum(quantity)       AS total_quantity,
    count()             AS events
FROM usage_events
GROUP BY day, customer_id, event_type, chain;
