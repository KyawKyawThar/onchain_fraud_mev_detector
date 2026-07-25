-- Safe-block-timing rollup: historical incident intensity by time-of-day and
-- "size" (severity band), the aggregation behind `GET /v1/timing/recommendation`.
--
-- Fed automatically by the materialized view in 0004; nothing inserts here
-- directly. "slot_of_day" is a derived 10-minute UTC time-of-day bucket
-- (0..143), not an on-chain/beacon slot — `incident_analytics` carries no
-- block/slot number today, so this is the closest signal available without
-- threading a new field through ingestion -> detection -> simulation.
-- "severity" doubles as the size band (low/medium/high/critical, already
-- stamped on every `IncidentCreated` snapshot by `events::scoring`) rather
-- than inventing a second USD-threshold scheme.
--
-- SummingMergeTree keeps one row per ORDER BY key per part and sums the
-- numeric columns on merge. Merges are eventual, so readers MUST aggregate:
--   SELECT slot_of_day, sum(incident_count), sum(total_victim_loss_usd)
--   FROM incident_timing_rollup WHERE chain = ... AND severity = ...
--   GROUP BY slot_of_day
-- (a bare SELECT sees partial sums across unmerged parts) — mirrors
-- `usage_rollup_daily`'s contract exactly.
--
-- Accuracy posture, stated honestly: the feeding view fires on raw INSERTs
-- into `incident_analytics` and cannot retract a count when a later
-- `IncidentRetracted` row arrives (no delete on a SummingMergeTree) - a
-- since-retracted incident stays counted here. That is acceptable for a
-- "guide, not a guarantee" heuristic (the API response says so explicitly);
-- anything that must be exact reads `incident_analytics` directly.
--
-- One statement per migration file, and no literal question marks anywhere
-- (the clickhouse client would parse one as a bind placeholder).
CREATE TABLE IF NOT EXISTS incident_timing_rollup
(
    chain                  UInt64,
    severity               String,
    slot_of_day            UInt16,
    incident_count         UInt64,
    total_victim_loss_usd  Float64
)
ENGINE = SummingMergeTree((incident_count, total_victim_loss_usd))
PARTITION BY chain
ORDER BY (chain, severity, slot_of_day);
