-- The feed for 0003's incident_timing_rollup: a materialized view is
-- ClickHouse's insert trigger - every block inserted into incident_analytics
-- is aggregated and appended to the rollup in the same write.
--
-- Only `IncidentCreated` rows are the canonical one-per-confirmed-incident
-- snapshot (see `WalletExposureStore`'s docs); `confirmed = 1` excludes a
-- snapshot that never actually became a live incident. See 0003 for the
-- accuracy posture (fires on raw inserts, can't retract a count on a later
-- `IncidentRetracted`) - this rollup is the timing-guide surface, not an
-- exact ledger.
--
-- The `10` below is `crate::timing::SLOT_MINUTES` (10-minute buckets, 144/day
-- per `crate::timing::SLOTS_PER_DAY`), duplicated here because SQL can't
-- `use` a Rust const - if `SLOT_MINUTES` ever changes, this literal must
-- change with it or the rollup's buckets silently stop lining up with what
-- `crate::timing::rank_windows` expects.
CREATE MATERIALIZED VIEW IF NOT EXISTS incident_timing_rollup_mv
TO incident_timing_rollup
AS SELECT
    chain,
    severity,
    intDiv(toHour(occurred_at) * 60 + toMinute(occurred_at), 10) AS slot_of_day,
    count()                                                      AS incident_count,
    sum(coalesce(victim_loss_usd, 0))                            AS total_victim_loss_usd
FROM incident_analytics
WHERE event_type = 'IncidentCreated' AND confirmed = 1
GROUP BY chain, severity, slot_of_day;
