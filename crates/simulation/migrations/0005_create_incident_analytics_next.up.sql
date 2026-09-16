-- Readiness Epic D capacity plan: the replacement definition of
-- `incident_analytics`.
--
-- The original key, PARTITION BY (chain, toDate(occurred_at)), is a partition
-- per chain per day with no TTL: about 730 a year on two chains, past the
-- capacity plan's 1000-partition budget in under a year and a half, and past
-- the 100-partition insert-block limit (a backup restore) after about 50 days
-- of data. The monthly key holds twelve a year whatever the number of chains;
-- chain stays the leading ORDER BY column.
--
-- DDL only, under the staged name ch_migrate::swap derives. Boot swaps it in
-- when the live table is empty; a table with data is a derived projection, so
-- it is rebuilt from the event store (`simulation-projection rebuild --model
-- dashboards --yes`), whose staging database gets this definition from the
-- same migrations and promotes it by EXCHANGE — the materialized view follows
-- the table name across an exchange.
--
-- Column order is identical to the table 0001 + 0002 produce. One statement,
-- and no literal question mark.
CREATE TABLE IF NOT EXISTS incident_analytics__next
(
    event_id         UUID,
    occurred_at      DateTime64(3, 'UTC'),
    chain            UInt64,
    event_type       String,
    alert_id         UUID,
    incident_id      Nullable(UUID),
    kind             String,
    severity         String,
    status           String,
    confirmed        UInt8,
    profit           Float64,
    victim_loss      Float64,
    appended_at      DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC'),
    victim_address   Nullable(String),
    victim_loss_usd  Nullable(Float64),
    INDEX idx_victim_address victim_address TYPE bloom_filter GRANULARITY 1
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (chain, occurred_at, event_id)
