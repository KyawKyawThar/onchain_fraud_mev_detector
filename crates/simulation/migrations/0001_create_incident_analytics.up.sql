-- Incident analytics projection (§7, §14) — the simulation service's append-only
-- ClickHouse firehose, the analytical complement to the mutable Postgres read model.
--
-- One row per *non-duplicate* result-path event the `simulation-projection` consumer
-- folds (it appends only when the pure `IncidentProjection` reports a real change, so
-- the aggregations stay dedup-consistent with the Postgres rows). This is the wide-
-- scan surface for "incidents by kind / severity over time", "total attacker profit /
-- victim loss per window", etc. — queries ClickHouse's MergeTree is built for and the
-- row-oriented Postgres table is not. Immutable, like the event store: no updates, no
-- deletes; a later lifecycle event is a *new* row carrying the folded snapshot at that
-- point, and a query reads the latest per `alert_id` when it wants current state.
--
-- One statement per migration file (the boot-time runner executes each file as a
-- single query — see `src/ch_migrate.rs`, ported from the event store).
CREATE TABLE IF NOT EXISTS incident_analytics
(
    event_id     UUID,
    -- The triggering event's occurrence time (§7 last-writer key), not ingest time.
    occurred_at  DateTime64(3, 'UTC'),
    chain        UInt64,
    -- Which result-path event produced this snapshot: SimulationCompleted /
    -- IncidentCreated / IncidentRetracted / IncidentFinalized.
    event_type   String,
    alert_id     UUID,
    -- Set once IncidentCreated has been folded; NULL for a bare SimulationCompleted.
    incident_id  Nullable(UUID),
    -- AlertKind / Severity as their snake_case wire strings ('' when not yet known).
    kind         String,
    severity     String,
    -- The folded lifecycle status at this event (unconfirmed/confirmed/finalized/retracted).
    status       String,
    -- Whether this snapshot represents a live confirmed incident (a confirmed/finalized
    -- row that has not been retracted) — a denormalized flag so the common
    -- "confirmed incidents only" filter is a column read, not a status-string parse.
    confirmed    UInt8,
    profit       Float64,
    victim_loss  Float64,
    -- Server-side ingest timestamp; defaulted so inserts never set it.
    appended_at  DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC')
)
ENGINE = MergeTree
-- Partition by chain + event date (mirrors the event store): analytics queries scan
-- time windows per chain, and old partitions drop cheaply if retention is added.
PARTITION BY (chain, toDate(occurred_at))
-- Ordered for the time-window scans and the latest-per-incident read; event_id is the
-- uniqueness tie-breaker.
ORDER BY (chain, occurred_at, event_id);
