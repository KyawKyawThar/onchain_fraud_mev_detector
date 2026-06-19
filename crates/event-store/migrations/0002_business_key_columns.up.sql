-- Business-key projection columns for the §4 query API.
--
-- §4 requires the store be "queryable by business key (address, incident_id)".
-- Those keys live inside the JSON `payload`, off the primary key
-- (chain, event_type, occurred_at, event_id) — so the write path denormalizes
-- them into typed columns (see `store::EventRow` / `DomainEvent::addresses` +
-- `::incident_id`), each backed by a bloom-filter data-skipping index. A
-- by-address / by-incident lookup then prunes granules instead of scanning and
-- JSON-parsing every row.
--
-- These are pure read accelerators: NULL / empty when an event names no such key
-- (most chain events), and never consulted when reconstructing an envelope — the
-- `payload` stays the sole source of truth, so the columns can be rebuilt from it.
--
-- One statement per file (the migrate.rs convention): a single ALTER with
-- comma-separated actions. New inserts populate the columns and indexes
-- immediately; back-filling pre-existing rows would need a one-off
-- `ALTER TABLE events MATERIALIZE INDEX ...` (there is no production data at
-- Sprint 1, so this is intentionally omitted).
ALTER TABLE events
    ADD COLUMN incident_id Nullable(UUID),
    ADD COLUMN addresses Array(String),
    ADD INDEX idx_incident_id incident_id TYPE bloom_filter GRANULARITY 1,
    ADD INDEX idx_addresses addresses TYPE bloom_filter GRANULARITY 1;
