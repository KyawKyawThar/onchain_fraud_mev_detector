-- Revert 0002_business_key_columns.
--
-- Drops the read-accelerator indexes and columns. Non-destructive to the audit
-- log itself: the `payload` is unchanged and remains the source of truth, so the
-- columns can be recreated and back-filled from it. One ALTER, comma-separated
-- actions (indexes dropped before the columns they cover).
ALTER TABLE events
    DROP INDEX IF EXISTS idx_incident_id,
    DROP INDEX IF EXISTS idx_addresses,
    DROP COLUMN IF EXISTS incident_id,
    DROP COLUMN IF EXISTS addresses;
