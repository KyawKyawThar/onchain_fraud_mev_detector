-- Revert 0005_alert_evidence_lookup.
ALTER TABLE events
    DROP INDEX IF EXISTS idx_alert_id,
    DROP COLUMN IF EXISTS alert_id;
