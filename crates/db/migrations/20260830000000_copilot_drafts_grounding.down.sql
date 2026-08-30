-- Reverse of the Sprint 20 t3 grounding / announcement / backfill schema.
DROP TABLE IF EXISTS copilot_outbox;
DROP TABLE IF EXISTS copilot_batches;

DROP INDEX IF EXISTS copilot_drafts_batch_idx;
DROP INDEX IF EXISTS copilot_drafts_queue_idx;
CREATE INDEX copilot_drafts_queue_idx ON copilot_drafts (created_at)
    WHERE status IN ('queued', 'in_flight');

ALTER TABLE copilot_drafts
    DROP COLUMN IF EXISTS batch_id,
    DROP COLUMN IF EXISTS grounding,
    DROP COLUMN IF EXISTS source;
