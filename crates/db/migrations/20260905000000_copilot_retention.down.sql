DROP INDEX IF EXISTS copilot_drafts_retention_idx;
ALTER TABLE copilot_drafts DROP CONSTRAINT IF EXISTS copilot_drafts_legal_hold_complete;
ALTER TABLE copilot_drafts
    DROP COLUMN IF EXISTS legal_hold_matter,
    DROP COLUMN IF EXISTS legal_hold_placed_at,
    DROP COLUMN IF EXISTS legal_hold_placed_by;
