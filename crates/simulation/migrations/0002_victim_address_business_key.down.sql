-- Revert 0002_victim_address_business_key. Non-destructive to the underlying
-- events: these are read accelerators only, rebuildable from the result-path
-- events if re-added.
ALTER TABLE incident_analytics
    DROP INDEX IF EXISTS idx_victim_address,
    DROP COLUMN IF EXISTS victim_address,
    DROP COLUMN IF EXISTS victim_loss_usd;
