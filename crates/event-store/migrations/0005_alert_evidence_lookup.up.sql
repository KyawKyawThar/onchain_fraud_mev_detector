-- Durable `alert_id → DetectorTriggered` lookup for simulation fork resolution.
--
-- The relationship is stamped at emission, indexed here, and remains optional
-- for historical/shadow triggers that never raised a provisional alert.
ALTER TABLE events
    ADD COLUMN alert_id Nullable(UUID),
    ADD INDEX idx_alert_id alert_id TYPE bloom_filter GRANULARITY 1;
