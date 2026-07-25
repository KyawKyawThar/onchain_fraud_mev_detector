-- Wallet MEV-exposure business-key columns (§11) — mirrors event-store's
-- `0002_business_key_columns` denormalization: the victim wallet an
-- `IncidentCreated` named, and their USD-valued loss, so the §11
-- `/v1/wallet/{addr}/mev-exposure` read path can prune to one wallet's rows via a
-- bloom-filter index instead of scanning every incident.
--
-- NULL for a snapshot row from a scenario that named no victim (e.g. Honeypot's
-- synthetic prober) or for any row folded before `IncidentCreated` was seen
-- (SimulationCompleted/SimulationRequested snapshots). Only the
-- `event_type = 'IncidentCreated'` row is the canonical one-per-confirmed-
-- incident snapshot the exposure query reads (see `WalletExposureStore`) — a
-- later `IncidentRetracted`/`IncidentFinalized` row also carries the address
-- (the fold never clears it once set) but is not queried by it.
--
-- One statement per file, comma-separated actions (the migrate.rs convention).
ALTER TABLE incident_analytics
    ADD COLUMN victim_address Nullable(String),
    ADD COLUMN victim_loss_usd Nullable(Float64),
    ADD INDEX idx_victim_address victim_address TYPE bloom_filter GRANULARITY 1;
