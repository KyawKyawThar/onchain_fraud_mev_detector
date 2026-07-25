-- Wallet MEV-exposure projection: name the external wallet an `IncidentCreated`
-- named as its victim, and their USD-valued loss, so the confirmed-incident read
-- model can answer "what has this address lost to MEV?" (§11). NULL for a scenario
-- that named no victim (e.g. Honeypot's synthetic prober) or a pre-exposure incident
-- folded before this column existed.
ALTER TABLE incidents
    ADD COLUMN victim_address TEXT,
    ADD COLUMN victim_loss_usd DOUBLE PRECISION;

-- Look up a wallet's incidents (the §11 `/v1/wallet/{addr}/mev-exposure` read path).
CREATE INDEX incidents_victim_address_idx ON incidents (victim_address);
