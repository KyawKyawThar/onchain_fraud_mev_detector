DROP INDEX incidents_victim_address_idx;
ALTER TABLE incidents
    DROP COLUMN victim_address,
    DROP COLUMN victim_loss_usd;
