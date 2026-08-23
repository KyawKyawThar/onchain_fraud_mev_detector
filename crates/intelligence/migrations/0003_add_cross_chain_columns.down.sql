-- Reverse of 0003_add_cross_chain_columns: drop the cross-chain contribution columns.
ALTER TABLE block_production
    DROP COLUMN cross_chain_bridge_count,
    DROP COLUMN cross_chain_arb_count,
    DROP COLUMN cross_chain_provisional_usd
