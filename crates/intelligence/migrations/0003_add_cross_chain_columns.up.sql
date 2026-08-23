-- Cross-chain finding contribution columns (§24, Sprint 17 t4): additive to
-- the block_production snapshot so the builder/relay leaderboard surfaces
-- BridgeMevDetected/CrossChainMevDetected findings alongside confirmed
-- incidents. Kept separate from mev_extracted_usd on purpose: a cross-chain
-- finding is never simulation-confirmed and stays provisional forever, so
-- folding it into the confirmed total would misreport a builder's confirmed
-- MEV with an estimate the platform never upgrades to confirmed.
--
-- NOTE: no literal question mark may appear anywhere in this file (even in a
-- comment) - the clickhouse client parses each one as a bind placeholder.
ALTER TABLE block_production
    ADD COLUMN cross_chain_bridge_count UInt32 DEFAULT 0,
    ADD COLUMN cross_chain_arb_count UInt32 DEFAULT 0,
    ADD COLUMN cross_chain_provisional_usd Float64 DEFAULT 0
