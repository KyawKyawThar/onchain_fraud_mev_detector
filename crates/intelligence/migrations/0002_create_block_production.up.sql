-- Block-production records (§10, §14): who built and relayed each canonical
-- block, and how much confirmed MEV it carried. One immutable row per *fold* of
-- the block-production consumer — the record starts as header/relay facts when
-- the block canonicalizes, and each later confirmed incident (or retraction, or
-- reorg) appends a fresh snapshot rather than updating in place, exactly the
-- append-only stance of `incident_analytics` (§14). A reader wanting current
-- state takes the latest snapshot per (chain, block_hash) via argMax on
-- snapshot_at; the Sprint 11 t2 builder leaderboard aggregates over exactly
-- that read.
--
-- NOTE: no literal question mark may appear anywhere in this file (even in a
-- comment) — the clickhouse client parses each one as a bind placeholder.
CREATE TABLE block_production
(
    chain                   UInt64,
    block_number            UInt64,
    -- Lowercase 0x-hex block hash — the reorg-safe identity (a replaced block
    -- at the same height is a different row set).
    block_hash              String,
    -- The header's feeRecipient (coinbase), lowercase 0x-hex — the builder's
    -- payout address, the primary attribution signal (§10).
    fee_recipient           String,
    -- The header's extraData graffiti, UTF-8 (lossy, control chars stripped).
    -- Raw evidence — builder naming comes from intelligence labels, never from
    -- hardcoding graffiti (§10).
    extra_data              String,
    -- BLS pubkey of the builder that won the MEV-Boost auction, from the relay
    -- data API bid trace; '' when no configured relay delivered this block.
    builder_pubkey          String,
    -- The builder's display name as intelligence knows it: the active
    -- BuilderAddress label on fee_recipient at fold time ('' when unlabeled).
    builder_label           LowCardinality(String),
    -- The configured relay (by name) whose data API reported delivering this
    -- block's payload; '' when none did (locally built, or an unconfigured relay).
    relay                   LowCardinality(String),
    -- Confirmed MEV attributed to this block so far: summed profit of folded
    -- IncidentCreated events (USD, from counterfactual simulation §7).
    mev_extracted_usd       Float64,
    sandwich_count          UInt32,
    arb_count               UInt32,
    -- Confirmed incidents of every other kind (liquidation, rugpull, ...).
    other_mev_count         UInt32,
    -- Direct value transfers to the fee recipient inside its own block — the
    -- classic MEV tip channel (§10). JSON array of
    -- {from, tx, value_wei} objects; the count is denormalized for cheap scans.
    coinbase_transfer_count UInt32,
    coinbase_transfers      String,
    -- 1 when the block was reverted by a reorg after its record opened; the
    -- latest snapshot wins, so a reader excludes reverted blocks by flag.
    reverted                UInt8,
    -- Event-time of the fold that produced this snapshot (the consumed event's
    -- occurred_at) — the argMax key for latest-per-block reads.
    snapshot_at             DateTime64(3, 'UTC'),
    appended_at             DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC')
)
ENGINE = MergeTree
ORDER BY (chain, block_number, block_hash, snapshot_at)
