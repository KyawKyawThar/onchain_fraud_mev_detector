-- The full address graph (§8.2, §14): one immutable row per observed relation
-- (A funded B, A deployed B, ...), the store hop queries walk. Append-only —
-- observations are facts; a contradicting one is a later row, never an UPDATE —
-- so MergeTree fits exactly (the same rationale as the event store, §14).
--
-- NOTE: no literal question mark may appear anywhere in this file (even in a
-- comment) — the clickhouse client parses each one as a bind placeholder.
--
-- The primary ORDER BY serves the outbound read (filter on chain + src);
-- the `by_dst` projection materializes the same rows dst-first so the inbound
-- half of a neighborhood read is an index scan too, not a full sweep. Both
-- reads are always LIMIT-capped by the caller — the §8.2 hub-node degree cap;
-- an uncapped walk through a CEX hot wallet is the query this schema exists to
-- make refusable.
CREATE TABLE address_adjacency
(
    chain        UInt64,
    -- Lowercase 0x-hex addresses (the shared `address_key` rendering).
    src          String,
    dst          String,
    -- EdgeKind wire string: funded | deployed | profit_receiver | interacted.
    kind         LowCardinality(String),
    -- The tx hash / evidence ref that witnessed the relation (§8.2 — every
    -- cluster edge is justified).
    evidence     String,
    block_number UInt64,
    observed_at  DateTime64(3, 'UTC'),
    ingested_at  DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC'),
    PROJECTION by_dst
    (
        SELECT * ORDER BY (chain, dst, src)
    )
)
ENGINE = MergeTree
ORDER BY (chain, src, dst, kind, block_number)
