-- Materialized top-k behavioral neighbours (§20.3, Sprint 19 t2): the read
-- model that turns a similarity search from "ANN scan plus a bounded re-rank"
-- into a single key lookup.
--
-- **This table is a cache, and it is allowed to be wrong only by being empty.**
-- Every row carries the `baseline_fingerprint` that produced its ranking, and
-- a read that does not match the *current* baseline discards the row and falls
-- through to the live path. That is the whole design: §20.3's contract is that
-- a re-derived baseline changes rankings **without rewriting history**, and a
-- cache with no such stamp would quietly repeal it — serving yesterday's
-- ordering forever while looking perfectly healthy. Invalidation is therefore
-- not a delete sweep but an equality check that fails.
--
-- Consequently a baseline re-derivation invalidates every row for that
-- (chain, embedding_version) at once. That is intended and cheap: entries are
-- repopulated lazily by the reads that actually happen, and investigation
-- traffic is heavily skewed toward a small set of addresses, so the working
-- set refills quickly without a backfill job.
--
-- `neighbor_*` are parallel arrays rather than a Nested type: the ranking is
-- read and written whole, never queried into, so the simplest shape that
-- round-trips through the `clickhouse` client's RowBinary is the right one.
-- Their lengths are equal by construction and checked on decode.
--
-- ReplacingMergeTree on (chain, embedding_version, address), like
-- `address_embeddings`: a recomputed ranking fully supersedes its predecessor
-- and nothing reads the history. Reads take the latest explicitly rather than
-- assuming a merge has happened.
--
-- NOTE: no literal question mark may appear anywhere in this file (even in a
-- comment) - the clickhouse client parses each one as a bind placeholder.
CREATE TABLE address_neighbors
(
    chain                  UInt64,
    -- The subject address, lowercase 0x-hex.
    address                String,
    embedding_version      LowCardinality(String),
    -- Hex SHA-256 over the baseline's centre/spread/version/sample count. A
    -- read whose current baseline fingerprints differently ignores this row.
    baseline_fingerprint   LowCardinality(String),
    -- The ranked neighbours, most similar first. Parallel arrays, equal length.
    neighbor_address       Array(String),
    neighbor_similarity    Array(Float32),
    -- '' where the neighbour belonged to no entity, the same flatten-an-Option
    -- convention `address_embeddings` uses.
    neighbor_entity_id     Array(String),
    -- The per-neighbour explanation, one JSON array of factor objects each.
    neighbor_factors       Array(String),
    -- Carried through from the live search so a cached answer reports the same
    -- fidelity the uncached one would.
    approximate            UInt8,
    -- When this ranking was computed. Both the ReplacingMergeTree version
    -- column and what a TTL-style freshness bound is measured against.
    computed_at            DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(computed_at)
ORDER BY (chain, embedding_version, address)
