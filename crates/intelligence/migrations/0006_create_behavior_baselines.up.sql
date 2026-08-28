-- Population baselines for behavior vectors (§20.3): the per-feature median and
-- scaled MAD that make two vectors comparable.
--
-- Small by construction — one row per (chain, embedding_version, schema_hash)
-- refresh, not one per address — so this stays append-only MergeTree and keeps
-- its history: a ranking is only reproducible if the baseline it was computed
-- against can still be read back, and an operator debugging "why did this pair
-- rank differently last week" needs exactly that.
--
-- Robust statistics, not mean and sigma: on-chain feature distributions are
-- heavy-tailed, and the point of a baseline is to make an unusual address
-- visible rather than hide it behind one router's inflated variance.
--
-- NOTE: no literal question mark may appear anywhere in this file (even in a
-- comment) - the clickhouse client parses each one as a bind placeholder.
CREATE TABLE behavior_baselines
(
    chain             UInt64,
    embedding_version LowCardinality(String),
    -- The schema the sample was drawn under. A baseline whose hash does not
    -- match the vector being standardized is a refused comparison, never a
    -- plausible-looking distance in the wrong units.
    schema_hash       LowCardinality(String),
    -- Per-feature median, in schema order.
    centre            Array(Float32),
    -- Per-feature MAD scaled by 1.4826, in schema order.
    spread            Array(Float32),
    -- How many vectors went into it. A thin sample is refused rather than
    -- ranked against noise.
    sample_count      UInt64,
    computed_at       DateTime64(3, 'UTC'),
    appended_at       DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC')
)
ENGINE = MergeTree
ORDER BY (chain, embedding_version, schema_hash, computed_at)
