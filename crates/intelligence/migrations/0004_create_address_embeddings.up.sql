-- Per-address behavior vectors (§20.3, §14): the embedding job's output.
--
-- **ReplacingMergeTree, not the append-only MergeTree its neighbours use** —
-- a deliberate divergence, because the write semantics differ. `block_production`
-- is append-only because a record legitimately *evolves*: incidents fold in, a
-- retraction subtracts, a reorg reverts, and every snapshot is part of the
-- story. A recomputed behavior vector instead **fully supersedes** its
-- predecessor, and nothing reads the history (similarity search and the
-- clustering signal both want latest-only). Keeping every hourly recomputation
-- of every address forever would grow the table as address-space x time rather
-- than address-space, for data no consumer reads.
--
-- So: one logical row per (chain, address, embedding_version), collapsed on
-- merge by computed_at. Reads still take the latest explicitly (ORDER BY
-- computed_at DESC LIMIT 1, or FINAL) rather than assuming a merge has already
-- happened, since ReplacingMergeTree deduplicates eventually, not immediately.
--
-- The version columns are part of the identity, not decoration: vectors from
-- two different embedding_versions are not comparable, and neither are two
-- vectors whose schema_hash differs under the same version name (which is what
-- an accidental edit to a frozen schema would look like). Both are in the
-- sorting key so the version registry's shadow-rollout — v1 and v2 stored side
-- by side for the same address — is the schema's normal state, not a special
-- case.
--
-- Sprint 19 t2 adds the vector similarity index over `vector` on top of this
-- table; the column type (Array(Float32), fixed length per version) is chosen
-- so that index can be added by ALTER without rewriting the schema.
--
-- NOTE: no literal question mark may appear anywhere in this file (even in a
-- comment) - the clickhouse client parses each one as a bind placeholder.
CREATE TABLE address_embeddings
(
    chain                  UInt64,
    -- Lowercase 0x-hex address (the shared `address_key` rendering).
    address                String,
    -- The schema/model version that produced `vector` (e.g. 'behavior-v1').
    embedding_version      LowCardinality(String),
    -- Hex SHA-256 of the frozen feature schema behind embedding_version.
    schema_hash            LowCardinality(String),
    -- The address's resolved entity at compute time; '' when unclustered.
    entity_id              String,
    -- The scaled feature values, in schema order. Fixed length per version.
    vector                 Array(Float32),
    -- The bounded explainability view (JSON array of name/value/share objects)
    -- carried alongside the vector so an investigation surface can say *why*
    -- two addresses look alike without re-deriving it from the raw values.
    top_factors            String,
    -- 1 when the address's observation history hit the read cap, so `vector`
    -- describes a recent window rather than its whole life (§8.2 hub rule).
    -- A fidelity flag, marked rather than assumed.
    observations_truncated UInt8,
    -- The `as_of` instant the vector was computed for (event time, never the
    -- wall clock of the writer) — the version column ReplacingMergeTree keeps
    -- the maximum of, and the key latest-per-address reads order by.
    computed_at            DateTime64(3, 'UTC'),
    appended_at            DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(computed_at)
ORDER BY (chain, embedding_version, address)
