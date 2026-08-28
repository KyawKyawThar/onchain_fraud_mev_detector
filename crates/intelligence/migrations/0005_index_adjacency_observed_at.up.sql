-- A minmax skip index on `address_adjacency.observed_at` (§20.3): the embedding
-- job's scheduled sweep asks "which addresses were observed since T", and the
-- table's ORDER BY is (chain, src, dst, kind, block_number) — nothing in it
-- prunes by time, so without this the sweep is a full scan every tick.
--
-- Observations arrive broadly in time order, so per-granule minmax bounds are
-- tight and the skip is effective. This only affects parts written from here
-- on. Applying it to existing data is an operator step, deliberately not part
-- of the migration: MATERIALIZE INDEX rewrites every existing part, which on a
-- production-sized graph is a maintenance window, not a boot-time action.
--
--   ALTER TABLE address_adjacency MATERIALIZE INDEX idx_adjacency_observed_at
--
-- NOTE: no literal question mark may appear anywhere in this file (even in a
-- comment) — the clickhouse client parses each one as a bind placeholder.
ALTER TABLE address_adjacency
    ADD INDEX IF NOT EXISTS idx_adjacency_observed_at observed_at TYPE minmax GRANULARITY 4
