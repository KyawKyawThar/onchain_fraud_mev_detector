-- Export manifests: one row per export run (§20.1, Sprint 18 t2).
--
-- This is where a feature matrix stops being an anonymous pile of floats. It
-- carries the spec that produced the rows, the feature names their positions
-- mean, the label rule that assigned their labels, and the content hash over
-- the rows themselves.
--
-- That last column is the reproducibility check, and it is why this table is a
-- plain MergeTree rather than a Replacing one: every run is kept, so
--
--   SELECT dataset_id, uniqExact(content_hash) FROM ml_dataset_manifests
--   GROUP BY dataset_id HAVING uniqExact(content_hash) > 1
--
-- names any dataset that two runs disagreed about - which, given a deterministic
-- replay, a deterministic extractor and an immutable event store, should be the
-- empty set. Collapsing re-runs into one row would throw away exactly the
-- evidence that check needs.
--
-- One statement per migration file, and no literal question marks anywhere
-- (the clickhouse client would parse one as a bind placeholder).
CREATE TABLE IF NOT EXISTS ml_dataset_manifests
(
    -- DatasetSpec::dataset_id - joins to ml_dataset_rows.dataset_id.
    dataset_id        String,
    -- SHA-256 over every row's fields in row order, floats hashed by bit
    -- pattern. Equal hashes mean equal datasets.
    content_hash      String,
    chain             UInt64,
    -- The half-open replay window the dataset was materialised from.
    window_from       DateTime64(3, 'UTC'),
    window_to         DateTime64(3, 'UTC'),
    feature_version   UInt32,
    granularity       LowCardinality(String),
    -- FeatureSchema::content_hash - what a serving-time skew check compares
    -- against (§20.5).
    schema_hash       String,
    -- Feature names in vector order: the key to reading ml_dataset_rows.features.
    feature_names     Array(String),
    label_rule        LowCardinality(String),
    min_fidelity      LowCardinality(String),
    include_ambiguous UInt8,
    rows_written      UInt64,
    -- The whole manifest verbatim: every count and histogram, without a column
    -- per bucket. The typed columns above are the ones worth indexing; this is
    -- the rest, so a read is the write (the event-store payload discipline).
    manifest_json     String CODEC(ZSTD(3)),
    generated_at      DateTime64(3, 'UTC'),
    tool_version      String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(window_from)
-- Orders for the two questions asked of this table: "what does dataset X look
-- like" and "did two runs of X agree".
ORDER BY (dataset_id, generated_at);
