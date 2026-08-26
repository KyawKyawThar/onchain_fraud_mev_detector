-- Training rows: one labeled `(features, label)` example per exported finding
-- (§20.1, Sprint 18 t2).
--
-- ReplacingMergeTree, not plain MergeTree: an export is deterministic, so
-- re-running the same spec produces byte-identical rows with identical ORDER BY
-- keys, and background merges converge the duplicates away. That is what makes
-- "re-export the window after a schema fix" a safe operation instead of one
-- that silently doubles a dataset. Merges are eventual, so an exact count still
-- uses count(DISTINCT ...) or FINAL; the engine keeps the table from
-- accumulating re-run noise, it is not the correctness mechanism. Still
-- append-only: this binary never updates or deletes a row.
--
-- Sentinels rather than Nullable for the two optional keys: tx_hash is the
-- empty string for a block-granularity row and alert_id is the nil UUID when no
-- alert was bound. Both are in the ORDER BY key, and ClickHouse's own guidance
-- is against nullable key columns (worse compression, no min/max skip index).
-- No real hash is empty and no minted alert id is all-zero, so neither sentinel
-- can collide.
--
-- Feature *names* are deliberately absent: they live once per export on
-- ml_dataset_manifests, keyed by the same dataset_id, because storing a
-- 24-string array on every row of a million-row dataset buys no query the
-- manifest cannot answer. schema_hash is kept per row so the §20.5
-- serving/training skew check needs nothing but the row.
--
-- One statement per migration file (the shared ch-migrate runner executes each
-- file as a single query), and no literal question marks anywhere in this file
-- (the clickhouse client would parse one as a bind placeholder).
CREATE TABLE IF NOT EXISTS ml_dataset_rows
(
    -- DatasetSpec::dataset_id - the identity of the dataset this row belongs
    -- to. Two datasets can share this table without being confused.
    dataset_id            String,
    -- The DetectorTriggered envelope this row was derived from: the walk-back
    -- point into the event store's audit trail.
    trigger_event_id      UUID,
    chain                 UInt64,
    block_number          UInt64,
    -- 0x-prefixed lowercase hex, matching every other hash column in the system.
    block_hash            String,
    -- The trigger's own occurrence time, NOT the export's. Using the finding's
    -- time is what keeps a time-ordered train/test split reproducible.
    occurred_at           DateTime64(3, 'UTC'),
    detector_id           String,
    detector_version      String,
    detector_config_hash  String,
    -- Empty string for a block-granularity row (see the sentinel note above).
    tx_hash               String,
    -- Nil UUID when no alert was bound (a Shadow detector's trigger).
    alert_id              UUID,
    -- How the finding was tied to its alert: exact / corrected / ambiguous /
    -- conflicted / unbound. Kept so a consumer can re-filter without exporting
    -- again.
    binding               LowCardinality(String),
    -- How faithful the reconstructed DetectionCtx was: header_only /
    -- partial_bundle / full_bundle / enriched.
    fidelity              LowCardinality(String),
    feature_version       UInt32,
    granularity           LowCardinality(String),
    -- FeatureSchema::content_hash for the layout `features` is in.
    schema_hash           String,
    -- Values in schema order. Names are on the manifest row.
    features              Array(Float64),
    -- 1 positive, 0 negative.
    label                 UInt8,
    -- The outcome the label was derived from (confirmed / refuted / retracted),
    -- so a refutation is distinguishable from a retraction without re-joining.
    outcome               LowCardinality(String),
    raw_confidence        Float64,
    -- Simulation's measured figures, metadata beside the label and never a
    -- feature: they are measured after the fact, so a model given them would be
    -- reading its own answer.
    profit                Float64,
    victim_loss           Float64,
    -- Server-side write time; defaulted so inserts never set it, and the
    -- ReplacingMergeTree version column so a re-export supersedes its
    -- predecessor.
    exported_at           DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(exported_at)
-- Monthly partitions on the finding's own time: a dataset is a time window, so
-- window-shaped scans prune whole partitions, and date-grained parts would only
-- multiply them.
PARTITION BY toYYYYMM(occurred_at)
-- Orders for the query shapes that matter: one dataset at a time, sliced by
-- block range or detector. The trailing three columns make the key unique,
-- which is what makes the ReplacingMergeTree dedup precise.
ORDER BY (dataset_id, block_number, detector_id, trigger_event_id, tx_hash);
