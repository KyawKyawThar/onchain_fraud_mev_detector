-- Revert 0001_create_ml_dataset_rows.
--
-- Destructive but recoverable, unlike the event store's own down migration:
-- every row here is *derived*, so the remedy for dropping this table is to
-- re-run the exports. That is exactly the property the whole binary is built
-- around - a dataset is defined by its spec, not by these bytes.
DROP TABLE IF EXISTS ml_dataset_rows;
