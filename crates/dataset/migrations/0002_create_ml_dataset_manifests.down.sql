-- Revert 0002_create_ml_dataset_manifests.
--
-- Drops the run records. The rows in ml_dataset_rows survive, but without their
-- feature names and content hashes they are uninterpretable - so treat this the
-- same way as dropping the rows themselves: recoverable only by re-running the
-- exports.
DROP TABLE IF EXISTS ml_dataset_manifests;
