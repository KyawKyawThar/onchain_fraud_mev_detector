-- Reverse of sanctions list versioning. The live designations in `sanctions`
-- are untouched. What is lost is the version history (which list version a
-- past screening decision cited) and any unpublished announcements, so do not
-- run this against production without an export of the history tables.
DROP INDEX IF EXISTS sanctions_list_name_idx;
DROP TABLE IF EXISTS sanctions_outbox;
DROP TABLE IF EXISTS sanctions_list_promotions;
DROP TABLE IF EXISTS sanctions_list_snapshot_entries;
DROP TABLE IF EXISTS sanctions_list_snapshots;
DROP TABLE IF EXISTS sanctions_list_syncs;
