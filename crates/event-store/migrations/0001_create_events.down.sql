-- Revert 0001_create_events.
--
-- This is destructive: the event store is the system of record (§4), so a
-- `down` in any real environment throws away the audit log. It exists for local
-- iteration and for symmetry with the forward migration; guard production use
-- behind the environment's migration approval, same as the sqlx/Postgres side.
DROP TABLE IF EXISTS events;
