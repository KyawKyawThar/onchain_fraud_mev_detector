-- Reverse of 0004: remove the staged replacement. After a swap the name no
-- longer exists (the table is `events`), so this is a no-op then, and a swap
-- is reversed by the runbook, not by a migration.
DROP TABLE IF EXISTS events__next
