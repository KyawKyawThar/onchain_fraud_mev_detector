-- Revert to no retention decision at all. Non-destructive in itself (removing
-- a TTL deletes nothing), and the only reason it exists is that every
-- migration in this set has a down: rolling this back leaves the store
-- unbounded, which is the state engineering conventions §18 was written to end.
ALTER TABLE events REMOVE TTL;
