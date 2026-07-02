-- Reverse of 0001_create_incident_analytics: drop the analytics projection table.
-- Destructive — this is the append-only analytics firehose.
DROP TABLE IF EXISTS incident_analytics;
