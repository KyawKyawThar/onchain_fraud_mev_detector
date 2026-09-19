-- Reverse of 0006: drop the analyst-feedback ledger. The verdicts themselves
-- survive in the event store as `AlertFeedbackRecorded`, so this table can be
-- rebuilt by replaying them (`simulation-projection rebuild`).
DROP TABLE IF EXISTS incident_feedback;
