-- Reverse of the feedback outbox. The verdicts themselves are not here — a
-- published row's event lives in the event store — so dropping this table
-- loses only what had not yet been announced.
DROP TABLE IF EXISTS feedback_outbox;
ALTER TABLE rule_outbox DROP COLUMN IF EXISTS claimed_until;
ALTER TABLE rule_outbox DROP COLUMN IF EXISTS idempotency_key;
