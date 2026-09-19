-- The §19 feedback loop's durable front door (readiness Epic E), plus the
-- columns that let `rule_outbox` and this table share one flusher
-- (`crates/outbox`).
--
-- Why an outbox and not a queue in memory: a verdict is a *sample* in an
-- accuracy measurement that has very few, and the losses are non-random —
-- an in-process queue drops exactly when the platform is unhealthy, which is
-- when analysts are most likely to be marking incidents noise. The bias runs
-- toward flattering the platform. So the request path makes one fast INSERT
-- and answers 202, and the flusher owns the broker's availability instead of
-- the customer doing so.
--
-- `idempotency_key` is what makes a retried submission a no-op rather than a
-- second event: the API service derives it from (incident, customer, verdict)
-- plus the caller's own `Idempotency-Key` when one is supplied.
--
-- `claimed_until` is the lease. The API service runs behind an HPA, so
-- without it every replica would drain every pending row and publish it once
-- per replica.
CREATE TABLE feedback_outbox (
    -- Monotonic id = publish order (the flusher drains oldest-first).
    id              BIGSERIAL   PRIMARY KEY,
    -- The full EventEnvelope, wire form — exactly the bytes to publish, so the
    -- flusher never rebuilds (and never diverges from) what the handler wrote.
    envelope        JSONB       NOT NULL,
    -- NULL means "queue unconditionally"; a duplicate key is dropped by the
    -- INSERT's ON CONFLICT rather than becoming a second verdict.
    idempotency_key TEXT UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Held by whichever flusher claimed this row, until it expires.
    claimed_until   TIMESTAMPTZ,
    -- Stamped after a successful publish. Rows are kept, not deleted: what did
    -- we announce, and when.
    published_at    TIMESTAMPTZ
);

-- The flusher's working set: pending rows only, in id order.
CREATE INDEX feedback_outbox_pending_idx ON feedback_outbox (id) WHERE published_at IS NULL;

-- Bring `rule_outbox` up to the same shape so one flusher serves both. Both
-- columns are nullable with no default, so existing rows and the running
-- rule-engine are unaffected: a NULL `claimed_until` reads as "unclaimed",
-- which is exactly what every pending row is today.
ALTER TABLE rule_outbox ADD COLUMN idempotency_key TEXT UNIQUE;
ALTER TABLE rule_outbox ADD COLUMN claimed_until TIMESTAMPTZ;
