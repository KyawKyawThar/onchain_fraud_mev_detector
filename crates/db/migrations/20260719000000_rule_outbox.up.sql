-- Transactional outbox for the rule-definition store (§20, production
-- hardening): POST /v1/rules must make its Postgres write and its
-- `RuleCreated` announcement atomic. Publishing straight to Kafka after the
-- INSERT leaves a crash window where the rule exists but the engine never
-- hears about it until the periodic backstop refresh; writing the announcement
-- into this table IN THE SAME TRANSACTION as the rule closes that window. The
-- rule-engine binary's outbox flusher then publishes each pending row
-- (at-least-once — the consumer side is already idempotent) and stamps
-- `published_at`.
--
-- Owned by the rule-engine service like `rules` itself (§14: no shared
-- tables); rows are audit-kept after publish (`published_at IS NOT NULL`),
-- so the flusher's scan uses the partial index below and stays O(pending).
CREATE TABLE rule_outbox (
    -- Monotonic id = publish order (the flusher drains oldest-first).
    id           BIGSERIAL   PRIMARY KEY,
    -- The full EventEnvelope, wire form — exactly the bytes to publish, so
    -- the flusher never rebuilds (and never diverges from) the announcement
    -- the request handler composed.
    envelope     JSONB       NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL,
    published_at TIMESTAMPTZ
);

-- The flusher's working set: pending rows only, in id order.
CREATE INDEX rule_outbox_pending_idx ON rule_outbox (id) WHERE published_at IS NULL;
