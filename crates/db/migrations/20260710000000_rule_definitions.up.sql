-- Rule engine's Postgres table (§9, §14, Sprint 9 t1): customer-defined rule
-- definitions — the mutable system of record the rule compiler (t2) loads and
-- the POST /v1/rules surface (t4) writes. Owned solely by the rule-engine
-- service (§14: no shared tables, no cross-service joins); temporal *state*
-- lives in Redis (TTL-bounded, t3), never here.
--
-- Customer isolation is structural: `owner` (the billing CustomerId, §13 — the
-- JWT `sub` the API service authenticates) is part of the key of every
-- customer-facing read/write the store exposes, so no query path can return or
-- mutate another customer's rules. Only the engine's internal load path
-- (`enabled_rules`) crosses owners, and it never leaves the service.
CREATE TABLE rules (
    -- Stable id: the idempotency key (redelivered create → ON CONFLICT no-op)
    -- and what RuleCreated/RuleTriggered/RuleAlertCreated events reference.
    rule_id    UUID        PRIMARY KEY,
    owner      UUID        NOT NULL,
    name       TEXT        NOT NULL,
    -- Disabled rules stay stored (and editable) but are never evaluated.
    enabled    BOOLEAN     NOT NULL,
    -- The §9 document, in its exact wire form (externally tagged snake_case
    -- enums, exact-string decimal thresholds): what POST /v1/rules carried is
    -- what evaluation loads. JSONB documents, not join targets — the closed
    -- condition vocabulary is enforced by the model's parse boundary, not by
    -- columns-per-condition-type.
    conditions JSONB       NOT NULL,
    -- LogicOp wire string: all | any | not.
    logic      TEXT        NOT NULL,
    -- NULL = non-temporal rule; else the sequence/frequency clause (§9).
    temporal   JSONB,
    actions    JSONB       NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    -- Soft delete: a deleted rule vanishes from every read path but the row is
    -- kept for audit (which definition fired that historical alert?) — same
    -- stance as labels' revoked_at. rule_ids are never reused.
    deleted_at TIMESTAMPTZ
);

-- The customer-facing read path ("my rules"), and the isolation filter every
-- owner-scoped query starts from.
CREATE INDEX rules_owner_idx ON rules (owner);

-- One live rule name per customer: two rules a customer can't tell apart in
-- their alert feed are an authoring error. Scoped to live rows so a deleted
-- rule's name is reusable.
CREATE UNIQUE INDEX rules_owner_name_live_idx ON rules (owner, name)
    WHERE deleted_at IS NULL;

-- The engine's boot/refresh load ("every enabled rule, all customers").
CREATE INDEX rules_enabled_idx ON rules (enabled)
    WHERE enabled AND deleted_at IS NULL;
