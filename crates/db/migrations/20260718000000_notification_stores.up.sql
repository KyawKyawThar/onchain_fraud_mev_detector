-- Notification service's Postgres tables (§11, §14, Sprint 12 t4): alert
-- subscriptions, delivery receipts (the dedup + retry ledger), and the
-- incident<->alert correlation index. Owned solely by the notification
-- service (§14: no shared tables, no cross-service joins).

-- One customer's alert subscription: a set of delivery channels plus the
-- filter that gates severity-routed delivery. `min_severity`/`kinds`/`chains`
-- are all nullable — NULL means "no gate on this axis", the same
-- Option-bypass semantics the consumer's routing logic reads directly (a
-- `RuleAlertCreated`/`SanctionHit` notice with no severity/kind of its own
-- also bypasses the corresponding gate; see `notice.rs`).
CREATE TABLE subscribers (
    subscriber_id UUID        PRIMARY KEY,
    owner         UUID        NOT NULL,
    -- Vec<Channel> (webhook/email/slack/pagerduty targets), JSONB document —
    -- a delivery target set, not a join target, same stance as the rule
    -- store's `actions` column.
    channels      JSONB       NOT NULL,
    -- The serde form of `Option<Severity>` (a JSON string, e.g. `"high"`), or
    -- SQL NULL for "no severity floor" — same JSONB-document stance as the
    -- rule store's `conditions` column: parsed at the store's boundary
    -- (`serde_json::from_value`), never hand-parsed SQL text.
    min_severity  JSONB,
    -- Vec<AlertKind>'s serde form, or NULL for "every kind".
    kinds         JSONB,
    -- Vec<Chain>'s serde form (a JSON array of chain ids), or NULL for
    -- "every chain".
    chains        JSONB,
    enabled       BOOLEAN     NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL,
    -- Soft delete, same stance as `rules.deleted_at`: kept for audit,
    -- subscriber_ids are never reused.
    deleted_at    TIMESTAMPTZ
);

-- The owner-scoped fan-out path (a `RuleAlertCreated`/`SanctionHit`-style
-- notice with `owner = Some(_)` only reaches that customer's subscribers).
CREATE INDEX subscribers_owner_idx ON subscribers (owner);

-- The platform-wide fan-out path (detection/simulation events have no
-- customer in scope, §11 — every enabled subscriber is a candidate, filtered
-- by severity/kind/chain downstream).
CREATE INDEX subscribers_enabled_idx ON subscribers (enabled)
    WHERE enabled AND deleted_at IS NULL;

-- The delivery ledger: one row per (subscriber, dedup_key, lifecycle stage,
-- channel) — the dedup + retry + receipt contract in one table.
--
-- `dedup_key` is the alert_id/incident_id lineage a notice carries (see
-- `notice.rs`); `stage` is provisional/confirmed/retracted/standalone.
-- `UNIQUE (subscriber_id, dedup_key, stage, channel)` is what makes a
-- redelivered Kafka record idempotent: `INSERT ... ON CONFLICT DO NOTHING`
-- claims the row once, and the store re-reads the existing row's `status` on
-- conflict — `delivered` means true dedup (skip), anything else (a crash
-- mid-attempt left it `pending`/`failed`) means retry the same row rather
-- than silently dropping it.
CREATE TABLE notice_deliveries (
    id            UUID        PRIMARY KEY,
    subscriber_id UUID        NOT NULL REFERENCES subscribers (subscriber_id),
    dedup_key     TEXT        NOT NULL,
    stage         TEXT        NOT NULL,
    channel       TEXT        NOT NULL,
    status        TEXT        NOT NULL,
    attempts      INTEGER     NOT NULL DEFAULT 0,
    last_error    TEXT,
    created_at    TIMESTAMPTZ NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL,
    delivered_at  TIMESTAMPTZ,
    -- Set when the paired `IncidentFinalized` lands — a ledger-only mark (no
    -- new outbound send; see `notice.rs`'s module docs).
    finalized_at  TIMESTAMPTZ
);

CREATE UNIQUE INDEX notice_deliveries_dedup_idx
    ON notice_deliveries (subscriber_id, dedup_key, stage, channel);

-- The retraction/finalization re-targeting path (`delivered_targets_for`):
-- who already received a delivered notice for this dedup_key, across every
-- stage — retraction must reach exactly those recipients, not whoever
-- currently matches the (possibly since-changed) filter.
CREATE INDEX notice_deliveries_dedup_key_idx ON notice_deliveries (dedup_key)
    WHERE status = 'delivered';

-- The durable half of the incident<->alert correlation: `IncidentCreated`
-- carries both ids, but `IncidentRetracted`/`IncidentFinalized` carry only
-- `incident_id` and are keyed on a *different* Kafka partition key
-- (`PartitionKey::Incident` vs `PartitionKey::Alert`), so they can arrive out
-- of order relative to the confirm. This table is the primary lookup; a
-- small in-memory bounded buffer (mirroring `rule_engine::consumer`'s
-- `BoundedFifoMap`) covers a retraction that outruns its confirm within one
-- process lifetime.
CREATE TABLE incident_alerts (
    incident_id UUID        PRIMARY KEY,
    alert_id    UUID        NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL
);
