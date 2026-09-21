-- Sanctions lists as versioned snapshots, with a freshness SLA (§8.5,
-- readiness Epic E).
--
-- `SanctionHit` is a hard alert and `/screen` hard-blocks on a match, so the
-- live `sanctions` rows are compliance data. Until now they were written by an
-- upsert-only import: nothing recorded when a list was last confirmed, nothing
-- could delist, a bad file's extra addresses became permanent designations,
-- and nobody could say which version of a list a past decision was screened
-- against. These tables fix all four:
--
--   fetch ─► sanctions_list_snapshots (+ _entries)   staged, content-addressed
--              │ checks (empty / shrink / growth / sentinels)
--              ▼
--            promote: ONE transaction
--              · make `sanctions` rows for the list equal the snapshot
--              · append sanctions_list_promotions (the diff it applied)
--              · advance sanctions_list_syncs (the freshness ledger)
--              · queue SanctionsListUpdated + SanctionHit in sanctions_outbox
--
-- The snapshot and promotion tables are append-only: they are the
-- point-in-time provenance a screening decision cites by digest, so they fall
-- under the five-year regulatory retention decision (engineering conventions
-- §18) and nothing here purges them. They are small: a snapshot is written
-- only when a list's content changes (content-addressed, so a re-fetch of the
-- same content is one row update, not a copy).

-- One row per list: its current version and when that was last confirmed.
--
-- `synced_at` is the *fetch* time of the last sync that confirmed or promoted
-- the current version, taken from this database's clock. A sync that finds
-- the list unchanged still advances it: freshness means "checked against the
-- source", not "the source changed". `content_changed_at` is when the current
-- version was promoted. `failed_at`/`failure_reason` record the most recent
-- failed attempt and are kept after a later success; "the latest attempt
-- failed" is `failed_at > synced_at`. `http_*` are the cache validators of the
-- fetch that confirmed the current version, replayed as a conditional GET.
CREATE TABLE sanctions_list_syncs (
    list_name          TEXT PRIMARY KEY,
    synced_at          TIMESTAMPTZ,
    entries            BIGINT CHECK (entries >= 0),
    content_digest     TEXT,
    content_changed_at TIMESTAMPTZ,
    source             TEXT,
    http_etag          TEXT,
    http_last_modified TEXT,
    failed_at          TIMESTAMPTZ,
    failure_reason     TEXT
);

-- A fetched version of a list, keyed by its content digest.
CREATE TABLE sanctions_list_snapshots (
    list_name        TEXT        NOT NULL,
    digest           TEXT        NOT NULL,
    entries          BIGINT      NOT NULL CHECK (entries >= 0),
    source           TEXT        NOT NULL,
    first_fetched_at TIMESTAMPTZ NOT NULL,
    -- Advanced on every re-fetch of the same content: an operator promoting a
    -- refused snapshot vouches for it as of this instant, not its first fetch.
    last_fetched_at  TIMESTAMPTZ NOT NULL,
    status           TEXT        NOT NULL CHECK (status IN ('staged', 'refused', 'promoted')),
    refusal          TEXT,
    PRIMARY KEY (list_name, digest)
);

CREATE TABLE sanctions_list_snapshot_entries (
    list_name TEXT NOT NULL,
    digest    TEXT NOT NULL,
    address   TEXT NOT NULL,
    entry     TEXT NOT NULL,
    PRIMARY KEY (list_name, digest, address),
    FOREIGN KEY (list_name, digest) REFERENCES sanctions_list_snapshots (list_name, digest)
);

-- "Which versions of which lists contained this address" — the point-in-time
-- question a compliance review asks.
CREATE INDEX sanctions_list_snapshot_entries_address_idx
    ON sanctions_list_snapshot_entries (address);

-- Every promotion, with the diff it applied to the live rows. A version can be
-- promoted more than once (A → B → back to A), hence its own id.
--
-- `effects_applied_at` tracks the post-commit side effects Postgres cannot
-- share a transaction with (hot-cache evictions) and the label writes that
-- follow them; NULL means the next sync resumes them.
CREATE TABLE sanctions_list_promotions (
    promotion_id       UUID        PRIMARY KEY,
    list_name          TEXT        NOT NULL,
    digest             TEXT        NOT NULL,
    previous_digest    TEXT,
    entries            BIGINT      NOT NULL CHECK (entries >= 0),
    added              TEXT[]      NOT NULL,
    changed            TEXT[]      NOT NULL,
    removed            TEXT[]      NOT NULL,
    promoted_by        TEXT        NOT NULL,
    promoted_at        TIMESTAMPTZ NOT NULL,
    effects_applied_at TIMESTAMPTZ,
    FOREIGN KEY (list_name, digest) REFERENCES sanctions_list_snapshots (list_name, digest)
);

-- "What was current at time T": the latest promotion at or before T.
CREATE INDEX sanctions_list_promotions_list_at_idx
    ON sanctions_list_promotions (list_name, promoted_at DESC);
CREATE INDEX sanctions_list_promotions_pending_idx
    ON sanctions_list_promotions (list_name) WHERE effects_applied_at IS NULL;

-- The announcements a promotion queues, published by the shared `outbox`
-- flusher (same shape as `feedback_outbox`).
CREATE TABLE sanctions_outbox (
    id              BIGSERIAL   PRIMARY KEY,
    envelope        JSONB       NOT NULL,
    idempotency_key TEXT UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    claimed_until   TIMESTAMPTZ,
    published_at    TIMESTAMPTZ
);

CREATE INDEX sanctions_outbox_pending_idx ON sanctions_outbox (id) WHERE published_at IS NULL;

-- A promotion reads and rewrites one list's live rows; the primary key leads
-- with the address, so without this that is a scan of every list.
CREATE INDEX sanctions_list_name_idx ON sanctions (list_name);
