-- Intelligence service's Postgres tables (§8, §14, Sprint 7 t1): the relational,
-- transactional side of the moat — labels with provenance, versioned entities,
-- attribution records and sanctions lists. All four are owned solely by the
-- intelligence service (§14: no shared tables, no cross-service joins); the hot
-- read path is served by the Redis cache and the graph by ClickHouse adjacency,
-- both fed from these system-of-record rows.
--
-- Addresses are stored as lowercase 0x-hex TEXT, the same rendering the
-- simulation service uses for tx hashes — Postgres has no native 20-byte type
-- and the hex form keeps rows greppable/joinable in ad-hoc ops queries.

-- Wallet labels (§8.1). Append-only in spirit: conflicting labels for the same
-- address COEXIST as separate rows (deliberately no UNIQUE(address, kind) — a
-- manual label overrides a heuristic one at read time by confidence/source, but
-- both are retained for audit). A label leaves the active set by revocation
-- (soft, audited) or `valid_until` expiry, never by DELETE/UPDATE of its facts.
CREATE TABLE labels (
    -- Stable id: the idempotency key (redelivered LabelAdded → ON CONFLICT no-op)
    -- and what LabelUpdated/LabelRevoked events reference.
    label_id          UUID PRIMARY KEY,
    address           TEXT             NOT NULL,
    -- LabelKind wire string: cex_wallet | mev_bot | known_scammer | bridge |
    -- protocol | deployer | mixer_user | sanctioned_entity | scammer_associate |
    -- builder_address (§8.1).
    kind              TEXT             NOT NULL,
    value             TEXT             NOT NULL,
    -- §8.1 provenance axis: 1.0 manual | 0.7 heuristic | 0.4 external feed.
    confidence        DOUBLE PRECISION NOT NULL,
    -- Provenance class: manual | heuristic | external_feed | entity_derived.
    source            TEXT             NOT NULL,
    -- The specific origin within the class (e.g. 'etherscan', 'ofac_sdn',
    -- 'funding-cluster-v1', an operator id) — the audit trail §8.1 demands.
    source_detail     TEXT             NOT NULL,
    created_at        TIMESTAMPTZ      NOT NULL,
    valid_until       TIMESTAMPTZ,
    revoked_at        TIMESTAMPTZ,
    revocation_reason TEXT
);

-- The read path is by address (labels_for, cache fill, screening §11).
CREATE INDEX labels_address_idx ON labels (address);
-- Sanction-kind sweeps and per-kind maintenance jobs (re-scoring a feed).
CREATE INDEX labels_kind_idx ON labels (kind);

-- Entities — wallet clusters (§8.2), versioned. `version` increments on every
-- merge/split so downstream projections (risk scores, rule engine) can detect
-- staleness; an absorbed entity is never deleted — it is marked with the
-- survivor it merged into, so historical attributions stay resolvable.
CREATE TABLE entities (
    entity_id     UUID        PRIMARY KEY,
    version       BIGINT      NOT NULL DEFAULT 1,
    -- 'active' | 'absorbed'. An absorbed entity is a tombstone pointing at its
    -- survivor; only active entities own addresses.
    status        TEXT        NOT NULL DEFAULT 'active',
    absorbed_into UUID        REFERENCES entities (entity_id),
    created_at    TIMESTAMPTZ NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Entity membership. The PRIMARY KEY on `address` IS the clustering invariant
-- attribution depends on: an address belongs to at most one entity at a time.
-- A merge MOVES the absorbed entity's rows to the survivor inside one
-- transaction, so the invariant holds throughout. `linked_at` + `evidence`
-- audit why the address joined (§8.2 — every cluster edge is justified).
CREATE TABLE entity_addresses (
    address   TEXT        PRIMARY KEY,
    entity_id UUID        NOT NULL REFERENCES entities (entity_id),
    -- The clustering signal that justified membership (common funder/deployer/
    -- code-hash/profit-receiver, or the seed itself).
    evidence  TEXT        NOT NULL,
    linked_at TIMESTAMPTZ NOT NULL
);

-- The membership read path ("all addresses of this entity").
CREATE INDEX entity_addresses_entity_idx ON entity_addresses (entity_id);

-- Attribution records (§8): the mutable overlay linking a confirmed incident to
-- the entity/entities behind it. Keyed (incident_id, entity_id) so re-running
-- attribution on a redelivered IncidentCreated is an idempotent upsert.
CREATE TABLE attributions (
    incident_id   UUID             NOT NULL,
    entity_id     UUID             NOT NULL REFERENCES entities (entity_id),
    -- How sure attribution is of THIS link (0–1) — an axis independent of any
    -- risk score (§8.3 "confidence vs. score").
    confidence    DOUBLE PRECISION NOT NULL,
    -- Evidence ref (label id, cluster edge, sim run) making the link auditable.
    evidence      TEXT             NOT NULL,
    attributed_at TIMESTAMPTZ      NOT NULL,
    PRIMARY KEY (incident_id, entity_id)
);

-- The entity-profile read path ("every incident this entity is behind").
CREATE INDEX attributions_entity_idx ON attributions (entity_id);

-- Sanctions lists (§8.5): OFAC SDN, EU, national lists. Keyed
-- (address, list_name) so re-importing a refreshed feed is an idempotent upsert;
-- `entry` carries the list's own designation for the match report. The read path
-- is the exact-address lookup behind the immediate SanctionHit (hard alert,
-- bypasses the slow path).
CREATE TABLE sanctions (
    address     TEXT        NOT NULL,
    -- Which list designated it (e.g. 'ofac_sdn', 'eu_consolidated').
    list_name   TEXT        NOT NULL,
    -- The list's entry (SDN name / programme) echoed into SanctionHit.
    entry       TEXT        NOT NULL,
    -- When the list designated the address (from the feed), if known.
    listed_at   TIMESTAMPTZ,
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (address, list_name)
);
