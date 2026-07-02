-- Simulation service's Postgres tables (§7, §14): the *mutable, transactional*
-- state the append-only event store deliberately can't hold — in-flight simulation
-- jobs and the confirmed-incident read model. Both are owned solely by the
-- simulation service (§14: no shared tables, no cross-service joins) and are derived
-- by the `simulation-projection` consumer from the Kafka result-path events, folded
-- through the pure `IncidentProjection` (idempotent + reorg-safe) before write-through.

-- In-flight simulation jobs. Keyed by the provisional `alert_id` that spans a job's
-- whole lifecycle (the `SimulationJob` command itself never enters this system of
-- record — only its request/result events do, §7). Derived from `SimulationRequested`
-- (queued) → `SimulationCompleted` (finished), so redelivery is a harmless upsert.
CREATE TABLE sim_jobs (
    alert_id     UUID PRIMARY KEY,
    chain        BIGINT      NOT NULL,
    -- 'requested' once queued, 'completed' once the worker's result lands. A lean
    -- lifecycle: cancellation/retraction is an incident concern, tracked below.
    status       TEXT        NOT NULL,
    requested_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The confirmed-incident read model — one row per provisional alert that reached the
-- slow path, mutated in place as its lifecycle advances (the opposite of the event
-- store's append-only log, §14). Keyed by `alert_id` (spans the whole lifecycle);
-- `incident_id` is set once `IncidentCreated` is folded in. Every column mirrors an
-- `IncidentRecord` field, including the event-time watermarks, so the row is a
-- faithful, self-describing snapshot of the fold and the write-through is a plain
-- last-writer upsert.
CREATE TABLE incidents (
    alert_id          UUID PRIMARY KEY,
    incident_id       UUID,
    -- 'unconfirmed' | 'confirmed' | 'finalized' | 'retracted' — the monotonic
    -- lifecycle ladder from `IncidentStatus` (retraction outranks finality, §7).
    status            TEXT             NOT NULL,
    -- AlertKind / Severity as their snake_case wire strings; NULL until IncidentCreated.
    kind              TEXT,
    severity          TEXT,
    profit            DOUBLE PRECISION NOT NULL,
    victim_loss       DOUBLE PRECISION NOT NULL,
    -- Implicated tx hashes as 0x-hex, in `IncidentCreated` order.
    txs               TEXT[]           NOT NULL DEFAULT '{}',
    retraction_reason TEXT,
    finalized_block   TEXT,
    -- Last-writer-by-event-time watermarks (mirror the fold's hidden fields), so a
    -- redelivered/stale event can never overwrite newer figures on re-projection.
    figures_at        TIMESTAMPTZ      NOT NULL,
    retracted_at      TIMESTAMPTZ,
    finalized_at      TIMESTAMPTZ,
    updated_at        TIMESTAMPTZ      NOT NULL DEFAULT now()
);

-- Resolve a row by its confirmed incident id (the §11 audit-by-incident read path).
CREATE INDEX incidents_incident_id_idx ON incidents (incident_id);
-- Scan open/confirmed/retracted incidents (dashboards, the §11 `/v1/incidents` list).
CREATE INDEX incidents_status_idx ON incidents (status);
