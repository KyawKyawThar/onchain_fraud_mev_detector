-- Entity merge log (§8.2, §15, Sprint 8 t3): one row per `EntityStore::absorb`
-- call, recording exactly which addresses moved and (if known) which incident
-- caused the merge — the durable link `BlockReverted`/`IncidentRetracted`
-- rollback needs to answer "which merges did this incident cause" and "what
-- would reversing this merge require". Append-only: a reversal marks
-- `reverted_at`, it never deletes the row (the merge itself stays audited).
CREATE TABLE entity_merges (
    merge_id        UUID        PRIMARY KEY,
    surviving_id    UUID        NOT NULL REFERENCES entities (entity_id),
    absorbed_id     UUID        NOT NULL REFERENCES entities (entity_id),
    -- The incident that caused this merge, if attribution-driven clustering
    -- triggered it (§8, attribution.rs). NULL for operator-driven clustering
    -- (the `intelligence cluster` CLI has no incident to name).
    incident_id     UUID,
    evidence_ref    TEXT        NOT NULL,
    -- Exactly the addresses `absorb` moved from `absorbed_id` to
    -- `surviving_id` — the precise partition a reversal needs to hand back to
    -- `EntityStore::split`.
    moved_addresses TEXT[]      NOT NULL,
    merged_at       TIMESTAMPTZ NOT NULL,
    reverted_at     TIMESTAMPTZ
);

-- The block→incident→merge join a reorg rollback walks (§15).
CREATE INDEX entity_merges_incident_idx ON entity_merges (incident_id)
    WHERE incident_id IS NOT NULL;
-- "was this entity ever absorbed, and by what" — audit/debug read path.
CREATE INDEX entity_merges_absorbed_idx ON entity_merges (absorbed_id);
