-- Cross-chain finding read model (§24, Sprint 17 t4) — `simulation-projection`'s
-- additive counterpart to `incidents`: a `BridgeMevDetected`/`CrossChainMevDetected`
-- folded row, surfaced alongside confirmed incidents on `GET /v1/incidents`
-- (see `crate::http::list_incidents`) without being shoehorned into that
-- table's alert/incident-shaped columns — a finding has no `alert_id`, no
-- single flat `txs` list (it has per-chain *legs*), and unlike a confirmed
-- incident it never leaves `retracted = false` for a "finalized" state: it
-- stays a provisional estimate forever, withdrawn outright on retraction
-- instead of being confirmed.
CREATE TABLE cross_chain_findings (
    finding_id        UUID PRIMARY KEY,
    -- 'bridge_mev' | 'cross_chain_mev' — CrossChainFindingKind's wire string.
    kind              TEXT             NOT NULL,
    bridge            TEXT             NOT NULL,
    -- Legs as a JSON array (`[{"chain":1,"block_number":N,"block_hash":"0x..",
    -- "tx":"0x.."}, ...]`) — two or more, spanning at least two chains. A flat
    -- JSONB column rather than a child table: no per-leg query pattern exists
    -- yet to justify one (mirrors `incidents.txs` being a flat array for the
    -- same reason), and the whole list is always read/written together.
    legs              JSONB            NOT NULL,
    -- The behaviour-derived correlation address (§24) — never itself a label,
    -- see `intelligence::cross_chain_attribution`'s module docs.
    entity_hint       TEXT             NOT NULL,
    profit            DOUBLE PRECISION NOT NULL,
    victim_loss       DOUBLE PRECISION NOT NULL,
    confidence        DOUBLE PRECISION NOT NULL,
    severity          TEXT             NOT NULL,
    retracted         BOOLEAN          NOT NULL DEFAULT FALSE,
    retraction_reason TEXT,
    -- Event-time of the fold that last changed this row (creation, or the
    -- retraction) — mirrors `incidents.figures_at`'s replay-deterministic
    -- watermark (§18).
    observed_at       TIMESTAMPTZ      NOT NULL,
    updated_at        TIMESTAMPTZ      NOT NULL DEFAULT now()
);

-- The entity-correlation read path ("every cross-chain finding this address
-- was the hint for").
CREATE INDEX cross_chain_findings_entity_hint_idx ON cross_chain_findings (entity_hint);
-- The §11 `/v1/incidents` listing order (newest-observed first).
CREATE INDEX cross_chain_findings_observed_at_idx ON cross_chain_findings (observed_at DESC);
