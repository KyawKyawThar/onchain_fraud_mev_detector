-- Behavioral candidate links (§20.3 / §8.1, Sprint 19 t3) — the clustering
-- *signal*, kept deliberately outside `entity_addresses`.
--
-- A row here is a proposal, not a fact: "these two addresses behave alike, and
-- one of them is a directly-known actor". Entity membership (the
-- `entity_addresses` primary key, the invariant attribution depends on) still
-- comes only from the §8.2 on-chain evidence heuristics. Writing a behavioral
-- match into that table would let a learned score silently rewrite the graph's
-- correctness story; giving it its own table keeps the recall widening and the
-- correctness claim separable — an operator (or a later evidence pass) decides
-- which proposals graduate.
CREATE TABLE entity_link_candidates (
    -- Deterministic (SHA-256 → UUIDv8) over the *unordered* address pair, the
    -- embedding version and the proposer's source_detail — so the same link
    -- rediscovered from either end, or on any later recomputation, is one row
    -- rather than two mirror-image rows and a new one per sweep.
    candidate_id      UUID PRIMARY KEY,
    -- The pair, canonically ordered (address_a < address_b as lowercase hex) so
    -- the "links touching this address" read is one predicate over two indexed
    -- columns and the direction a search happened to run in is not mistakable
    -- for a claim about who resembles whom.
    address_a         TEXT             NOT NULL,
    address_b         TEXT             NOT NULL,
    -- Whichever of the two carried the directly-known actor label. Always one
    -- of address_a/address_b (enforced below), never a third address.
    anchor            TEXT             NOT NULL,
    -- The anchor's label kinds at proposal time (LabelKind wire strings), as a
    -- JSON array — the evidence that made this pair worth proposing, frozen at
    -- proposal time so a later revocation doesn't silently rewrite why the
    -- proposal exists.
    anchor_labels     JSONB            NOT NULL,
    -- Each side's entity at proposal time, if the graph had already placed it.
    -- Both set and different is the merge-candidate shape; still never a merge.
    entity_a          UUID,
    entity_b          UUID,
    -- Cosine similarity between baseline-standardized vectors, in [-1, 1].
    similarity        DOUBLE PRECISION NOT NULL,
    -- The §8.1 reduced-confidence band this signal is worth (< 0.5, the
    -- entity-derived band: a behavioral match is weaker than a graph one).
    confidence        DOUBLE PRECISION NOT NULL,
    -- The feature space the comparison was made in. Two similarities are only
    -- comparable if both match, so both are stored rather than assumed.
    embedding_version TEXT             NOT NULL,
    schema_hash       TEXT             NOT NULL,
    -- The score's decomposition (one signed term per feature, largest first) —
    -- explainable like every other derived claim in §8.
    factors           JSONB            NOT NULL,
    -- 'proposed' | 'confirmed' | 'rejected'. A decision is an *operator* act;
    -- nothing in the pipeline moves a row out of 'proposed'.
    status            TEXT             NOT NULL DEFAULT 'proposed',
    decided_at        TIMESTAMPTZ,
    -- Who decided and why — the audit trail a confirmed link needs before it
    -- can justify a merge.
    decided_by        TEXT,
    decision_note     TEXT,
    -- When `EntityLinkProposed` was actually published for this row. NULL means
    -- "stored but not yet announced", and that is the whole point: the row and
    -- its announcement are two writes to two systems, so a crash between them
    -- would otherwise lose the event permanently (the proposer only announces
    -- rows it just inserted, and after a restart the row already exists). The
    -- consumer re-announces anything still NULL, which makes delivery
    -- at-least-once instead of at-most-once — the same trade `rule_outbox`
    -- makes, and one the consumer side already tolerates because every
    -- downstream write off this event is keyed.
    announced_at      TIMESTAMPTZ,
    proposed_at       TIMESTAMPTZ      NOT NULL,
    -- Refreshed every time the proposal is rediscovered: the difference
    -- between "seen once months ago" and "still true on every sweep" is the
    -- strongest signal an operator triaging the queue has.
    last_seen_at      TIMESTAMPTZ      NOT NULL,
    CONSTRAINT entity_link_candidates_pair_ordered CHECK (address_a < address_b),
    CONSTRAINT entity_link_candidates_anchor_in_pair CHECK (anchor IN (address_a, address_b))
);

-- The two read paths: "candidate links touching this address" (the
-- investigation surface) and "the open queue, strongest first" (triage).
CREATE INDEX entity_link_candidates_address_a_idx ON entity_link_candidates (address_a);
CREATE INDEX entity_link_candidates_address_b_idx ON entity_link_candidates (address_b);
CREATE INDEX entity_link_candidates_open_idx
    ON entity_link_candidates (status, similarity DESC);
-- The crash-recovery sweep: "which rows still owe an announcement". A partial
-- index because the answer is almost always none — the rows it covers exist
-- only between a commit and the publish that follows it.
CREATE INDEX entity_link_candidates_unannounced_idx
    ON entity_link_candidates (proposed_at)
    WHERE announced_at IS NULL;
