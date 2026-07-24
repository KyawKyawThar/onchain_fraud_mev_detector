-- Customer-authored decision-policy store (§11, Sprint 14 t2): named,
-- versioned score-threshold policies a customer can define beyond the
-- built-in catalog (`default`/`strict`/`monitor-only`, hardcoded in the
-- server crate's `screen` module — never rows here) to govern
-- POST /v1/address/{addr}/screen. Owned solely by the server service (§14:
-- no shared tables, no cross-service joins).
--
-- Versions are immutable and append-only: an upsert never updates a row in
-- place, it inserts (owner, name, version + 1). This is what lets a past
-- screening verdict's (policy_name, policy_version) always resolve back to
-- the exact thresholds that produced it, even after the customer retunes
-- the policy — so rows are never deleted or edited, only added.
--
-- Customer isolation is structural, the same as `rules.owner`: every
-- customer-facing read/write is keyed on `owner`, so no query path can
-- return or mutate another customer's policies.
-- The CHECK constraints below mirror `screen::Thresholds::new`'s invariants
-- (application-side is the primary enforcement, since a 400 with a reason
-- beats a 23514) — defense-in-depth so a future writer that bypasses the
-- constructor still can't land a threshold no score can reach, or an
-- inverted pair. MAX_SCORE (100) is the top of the §8.3 score domain.
CREATE TABLE screening_policies (
    id         BIGSERIAL   PRIMARY KEY,
    owner      UUID        NOT NULL,
    name       TEXT        NOT NULL,
    -- Starts at 1 per (owner, name); each retune inserts the next integer.
    version    INTEGER     NOT NULL,
    -- Score (0-100) at/above which an otherwise-clean address holds for
    -- review.
    review_at  SMALLINT    NOT NULL CHECK (review_at BETWEEN 0 AND 100),
    -- Score (0-100) at/above which an otherwise-clean address blocks
    -- outright. NULL = monitor-only: score can never block, only review —
    -- a sanctions hard-block (decided in application code, never stored
    -- here) still applies regardless.
    block_at   SMALLINT    CHECK (block_at BETWEEN 0 AND 100),
    created_at TIMESTAMPTZ NOT NULL,
    -- block_at, when present, is at/above review_at — otherwise a
    -- block-worthy score would read as merely "review".
    CONSTRAINT screening_policies_block_ge_review
        CHECK (block_at IS NULL OR block_at >= review_at)
);

-- Every (owner, name) version is a distinct, permanent row.
CREATE UNIQUE INDEX screening_policies_owner_name_version_idx
    ON screening_policies (owner, name, version);

-- The hot read path: "the latest version of owner's policy named X" (also
-- what backs "all of owner's policies, each at its latest version" via
-- DISTINCT ON). DESC on version so the latest-version scan is a index-order
-- read, not a re-sort.
CREATE INDEX screening_policies_owner_name_idx
    ON screening_policies (owner, name, version DESC);
