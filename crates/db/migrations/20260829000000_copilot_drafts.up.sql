-- Copilot service's Postgres table (§20.4, Sprint 20 t2): the draft job
-- queue, the draft itself, its approval state, AND the cross-pod LLM
-- response cache — deliberately one table, not four.
--
-- Why one table. The §7 slow-path shape means a draft has a lifecycle
-- (queued -> in_flight -> ready -> approved/rejected) rather than a row that
-- appears once finished, so the queue and the artifact are the same object at
-- different points in time. The cache is the same object again: a completion
-- filed under `(model_digest, request_digest)` IS a draft somebody already
-- paid for, and keeping it anywhere else would let the platform hold a billed
-- answer that no audit trail accounts for.
--
-- Owned solely by the copilot service (§14: no shared tables, no
-- cross-service joins — the incident's audit stream is read over
-- event-store's HTTP API, never by joining its ClickHouse).
CREATE TABLE copilot_drafts (
    draft_id         UUID        PRIMARY KEY,
    -- 'incident_narrative' | 'rule_draft' (`DraftKind`), which is also the
    -- `CompletionRequest::purpose` metrics label and the prompt artifact's id.
    kind             TEXT        NOT NULL,
    -- What the draft is about: the incident id today; a rule-draft request id
    -- when t4 lands. Not a foreign key — the subject lives in another
    -- service's store (§14).
    subject_id       UUID        NOT NULL,
    -- Who the tokens bill to (§13). NULL for platform-internal work with no
    -- customer in scope — the incident stream, today.
    customer_id      UUID,
    chain            BIGINT      NOT NULL,
    -- queued | in_flight | ready | blocked | failed | approved | rejected
    -- (`DraftStatus`). `blocked` is a *successful, billed* call whose answer
    -- is unusable (a refusal, or a `max_tokens` truncation): terminal and
    -- human-inspectable, never silently retried, because it will decline or
    -- truncate identically next time.
    status           TEXT        NOT NULL,
    -- Claim/lease bookkeeping for the worker pool. `attempts` counts claims,
    -- not provider calls: the LLM seam does its own bounded retry underneath.
    attempts         INTEGER     NOT NULL DEFAULT 0,
    lease_expires_at TIMESTAMPTZ,
    -- The cache key (`llm::CacheKey`), written by the worker *before* the
    -- call so the completion has a row to land on even if the worker dies
    -- between the provider's answer and its own bookkeeping.
    request_digest   TEXT,
    model_digest     TEXT,
    -- Provenance, stamped from the *response* (`Completion::model`), not the
    -- request: with server-side refusal fallbacks a rescued draft was written
    -- by a different model than the one asked, and §20.4 requires the draft to
    -- be attributable to what actually produced it.
    model            TEXT,
    prompt_id        TEXT,
    prompt_digest    TEXT,
    stop_reason      TEXT,
    body             TEXT,
    -- `llm::TokenUsage`'s four SKUs as one JSONB document — kept for
    -- per-draft cost forensics. Billing reads `UsageRecorded` (§13); this is
    -- not a second metering path.
    token_usage      JSONB,
    -- The event ids every factual claim derives from (§20.4). t2 records the
    -- audit-stream window the model was shown; t3 narrows this to the ids the
    -- narrative actually cites.
    grounded_event_ids JSONB     NOT NULL DEFAULT '[]'::JSONB,
    last_error       TEXT,
    -- Approval state (§20.4): a draft is provisional forever until a human
    -- flips it. Nothing in this service auto-approves.
    reviewed_by      TEXT,
    reviewed_at      TIMESTAMPTZ,
    review_note      TEXT,
    created_at       TIMESTAMPTZ NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL,
    completed_at     TIMESTAMPTZ
);

-- Idempotent enqueue: an at-least-once redelivery of the same
-- `IncidentCreated` must resolve to the same draft, not a second billed one.
-- `INSERT ... ON CONFLICT DO NOTHING` against this index is the whole dedup
-- contract (`DraftStore::enqueue`).
CREATE UNIQUE INDEX copilot_drafts_subject_idx ON copilot_drafts (kind, subject_id);

-- The claim scan (`DraftStore::claim_batch`, FOR UPDATE SKIP LOCKED): only
-- runnable rows, oldest first. Partial, so the index stays proportional to
-- the backlog rather than to every draft ever written.
CREATE INDEX copilot_drafts_queue_idx ON copilot_drafts (created_at)
    WHERE status IN ('queued', 'in_flight');

-- The cross-pod cache lookup (`PgCompletionCache::get`): the newest usable
-- answer for this exact (model, request) pair. `failed` rows are excluded by
-- the query, not here — a failure is precisely the case where trying again
-- might work, so it is never a cache entry.
CREATE INDEX copilot_drafts_cache_idx ON copilot_drafts (model_digest, request_digest, completed_at DESC)
    WHERE request_digest IS NOT NULL;
