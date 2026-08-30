-- Sprint 20 t3 — incident narratives / SAR drafts: the grounding check, the
-- `IncidentNarrativeDrafted` announcement, and the Batch API backfill.
--
-- Three objects, and the split is the design: `copilot_drafts` gains the
-- columns a *draft* owns, `copilot_batches` is the Batch API job as its own
-- entity (it has a lifecycle that outlives any one draft), and
-- `copilot_outbox` makes the draft write and its announcement atomic —
-- the same transactional-outbox shape `rule_outbox` already uses (§20).

-- ── copilot_drafts: what a draft gained ──────────────────────────

-- Which path drains this draft (`events::copilot::NarrativeSource`).
--
-- Load-bearing, not descriptive. The synchronous worker pool claims only
-- `live` rows and the backfill claims only `backfill` ones, because a
-- backfilled narrative is deliberately drafted through the Batch API at HALF
-- price (§20.4 — historical drafting is never latency-critical). A worker that
-- could pick up a backfill row would quietly pay double for it, and nothing in
-- any log would say so.
ALTER TABLE copilot_drafts
    ADD COLUMN source TEXT NOT NULL DEFAULT 'live';

-- What the citation check found (`copilot::grounding::GroundingSummary`):
-- claims made, claims cited, the cited ids and any that did not resolve in the
-- window the model was shown.
--
-- Stored beside `grounded_event_ids` rather than replacing it, because the two
-- answer different questions: that column becomes the *cited* subset once an
-- answer lands, while this records how the narrowing went — including the
-- fabricated ids, which are the single most important thing a reviewer can be
-- told about a draft that was blocked.
ALTER TABLE copilot_drafts
    ADD COLUMN grounding JSONB;

-- The Batch API job this draft rode, for backfilled drafts. FK-less on
-- purpose in the *draft* direction (a batch row can be pruned long after the
-- drafts it produced are reviewed); the join is by id when an operator asks
-- "which batch wrote this narrative".
ALTER TABLE copilot_drafts
    ADD COLUMN batch_id TEXT;

-- The claim scan is per-source now (see `source` above), so the partial queue
-- index gains it as a leading column. Dropping and recreating rather than
-- adding a second index: two overlapping partial indexes on the same predicate
-- is the shape that quietly doubles write cost for no read benefit.
DROP INDEX IF EXISTS copilot_drafts_queue_idx;
CREATE INDEX copilot_drafts_queue_idx ON copilot_drafts (source, created_at)
    WHERE status IN ('queued', 'in_flight');

-- The backfill's straggler sweep and its "which batch wrote this" lookup.
CREATE INDEX copilot_drafts_batch_idx ON copilot_drafts (batch_id)
    WHERE batch_id IS NOT NULL;

-- ── copilot_batches: the Batch API job as an entity ──────────────
--
-- A batch is not an attribute of a draft. It is a server-side job with its own
-- lifecycle (submitted -> ended -> results consumed) that spans process
-- restarts and outlives any single draft in it, so it gets a row.
--
-- `results_fetched_at` is the load-bearing column: the Batch API reports token
-- usage in the *results* stream, so fetching a batch's results twice bills its
-- tokens twice into the §13 metering stream. Claiming the fetch with a
-- conditional UPDATE makes "exactly once" a property of the schema instead of
-- a convention in a comment.
CREATE TABLE copilot_batches (
    -- The provider's own id (`msgbatch_…`).
    batch_id      TEXT        PRIMARY KEY,
    -- Requests handed over, for reconciling against what came back.
    items         INTEGER     NOT NULL,
    submitted_at  TIMESTAMPTZ NOT NULL,
    -- Set when this process consumed (and metered) the results. NULL means
    -- the results have never been read.
    results_fetched_at TIMESTAMPTZ,
    -- Set when every draft in the batch reached a terminal state — or when the
    -- drain gave up on the stragglers and released them back to the queue.
    -- A closed batch is never polled again, which is what bounds the drain.
    closed_at     TIMESTAMPTZ,
    -- Why it closed: 'landed' (every item accounted for) or
    -- 'released' (results were short and the remainder went back to the
    -- queue). Alert on a sustained 'released' rate: it means the provider is
    -- returning results this build cannot match to drafts.
    closed_reason TEXT
);

-- The drain's working set: batches still owed an outcome, oldest first.
CREATE INDEX copilot_batches_open_idx ON copilot_batches (submitted_at)
    WHERE closed_at IS NULL;

-- ── copilot_outbox: the announcement, written with the draft ─────
--
-- `IncidentNarrativeDrafted` must be atomic with the draft reaching `ready`:
-- publishing straight to Kafka after the UPDATE leaves a window where a
-- narrative exists that the audit trail never heard about, and stamping the
-- draft *before* publishing (the other order) loses the event on a crash.
-- Writing the envelope in the same transaction as the landing closes both;
-- the flusher then drains pending rows at-least-once (§20), exactly as
-- `rule_outbox` does for `RuleCreated`.
CREATE TABLE copilot_outbox (
    -- Monotonic id = publish order (the flusher drains oldest-first).
    id           BIGSERIAL   PRIMARY KEY,
    -- One announcement per draft. The UNIQUE constraint is the idempotency:
    -- every landing path inserts `ON CONFLICT DO NOTHING`, so a redelivery, a
    -- cache write and a worker write racing the same draft cannot announce it
    -- twice.
    draft_id     UUID        NOT NULL UNIQUE REFERENCES copilot_drafts (draft_id) ON DELETE CASCADE,
    -- The full EventEnvelope, wire form — exactly the bytes to publish, so the
    -- flusher never rebuilds (and never diverges from) the announcement the
    -- landing composed.
    envelope     JSONB       NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL,
    published_at TIMESTAMPTZ
);

-- The flusher's working set: pending rows only, in id order. Published rows
-- are stamped rather than deleted (audit: what did we announce, when), which
-- this partial index keeps free.
CREATE INDEX copilot_outbox_pending_idx ON copilot_outbox (id) WHERE published_at IS NULL;
