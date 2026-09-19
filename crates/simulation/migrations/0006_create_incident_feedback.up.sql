-- The analyst-feedback ledger (§19, production-readiness Epic E) — one row per
-- verdict a customer has recorded about one incident, and the table the §19
-- false-positive panel and its SLO are computed from.
--
-- Fed by the `simulation-projection` consumer from `AlertFeedbackRecorded`
-- (published by the API service's `POST /v1/incidents/{id}/feedback`). It sits
-- beside `incident_analytics` rather than in Postgres because the SLI is a
-- *join*: the numerator is verdicts, the denominator is the incidents created
-- in the same window, and that population only exists here. A ledger in
-- Postgres would have made the one query that matters a cross-store join.
--
-- ReplacingMergeTree keyed by (incident_id, customer_id), versioned by
-- `submitted_at`: a customer who changes their mind emits a second event and
-- the later submission wins, while a redelivered event (identical instant)
-- collapses to the same row — the fold is idempotent without the consumer
-- tracking anything. Two caveats, both handled at read time: merges are
-- eventual, and dedup is per *partition*, so a revision made in a later month
-- never merges with the original at all. Every read therefore re-aggregates
-- with argMax over the whole table rather than trusting a bare row (the same
-- contract `incident_timing_rollup` documents for its SummingMergeTree).
--
-- Kept for two years, which is a storage decision rather than a legal one: the
-- source events live in the event store under the §18 statutory window, so
-- this table is re-derivable, and no SLI here looks back further than a few
-- weeks. Two years leaves room for a year-over-year comparison and keeps the
-- partition count at twelve a year.
--
-- One statement per migration file, and no literal question mark anywhere in
-- it (the clickhouse crate binds every one, comments included).
CREATE TABLE IF NOT EXISTS incident_feedback
(
    incident_id  UUID,
    customer_id  UUID,
    -- 'true_positive' | 'false_positive' | 'unclear' — `FeedbackVerdict`'s
    -- wire form, stored as written so the ledger reads like the events do.
    verdict      String,
    -- `FeedbackReason`'s wire form ('our_own_activity', 'threshold_too_sensitive',
    -- …). The actionable half of a verdict: this is what a detector owner reads
    -- to decide between a threshold change and an investigation.
    reason_code  String,
    -- `FeedbackCohort`'s wire form: 'volunteered' (self-selected, a product
    -- signal) or 'solicited' (the platform picked this incident without looking
    -- at the finding, and asked). The two are never mixed into one rate —
    -- volume from the volunteered path would otherwise dominate the number a
    -- README quotes.
    cohort       String,
    -- The customer's own words. Never parsed; empty when they gave none.
    reason       String,
    -- Event time: the instant the API service accepted the verdict. Both the
    -- Replacing version and the window key.
    submitted_at DateTime64(3, 'UTC'),
    -- Server-side ingest timestamp; defaulted so inserts never set it.
    recorded_at  DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(submitted_at)
PARTITION BY toYYYYMM(submitted_at)
ORDER BY (incident_id, customer_id)
TTL toDateTime(submitted_at) + INTERVAL 730 DAY;
