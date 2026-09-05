-- Engineering conventions §18 — the regulatory retention policy's artifact
-- half, on the copilot's own table.
--
-- The policy (`crates/retention`) says a SAR narrative and the evidence it
-- cites must both survive five years from the artifact's disposition. Nothing
-- in this schema had to change for the *keeping* half — the table already keeps
-- everything forever — so what this migration adds is what the **purge** needs
-- in order to be safe: the one condition under which a row past its deadline is
-- still not destroyed, and an index so the scan does not read the whole table
-- on a schedule.
--
-- A legal hold is **not a boolean**. It overrides a statutory destruction
-- schedule, so "someone set a bit" is not a record anybody can stand behind
-- when asked why a document that should have been destroyed still exists — or,
-- worse, why one that was under subpoena was not. A hold is a decision with a
-- matter, a date and a name on it, and the CHECK constraint makes a partial one
-- unrepresentable rather than something every reader has to second-guess
-- (§4 — parse, don't validate, at the schema boundary).
--
-- `legal_hold_matter IS NOT NULL` is the predicate for "held"; there is no
-- separate flag to drift out of agreement with it.
ALTER TABLE copilot_drafts
    ADD COLUMN legal_hold_matter    TEXT,
    ADD COLUMN legal_hold_placed_at TIMESTAMPTZ,
    ADD COLUMN legal_hold_placed_by TEXT;

-- All three or none. A hold with no owner is not a hold, it is a mystery.
ALTER TABLE copilot_drafts
    ADD CONSTRAINT copilot_drafts_legal_hold_complete CHECK (
        (legal_hold_matter IS NULL
         AND legal_hold_placed_at IS NULL
         AND legal_hold_placed_by IS NULL)
     OR (legal_hold_matter IS NOT NULL
         AND legal_hold_placed_at IS NOT NULL
         AND legal_hold_placed_by IS NOT NULL)
    );

-- The disposition anchor, matching `copilot::retention::anchor`: when a human
-- decided, else when the answer landed, else when the row was created. A
-- narrative that was never reviewed still has a clock — "nobody looked at it"
-- is not a reason to keep a draft forever, nor to destroy it early.
--
-- `COALESCE` is immutable over these three columns, so this is a legal
-- expression index and the purge's `WHERE COALESCE(...) <= $1 AND
-- legal_hold_matter IS NULL` uses it directly. Partial on the hold, because a
-- held row is never a candidate and there is no reason to index it.
CREATE INDEX copilot_drafts_retention_idx
    ON copilot_drafts (COALESCE(reviewed_at, completed_at, created_at))
    WHERE legal_hold_matter IS NULL;
