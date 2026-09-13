-- What a customer's screening policy does when a decision has to be rendered
-- over last-known-good facts because intelligence is slow or unavailable (§11
-- graceful degradation, readiness Epic D — crates/server/src/degrade.rs).
--
--   serve  — decide on the stale facts as on fresh ones; the response and the
--            audit record still carry `stale: true` with the facts' age.
--   review — never auto-allow on facts intelligence could not confirm: a
--            stale `allow` is held as `review` (a stale `block` stays a block).
--
-- Part of a policy's versioned identity like its thresholds: changing it mints
-- a new version, so a past verdict's (policy_name, policy_version) still
-- resolves to the exact stale-handling that produced it.
--
-- Existing rows default to 'serve', which is precisely how every policy behaved
-- before this column existed — the backfill is a statement of fact, not a new
-- behaviour. The CHECK mirrors `screen::StalePolicy`'s closed set
-- (defense-in-depth; the application parses first so a 400 beats a 23514).
ALTER TABLE screening_policies
    ADD COLUMN on_stale TEXT NOT NULL DEFAULT 'serve'
        CONSTRAINT screening_policies_on_stale_known CHECK (on_stale IN ('serve', 'review'));
