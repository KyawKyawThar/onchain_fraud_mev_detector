# Runbook — Regulatory retention: how long a SAR draft and its evidence live

**Owner:** whoever is on call for compliance-facing data (the copilot's drafts, the event store).
**Covers:** engineering conventions [§18](../engineering-conventions.md). Surfaced by the Sprint 20 t5 grounding audit, whose `unverifiable` verdict fires precisely when event-store retention outlives the narratives citing it.
**Code:** [`crates/retention/`](../../crates/retention/) (the decision) · [`crates/event-store/src/retention.rs`](../../crates/event-store/src/retention.rs) (evidence) · [`crates/copilot/src/retention.rs`](../../crates/copilot/src/retention.rs) (artifacts)
**Related:** [backup + restore](backup-restore.md) — a backup does **not** satisfy retention (see §7).

> A retention policy that lives in two places is already wrong in one of them.

---

## 0. TL;DR

```bash
just retention-status                 # the policy, what the store holds, and what applying would do
just copilot-retention                # PLAN: the complete backlog the policy has released
just copilot-retention --apply        # carry out that same plan
just copilot-audit                    # does every retained narrative still have its evidence?
```

Every destructive step is **plan → apply**, and the plan is the whole truth: the
counts come from a `COUNT(*)` over the purge's own predicate, so a preview can
never under-report what an apply would destroy. Nothing on a timer, at boot, or
in a background task can reach a destructive apply — those take a
`DestructiveIntent` witness that only a CLI flag arm mints, so the question
"could this delete something?" is answered by the signature.

| | value | anchored on | enforced by |
|---|---|---|---|
| **artifact** (a SAR narrative) | **1827 days** (5 years) | its **disposition** — approved / rejected / answered / created, first that exists | `copilot retention --apply` deleting `copilot_drafts` rows |
| **evidence** (the events it cites) | **2192 days** (artifact + margin) | when the event **occurred** | the `events` table's ClickHouse `TTL`, reconciled at event-store boot |
| **margin** = max drafting lag | **365 days** | — | `copilot backfill` refuses a window older than this |

Both numbers come from one validated value (`retention::Policy`), read by both services from the same two environment variables. There is no per-service override, on purpose.

---

## 1. The decision, and why five years

A financial institution that files a SAR must retain a copy of the report **and its supporting documentation** for five years from the date of filing — 31 CFR 1020.320(d) in the US; Directive (EU) 2015/849 art. 40 sets the same five-year floor in the EU (member states may extend to ten).

This platform does not file. Its customers do. So the obligation it can actually discharge is narrower and sharper:

> **Never be the reason a filer cannot produce the record.**

Hence `RETENTION_ARTIFACT_DAYS` is a **floor**, not a default to tune down: every service that reads the policy refuses to boot below it. 1827 rather than `5 × 365` because five calendar years span one or two leap days, and the direction to round a retention floor is up.

**This is a compliance decision with a legal dimension.** The number above is a defensible reading of a rule this platform is adjacent to, not advice, and it is written where a lawyer can find it: one constant, `retention::STATUTORY_ARTIFACT_DAYS`, with the citation next to it. If counsel says ten years, that is a one-line diff and a `RETENTION_ARTIFACT_DAYS` bump — the enforcement follows automatically in both stores.

---

## 2. Why there are two numbers (the part that is easy to get wrong)

The two clocks start at different times and only one of them can ever be changed:

```
  evidence occurs ─────► narrative drafted ───────────► evidence expires
       E                        T                            E + evidence_days
                                └────────────────────────────────► artifact expires
                                                                     T + artifact_days
```

An artifact's clock starts at **disposition**. An event's clock started when it **occurred**, and it cannot be extended afterwards — the event store is append-only (§4), so there is no row to update and no mutation that would not compromise the property the whole audit trail rests on.

Set both to "five years" and every artifact quietly under-retains by exactly its drafting lag. So evidence is kept for the artifact window **plus a margin**, and the whole policy is one inequality:

```
  E + evidence_days  ≥  T + artifact_days      ⇔      T − E  ≤  margin
```

**The margin *is* the furthest back a narrative may legitimately be drafted.** That is why one knob does both jobs: raising `RETENTION_EVIDENCE_MARGIN_DAYS` is what lets a backfill reach further into the archive, *and* it is what lengthens the TTL that keeps the evidence for the narratives that backfill writes. There is deliberately **no `--allow-old-evidence` flag** — a flag would let someone unlock the older backfill without keeping the evidence, which manufactures undefendable documents on purpose.

---

## 3. What the grounding audit now means

Before there was a policy, `copilot audit` could see that a narrative's evidence was gone and had nothing to say about whether that was allowed. `CopilotGroundingAuditUnverifiable` said as much: *"if retention is the cause, that is a decision to make deliberately."* It has been made. The same observation now splits on one comparison:

| verdict | meaning | is it a finding? |
|---|---|---|
| `grounded` | every citation resolves, and the row agrees with the prose | no |
| `expired` | evidence gone, **artifact past its deadline** — retention working | no (but see §5) |
| `evidence_missing` | evidence gone, **artifact still retained** — **the policy is violated** | **yes — pages** |
| `unresolved` | cites ids the store does not have, on a non-empty stream | yes |
| `drifted` | `grounded_event_ids` disagrees with the prose | yes |
| `unchecked` | ready/approved and the citation boundary never ran | yes |
| `unverifiable` | *this sweep* could not look: stream unreadable, ceiling hit, no body | no — operational |

Plus one that is **not** a verdict, because a draft can be perfectly grounded and still have it: `at_risk`, printed as `outlives-its-evidence-by=Nd`. That is the leading indicator, and `N` is the number of days to add to `RETENTION_EVIDENCE_MARGIN_DAYS` to fix it — while there is still time for the fix to mean anything.

---

## 4. `CopilotGroundingAuditUnverifiable` fired. Now what?

It means: **a stored narrative that is still under retention cites evidence the event store no longer has.** Work down this list.

```bash
just retention-status
```

1. **Is the store's window shorter than the policy?** `retention-status` prints both. If the store is behind, event-store extends it on its next boot — restart it, or run `cargo run -p event-store -- retention apply`. Extending does not bring deleted evidence back; it stops the bleeding.
2. **Did someone shorten it?** `event-store retention apply --allow-shortening` is the only path that shortens, and it logs a warning naming both numbers. Check the boot logs of every event-store pod and the `event_store_evidence_retention_days` gauge — a pod running an older config map shows a different number.
3. **Was evidence deleted out of band?** A hand-run `ALTER TABLE events DELETE`, a dropped partition, a restore from a backup taken before the events existed (§7).
4. **Name the drafts.** `just copilot-audit` prints every finding with its draft id and subject. The metric deliberately cannot — an unbounded id set has no business in a time series (§19).
5. **Record it.** These drafts are regulatory artifacts that can no longer be substantiated. That is a fact a compliance owner has to know about, not one for a ticket that closes when the alert clears.

**What you cannot do is recover it here.** Evidence deleted by TTL is gone from the event store. If it is inside a backup's window, a restore into a scratch database (see [backup-restore](backup-restore.md)) will produce it — as an artifact, not as a live citation, since re-appending it would mint new rows in an append-only store.

---

## 5. `CopilotRetentionPurgeStalled` / a rising `expired` count

Artifacts past their deadline are still in `copilot_drafts`. Over-retention is a milder failure than under-retention, which is why it is informational — but it is still a policy nobody is keeping. Three causes:

* the `copilot-retention` CronJob is failing (`kubectl get jobs -l app.kubernetes.io/name=copilot-retention`),
* it is running **without `--apply`** — the binary is a dry run by default, deliberately, so check the CronJob's `args`,
* a **legal hold** is preserving them. `copilot retention` prints the held count on every run.

---

## 6. Legal hold

A held draft is never destroyed, whatever its deadline.

**A hold is not a boolean.** It overrides a statutory destruction schedule, so
the questions that follow it are always *which matter*, *since when* and *on
whose say-so* — and a flag answers none of them. Three columns, with a CHECK
constraint that makes a partial hold unrepresentable:

```sql
-- place (a subpoena, a regulatory request, an internal investigation)
UPDATE copilot_drafts
   SET legal_hold_matter    = 'SUBPOENA-2026-0042',
       legal_hold_placed_at = now(),
       legal_hold_placed_by = 'compliance@yourbank.example'
 WHERE draft_id = '…';

-- lift (all three together; the constraint refuses anything else)
UPDATE copilot_drafts
   SET legal_hold_matter = NULL, legal_hold_placed_at = NULL, legal_hold_placed_by = NULL
 WHERE draft_id = '…';
```

`legal_hold_matter IS NOT NULL` is the predicate for "held" — there is no
separate flag that can drift out of agreement with it.

The purge checks the hold twice — once when it selects and again inside the `DELETE` — because the realistic reason a hold appears between those two statements is that somebody is placing it *right now*, having just learned the record is wanted.

Every purge that destroyed anything publishes a `RetentionPurgeCompleted` fact
carrying the cutoff, the count destroyed and the count held back — see §9.

**A hold does not extend the evidence.** The event store's TTL knows nothing about `copilot_drafts`. If a held artifact matters, its evidence must be preserved separately (a backup snapshot, or an export attached to the matter), and that is a manual step for as long as it stays manual.

---

## 7. What retention is *not*

* **A backup is not retention.** Backups have their own, much shorter lifecycle and exist to recover from loss, not to answer a regulator. An artifact restored from a backup is evidence *about* the platform, not the platform's record.
* **Kafka retention is not evidence retention.** Kafka is the wire, not the record (§2/§4); its window is seven days.
* **Purging is not deletion everywhere.** Deleting a draft cascades its `copilot_outbox` row. That is intended: the durable copy of the announcement is the `IncidentNarrativeDrafted` event in the event store, which is under the *evidence* half of the same policy and outlives the draft by the margin.

---

## 8. Changing the policy

One PR, both stores, in this order:

1. Change `RETENTION_ARTIFACT_DAYS` / `RETENTION_EVIDENCE_MARGIN_DAYS` in `deploy/k8s/base/app-config.yaml` (they are commented out while the shipped defaults are the policy — uncommenting them *is* the record that a cluster departed from it).
2. **Lengthening**: roll event-store. It reconciles the TTL upward at boot, and logs `extended the events table's retention window`. Nothing else is needed.
3. **Shortening, or binding a store that had no TTL at all**: event-store
   **refuses to boot** rather than destroy evidence on a config change. Both are
   deliberate acts, with a ticket, on a human's command:
   ```bash
   cargo run -p event-store -- retention                                        # plan first
   cargo run -p event-store -- retention apply --i-understand-this-deletes-evidence
   ```
   Then roll the pods. Do this only after confirming no artifact still under retention depends on the evidence you are about to expire — `just copilot-audit`'s `at_risk` count is the closest thing to that check.

   Note the second case: **imposing a first bound is not "extending from
   nothing"**. A store that has never had a TTL and holds eight years of events
   loses two the moment a six-year window is written. The planner asks the store
   for its oldest row and refuses if the answer says the bind would destroy
   anything, so this only ever happens on purpose.

4. **A TTL the build cannot read** (`INTERVAL 10 YEAR`, `toIntervalMonth(72)`, a
   `GROUP BY` form) is **never overwritten**, witness or not. The only honest
   thing to say about a bound you cannot parse is that you will not touch it;
   rewrite it by hand into days first.
5. Never lower `retention::STATUTORY_ARTIFACT_DAYS` without counsel. It is a floor every service enforces at boot; a code change is the intended amount of friction.


---

## 9. The governance record

Retention used to be the one control in the platform that governed itself with
no record: an env var, a boot log line and a gauge. None of those answers *"on
what date did this window change, from what, to what, and who applied it"*, and
a counter is a poor answer to *"how many records did we destroy last quarter"* —
both get asked with a lawyer in the room, and by then the pod log has rotated.

Two facts on the backbone, landing in the event store — which is itself under
the policy they describe, so the record of a change outlives the change by the
margin:

| event | emitted by | carries |
|---|---|---|
| `RetentionPolicyChanged` | event-store, when it writes the `events` TTL | store, previous/current window, **`destructive`**, `applied_by` (`boot` \| `operator`) |
| `RetentionPurgeCompleted` | `copilot retention --apply` | store, cutoff, policy window, destroyed, **held back**, truncated |

`destructive` is the field to read first: it is what separates "we lengthened
retention" from "we deleted history", which are the same numbers moving in
different directions. `applied_by = boot` is necessarily non-destructive — the
boot path cannot mint the witness the destructive directions require.

Query them the way you query anything else in the store:

```bash
curl -s "$EVENT_STORE_URL/v1/events?event_type=RetentionPolicyChanged" | jq .
curl -s "$EVENT_STORE_URL/v1/events?event_type=RetentionPurgeCompleted" | jq .
```

**Both publishes are best-effort and neither is fatal.** By the time they run the
TTL is written or the artifacts are destroyed; failing the command would tell an
operator that something did not happen when it did. A failure logs at `error`
saying plainly that the audit trail is missing a record — and if that ever fires
in practice, the fix is a durable outbox (the shape `copilot_outbox` already
uses for `IncidentNarrativeDrafted`), not a retry loop.
