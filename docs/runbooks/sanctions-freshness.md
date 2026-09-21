# Runbook: sanctions lists and their freshness SLA (§8.5, readiness Epic E)

**What this covers:** keeping every sanctions list we screen against
confirmed against its source within a bounded window, what to do when that
fails, and how to answer "which version of the list were we screening with
when we cleared this withdrawal?".

**Why it matters.** `SanctionHit` is a hard alert and `/screen` hard-blocks on
a match, so these rows are compliance data. A list that stopped refreshing
lets a newly designated address through, and before this it did so silently.

---

## The model: a list is a versioned snapshot

A sync never writes the live table directly:

```
fetch (conditional GET when we have validators)
  ├─ 304 / same content ──► confirm: check the live rows still equal the
  │                          current version, then stamp it fresh
  └─ new content ──► stage a snapshot (keyed by content digest)
                       └─ checks: empty / shrink / growth / sentinels
                            ├─ refused ──► staged, recorded, waits for a human
                            └─ passed  ──► PROMOTE, one transaction:
                                           · live rows := the snapshot
                                           · log the promotion + its diff
                                           · advance the freshness ledger
                                           · queue the announcements
                                  then effects: labels, cache evictions
```

Consequences worth knowing before you touch it:

- **Delisting works.** A promotion removes what the list no longer carries and
  revokes that address's `SanctionedEntity` label.
- **Growth is the guarded direction.** Extra addresses hard-block withdrawals
  and are the damaging case; the growth check and the sentinel addresses stop
  a wrong file. A shrink is bounded too, but it is the recoverable direction.
- **Nothing is lost when a check refuses.** The version is staged; an operator
  promotes exactly that content by digest.
- **Freshness is "checked against the source"**, not "the source changed", and
  it is stamped at the *fetch* time from the database clock.
- **A confirmation is verified.** The live rows are digested and compared with
  the current version; drift is repaired (a `reconcile` promotion), never
  stamped fresh.
- **Effects are resumable.** Label writes and cache evictions happen after the
  commit; an unfinished set is completed by the next run.

**SLA configuration** (app-config, read by the `grpc` pods):

| Variable | Default | Meaning |
|---|---|---|
| `INTEL_SANCTIONS_LISTS` | `ofac_sdn,eu_consolidated` | Monitored lists, each `list[=max_age_secs]`. Unknown names, duplicates, zero ages and an empty set are boot errors. |
| `INTEL_SANCTIONS_MAX_AGE_SECS` | `21600` (6h) | SLA for a list named without `=secs`. |
| `INTEL_SANCTIONS_FRESHNESS_POLL_SECS` | `60` | How often the `grpc` pods re-read the ledger. |
| `INTEL_SANCTIONS_MAX_SHRINK_PERCENT` | `20` | Refuse a version that lost more than this share. |
| `INTEL_SANCTIONS_MAX_GROWTH_PERCENT` / `INTEL_SANCTIONS_GROWTH_FLOOR` | `100` / `500` | Refuse a version that grew past **both**. |
| `INTEL_SANCTIONS_SENTINELS` | none | `list:0xaddr,…;list:…` — addresses a list must always carry. |
| `INTEL_SANCTIONS_FETCH_TIMEOUT_SECS` / `INTEL_SANCTIONS_FETCH_MAX_BYTES` | `60` / 16 MiB | Fetch bounds. |
| `INTEL_SANCTIONS_OUTBOX_FLUSH_SECS` | `5` | How often the `grpc` pods publish announcements. |

Hourly syncs against a 6h SLA mean the first failure warns and five
consecutive failures page.

**The EU list needs a source.** The EU publishes persons and entities as
XML/CSV, with no maintained digital-currency extraction like OFAC's. The
`eu-consolidated` feed takes the same plain-text shape (one `0x` address per
line, `#` comments) from an extraction the operator trusts. The shipped
`INTEL_SANCTIONS_EU_URL` is a placeholder, so until it points at a real
extraction **the EU list pages. That is intended:** monitoring a list we don't
ingest is the gap this SLA exists to expose. To run without EU coverage,
remove it from `INTEL_SANCTIONS_LISTS` explicitly.

---

## Checking state

```sh
just intel-sanctions-status            # each list vs its SLA; non-zero if breached
just intel-sanctions-history ofac_sdn  # promotions + staged snapshots
```

`sanctions-status` prints each list's age against its SLA, its current
version, when the content last changed, its source, whether a promotion's
effects are unfinished, and the last failure if that was the most recent
attempt.

## SanctionsListSyncFailing (warning)

The latest attempt failed; the list is still served from its current version.
Read the reason with `sanctions-status`, or the failed Job's pod log.

| Reason | Meaning | Fix |
|---|---|---|
| `request to … failed` / `answered HTTP 5xx` / `429` | Source unreachable or throttling | Usually clears next hour (the Job retried it twice). |
| `answered HTTP 4xx` | URL moved, or a token expired | Fix `INTEL_SANCTIONS_*_URL`. Credentials in a query string are never written to the ledger. |
| `… feed, line N: address "…" is not 0x-hex` | Upstream changed format, or served an error page as 200 | Inspect the source. Never hand-edit the list to make it parse. |
| `larger than the …-byte cap` | Runaway or wrong response | Inspect the source; raise the cap only if the list really grew. |
| `snapshot … refused: the list has no addresses` | Empty | Never promotable. No real sanctions list is empty. |
| `snapshot … refused: the list grew/shrank …` | A size check | See below. |
| `snapshot … refused: N sentinel address(es) missing` | Right URL, wrong file (most likely) | Verify the source before promoting anything. |

**A refusal does not clear on its own.** The scheduled sync never overrides a
check. To resolve one:

1. `just intel-sanctions-history ofac_sdn` — the refused snapshot is listed
   with its digest, entry count and the reason.
2. Confirm the change upstream (OFAC's recent actions, the EU's publication).
   A mass delisting and a large designation round are both real events; so is
   a mirror serving the wrong file.
3. Promote exactly that content, naming yourself:

```sh
just intel-sanctions-promote ofac_sdn <digest> "alice (compliance)"
```

The promotion applies the diff, announces it, and stamps freshness as of the
snapshot's **last fetch** — the moment the content you reviewed was current,
not the moment you promoted it. An empty list is never promotable.

## SanctionsListStale (page)

The list has not been confirmed within its SLA. Treat it as a compliance
incident: designations made since the last confirmation are not in the live
rows, every screening decision now discloses the list as stale, and customers
on an `on_stale: review` policy have their allows held.

1. `sanctions-status`. **NEVER SYNCED** means no source is wired or the
   CronJob was never deployed (`kubectl -n mev get cronjob`). Otherwise the
   last failure reason points at the table above.
2. If the CronJob exists but has no recent Jobs, check whether it is suspended
   (`kubectl get cronjob … -o jsonpath='{.spec.suspend}'`) and its events.
3. Run one now: `kubectl -n mev create job --from=cronjob/intelligence-sanctions-sync-ofac ofac-now`.
   The page clears within one monitor poll plus the rule's 5m `for`.
4. If the source is down longer than the SLA, the list stays stale, which is
   correct. Decide with compliance whether to move customers to `on_stale:
   review` until it is restored.

## SanctionsPromotionEffectsPending (warning)

A promotion committed but its label writes and cache evictions did not
finish. **Screening is unaffected** — it reads the promoted rows directly —
but risk scores for the touched addresses may be stale. Each sync resumes the
effects first, so this persisting means the syncs themselves are failing
(usually Redis unreachable from the Job). Check `SanctionsListSyncFailing`.

## SanctionsAnnouncementsStuck (page)

An announcement has waited over 15 minutes in `sanctions_outbox`. It may be a
retroactive `SanctionHit` — a hard alert — for an address we already knew that
has just been designated. The designation is live and screening blocks it; the
*alert* is what is delayed. The `grpc` pods publish the outbox, so check Kafka
reachability from them. Nothing is lost: the rows are durable and publish when
the broker returns.

## SanctionsFreshnessUnreadable (warning)

The `grpc` pods cannot read `sanctions_list_syncs`. If the table is missing,
the `20260920000000` migration was not applied (`just migrate-up`). Gauges
stay frozen, so the staleness page still fires eventually.

---

## Answering "what were we screening against?"

Every screening decision records the digest of each list it was screened
against, on the response and in `ScreeningDecisionRecorded`. To resolve one:

```sql
-- which version was current at that instant
SELECT digest, promoted_at, promoted_by, entries
FROM sanctions_list_promotions
WHERE list_name = 'ofac_sdn' AND promoted_at <= '2026-09-20T11:00:00Z'
ORDER BY promoted_at DESC LIMIT 1;

-- was this address in that version
SELECT entry FROM sanctions_list_snapshot_entries
WHERE list_name = 'ofac_sdn' AND digest = '<digest>' AND address = '0x…';
```

Snapshots and promotions are append-only and are **not** purged: they are the
evidence behind past decisions, under the same five-year retention decision as
other regulatory artifacts (engineering conventions §18).

## What this does not cover

- **Upstream staleness.** We measure when we last *checked* the source, not
  when the source was last updated. If an upstream extraction stops, our fetch
  keeps succeeding against a stale file.
  `intel_sanctions_list_content_changed_timestamp_seconds` (dashboard only) is
  how that shows up: a fresh list whose content has not changed in a long
  time. No list promises a publication cadence, so there is no principled
  threshold to alert on.
- **Sentinels are unset by default.** They are the cheapest defence against a
  right-URL/wrong-file swap, but picking addresses that will certainly stay
  designated is a compliance judgement, not an engineering one.
