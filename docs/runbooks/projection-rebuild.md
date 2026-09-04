# Runbook — Projection rebuild

**Owner:** whoever is on call for `simulation-projection`.
**Covers:** production readiness [Epic B](../../production_readiness.md) — *"Projection rebuild runbook: wipe a read model, replay from the event store, confirm byte-identical result (§2 — projections are derived; prove it)."*

This runbook is **two things at once**, and that is deliberate:

| | command | when | what a divergence means |
|---|---|---|---|
| **The drill** | `verify` | on a schedule, and before GA sign-off | a **failure** — the read model was not purely derived from the event store |
| **The recovery** | `rebuild` | after a corruption incident | the **damage report** — the event store is the system of record, so the rebuilt state wins by definition |

They run the same code. That is the point: the procedure you run at 3am under pressure is the one exercised on every integration build, not a script written during the incident.

---

## 0. TL;DR

```bash
# Read-only fingerprint. Take one before anything risky.
just projection-fingerprint all

# The drill. NON-DESTRUCTIVE — safe against production, exits non-zero on divergence.
just projection-rebuild-verify

# The recovery. Promotes the rebuilt model over the live one.
just projection-rebuild            # or: ... -- rebuild --model incidents --yes
```

**`verify` never writes to the live read model.** It builds the replacement in a staging namespace, compares, and drops it. That is why it needs no `--yes` and no maintenance window — and why it should be on a timer, not a checklist.

---

## 1. How it works, in one picture

```
       ┌── GET /v1/watermark ──►  pin W  (the store's own ingest clock)
       │
  live tables ──fingerprint──┐
       │                     ├──► diff ──► promote (rebuild) | discard (verify)
  staging namespace ─────────┘
       ▲
       └── replay [epoch, W) ──► the REAL ProjectionConsumer ──► staged tables
```

Three properties follow, and they are the reason this is safe to run:

1. **Nothing is ever wiped.** The replacement is built beside the live model and swapped in. There is no window where readers see an empty table, and a fault mid-run leaves production *exactly as it was*.
2. **The replay is a consistent cut.** `W` bounds it on **ingest** time (`appended_at`), not event time, so all replay lanes stop at the same point in the log. Without it, events arriving *during* the run would show up as phantom divergences.
3. **The fold is the live fold.** Staging is a *namespace* — a Postgres schema on the `search_path`, a ClickHouse database — so the unmodified production write path targets it. The rebuild runs `ProjectionConsumer::handle`, the same handler Kafka drives.

---

## 2. What is rebuildable, and what "byte-identical" means

| `--model` | store | tables | promotion |
|---|---|---|---|
| `incidents` (aka `postgres`) | Postgres | `incidents`, `sim_jobs`, `cross_chain_findings` | **atomic** (transactional DDL) |
| `dashboards` (aka `analytics`) | ClickHouse | `incident_analytics`, `incident_timing_rollup` | two `EXCHANGE TABLES` — see below |
| `all` | both | both | one replay drives both |

**Byte-identical is over derived columns only.** Four are excluded, by name:

- `incidents.updated_at` · `sim_jobs.updated_at` · `cross_chain_findings.updated_at` · `incident_analytics.appended_at`

Each is `now()` at write time — a clock, not a projection. **Every other column is compared**, including the event-time watermarks (`figures_at`, `retracted_at`, `finalized_at`, `observed_at`).

> If you ever want to add a column to that list because "it comes out different", **that is the finding, not the fix.** A column that is not a function of wall-clock-at-write and does not reproduce is state that is not derived.

**A rebuild is total.** A scoped (`--chain`, windowed) rebuild is *refused*, not approximated: a staged replacement built from a window would be promoted missing everything outside it.

**ClickHouse promotion is not atomic across the pair.** `EXCHANGE TABLES` is pairwise, so between the two statements a dashboard query could read one table swapped and the other not — a sub-millisecond window. Acceptable because these are the trend surface, not the system of record. The Postgres read model, which the §11 API serves to customers, has no such window.

---

## 3. Before you start

`verify` needs only step 1. `rebuild` (promotion) needs all of them.

1. **Confirm the event store is healthy and current.** `GET /healthz`, and `kafka_consumer_lag` at zero for the event-store group. A rebuild from a *behind* event store reproduces a *stale* read model, and the diff will look like mass data loss.
2. **Stop the live `simulation-projection` consumer** *(promotion only)*. If it keeps consuming while you promote, its in-memory fold holds state the rebuild's fresh fold does not, and the two will write over each other.
3. **Know your disk headroom.** Staging is a full second copy of the read model until it is promoted or discarded.
4. **Size the run.** Duration is dominated by event count, not row count. `--page-size` (default 2000) tunes the replay round-trips.

You do **not** need to take the read model out of rotation. It stays readable throughout and is replaced only at the instant of promotion.

---

## 4. The procedure

### 4a. Fingerprint (read-only, always safe)

```bash
cargo run -p simulation --bin simulation-projection -- fingerprint --model incidents
```
```
simulation-incidents: 41823 row(s)
root: 9f2c…
```
Record the root hash in the ticket.

### 4b. Run it

```bash
# Drill — non-destructive, non-zero exit on divergence:
cargo run -p simulation --bin simulation-projection -- verify --model incidents

# Recovery — promotes:
cargo run -p simulation --bin simulation-projection -- rebuild --model incidents --yes
```

Environment: `DATABASE_URL`, the `CLICKHOUSE_*` set (for `dashboards`/`all`), and **`EVENT_STORE_URL`** (e.g. `http://event-store:8081`). The rebuild reads through the published `GET /v1/replay`, not the ClickHouse table behind it, so every replayed envelope goes through `EventEnvelope::from_json_slice` and therefore the `schema_version` check and the `events::upcast` seam (§17).

Progress logs every 30s. **Ctrl-C / SIGTERM stops cleanly**, discarding the staging area.

### 4c. Read the verdict

```
rebuild `simulation-incidents` as of 2026-09-04T11:02:13+00:00: 118402 events replayed,
  41823 live row(s) -> 41824 staged, 94.2s (PROMOTED — the staged model is now live)
live root:   9f2c…
staged root: 7a10…
verdict: 2 diverging row(s)
  lost (live only) (1): incidents/6f1e…
  gained (rebuild only) (1): incidents/b204…
```

---

## 5. Interpreting a divergence

Every diverging row lands in exactly one of three classes, and **the class is the diagnosis**.

### `lost` — live has it, the rebuild does not
Nothing in the event store produced this row.
- **Most serious class.** Either some path mutated state without emitting an event — a hole in the §4 audit-completeness guarantee, a Bucket-1 non-negotiable and a compliance problem — or somebody wrote the row by hand.
- Check the store first: `GET /v1/audit/incident/{incident_id}`.
- **Escalate before promoting.** A `verify` leaves the row in place; a `rebuild` moves it to the superseded schema (§6), where it is still recoverable — but investigate before you drop that schema.

### `gained` — the rebuild has it, live did not
The live projection dropped a write it owed.
- On `--model dashboards` this has a **known cause**: `incident_analytics` is appended only on a real change, so a store fault between the `incidents` upsert and the analytics append — followed by a redelivery that re-folds to `Duplicate` — loses that row permanently. Accepted debt, recorded in [`projection_consumer.rs`](../../crates/simulation/src/projection_consumer.rs). **The rebuild is the first thing that can measure how often it happens** — record the count.
- On `--model incidents` it should not happen. If it does, that is a real finding.

### `changed` — both have it, different content
The fold and the stored row disagree.
- Overwhelmingly: **projection logic deployed without a rebuild.**
- Otherwise: actual corruption (a bad migration, a hand-run `UPDATE`).
- Confirm the *new* value is the intended one before promoting — if the fold itself has a bug, the rebuild faithfully reproduces the bug.

---

## 6. After a promotion

1. **The previous generation is kept**, in a Postgres schema named `rebuild_…_superseded`. It is the only copy of any `lost` row and your rollback. Verify the new state, then drop it:
   ```sql
   DROP SCHEMA "rebuild_simulation_incidents_20260904_110213_superseded" CASCADE;
   ```
2. Compare the reported `staged root` with a fresh `fingerprint` — they must match.
3. **Restart the `simulation-projection` consumer.** This is part of the procedure, not cleanup: the rebuild is "as of `W`", and the consumer resuming from its committed Kafka offsets (which are behind `W`) is what carries the model forward across the narrow band of events in flight around the cut. Every write is idempotent, so re-consuming the tail is a no-op against the rebuilt rows.
4. Record in the ticket: the two root hashes, counts per divergence class, and the duration — the duration is Epic B's RTO input.

---

## 7. Failure modes of the procedure itself

| symptom | meaning | do this |
|---|---|---|
| `refusing to promote …: the plan is not confirmed` | `rebuild` without `--yes` | nothing happened; re-run with `--yes`, or use `verify` |
| `… live state is UNCHANGED` | a fault mid-run | the staging area was discarded and **production is intact**. Fix the fault and re-run from the top. |
| `… (staging area 'X' may need dropping)` | cleanup itself failed | `DROP SCHEMA "X" CASCADE` / `DROP DATABASE "X"`. It holds no live data. |
| `cancelled after N event(s)` | you stopped it | expected; production untouched |
| `event … was rejected as poison during a rebuild` | an event the fold cannot process | live, this would be dead-lettered and the projection would carry on silently missing it; during a rebuild it is a hard stop, because the alternative is a plausible **wrong** projection. Investigate that event. |
| `event … could not be decoded` | the binary is older than the event | deploy a build that can read it. Never skip it. |
| `supports only a full rebuild` | you passed a narrowed scope | see §2 — a rebuild is total by design |
| `two rows share the business key …` | the read model's own uniqueness is broken | a schema/constraint bug independent of the rebuild. Escalate. |

---

## 8. Monitoring

The CLI records §19 metrics on every run (`crates/rebuild/src/observed.rs`):

| metric | alert on |
|---|---|
| `projection_rebuild_divergence_rows{class="lost"}` | **> 0 — page.** An audit-completeness hole. |
| `projection_rebuild_divergence_rows{class="changed"}` | > 0 — projection logic deployed without a rebuild |
| `projection_rebuild_divergence_rows{class="gained"}` | trend only on `dashboards` (known debt); investigate on `incidents` |
| `projection_rebuild_runs_total{outcome="failed"}` | rising — the drill itself is broken, which is worse than a failing drill |
| `projection_rebuild_duration_seconds` | the RTO input; alert on growth, not on a threshold |

Because `verify` is non-destructive, **run it on a schedule.** A drill that needs an outage window gets run once before GA; a drill on a timer is a standing guarantee.

---

## 9. Adding a new rebuildable read model

The seam is [`crates/rebuild`](../../crates/rebuild/). Implement the three traits next to the projection they belong to (not in the `rebuild` crate):

- **`Projector`** — `event_types`/`apply`/`flush`. **`apply` must drive the live consumer**, not a copy of it. Share the consumer's own event-type constant, so a newly consumed type is replayed automatically instead of being silently absent from every future rebuild.
- **`Snapshotter`** — `digest` over the live model. Exclude only wall-clock-at-write columns, and name each one in the docs.
- **`Stageable`** — `stage`/`digest_staged`/`promote`/`discard`. **`stage` must return a projector that writes only to the staging area** — a leaked write to the live tables would corrupt production during a non-destructive verify. Prefer a *namespace* (schema/database) so the production write path needs no modification.

Then add a `verify` test alongside [`crates/simulation/tests/projection_rebuild.rs`](../../crates/simulation/tests/projection_rebuild.rs) and a `just` recipe.

**Not yet rebuildable, and known:** the intelligence service's Postgres store (labels, entities, attributions, sanctions) and its ClickHouse adjacency graph. Risk scores are a *cache* over that store — invalidated and recomputed by `intelligence::risk_scorer` — so they follow it rather than needing their own procedure. Wiring intelligence to this seam is the remaining work for Epic B's exit gate; the mechanism is in place for it.
