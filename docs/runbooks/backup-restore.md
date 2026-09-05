# Runbook — Backup, restore, and the RPO/RTO they measure

**Owner:** whoever is on call for the data plane (Postgres, ClickHouse, event store).
**Covers:** production readiness [Epic B](../../production_readiness.md) — *"Backups + tested restore for event store, Postgres, ClickHouse. Define and measure RPO/RTO."*
**Code:** [`crates/backup/`](../../crates/backup/) · **Related:** [projection rebuild](projection-rebuild.md), which is the *other* recovery path.

> An untested backup is a belief, not a control.

This runbook, like the rebuild one, is **two things at once** — and they run the same code, so the procedure you execute at 3am is the one exercised on every integration build.

| | command | when | what a failure means |
|---|---|---|---|
| **The drill** | `just backup-drill` | on a timer, and before GA sign-off | the artifact is **not restorable as claimed** — page |
| **The recovery** | `just backup-restore` | after data loss | the diff is a **damage report**; the restored state is what you have |

---

## 0. TL;DR

```bash
just backup-report          # where do we stand? exits 2 on a breached objective
just backup-list            # what artifacts exist, how old, and whether any is INCOMPLETE
just backup-fingerprint     # what is in the LIVE store right now (read-only)
just backup-snapshot        # take one now (before a risky migration)
just backup-drill           # THE CONTROL. Non-destructive. Exits 2 on divergence.

# Recovery — writes into a database you name. Requires --yes.
just backup-restore postgres detector_recovered
```

**`drill` never writes to a live database.** It restores into a throwaway database it creates and drops. That is why it needs no maintenance window, and why it belongs on a timer rather than on a quarterly checklist.

---

## 1. What is backed up, and what that buys you

| target | store | cut | role |
|---|---|---|---|
| `postgres` | Postgres, every non-system schema | **one exported MVCC snapshot**, shared by `pg_dump` and the fingerprint | mostly **system of record** — rules, approvals, labels, entities, sanctions, delivery ledgers. `incidents` / `sim_jobs` / `cross_chain_findings` are derived and marked so. |
| `clickhouse` | the whole ClickHouse database | `events`: **`appended_at < W`** watermark. Everything else: streamed read. | `events` is the **system of record** (§4). Every other table is a fold over it. |

**Tables are discovered, never listed.** Both targets enumerate what is actually present at snapshot time, so a table added by the next migration is in the next artifact without anyone remembering to update anything. The manifest records the set, and the drill fails if the restore's set differs.

**Backing up derived state is a convenience.** Restoring `incident_analytics` is far faster than re-deriving it — but if a restore and a [projection rebuild](projection-rebuild.md) ever disagree, **the rebuild wins by definition**. The rows with no second path are what the RPO is really about.

### Not covered, deliberately

* **Redis** — a cache. Cold-start repopulates it; there is nothing in it that is not derivable.
* **Kafka** — the wire, not the record (§2/§4). Its 7-day retention is a replay buffer, not a backup.
* **RabbitMQ** — in-flight `SimulationJob` *commands*. A lost job is re-derivable from the alert that caused it.
* **A materialized view declared without `TO <table>`** — its data lives in an inner table whose name embeds a UUID that cannot be recreated elsewhere. The snapshot records this as a typed `NotCovered` note, which makes the artifact **incomplete**: `just backup-list` prints `INCOMPLETE`, `backup_artifact_incomplete_objects` alerts (`BackupArtifactIncomplete`), and **the drill refuses to pass** — an artifact known not to cover part of the system can restore perfectly and still not be a backup of that system. There are none today; if one appears, declare it with an explicit `TO`. Contrast a `Skipped` note (a view definition, a `Memory` table), which loses nothing and does not fail anything.

---

## 2. The definitions (this is the "define" half of the epic)

**RPO — how much recent data an incident may destroy.**
Measured as `now − cut_at` of the newest artifact **that a recent drill has shown to be restorable**. Three deliberate choices:

* measured from the artifact's **cut**, not from when the dump *finished* — a dump that starts at 01:00 and lands at 03:00 protects you to 01:00, and the gap grows with the data;
* an **unverified** artifact does not count. If the last passing drill is older than `BACKUP_DRILL_MAX_AGE`, the objective is breached even while snapshots land on schedule. That is the entire point;
* it is **per target**, and the exposure is the *worst* of them.

For the event store, events accepted by Kafka but not yet appended are **not** in this window — they are replayable from the broker for `KAFKA_RETENTION_MS` (7 days), provided the brokers survive. The measured RPO is the bound on *unrecoverable* loss given a total ClickHouse loss, which is the number that belongs in a customer commitment.

**RTO — how long recovery may take.**
Measured as the drill's own wall clock (integrity → provision → restore → verify) against the **real, current-sized** artifact, **plus a declared orchestration overhead** for what a drill cannot execute: deciding to fail over, getting hands on a terminal, repointing services, warming caches. That overhead is an estimate a human wrote down. It is reported on its own line and labelled as such — a measurement and an estimate presented as one number is how RTOs come to be wrong by an order of magnitude.

### The budgets

Configured, not compiled — and exported as metrics, so the alert rules compare two series and cannot drift from the commitment.

| variable | default | meaning |
|---|---|---|
| `BACKUP_RPO` | `1h` | data-loss budget |
| `BACKUP_RTO` | `4h` | recovery-time budget |
| `BACKUP_ORCHESTRATION_OVERHEAD` | `30m` | declared, un-measured human time added to every measured restore |
| `BACKUP_DRILL_MAX_AGE` | `7d` | how stale the *evidence* may get |
| `BACKUP_SNAPSHOT_INTERVAL` | `BACKUP_RPO / 4` | three consecutive failures before the budget is actually blown |
| `BACKUP_DRILL_INTERVAL` | `24h` | |
| `BACKUP_RETENTION` | `30d` | pruning never removes the newest artifact |
| `BACKUP_DIR` | `/var/lib/mevwatch/backups` | must not share a failure domain with the databases |

---

## 3. How it works, in one picture

```
  snapshot ──► BEGIN REPEATABLE READ READ ONLY
               pg_export_snapshot() ──┬──► fingerprint every discovered table
                                      └──► pg_dump --snapshot=<id>     ONE instant
                                                    │
                                              artifact + manifest.json
                                                    │
  drill ──► checksums ──► CREATE DATABASE …_drill_… ──► restore ──► re-fingerprint
                                                    │                     │
                            manifest.tables ────────┴──── diff ───────────┘
                                                    │
                                     pass → RTO recorded, RPO armed
                                     fail → missing / unexpected / changed
```

The mechanism that makes this different from a cron'd `pg_dump`: **the fingerprint is taken inside the dump's own cut.** `pg_dump --snapshot=<id>` reads the same MVCC snapshot the fingerprint queries ran in, so the manifest describes *the bytes*, not the database at some nearby instant. ClickHouse's log gets the same guarantee from the `appended_at < W` watermark; its derived tables are fingerprinted from the streaming rows as they are written.

Without that, a restore is compared against a description of an instant that never existed, and the drill either fails constantly (so it gets switched off) or is only ever run against a quiesced database (which is not the thing you need to restore).

---

## 3a. Failures are classified, and only one kind pages

Every failure answers one question: *will retrying on the next cycle plausibly succeed without a human?*

| `backup_runs_total{outcome}` | meaning | alert |
|---|---|---|
| `transient` | a store restart, a reset connection, a 503 | none per-occurrence; `BackupSnapshotRetryingPersistently` if they pile up |
| `permanent` | `pg_dump` older than the server, an unwritable volume, DDL that will not replay | **`BackupSnapshotFailingPermanently` pages immediately** |
| `cancelled` | a rolling deploy drained the agent | none — this is not a failure |

The reason this split exists: before it, all three logged identically, and "ClickHouse blipped for ten seconds" was indistinguishable from "no backup has been possible since the Postgres upgrade". A permanent failure now pages **long before** the RPO budget would have caught it. Ambiguous cases are deliberately classified `permanent` — a spurious page is cheaper than a silent gap in the one control standing between an incident and permanent data loss.

Postgres failures go through `db::is_permanent`, the workspace's single classifier, so retry decisions here cannot drift from every other crate's.

## 3b. Scratch databases: cleanup happens on the next run

A drill restores into a throwaway database named `<db>_drill_<YYYYMMDDHHMMSS>_<pid>`. **That timestamp is load-bearing** — neither Postgres nor ClickHouse exposes a per-database creation time to an unprivileged role, so the name is the clock.

Every drill **sweeps first**: any `…_drill_…` database older than 6 hours is dropped before the run starts. That, not a `Drop` impl, is the leak guarantee — Rust has no async destructor and a `SIGKILL` runs none at all, so a design that cleaned up only on the way out would leak the first time a pod is evicted. A leak is also logged loudly by the run that caused it, and counted (`backup_scratch_swept_total`).

The sweep will **only** touch a name it can positively identify as a scratch database with a parseable timestamp. `mev`, `customer_drilling_data` and `mev_drill_notatimestamp` are all left alone, at any age.

If you find a stray one by hand: it is safe to drop, and the next drill would have removed it anyway.

---

## 4. The drill

### 4a. Run it

```bash
just backup-drill                    # both targets
just backup-drill postgres           # one
cargo run -p backup -- drill --target clickhouse --keep   # leave the copy to poke at
```

Needs `DATABASE_URL`, the `CLICKHOUSE_*` set, `BACKUP_DIR`, and — for the Postgres target — `pg_dump`/`pg_restore` on `PATH` **at a major version ≥ the server's** (an older client refuses outright; the manifest records the version that wrote each artifact).

### 4b. Read the verdict

```
drill PASSED on postgres (postgres-20260904T110213Z): 0 table(s), 41823 row(s),
  184320104 bytes restored and verified in 94.2s (restore 71.4s, verify 22.8s) — 1m34s
no divergence: the restored copy matches the manifest exactly
```

A failure names the class, and the class **is** the diagnosis:

| class | meaning | first move |
|---|---|---|
| `missing from the restore` | the restore did not finish, or the dump could not be read | read the tool's stderr; check the client/server versions in the manifest |
| `present in the restore but not the artifact` | the scratch destination was not empty — the drill measured something other than this artifact | drop leftover `*_drill_*` databases and re-run |
| `restored but not equal` | **the dangerous one.** The restore "succeeded" and the data differs | see below |

For `restored but not equal`, the message distinguishes two very different things:

* `N row(s) expected, M restored` — rows were lost or gained.
* `same count, different data` — the right number of wrong rows. Almost always an unpinned session setting (a value's *text* form differs) or a genuinely corrupted dump. Check `pg_dump`'s major version against the manifest's `tool` field first.

### 4c. Exit codes

`0` fine · `1` the tool failed · **`2` the tool worked and the answer is bad** (divergence, or a breached objective). CI and the pager distinguish these.

---

## 5. The recovery

**Before you start:**

1. **Stop writers to the target database.** A restore into a database something is still writing produces a mixture nobody can reason about later.
2. **`just backup-report`** — know the RPO you are about to accept *before* you accept it. Everything after the artifact's `cut_at` is gone unless the event store can re-derive it.
3. **`just backup-verify`** — 30 seconds, and it distinguishes "the backup is damaged" from "the restore is broken" before you spend an hour on the wrong one.
4. **Restore into a NEW database, not over the old one.** The damaged original is evidence, and it may hold rows the backup does not.

```bash
# ClickHouse or Postgres, into a database you name:
cargo run -p backup -- restore --target postgres --into detector_recovered --yes
```

The restore ends with the same fingerprint comparison the drill uses, so you get a **damage report**, not a hope:

```
restored postgres-20260904T110213Z into detector_recovered in 1m41s — restored but not equal (1):
  - public.rules: 812 row(s) expected, 812 restored, but the contents differ — same count, different data
```

A divergence here is **not** a refusal — you have already lost the original and need to know exactly what came back.

**Then cut over:** repoint `DATABASE_URL` / `CLICKHOUSE_DB` at the recovered database, restart the services that hold pools, and re-run `just backup-report`.

### 5a. When to rebuild instead of restore

For a **derived** table (`incidents`, `sim_jobs`, `cross_chain_findings`, and every ClickHouse table except `events`), you have two paths:

| | restore | [rebuild](projection-rebuild.md) |
|---|---|---|
| speed | minutes | hours (it replays the log) |
| result | state as of `cut_at` | state as of **now** |
| authority | a copy | **the definition** |

**Rule of thumb:** if the event store is healthy, rebuild the derived state and restore only the system of record. You lose nothing between `cut_at` and now, which is the entire reason §2's "projections are derived" was worth proving.

If the **event store itself** is what was lost: restore `events` first, let the projection consumers catch up from their committed offsets, then rebuild anything that looks wrong.

---

## 6. The scheduled agent

`backup serve` holds the schedule and exports the gauges. Deployed as a Deployment (`deploy/k8s/base/services/backup.yaml`), not a CronJob, for one reason: **a CronJob cannot report that it did not run.**

**The schedule is driven by observed state, not by a timer.** A 30-second heartbeat publishes the gauges and then asks "is the newest artifact older than the cadence?" — and only then spawns the work, on its own task. Three things follow, and each of them was a bug in the first cut of this agent:

* a multi-hour `pg_dump` can no longer block the loop that publishes `backup_artifact_age_seconds`. It used to run inline, so the RPO gauge froze for the whole snapshot while Prometheus happily scraped the stale value — the exact "monitoring the monitor" failure this crate exists to prevent, self-inflicted;
* a restart cannot lose or double the schedule. A crash-looping pod used to take a full `pg_dump` on every restart, because `tokio::time::interval` fires its first tick immediately;
* a missed cycle is caught up on the next heartbeat rather than replayed as a burst of back-to-back runs (`MissedTickBehavior`'s default).

A drill is **not attempted when there is no artifact to drill** — that is not a drill failure, it is the absence of a backup, which `BackupRpoBreached` already covers. Similarly, an artifact directory with no `manifest.json` yet is an in-flight snapshot, not a damaged one: it is skipped quietly rather than warned about every 30 seconds for the duration of every snapshot. A warning that fires for hours is one an operator learns to ignore, and this one (a genuinely corrupt manifest) is worth keeping sharp.

Only one snapshot and one drill run at a time. A cycle that comes due while the previous is still running is **skipped and counted** (`backup_cycles_skipped_total`, `BackupCyclesSkipped`) — a steady stream of skips means the job has outgrown its interval, which is a capacity signal you get long before it becomes an RPO breach.

`SIGTERM` cancels in-flight work cooperatively, including killing a running `pg_dump` child, and the agent drains for up to 45 seconds before exiting. Delete it, scale it away, let its image fail to pull, and the metric it would have written is simply absent — indistinguishable on a dashboard from healthy. The signals that matter here are *ages*, and an age has to be published by something alive. `up{job="backup"}` covers the case where the agent is what died.

| metric | says |
|---|---|
| `backup_artifact_age_seconds{target}` | **the measured RPO** — climbs on its own the moment snapshots stop |
| `backup_drill_age_seconds{target}` | age of the last **passing** drill — the evidence's own freshness |
| `backup_objective_seconds{target,objective,kind}` | `budget` and `measured` side by side, so an alert rule hard-codes no threshold |
| `backup_drill_duration_seconds{target}` | **the RTO input**; alert on growth, not on a fixed value |
| `backup_drill_divergence_tables{target,class}` | `missing` / `unexpected` / `changed` |
| `backup_artifact_incomplete_objects{target}` | data the artifact does not cover at all |
| `backup_runs_total{target,outcome}` | `success` / `transient` / `permanent` / `cancelled` |
| `backup_cycles_skipped_total{target,job}` | the job no longer fits its interval |
| `backup_scratch_swept_total{target}` | leaked scratch databases cleaned up by a later run |
| `backup_artifact_bytes{target}` | a cliff here is a truncated backup that still "succeeded" |

Alerts ship in [`deploy/prometheus-rules.yml`](../../deploy/prometheus-rules.yml): `BackupRpoBreached`, `BackupRtoBreached`, `BackupDrillStale`, `BackupDrillFailing`, `BackupSnapshotFailingPermanently`, `BackupSnapshotRetryingPersistently`, `BackupArtifactIncomplete`, `BackupArtifactShrank`, `BackupCyclesSkipped`, `BackupAgentAbsent`.

---

## 7. Offsite

`BACKUP_DIR` must not share a failure domain with the databases — a backup on the disk that just died is not a backup. Replication is an `rsync`/`aws s3 sync` of that root; the per-file SHA-256 in every manifest is what makes the far copy checkable:

```bash
aws s3 sync "$BACKUP_DIR" s3://mevwatch-backups/ --delete-excluded
# then, ON THE FAR SIDE:
BACKUP_DIR=/mnt/restored cargo run -p backup -- verify
```

**`verify` checks bytes, not restorability.** A dump truncated *before* its checksum was taken passes it, and so does a perfectly-preserved dump of a schema no current binary can read. To actually trust the offsite copy, run a `drill` against it — which is a `BACKUP_DIR` change and nothing else.

Not yet done, and worth knowing: nothing in this crate replicates offsite for you, and the drill always restores to the **same server** — it does not prove you can obtain a new one.

---

## 8. After any drill or recovery, record in the ticket

1. The artifact id and its `cut_at`.
2. Measured **RPO** (`backup_artifact_age_seconds`) and measured **RTO** (`backup_drill_duration_seconds` + the declared overhead) — these are Epic B's exit-gate inputs.
3. Divergence counts per class, if any.
4. For a recovery: which database you cut over to, and what you did about the window after `cut_at`.

## 9. Verifying this runbook itself

```bash
just backup-drill-test    # the testcontainers suite: real Postgres + real ClickHouse
```

It backs up a live database, restores it elsewhere and asserts row-for-row equality — including a write landing *mid-backup*, a table added after the last release, a bit-rotted artifact, a materialized view that must not double-write, a merging engine whose raw rows collapse underneath the comparison, a leaked scratch database that a later run must sweep (and a production database it must not), and an incomplete artifact that must fail the drill however well it restores. CI runs it on every build (`--run-ignored all`).

One check has no test and is not supposed to have one: **you cannot pass a live database to `drop_scratch`.** A `Scratch` is only constructible by `provision_scratch` and is consumed by value, so the mistake does not compile. The compiler is the test.
