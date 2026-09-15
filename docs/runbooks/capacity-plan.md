# Runbook — Capacity plan: partitions, shards, storage growth, and the write path under them

**Owner:** whoever plans infrastructure spend and operates the data platform (ClickHouse, Kafka).
**Covers:** readiness Epic D, "Capacity plan". Related conventions: [§4](../engineering-conventions.md) (parse, don't validate), [§18](../engineering-conventions.md) (retention decides the window), [§19/§19b](../engineering-conventions.md) (an instrument that can fail; threshold provenance).
**Code:** [`crates/capacity/`](../../crates/capacity/) (model + gate) · [`model.json`](../../crates/capacity/model.json) · [`ch_migrate::swap`](../../crates/ch-migrate/src/swap.rs) · [`event_store::repartition`](../../crates/event-store/src/repartition.rs) · [`event_store::tiering`](../../crates/event-store/src/tiering.rs) · [`events::partitioning`](../../crates/events/src/partitioning.rs)
**Related:** [retention](retention.md) · [backup + restore](backup-restore.md) · [load test](load-test.md) · [projection rebuild](projection-rebuild.md)

> A bill grows smoothly and is noticed. A server limit is a cliff, and the live path never walks near it.

---

## 0. TL;DR

```bash
just capacity-plan                           # the plan at projected load (exit 1 on a breach)
just capacity-check                          # the gate CI holds: 1.5× projected load
just capacity-plan --evidence-days 3653      # what a ten-year retention policy would cost
just capacity-plan --partition-by "(chain, event_type, toDate(occurred_at))"   # the original key

event-store repartition                      # where the events table replacement stands
event-store repartition run                  # move data + swap (the event-store-repartition Job)
event-store repartition finalize --i-understand-this-drops-the-retired-table
```

Every input to the plan is a committed file, so a run needs no stack and is reproducible from a commit:

| input | from | why there |
|---|---|---|
| event rates | `crates/capacity/model.json` | projections, each term with a rationale |
| row + record sizes | `crates/events/schema/corpus/` | real envelopes through the production reader |
| every ClickHouse table's partition key, engine and TTL | each crate's `migrations/`, replayed in order | the tables that will exist, not a restatement |
| evidence window | `retention::PolicySet` | one retention decision (§18) |
| partition count, batch shape, volumes | `deploy/k8s/base/*` | pinned by test, so the gate judges what is deployed |

The same gate runs as `crates/capacity/tests/committed.rs` in the ordinary nextest pass.

---

## 1. What the plan says (1×, 2026-09-15)

```text
day one: 6.66M events/day · 1.1 GiB stored/day (one replica) · 2.5 GiB payload/day · 3.2 GiB on the wire/day
  AddressEmbeddingUpdated     2.00M   269 B   513 MiB   44.8%
  ScreeningDecisionRecorded   1.56M   244 B   361 MiB   31.5%
  UsageRecorded               2.67M    88 B   223 MiB   19.5%
year  events/day   stored     cold   shards nodes  provisioned  kafka/broker  $/month
   1      9.32M  485 GiB   350 GiB      1     2      3.9 TiB      32 GiB        718
   8     98.24M  15.2 TiB  13.8 TiB     1     2      3.9 TiB     335 GiB       1409
scenarios: low (1.15×/yr) 5.0 TiB · high (2×/yr) 145 TiB, 16 shards, $12.9k/month
sensitivity: annual_growth +10% → +78% storage · compression −25% → +33%
ingest: 4548 events/s at the horizon peak → 3.0 inserts/s (limit 10)
kafka: 41 topics × 12 partitions × RF 3; chains → partition 0 (Ethereum), 1 (Base)
```

- **stored** is one replica on disk after compression and index overhead; **cold** is the part past `cold_after_days` (90), on object storage.
- **shards** are sized by what sits on *local* disk. With tiering, one 2 TiB node per replica holds the hot 90 days through year 8. Without tiering (`cold_after_days: null`) the same load needs 11 shards × 2 by year 8.
- **$/month** is storage only: block storage for nodes and brokers, object storage for cold, at assumed prices.
- **Sensitivity** says what to measure first: the growth forecast, then the compression ratio.
- The store does not grow forever. It grows until the TTL drops parts at the evidence window (plus up to a month, `ttl_only_drop_parts`), then tracks the growth rate.

---

## 2. Breach or advisory — the check registry

Each check has a stable id (`capacity::checks::registry`). **A breach is a decision that is expensive to reverse**; **an advisory is a purchase**, reported with the day it arrives.

| id | severity | what it guards |
|---|---|---|
| `clickhouse.max_parts_in_total` | breach | a table passing the server's part limit refuses every insert |
| `clickhouse.partition_budget` | breach | merges, startup and metadata scale with partition count |
| `clickhouse.max_partitions_per_insert_block` | breach (inside the horizon) | a restore replays in the dump's order, so one block can touch every partition; over 100 it throws |
| `event-store.inserts_per_second` | breach | every insert is a part; an ingest shape that out-inserts merges is throttled, then refused |
| `clickhouse.shard_key` | breach | `ReplacingMergeTree` collapses duplicates within a shard only; the key must be a hash of `event_id` alone |
| `kafka.deployed_partitions` | breach | a topic whose peak needs more partitions than deployed (growing re-maps business keys) |
| `kafka.max_partition_replicas_per_broker` | breach | a broker that cannot hold its partitions |
| `kafka.chain_placement` | advisory | a chain without a partition slot shares a partition |
| `clickhouse.shards`, `deploy.volumes`, `kafka.broker_disk_gib` | advisory | purchases |
| `retention.window` | advisory | the widest evidence window the events key keeps restorable |
| `clickhouse.unbounded_tables` | advisory | tables with no TTL: no retention decision |
| `model.assumed` | advisory | parameters not yet measured |

**A breach on your PR** means one of the inputs moved: a new event type's rate, a payload that grew, a retention change, a new or changed ClickHouse table, the batch shape, the partition count. Change the decision the finding names, or change the model with a rationale a reviewer can check. There is no flag to update a baseline, by design.

---

## 3. Adding or changing an event type or a table

**Event type.** `every_domain_event_is_priced_and_nothing_else_is` fails until `model.json` prices it:

```json
"MyNewEvent": {
  "terms": [{ "driver": "alerting_block", "per": 0.5 }],
  "rationale": "What emits it, and how often."
}
```

Drivers: `block`, `transaction`, `alerting_block` (per chain); `api_request`, `screen`, `active_address`, `customer` (global); `day` (fixed daily, not scaled by headroom). A term may carry `payload_bytes` when the corpus fixture is not the production size, or when one type is published in two shapes (`AddressEmbeddingUpdated`: full and refresh).

**ClickHouse table.** Nothing to register: the gate replays every crate's migrations. A partition key it cannot price (`x % 16`) fails the build with the component to add to `capacity::key::Component`. Give the table a TTL, or it is listed by `clickhouse.unbounded_tables`.

**Changing a partition key, sorting key or engine.** ClickHouse cannot `ALTER` those. Create the new definition as `<table>__next` in a migration (DDL only). Boot completes the swap when the live table is empty. With data, see §5.

---

## 4. Replacing assumptions with measurements

Every report lists what is still assumed. Replace one by setting its `basis` to `{"kind": "measured", "on": "<date>", "how": "<the query>"}`.

**Compression ratio:**

```sql
SELECT sum(data_uncompressed_bytes) / sum(data_compressed_bytes) AS ratio
FROM system.columns WHERE database = currentDatabase() AND table = 'events';
```

**Real daily rates and payload sizes** (replace the projections once production runs):

```sql
SELECT event_type, count() / 7 AS per_day, avg(length(payload)) AS payload_bytes
FROM events FINAL WHERE occurred_at >= now() - INTERVAL 7 DAY
GROUP BY event_type ORDER BY per_day DESC;
```

The same is live in Prometheus: `sum by (event_type) (increase(event_store_appended_payload_bytes_total[1d]))`.

**Embedding changed share** (the 0.3 / 0.7 split of `AddressEmbeddingUpdated`):
`sum(rate(embeddings_written_total{reason=~"new|changed|schema_changed"}[1d])) / sum(rate(embeddings_written_total[1d]))`.

**Per-partition throughput:** `kafka-producer-perf-test.sh` against a production broker at the production replication factor, `acks=all`, record size ≈ the busiest topic's envelope.

**Prices:** the contracted $/GiB-month for the block volume class and the object-storage class.

---

## 5. Replacing a table definition that holds data

### The event store (`events`)

Migration `0004_create_events_next` creates the capacity plan's definition as `events__next`:

- **monthly partitions** — 74 across the evidence window whatever the number of chains or types; chain and type stay the leading `ORDER BY` columns;
- **`ReplacingMergeTree`** keyed by `(chain, event_type, occurred_at, event_id)` — a redelivered event collapses (§6);
- **`non_replicated_deduplication_window`** — an exact batch retry is refused at insert time;
- **`ttl_only_drop_parts`** — expiry drops whole parts.

What happens where:

| where | does | never |
|---|---|---|
| boot (`repartition::reconcile_safe`) | swaps when `events` is empty (fresh deployment, CI); otherwise sets `event_store_repartition_pending_rows` and serves on the current table | copies, drops |
| `event-store repartition` | prints the state and events still to move, per month | writes |
| `event-store repartition run` (Job `event-store-repartition`, suspended) | copies month by month into `events__next`, `EXCHANGE`s, then catches up any row a writer still on the old table landed late; re-run safe at every step | drops |
| `repartition finalize --i-understand-this-drops-the-retired-table` | proves `events__retired` ⊆ `events` by `event_id`, per month, then drops it | runs without the flag |

Procedure:

```bash
kubectl -n mev exec deploy/event-store -- event-store repartition          # PENDING, with months
kubectl -n mev patch job event-store-repartition -p '{"spec":{"suspend":false}}'
kubectl -n mev logs -f job/event-store-repartition                         # "moved N month(s) and swapped"
kubectl -n mev exec deploy/event-store -- event-store repartition          # "fully contained … can be finalized"
# after a recent backup (backup-restore.md):
kubectl -n mev exec deploy/event-store -- event-store repartition finalize --i-understand-this-drops-the-retired-table
```

If the Job reports `CatchUpIncomplete`, a writer is still on the old table (a rolling update that has not finished). Wait for the rollout, then re-run.

Every statement is bounded by one month: the copy's `NOT IN` set, its insert block, a failure's blast radius. A killed Job resumes, because the state is the data.

`EventStoreRepartitionPending` warns when a store has been pending for a week.

### Simulation analytics (`incident_analytics`)

A derived projection: nothing is copied. Migration `0005_create_incident_analytics_next` stages the monthly definition; boot swaps it when empty. With data:

```bash
simulation-projection rebuild --model dashboards --yes
```

The rebuild's staging database runs the same migrations, swaps (it is empty), replays from the event store and promotes by `EXCHANGE`. The rollup's materialized view follows the table name across an exchange (probed on ClickHouse 26.5). Boot then drops the leftover empty `incident_analytics__next`.

---

## 6. The write path under the plan

**Batched.** The Kafka ingest flushes up to `EVENT_STORE_BATCH_MAX_ROWS` (10000) rows or every `EVENT_STORE_BATCH_MAX_WAIT_MS` (1000) — one insert per flush, offsets committed after it lands. Both values are pinned to the model; the plan gates the insert rate they produce.

**Idempotent, in three layers.**

1. Each insert carries `insert_deduplication_token` = SHA-256 of its sorted event ids: an exact retry is refused at insert time.
2. A redelivery that forms a *different* batch lands duplicates with an identical sorting key, which `ReplacingMergeTree` collapses.
3. Reads use `LIMIT 1 BY event_id`, so no query shows a duplicate before the merge.

**Evidence is never dropped by the batch loop.** An envelope that cannot be encoded is parked on `mev.dlq.event-store` alone. A flush that fails is retried indefinitely, whatever the error: the shared loop's "drop a batch on a permanent error" is correct for a rollup and wrong for the system of record. A wedged ingest pages (`EventStoreAppendErrorsHigh`, consumer lag); nothing is committed past unstored events.

---

## 7. Kafka partition placement

Chain-keyed records go to their chain's registered slot (`Chain::partition_slot`: Ethereum 0, Base 1) modulo the partition count; every other key keeps librdkafka's CRC-32 placement. `KafkaEventSink` chooses the partition explicitly from cached topic metadata, because rdkafka 0.39's `FutureProducer` cannot carry a custom partitioner.

- **Adding a chain:** give it the next free slot. Never renumber one.
- **Growing the partition count:** chains with a slot below the old count stay put; business keys (alert, incident, customer) re-map, so drain lag first. `ensure_topics` never alters an existing topic — grow a topic with `kafka-topics.sh --alter --partitions N` deliberately, then update `KAFKA_TOPIC_PARTITIONS` and `model.json` together (a test pins them).
- **Existing 3-partition topics** (a dev stack): the new placement sends Ethereum to 0 and Base to 1 instead of both to 2. Drain lag before deploying the producer change, or per-chain order breaks across the deploy for records in flight.

---

## 8. Storage tiering

Set all three on event-store, on a server whose storage configuration has the policy ([`deploy/clickhouse/storage-tiered.xml`](../../deploy/clickhouse/storage-tiered.xml): local hot disk, S3-backed cold volume behind a cache):

```text
EVENT_STORE_STORAGE_POLICY=tiered
EVENT_STORE_COLD_VOLUME=cold
EVENT_STORE_COLD_AFTER_DAYS=90
```

**The policy's hot volume must be named `default`** (holding the `default` disk): ClickHouse accepts a table's new policy only if it contains every volume of the old one by name, and tables are created on the `default` policy. A policy whose hot volume is `hot` fails boot with `New storage policy … shall contain volumes of old one`.

Boot sets the table's storage policy and a `TTL … TO VOLUME 'cold'` rule after retention reconciliation. Moving parts deletes nothing, so boot applies it unattended. It refuses, and the service does not start, when the retention window is unreadable, when the move would come at or after expiry, or when the policy has no such volume.

**The trap this closed:** the retention reader used to stop at the first `TO VOLUME` and read the 90-day move rule as the retention window. Boot then saw a shortening and refused to start, so tiering was impossible. The reader now parses every rule, and every TTL write carries the move rules across (`MODIFY TTL` replaces the whole clause).

---

## 9. Re-pinning the drift alert

`EventStoreGrowthAboveCapacityPlan` fires when a day's appended payload bytes exceed 1.25 × the model's year-one projection. The threshold is the plan's `drift ceiling`, and `the_drift_alert_is_pinned_to_the_plan` fails the build when the rule and the model disagree.

When it fires: break the rate down by `event_type`, correct that type's rate or payload size in `model.json` from the measurement, run `just capacity-plan`, copy the printed drift ceiling into the rule, and review the new plan.

---

## 10. Decisions the plan surfaces but does not make

- **Eleven tables have no TTL** (`clickhouse.unbounded_tables` lists them). Five are monthly-partitioned — `usage/usage_events`, `usage/usage_rollup_daily`, `simulation/incident_analytics`, `dataset/ml_dataset_rows`, `dataset/ml_dataset_manifests` — and pass the 100-partition restore limit around year 8.3. The five intelligence tables and the simulation rollup are unpartitioned or keyed by chain, so they never hit a partition limit, but they grow without bound and cannot expire by dropping partitions. Metering retention is a billing and compliance decision; analytics, dataset and embedding retention are product decisions. Each needs one before the partition count or the disk makes it.
- **Retention beyond ~8 years.** The monthly events key keeps a restore within one insert block up to a 3012-day window. A ten-year policy needs a coarser key (`toYear`) or a restore that raises `max_partitions_per_insert_block` first.
- **The cluster itself.** The shard key is decided and gated (`cityHash64(event_id)`, two replicas). Standing up `ReplicatedMergeTree` behind `Distributed` with a Keeper ensemble is Epic A's HA item (Sprint 25 t2); tiering keeps one node per replica sufficient through year 8 at base growth, and the high scenario needs 16 shards.
- **The embedding changed share** (§4) is the largest single assumption inside the workload.
