# Sprint 1 · Event-store service — append API + ClickHouse MergeTree storage

## Context

Sprint 1 task 2 (§4, §14): stand up the **event-store service**, the system of
record. Every domain event from every service must land *immutably* and stay
queryable by business key. Today the repo has the locked event schema
(`crates/events`), telemetry with W3C trace propagation, and infra
(`docker-compose`: ClickHouse + Kafka), but **no service that actually persists
events**.

Per the chosen scope this PR delivers the *full* ingest path, not just the HTTP
endpoint:

1. **HTTP append API** — `POST /v1/events`, write-authenticated, internal-only.
2. **Kafka consumer** — subscribes to the domain-event topics, deserializes
   envelopes, appends them (continuing the producer's trace). This is what makes
   "any event published to Kafka lands immutably in the event store" true.
3. **ClickHouse `MergeTree` storage** — append-only, partitioned by
   `(chain, event_type, date)` (§4), created via a **dedicated ClickHouse
   migrations directory** with a boot-time runner.

Query API (by address/incident/time-range) is task 3 — explicitly out of scope
here, but the table/migrations are laid out so task 3 is purely additive.

## New crate: `crates/event-store` (binary service)

Follows the `crates/server` skeleton: `telemetry::init` → config → run → graceful
shutdown. Layout:

```
crates/event-store/
  Cargo.toml
  migrations/
    0001_create_events.sql          # the MergeTree DDL (reviewable, versioned)
  src/
    main.rs       # #[tokio::main]: telemetry, Config, EventStore::connect,
                  #   migrate::run, then spawn HTTP + Kafka, join on shutdown signal
    config.rs     # Config::from_env() — the one place env is read (mirrors telemetry)
    store.rs      # EventStore wraps clickhouse::Client; EventRow + append/append_batch
    migrate.rs    # CH migration runner: tracks applied versions in schema_migrations
    http.rs       # axum router: POST /v1/events (auth), GET /healthz; bearer middleware
    kafka.rs      # rdkafka StreamConsumer: subscribe, per-msg span w/ trace parent,
                  #   deserialize → append → commit offset
```

### Core: `EventStore` (`store.rs`)

`EventStore { client: clickhouse::Client }`. Single ingress-agnostic core; both
HTTP and Kafka call `append_batch(&[EventEnvelope])`.

The inserted row maps the envelope's metadata into columns + the `DomainEvent`
as a JSON blob (reconstructed on read via `EventEnvelope::with_metadata`, the
existing replay constructor):

```rust
#[derive(clickhouse::Row, Serialize, Deserialize)]
struct EventRow {
    #[serde(with = "clickhouse::serde::uuid")]
    event_id: Uuid,
    schema_version: u16,
    chain: u64,                 // envelope.chain.id()         -> UInt64
    event_type: String,         // envelope.event_type()       -> String
    event_family: String,       // envelope.payload.family()   -> snake_case String
    occurred_at: i64,           // occurred_at.timestamp_millis() -> DateTime64(3) (RowBinary = Int64 ms)
    payload: String,            // serde_json::to_string(&envelope.payload) — the DomainEvent
}
```

Notes:
- `occurred_at` is `i64` millis because a `DateTime64(3,'UTC')` column is an
  `Int64` of milliseconds in RowBinary — no extra serde feature needed.
- `appended_at` is a column `DEFAULT now64(3)` and is **not** in `EventRow`, so
  the insert omits it and ClickHouse fills it.
- `event_id` uses `clickhouse::serde::uuid` (ClickHouse's UUID byte order).
- Each event re-serializes byte-for-byte against the locked schema, so the
  golden wire format in `crates/events/tests/wire_format.rs` is the on-disk form.

### Schema (`migrations/0001_create_events.sql`)

```sql
CREATE TABLE IF NOT EXISTS events
(
    event_id        UUID,
    schema_version  UInt16,
    chain           UInt64,
    event_type      String,
    event_family    String,
    occurred_at     DateTime64(3, 'UTC'),
    payload         String CODEC(ZSTD(3)),
    appended_at     DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC')
)
ENGINE = MergeTree
PARTITION BY (chain, event_type, toDate(occurred_at))   -- §4: (chain, event_type, date)
ORDER BY (chain, event_type, occurred_at, event_id);
```

Plain `String` (not `LowCardinality`) for `event_type`/`event_family` in v1 to
keep the `clickhouse`-crate RowBinary insert robust; LowCardinality is a safe
later optimization once verified. Business-key columns (address, incident_id,
block_hash) are deferred to task 3 as a follow-up migration.

### Migration runner (`migrate.rs`)

A dedicated, versioned migrations dir (not inline DDL), applied on boot and
idempotent — the CH analogue of the sqlx/Postgres setup:

- Ensure `schema_migrations (version String, applied_at DateTime64(3) DEFAULT now64(3)) ENGINE = MergeTree ORDER BY version`.
- `const MIGRATIONS: &[(&str, &str)] = &[("0001_create_events", include_str!("../migrations/0001_create_events.sql"))];`
  (embedded so it ships in the Docker image; new migrations append one line).
- For each: `SELECT count() FROM schema_migrations WHERE version = ?`; if absent,
  execute the SQL then record the version. Convention: **one statement per file**.

## Shared contract: Kafka topic naming (in `crates/events`)

§20: "one topic per domain event type, partitioned by chain." Producers (Sprint 2)
and this consumer must agree, so the convention lives in the `events` crate:

- Add `pub const TOPIC_PREFIX: &str = "mev.events";` and a helper
  `topic_for(event_type: &str) -> String` (+ `EventEnvelope::topic()`), yielding
  e.g. `mev.events.BlockAssembled`.
- The consumer subscribes via the regex `^mev\.events\.` (rdkafka regex subscribe).
- Add `#[derive(strum::IntoStaticStr)] #[strum(serialize_all = "snake_case")]` to
  `EventFamily` for the `event_family` column string (consistent with how
  `DomainEvent` already derives `IntoStaticStr`). Family isn't on the wire, so the
  golden test is unaffected; add a small unit test for `topic_for`.

## Kafka consumer (`kafka.rs`)

`rdkafka` `StreamConsumer`, group `event-store`, `enable.auto.commit=false`,
`auto.offset.reset=earliest`. Loop:

1. Receive message → build `HeaderCarrier::from_map(headers)` from the Kafka
   record headers.
2. Open a `consume` span and `propagation::set_parent_from_headers(&span, &carrier)`
   so the trace continues from the producer (uses the existing
   `crates/telemetry/src/propagation.rs` API — exactly what its docstring promised
   for Sprint 1).
3. `EventEnvelope::from_json_slice(payload)` (this also rejects future schema
   versions) → `store.append_batch` → **commit the offset after a successful
   append** (at-least-once).
4. Malformed payload: log loudly and commit (skip the poison message rather than
   loop). A real dead-letter topic is a noted follow-up.

At-least-once means a crash between append and commit can re-insert an event;
plain `MergeTree` won't dedup. That's acceptable for v1 and matches the spec's
"`MergeTree`, append-only" wording; exactly-once dedup (e.g. ReplacingMergeTree
keyed by `event_id`, or query-time dedup) is a documented follow-up.

## HTTP append API + auth (`http.rs`)

- `POST /v1/events` — `Authorization: Bearer <token>`; body is a JSON **array** of
  `EventEnvelope` (batch). Each is `ensure_supported()`-checked; on success append
  and return `202 Accepted` `{ "appended": n }`. Bad/missing token → `401`.
- `GET /healthz` — unauthenticated; runs `SELECT 1` against ClickHouse for
  readiness.
- **Auth**: a static internal bearer token (`EVENT_STORE_WRITE_TOKEN`), compared in
  constant time (small hand-rolled CT compare — no new dep). This is internal
  service-to-service auth, deliberately distinct from the public §11 JWT.

## Graceful shutdown (`main.rs`)

Spawn the Kafka consumer task and the axum server; `tokio::select!` on
`ctrl_c()` / SIGTERM. axum uses `with_graceful_shutdown`; the consumer task is
signalled to stop and offsets are committed on the way out. The
`telemetry::TelemetryGuard` is held for the whole of `main` so spans flush.

## Dependencies (workspace `Cargo.toml`)

- Expand `tokio` features: add `net`, `signal`, `time` to the existing
  `rt-multi-thread, macros, sync`.
- `axum = "0.8"` — HTTP framework.
- `clickhouse = { version = "0.13", features = ["uuid"] }` — official client,
  RowBinary inserts.
- `rdkafka = { version = "0.37", features = ["cmake-build", "tokio"] }` — Kafka
  consumer (consumer groups, offset commit). **`cmake-build` requires `cmake` +
  a C/C++ toolchain**: GitHub `ubuntu-latest` has these preinstalled (CI is fine);
  macOS dev needs `brew install cmake` — will note in `mevwatch_dev_onboarding.md`
  and the `just tools` comment.
- dev-deps (for `#[ignore]` integration tests): `testcontainers` +
  `testcontainers-modules` with `clickhouse` and `kafka` features.

Exact versions resolved with `cargo add` during implementation; new transitive
licenses checked with `cargo deny check` and added to `deny.toml`'s allow-list if
flagged (rdkafka/librdkafka = MIT/BSD, clickhouse/axum = MIT/Apache — expected to
pass as-is).

## Config / env (`.env` additions)

```
# ── Event-store service (§4) ──
EVENT_STORE_HOST=0.0.0.0
EVENT_STORE_PORT=8081
EVENT_STORE_WRITE_TOKEN=changeme_event_store_internal_write_token
EVENT_STORE_KAFKA_GROUP=event-store
CLICKHOUSE_HTTP_URL=http://127.0.0.1:8123   # credential-free base for the clickhouse crate
```

`Config::from_env` builds the `clickhouse::Client` from `CLICKHOUSE_HTTP_URL` +
the existing `CLICKHOUSE_USER`/`PASSWORD`/`DB`; Kafka broker from `KAFKA_BROKERS`.

## justfile

- `ch-shell` recipe (clickhouse-client in the container), mirroring `db-shell`/`redis-shell`.
- `run-event-store: cargo run -p event-store` (migrations apply on boot).

## Tests

- **Unit (`store.rs`)**: `EventRow::from(&EventEnvelope)` maps every field
  correctly — `event_type`, snake_case `event_family`, `chain.id()`,
  `occurred_at` millis, and `payload == serde_json::to_string(&envelope.payload)`.
  No ClickHouse needed.
- **Unit (`http.rs`)**: constant-time token compare accepts the right token,
  rejects wrong/empty.
- **Unit (`events`)**: `topic_for("BlockAssembled") == "mev.events.BlockAssembled"`.
- **Integration `#[ignore]` (testcontainers ClickHouse)**: boot CH →
  `migrate::run` → `append_batch` of mixed `(chain, event_type)` envelopes →
  `SELECT count()` matches, and a `SELECT` round-trips a row back into an
  `EventEnvelope` equal to the original (proves immutable persistence +
  reconstruction). Runs in CI's `integration-test` job.
- **Integration `#[ignore]` (testcontainers Kafka + ClickHouse)**: produce an
  `EventEnvelope` JSON to `mev.events.BlockAssembled` with a `traceparent` header
  → consumer appends → assert the row is present (the end-to-end deliverable).

## Verification

1. `just up` (or rely on testcontainers) for ClickHouse + Kafka.
2. `cargo build -p event-store` and `cargo run -p event-store` — confirm migrations
   apply on boot (log line) and the table exists (`just ch-shell` → `SHOW TABLES`).
3. `curl` the append API: `POST /v1/events` with a Bearer token and a one-element
   envelope array → `202 {"appended":1}`; wrong token → `401`. Verify the row via
   `ch-shell`.
4. Produce an envelope to `mev.events.BlockAssembled` (Redpanda console at :8090 or
   a small script) → confirm it appears in `events`.
5. `just check` (fmt + clippy `-D warnings` + unit tests + build) and
   `cargo nextest run --run-ignored all` (integration) green.
6. `cargo deny check` + `cargo audit` clean (add any new license to `deny.toml`).

## Out of scope (follow-ups)

- Query/replay API (task 3) — additive migration for business-key columns + read
  endpoints.
- Dead-letter topic for poison messages; exactly-once dedup (ReplacingMergeTree).
- LowCardinality column optimization once RowBinary insert is verified.
