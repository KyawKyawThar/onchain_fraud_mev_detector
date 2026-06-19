# Workspace layout

Code is split by **service boundary**, not by layer (§5). Each crate is either a
shared library every service builds on, or (from Sprint 1 onward) a deployable
service binary. The `crates/*` glob in the root `Cargo.toml` auto-includes new
crates — scaffold them with `just new-lib <name>` / `just new-bin <name>`.

## Shared libraries (the foundation — Sprint 0)

| Crate | Role |
|---|---|
| [`events`](events/) | The domain event schema (§2): every event family, versioned, with an `EventEnvelope` wrapper. The contract every service produces/consumes; **Sprint 1 locks it**. Pure data — no I/O, no transport deps. |
| [`telemetry`](telemetry/) | Observability foundation (§19): `tracing` init (pretty/json) + **W3C trace-context propagation** across message boundaries, so traces stitch across services. Transport-agnostic header carrier (Kafka adapts it in Sprint 1). |
| [`db`](db/) | Database access layer; migrations under `db/migrations` (run via `just migrate-*`). |
| [`server`](server/) | Placeholder service binary + Docker target. Demonstrates the service skeleton (`telemetry::init` → run); real services replace/join it per sprint. |

## Service crates (added per sprint)

| Crate | Role |
|---|---|
| [`event-store`](event-store/) | **Sprint 1.** The immutable system of record (§4): an internal write-authenticated HTTP append API plus a Kafka consumer, persisting every domain event to an append-only ClickHouse `MergeTree` partitioned by `(chain, event_type, date)`. ClickHouse schema lives in [`event-store/migrations`](event-store/migrations/) (applied on boot). |

Still ahead — each lands as its own `crates/<service>` binary when its sprint
begins, consuming/producing `events` over the backbone (§3, §22):

`ingestion` · `detection` · `simulation` · `intelligence` · `rule-engine` ·
`api` · `notification` · `billing`

No cross-service database joins — services share data via events or read APIs
(§3). Keep that boundary at code review.

## Sprint 0 deliverable

`cargo run -p telemetry --example trace_propagation` (or `just trace-demo`)
shows one trace span propagating end-to-end across a stub producer/consumer —
the same `trace_id` on both sides. The CI-checked version is
[`telemetry/tests/propagation.rs`](telemetry/tests/propagation.rs).
