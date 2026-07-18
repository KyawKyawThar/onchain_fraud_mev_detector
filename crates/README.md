# Workspace layout

Code is split by **service boundary**, not by layer (§5). Each crate is either a
shared library every service builds on, or (from Sprint 1 onward) a deployable
service binary. The `crates/*` glob in the root `Cargo.toml` auto-includes new
crates — scaffold them with `just new-lib <name>` / `just new-bin <name>`.

> **New crate or service?** Hold it to the
> [engineering conventions](../docs/engineering-conventions.md) — the project's
> definition of done (seams, typed errors, test layers, backpressure, idempotency,
> observability). Match the nearest reference implementation listed there.

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
| [`ingestion`](ingestion/) | **Sprint 2.** Chain data into the backbone (§5). Task 1 (done): the **source adapter** layer — a health-checked, circuit-broken RPC failover pool ([`source::rpc`](ingestion/src/source/rpc.rs)) behind the `ChainSource` seam (so the reth-ExEx / node-IPC adapters slot in later, Phase 8), feeding an ordered head stream. The reorg-aware block tree + `RawBlockReceived`/`BlockAssembled`/… emission are tasks 2–4. |
| [`detector-api`](detector-api/) | **Sprint 3.** The detector **seam** (§6), extracted from `detection` so detectors decouple from the service: the [`DetectorPlugin`](detector-api/src/plugin.rs) trait every detector implements, the [`DetectionCtx`](detector-api/src/ctx.rs) it reads (raw `BlockBundle` facts + token/pool/price [`Enrichment`](detector-api/src/enrichment.rs), **no labels**), and the behaviour-only `Evidence` it returns. Detector crates depend on *this* thin, stable contract, not the heavy service crate; `detection` re-exports it (so `detection::DetectorPlugin` still resolves). |
| [`detection`](detection/) | **Sprint 3.** The fast path (§6): `BlockAssembled` → provisional alert in < 1s, attribution-blind. The **service side** — **compile-time** detector registration ([`registry`](detection/src/registry.rs): explicit, feature-gated `register_builtins`, no dynamic loading — §6), the model registry (task 2), and per-detector feature flags (task 2). Wires the built-in detectors (`sandwich`/`arb` features) into the roster. Event emission (task 5) layers on top; library-only until the service loop lands in task 5. |
| [`sandwich-detector`](sandwich-detector/) · [`arb-detector`](arb-detector/) | **Sprint 3 (task 4).** The first two detectors, `sandwich-v1.2` and `arb-v1.0` — independent crates implementing `detector-api`'s `DetectorPlugin`, pure single-block `Rule` detectors, attribution-blind. Sandwich: same-sender frontrun/backrun bracketing a victim on one pool. Arb: single-tx closed swap cycle netting one token positive, all others flat. Both gate on `min_profit_usd`. |

Still ahead — each lands as its own `crates/<service>` binary when its sprint
begins, consuming/producing `events` over the backbone (§3, §22):

`simulation` · `intelligence` · `rule-engine` ·
`api` · `billing`

No cross-service database joins — services share data via events or read APIs
(§3). Keep that boundary at code review.

## Sprint 0 deliverable

`cargo run -p telemetry --example trace_propagation` (or `just trace-demo`)
shows one trace span propagating end-to-end across a stub producer/consumer —
the same `trace_id` on both sides. The CI-checked version is
[`telemetry/tests/propagation.rs`](telemetry/tests/propagation.rs).
