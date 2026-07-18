# Domain event schema (§2) — the locked contract

This crate is the **single source of truth** for every fact the system records.
Every service produces and consumes these events over Kafka, and the event store
persists them verbatim as the canonical record (§4). Because everything depends
on this shape, the schema is a **contract that is locked and versioned**, not a
set of types that drift freely.

> Sprint-plan risk #1: *"if the §2 event schema changes after Sprint 1, every
> downstream service ripples. Lock it hard; version explicitly."* This document
> and [`tests/wire_format.rs`](tests/wire_format.rs) are how that lock is
> enforced.

## What's in the contract

- **[`DomainEvent`]** — the closed set of facts, one variant per §2 event.
  Serialized adjacently tagged: `{"type":"<EventName>","payload":{…}}`. The
  `type` tag is the variant name (derived by `strum`, so it can't drift), and it
  doubles as the Kafka topic discriminator and the event-store `event_type`
  partition key (§4, §20).
- **[`EventEnvelope`]** — the transport/storage wrapper carrying the metadata
  every event needs regardless of family: `event_id` (idempotency key, §7),
  `schema_version`, `chain` (partition key, §20), `occurred_at`, and the
  `payload`.

### Event families (§2)

| Family | Events | Owner |
|---|---|---|
| **Chain** (§5) | `RawBlockReceived`, `BlockAssembled`, `BlockCanonicalized`, `BlockReverted`, `BlockFinalized` | ingestion |
| **Detection** (§6) | `DetectorTriggered`, `PreliminaryAlertCreated` | detection |
| **Simulation** (§7) | `SimulationRequested`, `SimulationCompleted`, `IncidentCreated`, `IncidentRetracted`, `IncidentFinalized` | simulation |
| **Intelligence** (§8) | `LabelAdded`, `LabelUpdated`, `LabelRevoked`, `EntityCreated`, `EntityMerged`, `EntitySplit`, `AttributionUpdated`, `RiskScoreUpdated`, `SanctionHit` | intelligence |
| **Rule engine** (§9) | `RuleCreated`, `RuleTriggered`, `RuleAlertCreated` | rule-engine |
| **System** (§13) | `UsageRecorded` | api |
| **Predictive** (§16) | `PredictedAlert` | predictive |

### Not in the contract: commands

The system has exactly one *command* — `SimulationJob` ("run this simulation").
It is deliberately **not** a `DomainEvent` and never enters the event store; it
travels on the RabbitMQ work queue and is consumed once (§7). Only its *result*
re-enters the model, as `SimulationCompleted`. Keeping commands out of the log
is what keeps the audit trail a record of what *happened*, not what was
*attempted* (§2).

## How the lock is enforced

[`tests/wire_format.rs`](tests/wire_format.rs) pins every variant to an exact,
byte-for-byte JSON golden and proves it round-trips back to the same value. Two
guards run together:

1. **Exhaustiveness** — the golden table must cover every variant exactly once,
   checked against `DomainEvent::COUNT` / `DomainEvent::VARIANTS` (strum). Add a
   variant and forget its golden → the test fails.
2. **Byte-stability** — rename a field, change a tag, reorder a struct, or change
   a type and the serialized bytes no longer match the golden → the test fails.

Both the event bodies and the `EventEnvelope` wrapper (the columns the event
store keys on) are locked.

A red wire-format test is the system working as designed: it caught a wire-format
change before it shipped. Note that the goldens pin the *bytes*, which are
produced partly by our serde dependencies (`alloy-primitives` for addresses,
`chrono` for timestamps, `serde_json` for number formatting). A dependency
upgrade that changes how those types serialize will therefore also break a
golden — that is **intentional, not a false positive**: it is a real change to
the wire contract every downstream consumer reads, and you want CI to surface it.
Treat it like any other incompatible change (see versioning below).

To regenerate the golden strings after an intentional change, run the printer
instead of hand-editing them:

```sh
cargo test -p events --test wire_format -- --ignored --nocapture print_goldens
```

## Versioning policy

`SCHEMA_VERSION` (a `u16`, currently `1`) is stamped onto every envelope.
Readers reject any envelope written under a *higher* version than they
understand and accept equal-or-lower ones — i.e. new code stays
**backwards-compatible** with older data. (At `1` there is no older version yet;
the policy below is what keeps it true as the schema evolves.)

When you need to change the schema:

- **Backwards-compatible change** (adding a brand-new event variant, or adding
  an optional/defaulted field a reader can ignore): update the affected golden
  string(s) in the wire-format test; no version bump required. Old consumers
  keep working.
- **Backwards-incompatible change** (renaming/removing a field, changing a
  type, retagging, removing a variant): **bump `SCHEMA_VERSION` first**, then
  update the goldens to document the new version's shape. The intent is that
  downstream consumers branch on `schema_version` to migrate (no such per-version
  branching exists yet — at `1` there is nothing to branch on; add it when the
  first incompatible bump lands). Never reuse or repurpose an existing field
  meaning under the same version.

Nothing is ever deleted from `DomainEvent`: retired variants stay readable so
historical events replay (§18).

### Reading old events: the upcasting seam

The versioning above is only half a story. Today readers do two things with
`schema_version`: **reject newer** (`ensure_supported`) and **accept
equal-or-lower**. At `1` that is complete — `1` is the only shape that exists, so
"accept equal-or-lower" means "accept `1`", and `from_json_slice` deserializes
straight into the current `DomainEvent`.

It stops being complete at the **first backwards-incompatible bump** (`1 → 2`).
The event store is immutable and retained forever (§4, §18): every event ever
written under `1` stays on disk as `1`, byte-for-byte, permanently. A `v2` reader
replaying history (backtests, projections rebuilds, the `/v1/replay` stream) will
therefore be handed `1`-shaped bytes that no longer match its `DomainEvent`. The
current code path has no answer for that — `serde_json::from_slice` would just
fail on the renamed/retyped field.

The intended answer is an **upcasting chain on read**: deserialize old bytes into
a version-tagged raw form, then run a pure `v1 → v2 → … → vN` transform sequence
to bring the value up to the current shape *before* the rest of the system sees
it. So the contract is "all code works against the latest `DomainEvent`; old
on-disk versions are migrated forward at the deserialize boundary," not "every
consumer branches on `schema_version` everywhere."

The natural seam is **[`EventEnvelope::from_json_slice`]** — it is already the one
place that inspects `schema_version` (via `ensure_supported`). The upcast path
slots in there: on a below-current version, route through the transform chain
instead of a direct deserialize; the rest of the codebase is untouched.

**This is documented, not built — YAGNI at `1`.** There is exactly one version,
so there is nothing to upcast and no chain to write. Capturing the design here is
the point: when the first incompatible bump lands, adding a `1 → 2` upcaster plus
a version branch at that single seam is a *localized change*, not a refactor of
every reader. Two rules keep it that way:

- **Keep upcasters pure and total.** A `vN → vN+1` step is a plain data transform
  with no I/O — unit-testable against archived `vN` goldens (the same
  `tests/wire_format.rs` goldens already pin those bytes).
- **Never mutate an upcaster once shipped.** Old data on disk is forever; a step
  that produced wrong output for some historical event can't be "fixed" in place
  without re-reading all of history. Add a new step instead.

Related tradeoff: if an incompatible change is a pure *field rename* that should
stay internal (not alter the wire every downstream consumer reads), that is the
signal to split `DomainEvent` into a **wire DTO + a domain type** — the rename
lives in the domain type, the DTO (and its goldens) stay stable, and the mapping
between them is just another upcaster. Until that need is concrete, the fused
"one struct is both the wire format and the stored record" shape is simpler and
is what the crate ships.
