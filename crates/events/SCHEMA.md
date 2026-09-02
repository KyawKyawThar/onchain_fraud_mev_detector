# Domain event schema (§2) — the locked contract

This crate is the **single source of truth** for every fact the system records.
Every service produces and consumes these events over Kafka, and the event store
persists them verbatim as the canonical record (§4). Because everything depends
on this shape, the schema is a **contract that is locked and versioned**, not a
set of types that drift freely.

> Sprint-plan risk #1: *"if the §2 event schema changes after Sprint 1, every
> downstream service ripples. Lock it hard; version explicitly."* This document,
> [`tests/wire_format.rs`](tests/wire_format.rs) (the bytes are locked) and
> [`tests/schema_registry.rs`](tests/schema_registry.rs) (the change is
> classified) are how that lock is enforced.

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
| **System** (§13) | `UsageRecorded`, `ScreeningDecisionRecorded` | api |
| **Predictive** (§16) | `PredictedAlert`, `LiquidationRiskPredicted`, `LiquidationCascadeWarned` | predictive |
| **Cross-chain** (§24) | `BridgeMevDetected`, `CrossChainMevDetected`, `CrossChainFindingRetracted` | cross-chain-correlator |

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

## The schema registry and the compatibility gate

The wire-format lock says *"this changed"*. It cannot say *"this change is
safe"* — and safety is the actual requirement: a producer and a consumer are
deployed separately, minutes or days apart, and an event written a year ago is
still sitting in the event store waiting to be replayed. That is what the
**registry** in [`schema/`](schema/) is for.

```text
schema/v<N>/registry.json      the schema of every event at SCHEMA_VERSION N
schema/corpus/<Event>/*.json   every distinct shape ever emitted — append-only
```

The two have **different lifetimes on purpose**:

- `registry.json` is the *current belief* at version N. A compatible change (a
  new event, a defaulted field) rewrites it. Older versions' directories are
  never touched again — `v1/registry.json` is what a `v1` consumer still running
  in the cluster believes.
- The corpus is an **archive**. A shape is added the first time it is seen and
  then never rewritten or deleted, because the bytes it describes are in the
  event store forever (§4, §18). A single file serving as both the belief *and*
  the archive would lose the pre-change shape on the very blessing that
  introduced the change — which is the whole failure this split prevents. It is
  also where genuinely historical shapes live that no current code can produce:
  the pre-§15 `PreliminaryAlertCreated` and `IncidentCreated`, seeded by hand.

### Where the committed schema comes from

Not from a second derive (`schemars`, `utoipa`) that can quietly disagree with
serde, and not from parsing the source: every property in `registry.json` is
**probed out of the real `Deserialize` impl**
([`events::schema::probe`](src/schema/probe.rs)).

| Question | How it is answered |
|---|---|
| Is this field optional? | Delete it from a real event; does it still decode? (so `Option<T>` and `#[serde(default)]` both read as optional — the property backwards compatibility actually turns on) |
| What type is it? | The JSON type the real codec emits, `integer` and `float` distinguished |
| Is it a closed enum, and which values? | Feed it an unknown string and read the accepted set back out of serde's own `unknown variant` error (pinned by a canary test against a local enum, so a serde reword reads as "serde changed", not "your enum changed") |
| Is it a validated string (address, hash, timestamp)? | Same probe: it rejects the unknown string *without* being an enum |
| Is it free-form JSON? | Hand it three mutually incompatible values; only a `serde_json::Value` takes all three, and the walk stops there — an evidence blob's interior is payload, not schema |
| Where does it land, and what is ordered with what? | `topic` and `partition_key` come off the real [`EventEnvelope`] — see below |

So the registry describes what the wire format *does*, not what an annotation
claims, and it cannot drift from serde by construction.

**One shape it cannot describe**, and therefore one rule: a map with dynamic keys
(`HashMap<String, T>`) is indistinguishable from a struct through serde — both
take an object, both ignore unknown keys — so its *data* keys would be recorded
as schema and every new key would read as an added field. `DomainEvent` contains
none, and must not: free form goes in a `serde_json::Value` (which the opacity
probe recognises and stops at), and anything with meaningful keys is a `Vec` of
pairs.

### The transport contract is part of the schema

`topic` is where a consumer subscribes; `partition_key` is the *ordering*
guarantee it inherits (§20). Changing either leaves every field identical while
breaking a consumer that depends on two events co-partitioning — `UsageRecorded`
silently moving from customer-keyed back to chain-keyed would funnel the metering
firehose onto one partition and change every consumer's ordering at once. Both
are generated from the real envelope and classified like any other change.

### The rules it enforces

Any difference from the committed schema fails the build; the message classifies
each one:

| Change | Verdict | Why |
|---|---|---|
| New event type | compatible | Its own topic; nobody was reading it |
| Field added, optional on read | compatible | History decodes; old readers ignore it |
| Required → optional; enum → validated string → free-form string (widening) | compatible | Strictly more values accepted than before |
| **New value in a closed enum** | **consumers first** | Old consumers reject an unknown variant — legal, but every consumer deploys *before* the producer that emits it |
| Field removed, or retyped | **breaking** | Archived events carry it; deployed readers expect it |
| Field added as *required* | **breaking** | No archived event has it, so replay stops |
| Optional → required; any narrowing along the string lattice | **breaking** | Values already on disk may no longer parse |
| Event type removed; topic moved; partition key changed | **breaking** | History drops out of replay (§18), or the ordering guarantee silently changes |

The string forms are three variants of one type (`string` /
`validated_string` / `enum`) rather than a string plus flags, so "an enum that is
also a validated format" cannot be written down, and every rule about strings is
one comparison along that lattice.

Three further tests hold the ends down:

- **Every archived shape still decodes** — the whole corpus is replayed through
  today's reader. This is the one that stays red after a version bump until the
  upcasting step below exists.
- **Readers ignore fields from a newer producer** — the forward half. An event is
  decoded with unknown fields injected at every level; if that ever fails (a
  stray `deny_unknown_fields`), no producer could ship before its consumers.
- **The fixtures describe every field** — no `null`, no empty collection in
  [`events::schema::fixtures`](src/schema/fixtures.rs), because an unset field
  has no observable type and the gate would go blind underneath it.

### Who was reading that field?

The gate can prove a field was removed. It cannot know *who* was reading it —
the dependency points the other way, from consumer to schema. So the declaration
lives with the consumer, in the same shape as [`topics_for`], which already makes
a consumer state the event types it subscribes to and validates them against the
schema:

```rust
pub const EVENT_READS: &[(&str, &str)] = &[("UsageRecorded", "quantity"), …];

#[test]
fn declared_reads_still_exist_in_the_committed_schema() {
    events::schema::assert_reads("usage", EVENT_READS);
}
```

A removed field then fails *that crate's* test, naming itself, instead of turning
into a silent `None` in production. `usage` and `notification` declare theirs;
coverage grows as consumers opt in, and a declaration cannot go stale — a path
that no longer exists fails the same test.

### The engine is a library, the gate is a shell

Describing a type from its own codec and classifying the difference between two
descriptions are pure functions ([`events::schema`](src/schema/mod.rs), behind
the off-by-default `schema` feature). Reading what is committed, walking the
archive, failing the build and rewriting the committed schema are the shell
([`tests/schema_registry.rs`](tests/schema_registry.rs)). That split is what lets
the same engine serve the CI gate, a consumer's own test, and any tool that wants
to publish the schema elsewhere — and it keeps the classifier unit-testable
against hand-built registries rather than only against the real one.

The registry file carries its own `registry_format` version, separate from
`schema_version`: a change to *how a schema is written down* must not read as a
change to every event that has a string in it.

### Changing the schema on purpose

```sh
just schema-check    # the gate on its own, while iterating
just schema-bless    # re-commit the registry; append any new shape to the archive
```

`schema-bless` **refuses an incompatible change outright**. The only way through
is a `SCHEMA_VERSION` bump plus the upcasting step described below, after which
it writes a fresh `v<N+1>/` directory and leaves the old one frozen. That
asymmetry is deliberate: a compatible change costs one command, an incompatible
one costs a deliberate act. The archive is append-only in either case.

## Versioning policy

`SCHEMA_VERSION` (a `u16`, currently `1`) is stamped onto every envelope.
Readers reject any envelope written under a *higher* version than they
understand and accept equal-or-lower ones — i.e. new code stays
**backwards-compatible** with older data. (At `1` there is no older version yet;
the policy below is what keeps it true as the schema evolves.)

When you need to change the schema:

- **Backwards-compatible change** (adding a brand-new event variant, or adding
  an optional/defaulted field a reader can ignore): update the affected golden
  string(s) in the wire-format test and re-commit the registry (`just
  schema-bless`); no version bump required. Old consumers keep working — except
  for a **new value in an existing closed enum**, which old consumers reject as
  an unknown variant: the registry classifies that one as *consumers first*, and
  they deploy before the producer that emits it.
- **Backwards-incompatible change** (renaming/removing a field, changing a
  type, retagging, removing a variant): **bump `SCHEMA_VERSION` first**, then
  update the goldens and bless the new version's directory to document its
  shape. The compatibility gate refuses this change at the current version, so
  the bump is not a discipline anyone has to remember. The intent is that
  downstream consumers branch on `schema_version` to migrate (no such per-version
  branching exists yet — at `1` there is nothing to branch on; add it when the
  first incompatible bump lands). Never reuse or repurpose an existing field
  meaning under the same version.

Nothing is ever deleted from `DomainEvent`: retired variants stay readable so
historical events replay (§18).

### Reading old events: the upcasting seam

The event store is immutable and retained forever (§4, §18): every event ever
written under `1` stays on disk as `1`, byte-for-byte. So the moment
`SCHEMA_VERSION` makes an incompatible move, a current build replaying history
(backtests, projection rebuilds, the `/v1/replay` stream) is handed `1`-shaped
bytes that no longer match its `DomainEvent`.

The answer is an **upcasting chain on read** — [`events::upcast`](src/upcast.rs),
wired into [`EventEnvelope::from_json_slice`], which is the single place in the
codebase that inspects `schema_version`:

```rust
pub struct Upcaster {
    pub from: u16,
    pub event_type: Option<&'static str>,   // None = an envelope-level change
    pub apply: fn(&mut Value),
}
pub static STEPS: &[Upcaster] = &[];        // empty at v1: nothing is older
```

`decode` keeps the current shape on the fast path — one direct deserialize, no
intermediate tree, exactly what it cost before the seam existed. Only when that
*fails* does it parse loosely, run every step from the version the document
declares up to the current one, and retry; a document that was simply malformed
comes back with its original error. The contract is therefore "all code works
against the latest `DomainEvent`; old on-disk versions are migrated forward at
the deserialize boundary", not "every consumer branches on `schema_version`".

The mechanism is built and tested (with a synthetic `v0 → v1` chain, since there
is legitimately nothing real to migrate yet); the *steps* are empty. Four rules
keep it that way:

- **Steps are pure and total.** A `vN → vN+1` step is a plain JSON transform with
  no I/O and no failure — unit-testable against `schema/corpus/`, which is
  precisely the set of shapes it must handle.
- **A shipped step is never edited.** Old data on disk is forever; a step that
  produced wrong output for some historical event can't be "fixed" in place
  without re-reading all of history. Add another step instead.
- **Upcast on read; never rewrite what is stored.** The stored bytes are the
  audit record. A log you rewrote to make it decode is not one.
- **An incompatible change must actually stop the old shape decoding.** Because
  the chain is only consulted after a failed decode, renaming a field to one that
  is `#[serde(default)]`ed — where the old bytes still decode, into the default,
  silently — is the one change shape that would slip past. The gate classifies it
  as breaking for exactly this reason.

Related tradeoff: if an incompatible change is a pure *field rename* that should
stay internal (not alter the wire every downstream consumer reads), that is the
signal to split `DomainEvent` into a **wire DTO + a domain type** — the rename
lives in the domain type, the DTO (and its goldens) stay stable, and the mapping
between them is just another upcaster. Until that need is concrete, the fused
"one struct is both the wire format and the stored record" shape is simpler and
is what the crate ships.
