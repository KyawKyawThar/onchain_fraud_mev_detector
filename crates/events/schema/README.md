# The event schema registry

Generated, committed, and diffed by
[`../tests/schema_registry.rs`](../tests/schema_registry.rs) over the engine in
[`../src/schema`](../src/schema) — **do not hand-edit**.

```text
v<N>/registry.json      the schema of every DomainEvent at SCHEMA_VERSION N
corpus/<Event>/*.json   every distinct shape ever emitted — append-only
```

The two have different lifetimes on purpose:

- **`v<N>/registry.json` is the current belief** at version N. A compatible
  change rewrites it; older versions' directories are never touched again, so
  `v1/registry.json` stays what a `v1` consumer still running in the cluster
  believes.
- **`corpus/` is the archive.** A shape is added the first time it is seen and
  never rewritten or deleted, because the bytes it describes sit in the event
  store forever. Every file here is replayed through today's reader on every CI
  run — a change that stops history decoding fails the build. Files with no
  current equivalent (`PreliminaryAlertCreated/002.json`,
  `IncidentCreated/002.json`) are genuinely historical shapes, written before
  §15 added the scoring fields, seeded by hand.

Regenerate the current version with `just schema-bless` — it refuses an
incompatible change and only ever *appends* to the archive. The rules, and what
to do when it refuses, are in [`../SCHEMA.md`](../SCHEMA.md).
