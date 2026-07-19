# Engineering conventions — the definition of done

This is the checklist every new crate, service, and PR in this system is held to.
It exists because the system is a **distributed, event-driven** pipeline (§3, §17,
§22): many services producing and consuming domain events over Kafka, with one
command queue on RabbitMQ. At that shape, the unglamorous foundation — seams,
idempotency, backpressure, typed failure — *is* the senior signal (§22). These
conventions are not style preferences; they are what keeps the system testable,
operable, and replay-correct as it grows.

Each convention below states **the rule**, **why it matters here**, and a
**reference implementation already in the tree** to copy from. When you add code,
match the nearest reference.

---

## The checklist

A change is "done" when:

- [ ] **Pure core / I/O shell** — the logic is a pure function, the transport is a thin shell around it.
- [ ] **Seams are object-safe traits** with an in-memory double used in tests.
- [ ] **Errors are typed and classified** (`thiserror` in libs), carrying the retry/poison *decision*.
- [ ] **Illegal states are unrepresentable** — newtypes and enums at the boundary, not re-validation in the core.
- [ ] **Three test layers** present as applicable: pure unit · property · `#[ignore]` integration (+ `oneshot` for HTTP).
- [ ] **Backpressure is bounded** — no unbounded `spawn`, no CPU on the reactor.
- [ ] **At-least-once + idempotent** — commit/ack only after a durable downstream write; dedup by a stable key.
- [ ] **Observability is wired through the seam** — a span that propagates, a metric, both no-op until the binary opts in.
- [ ] **A cross-cutting concern (timing, a span) is a wrapper + `_inner` split**, not a call scattered across every return site (§14).
- [ ] **Config is resolved once at boot**, fail-fast.
- [ ] **Supply chain is deliberate** — heavy deps pinned `default-features = false` with a comment; `just deny` clean.
- [ ] **The gates pass locally** — `just check` green (local == CI).
- [ ] **New Kafka consumer?** — every line of the §12 conformance list, no exceptions.
- [ ] **Doc comments state constraints** the code can't express (§13) — never narration of the next line.

---

## 1. Pure core / I/O shell split

**Rule.** Separate the *decision* (a pure, synchronous function of its inputs) from
the *effects* (Kafka/RabbitMQ/HTTP/DB/EVM). The core returns a value; the shell
performs the I/O and interprets that value.

**Why here.** A domain event pipeline must be **replayable and backtestable** (§18):
the same inputs must deterministically produce the same outputs, with no broker in
the loop. A pure core is `assert_eq!`-testable in microseconds and is the literal
code path the backtest harness re-runs. It also keeps the async/transport churn out
of the logic.

**Reference.**
- [`simulation/src/command.rs`](../crates/simulation/src/command.rs) (pure `job_for_alert`) vs [`dispatcher.rs`](../crates/simulation/src/dispatcher.rs) (Kafka loop).
- [`simulation/src/simulator.rs`](../crates/simulation/src/simulator.rs) (pure scenario→outcome) vs [`worker.rs`](../crates/simulation/src/worker.rs) (broker drain).
- [`detection/src/emit.rs`](../crates/detection/src/emit.rs) (mapping) vs [`scheduler.rs`](../crates/detection/src/scheduler.rs) (loop); [`ingestion`](../crates/ingestion/) `tree.rs` (pure reorg logic) vs `pipeline.rs` (fetch/publish).

**Anti-pattern.** A function that takes a `StreamConsumer`/`Channel` and also contains
business logic. Split it: the shell extracts the data, the core decides.

---

## 2. Object-safe seams with in-memory doubles

**Rule.** Every boundary to the outside world is a `trait` + `Arc<dyn Trait>`, kept
**object-safe** (no generic methods, no `-> Self`, no `Self`-typed args). Production
is one impl; tests use an in-memory double. The trait speaks the domain, never the
transport.

**Why here.** Services are swappable nodes in a distributed graph. A seam lets the
core be tested with zero infrastructure, lets one transport be replaced (Kafka →
in-memory, RPC → reth-ExEx) without touching callers, and makes the dependency
direction explicit and acyclic.

**Reference.** [`event-bus::EventSink`](../crates/event-bus/src/lib.rs),
[`simulation::queue::JobSink`](../crates/simulation/src/queue.rs),
[`simulation::consumer::JobSource`](../crates/simulation/src/consumer.rs),
[`simulation::simulator::Simulator`](../crates/simulation/src/simulator.rs),
[`detector-api::DetectorPlugin`](../crates/detector-api/src/plugin.rs),
[`ingestion`](../crates/ingestion/) `ChainSource`,
[`intelligence::cache::HotCache`](../crates/intelligence/src/cache.rs),
[`rule_engine::state_store::TemporalStateStore`](../crates/rule-engine/src/state_store.rs).
Each pairs with a `Recording*` / canned double in its `#[cfg(test)]` module.

**Anti-pattern.** Reaching for `rdkafka`/`lapin`/`reqwest` types directly in service
logic. If a test needs a broker to run, the seam is missing.

**Enforcement.** The dependency-direction half of this rule is *mechanical*, not
review-vigilance: [`crates/arch-conformance`](../crates/arch-conformance/) runs the
seam rules (detector crates → `detector-api` never `detection`; `rdkafka` never
without `event-bus`; `lapin` in `simulation` only; one Prometheus exporter; `sqlx`
alongside `db`; `redis` alongside `db` too (§8/§9 — `db::redis` is the shared
connect + transient/permanent classification, the Redis analog of the sqlx rule);
`clickhouse` alongside `ch-migrate`; `events`/`detector-api` stay at
the bottom of the graph) against `cargo metadata` on every `cargo test` — a
violation fails the same gate locally and in CI. Changing a rule is an architecture
decision: edit the rule in the same PR, with the reasoning in the commit.

---

## 3. Typed errors that carry the decision

**Rule.** Library errors are an `enum` (`thiserror`), one variant per distinct
failure, and they encode the **operational decision** — not just a message. Our
canonical split is `is_transient()`: a transient error is retried/requeued; a
permanent ("poison") one is dead-lettered/skipped. Never leak a transport type
(`lapin::Error`, `rdkafka::KafkaError`) through a seam — wrap it.

**Why here.** In a distributed system, *what to do about a failure* is the whole
game: retry a broker blip, dead-letter hostile input, skip a poison record so it
can't wedge a partition. Encoding that in the type makes the handling exhaustive and
uniform across services.

**Reference.** [`queue::JobError`](../crates/simulation/src/queue.rs),
[`simulator::SimError`](../crates/simulation/src/simulator.rs) (`Transient`/`Poison`),
[`resolver::ResolveError`](../crates/simulation/src/resolver.rs),
[`event-bus::PublishError`](../crates/event-bus/src/lib.rs),
`event-store::StoreError`. All expose `is_transient()`.

**Anti-pattern.** `anyhow::Result` on a library seam, or matching on
`err.to_string().contains(...)`. Use `anyhow` only in **binaries** (`main.rs`),
where an error just needs context + a backtrace.

---

## 4. Make illegal states unrepresentable ("parse, don't validate")

**Rule.** Validate once, at the boundary, into a type that can't hold an invalid
value — then the core never re-checks. Prefer enums over booleans/strings so a new
case is a compile error at every `match`.

**Why here.** Events cross service boundaries and get persisted forever (§4). A
value that's wrong should be rejected at the edge, not discovered deep in a detector
or a projection months later in replay.

**Reference.** `Priority(0..=9)` clamped on construction, `Confidence` /
[`UsdPrice`](../crates/detector-api/src/enrichment.rs) (reject non-finite/negative),
`AlertId`/`IncidentId` newtypes ([`events/src/primitives.rs`](../crates/events/src/primitives.rs)),
and the `Disposition { Ack, Requeue, DeadLetter }` / `Scope::{Block, CrossBlock}`
enums over booleans.

**Anti-pattern.** Passing a raw `u8` priority or `f64` price into the core and
checking the range there. Parse it into a newtype at the seam.

**Standing review question.** Every new Sprint adds new domain concepts under time
pressure, and a bare `String`/`u64`/`f64` field is the path of least resistance in
the moment. When a new field shows up that isn't already a newtype elsewhere, ask
"can this hold an invalid value, and would that value be wrong at every use site?" —
if yes, it's a newtype, not a review comment for later.

---

## 5. Three test layers

**Rule.** As applicable to the crate:

1. **Pure unit tests** over the core — deterministic, no I/O (every `command.rs`/`emit.rs`/`simulator.rs`).
2. **Property tests** (`proptest`) for invariants and round-trips — see the event-schema round-trip tests.
3. **Integration tests** behind `#[ignore]`, using **testcontainers** for the real broker/DB — run via `just test-integration`. Default `cargo test` stays hermetic.
4. **For HTTP services, add the middle layer:** axum handler tests via `tower::ServiceExt::oneshot` against `router()` — exercises auth/extractors/status codes/routing with **no network and no Docker**. (This layer is currently the one gap — add it with any new HTTP surface.)

**Why here.** Each layer catches what the others can't: units pin logic, properties
find edge cases, `oneshot` catches routing/extractor bugs cheaply, and containers
prove the real broker honours our semantics (ack/redelivery/DLX — see
[`simulation/tests/worker.rs`](../crates/simulation/tests/worker.rs)).

**Reference.** [`simulation/tests/worker.rs`](../crates/simulation/tests/worker.rs)
and [`topology.rs`](../crates/simulation/tests/topology.rs) (testcontainers RabbitMQ);
`event-store/tests/integration.rs` (testcontainers ClickHouse). Gotchas worth
knowing live in the project memory (e.g. exact-equality f64 round-trips flake;
`DebuggingRecorder::snapshot()` drains).

---

## 6. Backpressure is a type, not a hope

**Rule.** Inter-stage handoffs use **bounded** channels (`mpsc` with a capacity);
consumers bound in-flight work (RabbitMQ `basic_qos` prefetch). Never `tokio::spawn`
unbounded work. **Never run CPU-bound work on the async reactor** — hand it to
`spawn_blocking` / a `rayon` pool (§17).

**Why here.** "Falling behind" must be a *measurable signal* (channel full, queue
depth) that drives backpressure and autoscaling — not silent unbounded memory growth
ending in OOM. Queue depth is literally the simulation autoscaler input (§17, §20).

**Reference.** [`detection/src/scheduler.rs`](../crates/detection/src/scheduler.rs)
(two bounded `mpsc` channels between consumer→scheduler→committer);
[`simulation/src/consumer.rs`](../crates/simulation/src/consumer.rs) (`basic_qos`
prefetch); CPU off the reactor in [`detection/src/emit.rs`](../crates/detection/src/emit.rs)
(`spawn_blocking` + rayon fan-out) and [`simulation/src/worker.rs`](../crates/simulation/src/worker.rs)
(revm on a shared rayon pool via a oneshot bridge).

---

## 7. At-least-once delivery + idempotent processing

**Rule.** Commit a Kafka offset / ack a RabbitMQ job **only after** the downstream
effect is durably written (event published, result persisted). Make reprocessing
safe by keying every output on a **stable id** so a duplicate is a no-op the
projection dedups. Don't reach for exactly-once machinery — you don't need it if
processing is idempotent.

**Why here.** Distributed delivery is at-least-once by nature; crashes happen
mid-step. The discipline "effect first, then commit" + "dedup by key" is what makes
redelivery harmless. Order is reasserted at the projection (commutative by key), not
demanded of the queue (§7).

**Reference.** `event_bus::publish_resilient` / `queue::publish_resilient` (retry
transient, give up on shutdown/permanent); the dispatcher commits after the job is
queued *and* audited; the worker acks after the result is published; results are
`alert_id`-keyed for dedup. Commands (`SimulationJob`) live only on RabbitMQ and
**never** enter the event store — only their *outcomes* do (§2/§7).

---

## 8. Observability wired through the seam

**Rule.** Every service emits a `tracing` span that **propagates** across the message
boundary (W3C trace-context headers) and the relevant metric. Both go through a
facade that is a **no-op until the binary installs an exporter** — so libraries,
replay, and backtests stay exporter-agnostic and never change the events produced.

**Why here.** A request crosses many services; a trace is only useful if it stitches
across them. Keeping the exporter install in the binary (not the library) means the
same code path is used in production, in tests, and in replay without divergence.

**Reference.** [`telemetry::init`](../crates/telemetry/) + `telemetry::propagation`
(the W3C header carrier; Kafka/RabbitMQ consumers call `set_parent_from_headers`),
and `telemetry::metrics::init` + the `metrics` facade call sites
([`detection/src/metrics.rs`](../crates/detection/src/metrics.rs) — hit rate derived
in PromQL, not stored).

---

## 9. Config resolved once, at boot, fail-fast

**Rule.** Each binary reads the environment in exactly one place (`config.rs`),
parses everything up front, and errors at startup on anything missing or malformed.
Downstream code takes an explicit `Config`; nothing else reads `std::env`.

**Why here.** A misconfigured broker URL should fail the pod at boot, visibly — not
at the first event, silently, an hour later. One place to read also keeps the rest of
the service pure and testable.

**Reference.** [`simulation/src/config.rs`](../crates/simulation/src/config.rs)
(`Config::from_env`, `env`/`env_or`/`env_parse`), mirrored by `detection`,
`ingestion`, `event-store`.

---

## 10. Deliberate supply chain

**Rule.** A heavy dependency is pinned with `default-features = false` and an
**explanatory comment** in the workspace `Cargo.toml` listing exactly which features
are on and why. New subtrees must pass `just deny` (licenses + bans). When a spec
can't be taken literally, document the deviation at the call site.

**Why here.** Every dependency is attack surface, compile time, and a binary-size
cost (we target self-contained images). Defaults are not a decision; the comment is.

**Reference.** The `revm` entry in the root [`Cargo.toml`](../Cargo.toml)
(`default-features = false`, precompiles enumerated, `alloydb` deliberately *not*
enabled with the reason); the `rdkafka` vendored-build note; the quorum-queue
"can't-set-`x-max-priority`" deviation documented in
[`simulation/src/topology.rs`](../crates/simulation/src/topology.rs).

---

## 11. The gates: local == CI

**Rule.** Before a PR, `just check` is green. It runs the same gates CI does:
`fmt-check`, `lint` (clippy `-D warnings`), `test`, and a `--locked` build (the
`Cargo.lock` must be committed and current). Integration tests run via
`just test-integration`; supply chain via `just deny`.

**Why here.** "Works on my machine" is a distributed-systems failure mode too. One
command, the same result locally and in CI, keeps the foundation trustworthy.

**Reference.** [`Justfile`](../Justfile) (`check: fmt-check lint test build`),
mirrored by the GitHub Actions workflows (§20).

---

## 12. New Kafka consumer conformance

Every new consumer binary (or new consumer inside an existing binary) adopts the
whole hardening surface — none of it is optional, because each line exists as the
fix for a production failure mode:

- [ ] **`event_bus::run_consumer`** with `Handled::Skip` + a DLQ topic for records
  this consumer can *never* process — parked and replayable, not skip-and-forgot,
  never a poison loop.
- [ ] **Lag-reporting consumer builder** — `kafka_consumer_lag` is the
  keeping-up signal ops actually pages on; a consumer without it is invisible.
- [ ] **Commit discipline**: commit/ack only after the durable downstream write
  (§7). A record that isn't yours (foreign chain, misrouted type) rides the work
  channel as a *commit-only* marker so its offset advances **in order** with real
  work — an out-of-band commit can overtake unpublished work sharing the
  partition; dropping it uncommitted pins lag and forces full re-reads on
  restart.
- [ ] **Per-chain consumer group naming** where the consumer is
  one-instance-per-chain (`detection-8453` pattern): same-group instances would
  partition-split and commit-skip each other's chains. Keep the legacy bare name
  for chain 1 so committed offsets survive.
- [ ] **Idempotent processing** keyed on a stable id — redelivery after a crash
  is normal, not exceptional (§7).
- [ ] **`telemetry::health` wired** (two lines: `spawn_from_env` right after
  telemetry init, `set_ready(true)` after boot wiring) + a `*_METRICS_ADDR`
  standardized to `0.0.0.0:9100` in K8s.
- [ ] **Config through `telemetry::env`** (`required`/`parse_or`), resolved once
  at boot, fail-fast (§9).
- [ ] **Publishing through `event-bus`** (`EventSink` / `publish_resilient`) —
  never raw `rdkafka` producers (§2, enforced by arch-conformance).
- [ ] **A K8s manifest entry** in `deploy/k8s/base/services/` that states its
  scaling shape honestly (see the README table there): HPA only if replicas are
  truly interchangeable; `Recreate` + 1 if there's a single-writer anywhere in
  the loop; reorg-rewindable if it holds cross-block state (§15).

**Reference.** [`usage`](../crates/usage/) is the smallest complete example;
[`detection`'s scheduler](../crates/detection/src/scheduler.rs) shows the
foreign-record commit-ordering pattern.

---

## 13. Doc comments state the constraint, not the mechanics

**Rule.** A comment earns its place by stating something the code *cannot* express:
an invariant ("starts **not ready** — a booting pod must stay out of rotation"), a
rejected alternative and why, a cross-service contract, a production lesson
("probe the broker, not the port"). Never what the next line does, where code was
moved from, or why a change is correct — that's PR-review talk, noise the moment it
merges.

**Why here.** At this codebase's scale the doc comments *are* the architecture
record: the §-references and invariant statements are how the next engineer learns
which lines are load-bearing. Narration comments train readers to skip all
comments, including the load-bearing ones.

**Reference.** [`telemetry/src/health.rs`](../crates/telemetry/src/health.rs) and
[`event-store`'s config](../crates/event-store/src/config.rs) — every comment is a
constraint, a trade-off, or a trap.

---

## 14. Wrap cross-cutting concerns with a thin timed/observed outer, never scatter them

**Rule.** When a function needs a cross-cutting concern applied uniformly regardless
of which branch it returns from — timing for a metric, a tracing span, anything that
must fire on every exit path including early `return`s and `?`-propagated errors —
split it: a thin **outer** function owns the concern and calls a private **`_inner`**
that owns the actual logic. Never scatter the same `record_*`/span-entry call across
every return site by hand.

**Why here.** A function with several early returns is exactly where a
hand-maintained metric or span goes stale first: someone adds a new branch six
months later, forgets the one line that records it, and the dashboard quietly
under-counts with no compile error to catch it. The wrapper/`_inner` split makes the
concern *structural* — it fires because of where the code sits, not because every
future editor remembers to keep four call sites in sync.

**Reference.**
[`simulation::worker::Worker::process`](../crates/simulation/src/worker.rs) (timed
outer) / `process_inner` (the resolve → simulate → publish logic);
[`event_store::store::EventStore::append_batch`](../crates/event-store/src/store.rs)
(timed outer, records success/error via [`crate::metrics`](../crates/event-store/src/metrics.rs))
/ `append_batch_inner` (the actual RowBinary insert).

**Anti-pattern.** A function with a metric recorded at its single `Ok` return but not
at its three early `Err` returns — the classic way a "detector run" counter and a
"detector error" counter drift out of sync with each other.

---

## Distributed-systems invariants (cross-cutting)

Beyond the per-crate checklist, these system-wide rules hold:

- **Commands vs events.** The event store is a log of **facts** (what happened), not
  intentions. The one *command* (`SimulationJob`) lives on RabbitMQ and never enters
  the event store; only its outcome re-enters Kafka (§2/§7).
- **Ordering where it's needed, not everywhere.** Cross-block detector state is
  order-sensitive → it stays on Kafka's per-chain ordered partitions. Simulation jobs
  are independent → they ride a reorder-free competing-consumer queue. Don't impose
  ordering the workload doesn't need (§7, §17).
- **Reorg-versioned state.** In-memory cross-block state is snapshot-per-block and
  rewound to the common ancestor on `BlockReverted` (§15). Any new stateful consumer
  must be rewindable.
- **Attribution-blind hot path.** The fast path names *behaviour*, never actors — no
  labels in detection/enrichment (§6/§8). Identity attribution is the intelligence
  service's job, off the hot path.
