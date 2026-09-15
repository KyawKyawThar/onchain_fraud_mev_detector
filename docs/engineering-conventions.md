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
- [ ] **Monitoring code fails open *and* counts that it did** — `try_lock`, bounded queues, a `reason`-labelled counter for every dropped observation (§15).
- [ ] **Config is resolved once at boot**, fail-fast.
- [ ] **Supply chain is deliberate** — heavy deps pinned `default-features = false` with a comment; `just deny` clean.
- [ ] **The gates pass locally** — `just check` green (local == CI).
- [ ] **New Kafka consumer?** — every line of the §12 conformance list, no exceptions.
- [ ] **Doc comments state constraints** the code can't express (§13) — never narration of the next line.
- [ ] **Changed a prompt?** — the artifact is versioned, the manifest is regenerated, and the diff is reviewed (§16).
- [ ] **Touched the event schema?** — the committed registry is re-blessed and the diff reviewed; an incompatible change bought a `SCHEMA_VERSION` bump and an upcaster (§17).
- [ ] **Storing a regulatory artifact, or the evidence under one?** — its lifetime comes from the shared `retention::Policy`, never a local constant, and the store enforces it (§18).
- [ ] **Stating a latency or throughput number?** — one series spans the whole claim (not its cheapest stage), and a load gate reads it under load with a three-way verdict where "could not decide" exits non-zero (§19).

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
[`rule_engine::state_store::TemporalStateStore`](../crates/rule-engine/src/state_store.rs),
[`inference::InferenceEngine`](../crates/inference/src/engine.rs) (§20.2 — the
`ort` ONNX backend vs. `StubEngine`, so ML detector logic is testable with no
native runtime present).
Each pairs with a `Recording*` / canned double in its `#[cfg(test)]` module.

**Anti-pattern.** Reaching for `rdkafka`/`lapin`/`reqwest` types directly in service
logic. If a test needs a broker to run, the seam is missing.

**Corollary — size a seam for its most expensive implementation.** A trait's
signature is a tax the *other* implementations pay. `llm::CompletionCache` was
first written synchronous because the in-process map needs no `await`; the
copilot's cross-pod cache then had to bridge with `block_in_place` +
`Handle::block_on`, blocking a runtime worker on a database round trip and
constraining the whole binary to the multi-threaded scheduler. Making it async
costs the map one boxed future per call and deletes that. The question to ask
of a new seam is not "what does the first implementation need?" but "what will
the one that runs in production need?"

**Corollary — give each collaborator the narrowest trait that does its job.** A
nine-method store trait means the double implements nine methods to test one,
and the type system stops saying which component may do what.
`copilot::store` splits into `DraftQueue` (the consumer: one method),
`DraftWorkQueue` (the pool), `DraftCache` (the `llm` adapter) and `DraftReview`
(the human surface), with a blanket supertrait for the one type that owns the
table. The consumer *cannot* call a model or approve a draft, which is the §7
slow-path constraint expressed as a type rather than a comment.

**Enforcement.** The dependency-direction half of this rule is *mechanical*, not
review-vigilance: [`crates/arch-conformance`](../crates/arch-conformance/) runs the
seam rules (detector crates → `detector-api` never `detection`; `rdkafka` never
without `event-bus`; `lapin` in `simulation` only; one Prometheus exporter; `sqlx`
alongside `db`; `redis` alongside `db` too (§8/§9 — `db::redis` is the shared
connect + transient/permanent classification, the Redis analog of the sqlx rule);
`clickhouse` alongside `ch-migrate`; `ml-features`/`dataset`/`inference` never
touch `intelligence`, so attribution-blindness holds upstream and downstream of
the model as well as inside it; `llm` stays a seam and `copilot` reaches both the
model and other services only through theirs (§20.4 — the copilot's safety
argument is that a draft crosses a *validating boundary* it does not own);
`events`/`detector-api` stay at
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
  the loop; reorg-rewindable if it holds cross-block state (§15). If it drains a
  queue, the HPA scales on that queue divided by a per-replica capacity gauge
  the binary exports, not on CPU alone and never against a literal target
  (`simulation-worker` is the reference). If it holds a shared, rate-limited
  budget (the copilot), it is not autoscaled at all.
- [ ] **Nothing slow inside the handler.** `run_consumer` awaits the handler
  *before* committing, so the handler's worst case is the poll interval: a
  call that can take minutes (a model, a third-party API, a long simulation)
  blows `max.poll.interval.ms`, gets the member evicted, rebalances the
  partition, and redelivers the record into a *second* run of the same
  expensive work — with the first still in flight. Raising the poll interval
  only trades that for a fleet that takes minutes to notice a dead pod. The
  fix is structural: the handler records a durable work item and commits, and
  a pool drains it on its own clock (§7's slow path; §20.4's copilot).

- [ ] **A retry re-fetches its record.** `Handled::Retry` seeks the partition
  back before re-polling. Without the seek, librdkafka hands the next record,
  and the next `Commit` on that partition commits past the one being retried:
  a retry that silently skips. Any hand-rolled consume loop must do the same.
- [ ] **Settle on delivery, never on the shutdown token.** `publish_resilient`
  returns `Result<(), Undelivered>`. A caller that advances an offset or acks a
  job maps it (`handled`, `handled_undelivered`, or its own error's `#[from]`).
  A caller with nothing upstream to hold back writes `.accept_loss(why)`, and
  `why` is a claim a reviewer should check. `if shutdown.is_cancelled()` as a
  stand-in for "was it published?" is the bug this replaced: it requeued work
  whose results had already landed, and elsewhere committed past events that
  had not.
- [ ] **A work queue is bounded, and full means refuse.** `x-max-length-bytes`
  with `x-overflow: reject-publish`, never `drop-head`. The producer turns the
  nack into its *consumer's* `Retry`, so the backlog waits on Kafka (durable,
  lag-alerted) instead of in broker memory, and the handler never spins long
  enough to be evicted from its group.
- [ ] **A slow-path worker has a job deadline, and its grace period is derived.**
  `terminationGracePeriodSeconds ≥ deadline + overshoot allowance + result
  publishes × send timeout`, checked by a test against the manifest
  (`simulation/tests/grace_period.rs`). A guessed grace period turns every
  scale-down into a SIGKILL of a job that was about to settle.

**Reference.** [`usage`](../crates/usage/) is the smallest complete example;
[`detection`'s scheduler](../crates/detection/src/scheduler.rs) shows the
foreign-record commit-ordering pattern; [`copilot`](../crates/copilot/) shows
the slow-path split — a thin consumer over a leased Postgres queue, where the
work item's row doubles as the durable cache of the expensive answer.

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

**Variant: when the thing being wrapped is a *seam*, wrap the trait, not the
function.** [`inference::ObservedEngine`](../crates/inference/src/observe.rs) is an
`InferenceEngine` that records and delegates. That is strictly stronger than the
`_inner` split for the same cost: it observes *any* backend (so a future engine
cannot ship unmeasured), it observes the test double too (so a consumer's tests
assert on what the dashboard will show), and it cannot miss a call path, because
the trait's methods are the only call paths there are. Compose it **once**, at the
boot site that owns the value — wrapping is not idempotent, and a nested decorator
compiles while double-counting.

**Stacking two of them is an ordering decision, not a formality.** `DriftEngine`
(§20.5) wraps `ObservedEngine`, not the reverse, because
`model_inference_duration_seconds` is the number a latency budget is checked
against and so must measure the work, not the work plus the bookkeeping. Rule of
thumb: **the decorator whose measurement must stay pure goes innermost**, and the
cost of the outer ones lands in whatever histogram is already measuring the caller
— which is where a monitor that has grown too expensive should show up anyway.

---

## 15. A monitor fails open — and says that it did

**Rule.** Observability code on a request/block path must never be the reason
that path stops working: take locks with `try_lock`, recover from poisoning
rather than latching off, bound any queue it accumulates into, and never
propagate its own errors into the work it is watching. **Every one of those
degradations gets a counter**, with a `&'static str` reason from a closed set.

**Why here.** The two halves are one rule, and shipping only the first is the
trap. Failing open is obvious and easy; failing open *silently* produces the
worst possible artifact — a dashboard that is confidently wrong. A drift
monitor that stopped monitoring, a lag reporter whose lock is poisoned, a
metering sink whose queue is full: all three render identically to "everything
is fine" unless the degradation is itself a signal. If the only evidence that a
monitor died is that its graph went flat, nobody will notice, because a flat
graph is also what healthy looks like.

Corollary for alerting: a metric that can go *stale* needs a liveness rule
beside it (`model_drift_windows_total` flat while `model_inference_vectors_total`
climbs), because a gauge holding its last value looks exactly like a gauge
reporting a steady state.

**Reference.** [`inference::DriftEngine::observe`](../crates/inference/src/drift.rs)
— `try_lock` over `lock`, poison recovery with the partial window discarded, a
bounded pending queue that drops oldest, and `model_drift_skipped_total{model,
reason}` counting `contended` / `poisoned` / `undrained`.

**Anti-pattern.** `let Ok(guard) = mutex.lock() else { return; }` — correct
about not panicking, silent about having given up, and permanent once the lock
is poisoned.

### 15b. Declare your arming state

**Rule.** An optional control — anything that can be switched off by config —
publishes a `..._enabled` gauge (`1`/`0`) **unconditionally at boot, before the
disabled path returns**. Never infer "this is off" from a series being absent.

**Why here.** A control that ships dark exports nothing at all, and *absence
satisfies a threshold rule vacuously*: `max(x{level="alarm"}) > 0` over a
missing series is an empty vector, which is not a breach. So the control, its
alarm, and the §15 liveness rule watching the alarm are all green — for the
same reason, which is that nobody ever asked the question. This is §15's
failure one level up: §15 stops a *running* monitor from dying silently; this
stops a monitor that never started from looking like one with nothing to report.

`absent()` in PromQL is the tempting shortcut and is not equivalent. It also
fires on a renamed metric, a relabelled scrape job, or a scrape that never
landed, and it silently stops working the day anything else exports that name.
An alert that infers a fact from a missing series is the same shape of mistake
as one whose threshold cannot be reached.

**Reference.** [`usage::budget::BUDGET_ENABLED`](../crates/usage/src/budget.rs)
— set before the `USAGE_TOKEN_BUDGET`-unset return, with
`CopilotTokenBudgetDisarmed` reading it directly and
`CopilotTokenBudgetMonitorStale` gated on it so a disarmed deployment cannot
satisfy the staleness rule by accident. The same shape is owed by
`LLM_SPEND_CEILING_TOKENS`, `COPILOT_HTTP_ADDR` and `DETECTION_ANOMALY_CONFIG`.

**Anti-pattern.** `if !enabled { return; }` as the first statement of a
monitor's run loop. Correct, and it makes the "off" state invisible.

---

## 16. A prompt is code, and a prompt change is a reviewed diff

**Rule.** Every instruction sent to a model is a **versioned, content-hashed
artifact checked into the repository** — never a string literal at a call site,
never a value in a console or a database row. Concretely:

1. The text lives in `crates/<service>/prompts/<purpose>.<version>.md` and reaches
   the code through `include_str!`, so the deployed binary physically contains the
   instructions it claims to run.
2. It is wrapped in a `llm::PromptDescriptor` (purpose, version, SHA-256 of the
   bytes) and linked at boot through a `PromptRegistry` — link-or-fail, one live
   version per purpose.
3. Every artifact in the tree, **including retired ones**, has a line in the
   service's checked-in `prompts/MANIFEST`, and a unit test fails when the file and
   the artifacts disagree. Regenerate with `just prompt-manifest`.
4. A change to what the model is *told to do* moves the version and retires the old
   artifact in place (kept, never deleted). A typo fix may stay on the version; the
   manifest still moves, because the manifest is over bytes.
5. `.github/CODEOWNERS` covers `prompts/**`, so the diff needs a second pair of
   eyes wherever branch protection requires code-owner review.

**Why here.** The output of these prompts is a **suspicious-activity report a human
files with a regulator**, and a rule proposal that will run against customer alerts.
Three specific failures follow from treating the text as configuration:

* **Unattributable history.** "Which instructions produced this narrative?" must be
  answerable for a document written eleven months ago. A version string alone cannot
  answer it — an edit made underneath an unmoved version is invisible — which is why
  the digest is stamped beside the id on every draft, exactly as a detector stamps
  `(id, version, config_hash)` and `inference` hashes weights instead of trusting a
  filename. It is also why a retired artifact stays in the tree: a provenance stamp
  pointing at bytes nobody kept proves nothing.
* **Unreviewed behaviour change.** A prompt edit changes what the system says about
  people's money, with no type error, no failing test, and no deploy artifact that
  looks different. The manifest is what turns it into a hunk somebody has to
  approve. This is not hypothetical: `incident_narrative@v1`'s own example wrote
  event ids elided (`[3f2a...-...]`), teaching the model to produce citations that
  the grounding check can never resolve — the artifact was training the failure the
  checker exists to catch, and it took a reader of the *text* to see it.
* **Silent drift in a retired artifact.** A retired prompt is linked to no purpose,
  so no cache key, no boot check and no request digest covers it. Without a manifest
  line, it is the one file in the tree that can be edited with nothing noticing —
  and it is the file that historical drafts are attributed to.

Two smaller rules follow from the same reasoning. **Load-bearing instructions are
pinned by assertions**, not by hoping a reviewer notices they went missing: a test
asserts that the narrative artifact still demands full event ids and still states
the injection boundary. And **the prompt's own examples are held to the format the
parser reads** — an artifact that demonstrates an unparseable citation is a bug in
the same way a wrong constant is.

**Reference.**
- [`llm::prompt`](../crates/llm/src/prompt.rs) — `PromptDescriptor`, `PromptRegistry`, `manifest`.
- [`copilot::prompts`](../crates/copilot/src/prompts.rs) — the linked + retired roster, and the three tests that are the gate: the manifest match, the "every `.md` in the tree is described" sweep, and the instruction assertions.
- [`crates/copilot/prompts/MANIFEST`](../crates/copilot/prompts/MANIFEST) — the reviewed file itself.

**Anti-pattern.** `let system = format!("You are a compliance analyst. {extra}");` at
a call site — unversioned, unhashed, unreviewable, and one interpolation away from
putting attacker-controlled chain data into the instruction channel (which is what
`Untrusted` and the user-turn fence exist to prevent).

**Corollary — governance is checked, not asserted.** The same posture applies to the
*output*: `copilot audit` re-resolves every landed narrative's citations against
event-store and exits non-zero when a stored draft makes a claim the record does not
support ([`copilot::grounding_audit`](../crates/copilot/src/grounding_audit.rs)). A
governance property nobody re-checks after the fact is a governance property that
holds until the first time it doesn't.

---

## 17. The event schema is a contract, and a compatibility gate is what makes it one

**Rule.** Every `DomainEvent` has a committed schema under
[`crates/events/schema/`](../crates/events/schema), and a change to any event is
*classified* before it merges — not merely noticed. Compatible (a new event type,
a field that reads as defaulted, a widened string): re-commit with `just
schema-bless` and review the diff. Consumers first (a new value in a closed
enum): legal, but every consumer deploys before the producer that emits one.
Breaking (a field removed, retyped or newly required; an event type removed; a
topic moved; a partition key changed): blessing refuses — it costs a
`SCHEMA_VERSION` bump plus an [`events::upcast`](../crates/events/src/upcast.rs)
step.

**Why here.** The wire-format goldens already lock the *bytes*, and that is a
different property: they say "this changed", never "this change is safe". Safety
is the operational requirement — a producer and a consumer are deployed minutes
or days apart, and an event written a year ago is still in the event store
waiting to be replayed (§4/§18). The sprint plan's #1 risk is schema churn
rippling downstream, and the half that was still a *convention* ("don't remove a
field") is now the half that fails the build.

Five design choices carry the weight, and each is worth copying the next time
something needs a gate rather than a guideline:

- **The schema is probed out of the real `Deserialize` impl**, not derived a
  second time. Optionality is "delete the field and see whether it still
  decodes"; a closed enum's variants are read out of serde's own `unknown
  variant` error; free-form JSON is "accepts three mutually incompatible
  values". A parallel `schemars`/`utoipa` derive would be a second description
  of the wire format, free to disagree with the first.
- **The archive is append-only, and separate from the belief.**
  `v<N>/registry.json` is rewritten as compatible changes land; `corpus/` only
  ever grows. Fusing them would destroy the pre-change shape on the very
  blessing that introduced the change — a snapshot that regenerates itself is
  not an archive, and this is the failure mode of every "committed golden" that
  is also its own baseline.
- **The transport contract is part of the schema.** `topic` and `partition_key`
  are generated from the real envelope, because a re-keyed event changes every
  consumer's ordering guarantee without touching a field (§20).
- **The engine is a library; the gate is a shell** (§1 applied to tooling).
  Probing and classifying are pure functions in `events::schema`; the file
  handling and the assertions are the test. That is what lets a *consumer* crate
  declare the fields it reads and check them itself.
- **The file format is versioned separately from what it describes**
  (`registry_format` vs `schema_version`), so a change to the tool never reads
  as a change to every event.

**Corollary — the consumer declares what it reads.** The gate can prove a field
was removed; it cannot know who was reading it, because the dependency points
the other way. So each consumer keeps an `EVENT_READS` list and asserts it
against the committed schema (`events::schema::assert_reads`), the same shape as
`topics_for` for topic names — a removed field fails *that* crate's test, naming
itself.

**Reference.**
- [`crates/events/SCHEMA.md`](../crates/events/SCHEMA.md) — the rules table, the archive, and the upcasting seam.
- [`crates/events/src/schema`](../crates/events/src/schema) — the probe, the classifier, the canonical fixtures.
- [`crates/events/tests/schema_registry.rs`](../crates/events/tests/schema_registry.rs) — the shell that fails the build.
- `just schema-check` / `just schema-bless`; the `Event schema compatibility` job in both workflows.

**Anti-pattern.** Adding a field without `#[serde(default …)]` because "every
producer writes it now" — every producer *from now on* writes it; the archive
does not, and replay is what the event store exists for. And no dynamic-key maps
(`HashMap<String, T>`) in a `DomainEvent`: serde cannot tell one from a struct,
so its data keys would be recorded as schema and every new key would read as an
added field. Free form goes in a `serde_json::Value`; anything with meaningful
keys is a `Vec` of pairs.

---

## 18. A retention window is a decision, and one decision has one home

**The rule.** How long a regulatory artifact and the evidence under it must live
is decided **once**, in [`crates/retention`](../crates/retention/), and every
store that has to make it true reads that value. No service computes a window of
its own, and no service reads a differently-named environment variable for it.
A crate that enforces retention without a `retention` dependency fails
[arch-conformance](../crates/arch-conformance/src/lib.rs).

**Why it needs a rule at all.** The failure is not "somebody forgot to expire
data" — that is visible, and cheap to fix. It is **two windows that agree**: an
artifact kept for five years and the evidence under it kept for five years look
identical in a config map and in every code review, and they are not the same
policy. They diverge silently, and the first person to notice is the one who
cannot produce the record. This convention exists because that is exactly what
happened here: the copilot's grounding audit could see a SAR narrative whose
evidence was gone and had **nothing to say about whether that was allowed**, so
its alert could only ask for a decision to be made.

**Four properties any retention policy in this workspace must have.**

1. **A floor that a deployment cannot lower.** `retention::STATUTORY_ARTIFACT_DAYS`
   carries the citation (31 CFR 1020.320(d); Directive (EU) 2015/849 art. 40) and
   the constructor refuses anything shorter, so shortening it is a reviewed code
   change and not an env var. Config resolves *within* a decision; it does not
   make one (§9).
2. **The clocks are named, and their difference is a knob with meaning.** An
   artifact's window runs from its **disposition**; an event's runs from when it
   **occurred**, and in an append-only store (§4) that can never be extended
   afterwards. So evidence is kept for the artifact window *plus a margin* — and
   that margin **is** the furthest back an artifact may be drafted. One knob does
   both jobs deliberately: it must not be possible to unlock older work without
   also keeping the evidence that work will cite.
3. **Automation may widen; only a human may narrow — and the difference is a
   type, not a comment.** Every irreversible operation takes a
   [`retention::DestructiveIntent`](../crates/retention/src/lib.rs) witness whose
   only constructor is `from_operator_flag`. A boot path, a CronJob's default
   arm or a background task cannot reach one *by signature*, so a reviewer's
   question stops being "does this delete anything?" (unanswerable without
   reading the body) and becomes "does this signature mention
   `DestructiveIntent`?". Grep the type to enumerate every destructive operation
   in the platform. Same shape as `backup`'s `Scratch`, and for the same reason.
4. **Destructive work is planned, then applied — and the plan is the whole
   truth.** `plan()` is pure, printable and testable; `apply()` consumes that
   exact plan and does nothing else. A dry run is therefore not a second code
   path that *approximates* the real one: it is the same value with `apply`
   never called. Counts in a plan come from a `COUNT(*)` over the operation's own
   predicate, never from "how many the first page happened to hold" — a preview
   of a destructive action that under-reports is worse than no preview, because
   the number a human approved is not the number that happened.

**Model the observation, not the convenient subset of it.** The first version of
this module read the live TTL as `Option<u32>`, and `None` stood for two
situations with *opposite* safety properties — "there is no window" and "there is
a window I cannot parse". The planner folded both into "unbounded, free to widen
into", so a table carrying `INTERVAL 10 YEAR` was rewritten to six years at boot:
the one thing the module promised never to do, done by the path documented as
safe. A third case hid in the same `Option`: *imposing* a first bound is not
"extending from nothing" — everything already older than the new window is
deleted by the next merge. Three store states, three plans, and the destructive
two ask the store what they would destroy before anyone approves them.

**And the audit has to be able to tell the two apart.** Once a policy exists,
"the evidence is gone" is no longer one observation — it is `expired` (past the
deadline: retention working) or `evidence_missing` (still retained: **the policy
violated**), on one comparison against the same `Policy::is_expired` the purge
uses. If a checker and an enforcer can disagree about when a record was
released, there is a window in which a row is both too old to verify and too
young to delete, and everything in it is unexplainable.

**Reference implementation.**

- [`crates/retention/src/lib.rs`](../crates/retention/src/lib.rs) — the decision, the floor, the inequality.
- [`crates/event-store/src/retention.rs`](../crates/event-store/src/retention.rs) — evidence: the ClickHouse TTL, reconciled extend-only at boot.
- [`crates/copilot/src/retention.rs`](../crates/copilot/src/retention.rs) — artifacts: the purge (dry by default, never touches a legal hold) and the disposition anchor the audit shares.
- [`docs/runbooks/retention.md`](runbooks/retention.md) — the numbers, the alerts, and how to change them.

**The audit trail covers changes to its own governance.** A retention change and
a destruction are facts (`RetentionPolicyChanged`, `RetentionPurgeCompleted`),
published to the backbone and landing in the event store — which is under the
policy they describe, so the record outlives the change by the margin. A gauge is
sampled, a counter is aggregated and a pod log has rotated; none of them answers
"on what date, from what, to what, by whom" or "how many records did we destroy
last quarter". If a control governs regulatory data, its own operation is
regulatory data.

**Two clocks are two types.** An artifact's window runs from a `Disposition`, an
event's from an `Occurrence`, and the pair are newtypes because
`shortfall(anchored, oldest)` over two `DateTime<Utc>`s compiled with its
arguments swapped and returned a plausible wrong number — the exact
under-retention the crate exists to prevent, left representable by the crate
that prevents it (§4).

**A compliance override is a record, not a bit.** A legal hold carries its
matter, its date and the person who placed it, with a CHECK constraint making a
partial one unrepresentable. "Someone set a boolean" is not something anyone can
stand behind when asked why a document that should have been destroyed still
exists — or why one under subpoena was not.

**Anti-pattern.** A `const RETENTION_DAYS` beside the store that uses it; a
`--force`/`--allow-old` flag that lets one half of a policy be satisfied without
the other; a `bool` parameter selecting between a "preview" and a "real" code
path; an `Option<T>` standing for two states with different safety properties;
and a purge that deletes on a schedule with no plan — the flag that costs nothing
is the one to get wrong.

---

## 19. A performance claim needs an instrument that can fail it

**The rule.** If the product states a latency or throughput number, there must
be **one series that spans exactly the claim**, measured end to end across every
component the claim covers — including the queues and the network hops between
them — and a gate that reads *that* series under load. A metric that measures
one component of a multi-component claim is not a weak version of the right
instrument; it is a different instrument, and it will report health precisely
when the claim is most at risk.

Concretely:

1. **Measure the span, not a stage.** The clock starts where the claim starts
   (the producer's timestamp), not where the measuring process happens to
   receive the work.
2. **Load-generate on an absolute schedule, and stamp work with the time it was
   *due*.** A generator that paces itself by sleeping after each send slows down
   when the system does, and reports the latency of a system under light load.
3. **Drain before measuring.** The work still queued when the load stops is the
   slowest work there is.
4. **Measure a window, not a lifetime.** Difference two scrapes, or a
   long-running service's healthy idle history dilutes the breach.
5. **A verdict is three-way.** Held, breached, and *could not decide* — and the
   third one exits non-zero. A performance test has more ways to be
   uninformative than to fail, and every one of them produces a clean-looking
   number over a subset of the work.

**Why it needs a rule.** §6's "preliminary alert in under one second" is the
platform's headline claim, and for most of this codebase's life the only
latency it exported was `detector_detect_duration_seconds` — the wall time of a
single `DetectorPlugin::detect` call. That number is microseconds on a
header-only block, and it is *arithmetically unaffected* by a queue building up
in front of it. The Prometheus rule guarding the claim
(`FastPathLatencyHigh`) read that series, so the alert named after the fast path
could not fire on the failure it named: blocks backing up behind detection would
have left every panel green while alerts arrived seconds late. Nothing was
broken, nothing was untested, and the claim was unfalsifiable — which is worse
than an untested claim, because it looks measured.

The fix is structural, not a bigger dashboard:
[`detection::metrics::FAST_PATH_SECONDS`](../crates/detection/src/metrics.rs)
measures `BlockAssembled.occurred_at` → the alert's durable publication, across
the broker hop and the scheduler's bounded work channel, split into a queue-wait
and a processing term so a breach says *which* half grew.

**Reference.** [`crates/loadtest`](../crates/loadtest/) — the four rules above as
code, and the three-way [`Outcome`](../crates/loadtest/src/slo.rs). Note in
particular that a bucketed quantile is treated as a **bound**: the verdict is
"≥99% of samples at or below the budget", which the shared ladder decides
exactly, and a budget with no bucket boundary on it is rejected when the SLO
loads rather than making every future run silently inconclusive.

**Anti-pattern.** A p99 panel over the cheapest stage of a pipeline, labelled
with the whole pipeline's budget; a load generator that awaits each response
before issuing the next; a "SLO met" that was computed the instant the load
stopped; and — the one that undoes all the rest — a CI job that treats "could
not measure" as a pass.

### 19b. An alert rule is code, and it has no failing state

**Rule.** Thresholds in `deploy/prometheus-rules.yml` are one of exactly three
things, and each rule says which: a **published claim** (§6's <1s), an
**exported gauge** (the deployment's own config, compared as a series), or a
**measurement**. Latency thresholds must land on a boundary of the ladder their
metric is exported on, and strictly below its ceiling. Both are enforced by
[`crates/alert-conformance`](../crates/alert-conformance/), not by review.

**Why here.** This is §19's argument applied to the instrument that watches
production, and the asymmetry is what makes it worth a crate. Almost everything
else in this workspace announces its own failure — a test goes red, a service
crash-loops, a type stops compiling. **An alert has no failing state.** A rule
whose threshold is unreachable, whose series is never scraped, or whose window
is narrower than the job that writes it is *indistinguishable from a healthy
system*: it is green, and green is what you were hoping to see.

Four rules shipped in exactly that condition and were found by a human reading
PromQL. Two compared a `histogram_quantile` against a number above the ladder's
top bucket — and since a quantile landing in `+Inf` reports the highest finite
bound, neither expression could ever exceed 10, whatever it named. Four more
read a **weekly** CronJob's counters through a one-day `increase()`, blind six
days in seven and needing two samples where a short-lived Job may be scraped
once. None of this was a mis-tuned number; every one was a rule that could not
fire.

**Corollary — one ladder is not enough.** `_seconds` does not distinguish "how
long did this call take" from "how long until this comes round again". A
quantity that legitimately runs for minutes or hours belongs in
[`telemetry::metrics::JOB_DURATION_METRICS`](../crates/telemetry/src/metrics.rs);
left on the latency ladder its quantiles are silently pinned at 10s, which is
how the §19 lead-time signal — the predictive pipeline's headline claim — came
to be incapable of reporting a lead time above ten seconds. Note the damage is
confined to quantiles: `_sum`/`_count` are exact whatever the bucketing, so a
*mean* was always right. `histogram_quantile` returning the ceiling is worse
than an error, because 10.0 looks like an answer.

**Never keep a second copy of a ladder or a rule set.** `loadtest` imports
`LATENCY_BUCKETS_SECONDS` rather than copying it; `alert-conformance` asks
`buckets_for` rather than assuming; Kubernetes *generates* its rules ConfigMap
from `deploy/prometheus-rules.yml`. The inlined K8s copy that this replaced had
drifted for three sprints, and production was running a `FastPathLatencyHigh`
still pointed at the series the load test had already proved could not move.

**Severity is a response, not a confidence level.** `informational` is not the
parking space for an untuned number: if the threshold is invented *and* the
condition is an observation rather than a fault, the rule does not belong in the
file. `INFORMATIONAL_ALLOWLIST` is a short, argued list, and conformance fails
on an addition to it.

**Two gates, not one.** `alert-conformance` asks whether a rule *can fire*;
`promtool check rules` asks whether Prometheus will *load the file*. They are
complementary and both are required: a syntax error drops **every** alert in the
file, not just the broken one. `just alerts-check` runs both in CI's order.

**The ladders are a workaround, and there is an exit.** Prometheus **native
histograms** use exponential auto-scaling buckets: no top bucket, so no
threshold can sit above a ceiling, and no boundary alignment, because resolution
is relative rather than enumerated. The exporter already supports them
and the migration is opt-in on **two independent axes**:
`TELEMETRY_NATIVE_HISTOGRAMS` (this cluster's Prometheus can read them) *and*
`NATIVE_HISTOGRAM_METRICS` (these specific series have been moved, currently
empty). Both are required, and that is the design, not caution theatre: native
histograms render only in protobuf and this exporter *stores* a metric as native
once configured, so a migrated metric on a cluster that cannot render it is
**lost, not degraded**. A single suffix-matched switch would move every duration
metric in the platform at once — if the protobuf negotiation were wrong, every
latency panel and every SLO alert would go blank in the same instant, which is
the largest blast radius obtainable from one boolean. Migrate one metric,
confirm it renders, then widen; reverting is deleting a line. Nothing in
`deploy/` enables the flag, so until this is exercised against a real Prometheus
the path is code-complete and unproven. Migrating a metric also takes it outside
the ladder rules above, so conformance and deployment move together.

**Anti-pattern.** A threshold whose provenance nobody can state; `absent()` used
to infer that a subsystem is switched off (§15b); a cadence restated in Rust
next to the CronJob YAML that already declares it; and a contract written as a
comment at the top of a config file, which is what all of the above was before
it was a test.

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
