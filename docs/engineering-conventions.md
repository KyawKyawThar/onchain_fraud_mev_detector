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
  the loop; reorg-rewindable if it holds cross-block state (§15).
- [ ] **Nothing slow inside the handler.** `run_consumer` awaits the handler
  *before* committing, so the handler's worst case is the poll interval: a
  call that can take minutes (a model, a third-party API, a long simulation)
  blows `max.poll.interval.ms`, gets the member evicted, rebalances the
  partition, and redelivers the record into a *second* run of the same
  expensive work — with the first still in flight. Raising the poll interval
  only trades that for a fleet that takes minutes to notice a dead pod. The
  fix is structural: the handler records a durable work item and commits, and
  a pool drains it on its own clock (§7's slow path; §20.4's copilot).

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
