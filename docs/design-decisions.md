# Design decisions

The long-form reasoning behind MEVWatch: what was decided, why, and where the evidence stops. The [README](../README.md) is the short version. [ARCHITECTURE.md](../ARCHITECTURE.md) is the full system design. The [sprint log](history/sprint-log.md) records how each piece was built.

A rule this page keeps: a number is either **measured** (with where and how), a **declared budget** (a target the code is gated or alerted against), or an **illustration** (labelled as one).

---

## Contents

- [Confirm, don't guess](#confirm-dont-guess)
- [Events are facts, jobs are commands](#events-are-facts-jobs-are-commands)
- [A fast path and a slow path](#a-fast-path-and-a-slow-path)
- [The entity graph and explainable scores](#the-entity-graph-and-explainable-scores)
- [Screening: inline, and fail closed](#screening-inline-and-fail-closed)
- [Where the ML stops](#where-the-ml-stops)
- [Rules in CI, not in a wiki](#rules-in-ci-not-in-a-wiki)
- [Delivery correctness](#delivery-correctness)
- [Scaling by structure](#scaling-by-structure)
- [Measurement](#measurement)
- [Why Rust](#why-rust)
- [Reference: detectors, API, stack, repository](#reference)

---

## Confirm, don't guess

Most MEV detectors pattern-match transaction structure and stop there. MEVWatch does that too, on the fast path, and then replays the detection in `revm` to compute attacker profit and victim loss (for a sandwich, against a counterfactual run with the front-run removed). A heuristic says *probably a sandwich*; simulation says how much moved, and who paid.

*Illustration of the intended output, not a measured result:* "attacker gained 5.2 ETH; the victim paid 0.8 ETH more than without the front-run."

**Where the evidence stops.** The simulation engine is real and tested over seeded pre-state, but fork-from-chain (loading real mainnet state for the replay) is stubbed: revm 41's `alloydb` pins a different `alloy-provider` major than the workspace. Until that lands, confirmation has not run against real chain state.

## Events are facts, jobs are commands

The system runs on two transports, and the split is the most important decision in it.

- **Kafka carries domain events**: facts such as `IncidentCreated` or `RiskScoreUpdated`. They are ordered per partition, retained, and replayable, many services consume the same event, and the event store keeps every one as the audit log.
- **RabbitMQ carries simulation jobs**: work to do, not something that happened. They go to competing consumers with per-job ack, a dead-letter exchange, a delivery limit and a length bound. A command never enters the event store.

Mixing them would make the audit log record intentions, and make the work queue inherit Kafka's partition-count ceiling on parallelism.

## A fast path and a slow path

Detection publishes a *provisional* alert quickly, and simulation confirms or retracts it later. The two are deliberately decoupled: a simulation backlog must never delay provisional alerts. The WebSocket contract carries all three states (`provisional_alert` → `alert_confirmed` → `alert_retracted`).

The fast path's budget is < 1s p99 from block to published alert (declared, and measured; see [Measurement](#measurement)).

## The entity graph and explainable scores

An entity is a cluster of addresses believed to share an owner. Clustering signals are a common funder, a common deployer, the same bytecode hash, and a shared profit receiver, with a degree cap on hub nodes so an exchange hot wallet does not merge half the chain into one actor. Merges are serialized per entity, and every merge invalidates and recomputes the affected risk scores.

Scores are 0–100 with an independent `confidence`, versioned, and broken down into factors that each cite the events behind them. *Illustration of the shape:*

```
Score: 91 / 100   Confidence: 0.94   (model v1.4.2)
+25  sim-confirmed sandwich attacks
+20  entity cluster spanning several wallets
+10  funded via a mixer (2 hops, confidence 0.6)
```

Score answers *how risky*; confidence answers *how sure*. Showing both keeps a number backed only by heuristic labels from being over-trusted.

Behavioral embeddings widen recall without weakening that story. A strong similarity match to a known actor becomes a **candidate link** for a human to confirm, never an automatic merge, and a label the system derived itself can never anchor a further match.

## Screening: inline, and fail closed

`POST /v1/address/{addr}/screen` returns `allow` / `review` / `block` synchronously, for exchanges to call on every withdrawal. Latency here is contractual: **p50 < 100ms and p99 ≤ 250ms are declared budgets**, gated by the load test's degraded profile, and not yet measured against a real stack.

- **When intelligence is slow**, a stale-but-flagged snapshot answers (disclosed on the response *and* in the audit record) instead of blocking the withdrawal. The fresh read runs behind a bulkhead, a circuit breaker that also counts slow reads, and budgeted hedged reads.
- **When no snapshot exists**, it still fails closed (502). Degradation widens what can be answered; it never turns "could not decide" into "allow".
- **Sanctions never come from a snapshot.** A pod-local sanctions view is merged into every decision, and a stale `allow` it cannot vouch for is held as `review`.

## Where the ML stops

Built and shipped:
- a frozen feature schema, training-set export with provenance, and an ONNX inference seam
- an isolation-forest anomaly detector (shadow-staged)
- behavioral embeddings with similarity search
- an LLM copilot that drafts SAR narratives with per-claim event citations, and drafts rules from natural language

What no model here can do is **act**:
- A narrative waits for a human to approve it.
- A drafted rule must compile through the rule engine's own parser, so a hallucinated rule cannot run.
- Model output never enters the event store as evidence, and never touches the entity graph.
- An after-the-fact audit re-resolves every citation against the event store.

The copilot never calls the model inside a Kafka handler. A multi-minute completion there becomes the poll interval, and the rebalance it causes redelivers the record into a second billed call. The consumer records a job and commits in milliseconds; workers lease jobs from a Postgres queue whose row doubles as the cross-pod response cache.

## Rules in CI, not in a wiki

Invariants that matter are tests, because prose is how they drift:

| Gate | Fails the build on |
|---|---|
| `arch-conformance` (dependency graph) | a detector depending on the detection service, `rdkafka` without `event-bus`, `sqlx` without `db`, … |
| `arch-conformance/tests/deploy_users.rs` | a named Dockerfile `USER`, or a third-party image under `runAsNonRoot` without a numeric `runAsUser` |
| `arch-conformance/tests/deploy_scaling.rs` | an HPA over a `Recreate` (single-writer) workload, a dangling HPA target, or `replicas` fixed beside an HPA |
| `alert-conformance` | a quantile threshold off its bucket ladder or above its ceiling, a batch series read through too narrow a window, an unroutable severity |
| `simulation/tests/grace_period.rs` | a worker grace period shorter than job deadline + overshoot allowance + result publishes × send timeout |
| backtest | a detector regressing below its committed precision/recall baseline |

**Why alerts get a gate.** An alert has no failing state. A rule whose threshold is unreachable looks exactly like a healthy system. The latency calibration found four such rules, including the headline fast-path alert, which watched one `detect` call's duration: microseconds, and unmoved by a queue building up in front of it.

## Delivery correctness

Delivery is at-least-once with idempotent processing: every output is keyed on a stable id, so a redelivery is a no-op downstream. Two bugs found while making autoscaling safe show why the rules below exist.

- **A retry must re-fetch.** The shared consume loop's `Handled::Retry` backed off and called `recv()`, which returns the *next* record. librdkafka never redelivers an uncommitted record within a session, so the next commit passed the retried one. `run_consumer` now seeks the partition back, proven against a real broker (`event-bus/tests/retry_refetch.rs`).
- **Settle on delivery, not on the shutdown token.** Callers inferred "was it published?" from whether shutdown had fired. That made the simulation worker requeue jobs whose results had landed (re-running revm on every scale-down), and it let detection commit past alerts it had not published. `publish_resilient` now returns `Result<(), Undelivered>`, which a deny-warnings build will not let a caller ignore. Consumers settle on it; fire-and-forget callers write `.accept_loss(why)`, a claim a reviewer can check. One real gap is stated, not hidden: the cross-chain finality tracker releases a finding before its retraction is published.
- **A work queue is bounded, and full means refuse.** `sim.jobs` carries `x-max-length-bytes` with `x-overflow: reject-publish`. A nack becomes the dispatcher's `Retry`, so at the pool's maximum size the backlog waits in Kafka lag (durable, alerted) instead of broker memory, and nothing is silently dropped.

## Scaling by structure

A service gets an HPA only if its replicas are interchangeable; a service with a single writer anywhere in its loop runs as one replica with `Recreate`.

- **Simulation workers scale on queue depth**, the signal the queue was designed around. The metric is (ready + unacked) ÷ the replica's declared capacity (workers × prefetch, exported by the worker), against a target of 1. The scaling point is therefore the deployment's own prefetch, not a number in the HPA. On kind: 2 → 5 replicas in 37s under 300 queued jobs, and back down in 60s steps after a 300s window.
- **Detection has no HPA, on purpose.** The chain is the Kafka partition key, so a second replica would rebalance the one partition, stalling the fast path under exactly the load that triggered it, and then idle. The measured degradation came from co-resident load, so the lever is isolation: Guaranteed QoS, and anti-affinity that keeps autoscaled API pods off detection's nodes.
- **The copilot is not autoscaled.** What reaches the provider is replicas × concurrency against an org-wide rate limit, which makes it a spend decision.

Running the tree on kind found that **no pod could have started**: `deploy/Dockerfile` ended on `USER appuser`, a name, under `runAsNonRoot: true`, which the kubelet can only verify against a numeric uid. Rendering and schema validation both passed. That is now `deploy_users.rs`.

**The event store is priced before it is bought.** `crates/capacity` multiplies the committed load model (rates per event type as driver × multiplier), sizes measured from the schema corpus, the partition key read from the migrations, and the retention window. Out come partitions, shards, disk and a monthly bill over an eight-year horizon, and a gate that fails the build at 1.5× load. A breach is reserved for decisions that are expensive to reverse: a partition key or a Kafka partition count. Disks and shards are purchases, so they are reported with the year they arrive. The model's first run found the original daily `(chain, event_type, date)` key would pass `max_parts_in_total` inside the six-year evidence window and refuse every insert. It also found that a backup restore could not insert the table back at all, since one block would touch far more than 100 partitions. The live path appends one row at a time into a young table, so it could never have shown either. The table is now monthly and `ReplacingMergeTree`, put in place without a boot-time copy: a migration stages `events__next`, boot swaps only when the live table is empty, and a store with data moves through a resumable Job. The write path under it is idempotent in three layers (a per-batch insert deduplication token, the engine's key, `LIMIT 1 BY event_id` on read), batched to a few inserts a second, and never commits past evidence it did not store. Kafka chains occupy registered partition slots instead of colliding by hash. The projection: 6.7M events and 1.1 GiB a day, of which 96% is embeddings, screening decisions and metering, not chain data. At 1.4× a year it reaches 15 TiB a replica by year eight, 14 of them past the 90-day tiering threshold, so one node per replica holds the hot data.

## Measurement

**Detection accuracy.** Every PR replays the corpus through all detectors. It fails on a regression below the committed baseline, or on an active detector below the promotion floor. The corpus is **8 hand-built scenarios** (one per detector, plus a clean block) and **22 adversarial near misses**, and the committed numbers are precision 1.0 / recall 1.0 over it. That proves each detector's contract: the signature fires and the edges hold (each threshold near miss is shown to fire once that one threshold is loosened). It is not field accuracy, because an author can write any number of fixtures.

**The false-positive rate is a target, and CI keeps it one.** The claim is *< 4% of alerts refuted by simulation*. It can rest only on replayed mainnet windows (`crates/corpus`, captured by `dataset window`) labelled by the §20.1 flywheel. Those labels exist only where a detector already fired, so a window is open-world. An alert with no verdict is *unadjudicated*, not a false positive, and the windows measure precision, never recall. `backtest` states the claim only when two upper bounds are under 4% across at least 3 windows. The first is the one-sided 95% Wilson bound (with zero refutations, that takes 65 adjudicated alerts). The second is a seeded moving-block bootstrap, because mainnet refutations come in bursts and Wilson treats a burst as independent evidence. A README test fails if the README says more than that verdict allows. Windows are captured from an archive node by `crates/chain-enrich`. It keeps a `Swap` only when the emitting pool is proven to be a known factory's pair by recomputing its CREATE2 address, and prices come from Chainlink feeds whose identity is checked at boot. Today there are 0 committed windows: nobody has run a capture against an archive node yet.

**A measurement names the build it measured.** A precision number is a fact about one `(id, version, config_hash)` triple, and the hash covers each detector's real config (a required `config_value()`, hashed as canonical JSON; the shipped hashes are pinned by a golden test). The baseline and the model cards are both `BuildKeyed` stores, read through one three-way lookup: `Current`, `Stale` or `Missing`. So the gate can report `REGRESSION` (same build, worse numbers) apart from `REBUILT` (we changed it). A card never shows numbers for a config that was not scored. The model-card store is compiled into the binary it describes, and a stale card is exported as `detector_performance_stale` and alerted on.

**Fast-path latency.** The load test (`crates/loadtest`) is built to be able to fail:
- Blocks are stamped with the time they were *due*, not sent, so it avoids coordinated omission.
- It drains before measuring.
- Its window is the difference of two scrapes.
- Its verdict is three-way: held, breached, or undecided. An undecided run fails CI.

Result (`mainnet-peak`, 4 blocks/s, everything on one laptop): p99 ≤ 250ms with the API idle; with 100 qps of co-resident API load, queue wait rose from 2.5ms to 500ms and the fast path reached 1.000s, exactly on budget. That 4× came entirely from contention, and it would have been invisible to the old alert.

**In production, the number comes from customers.** The CI gate above measures the platform against fixtures and replayed windows; neither can see the incident that was technically correct and still noise to the person who received it. `POST /v1/incidents/{id}/feedback` is the only input to that judgement, and the §19 panel divides false positives by **adjudicated** incidents — not by all of them, because dividing into everything nobody read turns a 10% rate among reviewed findings into a reassuring 0.4%. Three consequences follow. A window nobody adjudicated publishes **no rate at all** (absent, not zero). The window is *settled*, ending a delay before now, because verdicts arrive days late and the fastest ones are not a random sample. And the SLO arms on its own gauge, so a rate over four verdicts cannot page anyone — with a second alert for the failure that looks like success, a platform nobody reviews.

**Not measured yet:** anything on real mainnet transactions, any staging run at 1.5× projected peak, and the screening budgets against a real stack.

## Why Rust

- `revm` and `alloy` are Rust-native: no FFI on the simulation path.
- CPU-bound EVM work runs on `rayon`, off the async reactor; `tokio` handles I/O.
- Bounded `mpsc` channels make backpressure between async stages and CPU workers a type, not a hope.
- The domain event hierarchy is modelled in the type system, with invalid transitions unrepresentable and newtypes validated at the parse boundary.
- `proptest` covers the sandwich and arbitrage detectors, event serialization round-trips, risk scoring, and feature invariants.

---

## Reference

### Detection coverage

| Attack type | Detection | Confirmation |
|---|---|---|
| Sandwich | Adjacency, direction, profit threshold | revm counterfactual |
| Atomic arbitrage | Multi-hop cycle detection | Balance diff |
| Flash-loan exploit | Borrow + oracle deviation + drain | revm replay |
| Rug pull / honeypot | LP drain + buy/sell probe | revm honeypot probe |
| Liquidation MEV | Liquidation events + bot clustering | On-chain verification |
| Wash trading | Cross-block transfer-graph cycles | Entity clustering |
| Address poisoning | Near-duplicate address pattern | Heuristic |
| Unknown patterns | Isolation-forest anomaly model (ONNX, shadow) | revm replay |

### API surface

```
POST /v1/address/{addr}/screen           synchronous allow / review / block
GET  /v1/address/{addr}/risk             risk score + confidence + factor breakdown
GET  /v1/address/{addr}/labels           labels with provenance
GET  /v1/address/{addr}/similar          behaviorally similar addresses, with per-feature contributions
GET  /v1/address/{addr}/link-candidates  proposed cluster links awaiting review
GET  /v1/entity/{id}                     entity profile
GET  /v1/entity/{id}/graph?hops=2        connected addresses (degree-capped)
GET  /v1/entity/{id}/timeline            milestone history
GET  /v1/incidents                       paginated incident feed
GET  /v1/audit/incident/{id}             the complete event stream for one incident
GET  /v1/builders                        builder leaderboard by MEV type
POST /v1/rules                           create a custom alert rule
POST /v1/incidents/{id}/feedback         adjudicate an incident: true_positive / false_positive / unclear
WS   /v1/stream                          live incidents: provisional → confirmed → retracted
```

Swagger UIs: `server` at `:8080/swagger-ui`, `event-store` at `:8081/swagger-ui`, `predictive` at `:9466/swagger-ui` (these need the dev stack from `just up`).

### Stack

- **Runtime:** Rust, `tokio`, `rayon`, `axum`, `tonic`
- **Chain:** `alloy`, `revm`; a reth ExEx ingestion node lives outside the workspace, with its own lockfile
- **Storage:** PostgreSQL (`sqlx`), ClickHouse (the event store and analytics), Redis (caches, rate limits)
- **Messaging:** Kafka (`rdkafka`), RabbitMQ (`lapin`)
- **Observability:** `tracing` + OpenTelemetry, Prometheus, Grafana, Alertmanager, Tempo
- **Deploy:** docker-compose for local development, and a kustomize tree for Kubernetes (validated on kind)

**Chains:** Ethereum and Base.

### Repository

One Cargo workspace: 42 member crates, 17 of which build the 19 service and tool binaries.

| Area | Crates |
|---|---|
| Backbone | `events`, `event-bus`, `event-store` |
| Pipeline | `ingestion`, `detection`, `detector-api`, nine `*-detector` crates (seven attack classes, the anomaly model, a demo), `simulation`, `cross-chain-correlator`, `predictive` |
| Intelligence and product | `intelligence`, `rule-engine`, `notification`, `server`, `auth`, `usage` |
| ML and LLM | `ml-features`, `dataset`, `inference`, `anomaly-detector`, `llm`, `copilot` |
| Operations | `backup`, `rebuild`, `retention`, `loadtest`, `backtest` |
| Guards and shared | `arch-conformance`, `alert-conformance`, `telemetry`, `db`, `ch-migrate`, `resilience`, `bounded-map`, `api-error` |

| Command | What it runs |
|---|---|
| `just test` | Unit tests and doctests: hermetic, no infrastructure |
| `just backtest` | Replay the ground-truth fixtures; fail on a regression |
| `just check` | The full CI gate, locally |
| `just up` / `just test-integration` | The docker-compose stack, and the `#[ignore]` tests against it |
| `just k8s-apply` / `just k8s-apply-cluster` | The kind overlay, and the once-per-cluster add-ons |
