# MEVWatch

**Real-time MEV detection and blockchain threat intelligence.**

[![CI](https://github.com/KyawKyawThar/onchain_fraud_mev_detector/actions/workflows/ci.yml/badge.svg)](https://github.com/KyawKyawThar/onchain_fraud_mev_detector/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/Rust-stable-orange?logo=rust&logoColor=white)
![License](https://img.shields.io/badge/license-proprietary-red)

MEVWatch monitors Ethereum and EVM-compatible chains block by block, detects
sandwich attacks, flash loan exploits, rug pulls, wash trading, and address
poisoning — then confirms every detection through EVM simulation before
surfacing it to customers. The result is simulation-backed threat intelligence,
served through a REST/WebSocket API, a live dashboard, and a configurable alert
rule engine. A false-positive rate below 4% is the **product target**; what is
*measured* today is a CI-enforced precision/recall gate over ground-truth
fixtures — see [Measurement: what the numbers cover](#measurement-what-the-numbers-cover)
for exactly what that does and does not establish.

---

<!--
Demo section — re-enable once the video and screenshots exist.
The image files go in docs/ (live-monitor.png, intelligence.png, rule-engine.png).

## Demo

> *Full demo video — architecture walkthrough, live incident detection,
> entity graph, rule engine test mode.*

[![MEVWatch Demo](https://img.shields.io/badge/▶_Watch_Demo-4_minutes-teal?style=for-the-badge)](https://loom.com/placeholder)

Screenshots:

| Live Monitor | Entity Intelligence | Rule Engine |
|---|---|---|
| ![Live Monitor](./docs/live-monitor.png) | ![Intelligence](./docs/intelligence.png) | ![Rules](./docs/rule-engine.png) |

---
-->

## What makes this different

**Most MEV detectors are heuristic-only.** They pattern-match transaction
structure and flag probable attacks. MEVWatch does that too — but then it
confirms every detection by replaying the transaction in a forked EVM state
using `revm`, computing exact attacker profit and victim loss through
counterfactual simulation. A heuristic says *probably a sandwich*. Simulation
says *attacker made $14,820. victim paid $9.19 per WETH above fair price.
here is the call trace.*

**The entity intelligence graph is the moat.** Raw incident detection
commoditises — anyone can copy a sandwich heuristic. An entity graph that has
clustered 32 wallets to a single actor, traced funding sources through two
mixer hops, tracked $8.2M in lifetime extraction across four chains, and built
a two-year behavioral history does not commoditise. It compounds. Every
incident makes it more accurate. Competitors cannot copy it by reading this
README.

**The rule engine is the commercial unlock.** Compliance teams at exchanges
and risk officers at DeFi protocols need custom alerting logic that goes beyond
predefined detectors: *"alert when any wallet within 2 hops of a
sanctions-listed address interacts with our protocol contracts with value above
$10K."* That is a rule, not a detector. Rules are the enterprise pricing tier.

**The screening API turns the graph into an inline product.** Detection and
rules are things you *watch*. The Counterparty Screening API is something you
*call* — a single synchronous request (`POST /v1/address/{addr}/screen`) that
returns an `allow` / `review` / `block` decision in under 100ms, for exchanges
and custodians to run inline on every withdrawal and onboarding. It is a thin
decision layer over the same intelligence graph, metered per call — the
highest-leverage way to sell the moat to non-dashboard buyers.

---

## Architecture

Full design document: [ARCHITECTURE.md](./ARCHITECTURE.md)

Eight Rust microservices on a dual-transport event backbone:

```
                    ┌──────────────────────────────────┐
                    │         EVENT BUS (Kafka)         │
                    │  domain events · ordered · replay │
                    └────────────────┬─────────────────┘
                                     │
        ┌────────────────────────────┼────────────────────────────┐
        ▼                            ▼                            ▼
  ingestion-service       detection-service            simulation-service
  reth ExEx · 4 chains    heuristic · < 1s fast path   revm · RabbitMQ queue
        │                            │                            │
        └────────────────────────────┼────────────────────────────┘
                                     ▼
                           intelligence-service
                           entity graph · risk scores · labels
                                     │
                          ┌──────────┴──────────┐
                          ▼                     ▼
                   rule-engine-service     api-service
                   custom alert logic      REST · WS · gRPC
                          │                     │
                          ▼                     ▼
                 notification-service    billing-service
```

**Two transports, split at the events/commands boundary:**

- **Kafka** — domain events (facts: `IncidentCreated`, `RiskScoreUpdated`).
  Ordered, replayable, retained. Multiple services consume the same event.
  The event store is the immutable audit backbone.
- **RabbitMQ** — simulation work commands only (`SimulationJob`). Competing
  consumers, per-job ack, dead-letter exchange, priority queue. A command is
  not a fact — it never enters the event store.

This distinction is the most important architectural decision in the system.
See [ARCHITECTURE.md §3](./ARCHITECTURE.md#3-service-topology) for the full
rationale.

---

## Detection coverage

| Attack type | Detection method | Confirmation |
|-------------|-----------------|-------------|
| Sandwich attack | Heuristic (adjacency, direction, profit threshold) | revm counterfactual sim |
| Atomic arbitrage | Multi-hop cycle detection | Balance diff |
| Flash loan exploit | Borrow + oracle deviation + drain pattern | revm full replay |
| Rug pull / honeypot | LP drain detection + buy/sell sim | revm honeypot sim |
| Liquidation MEV | Protocol liquidation event + bot clustering | On-chain verification |
| Wash trading | Cross-block transfer graph cycle detection | Entity clustering |
| Address poisoning | Near-duplicate address generation pattern | Heuristic |
| Novel patterns *(Sprint 18)* | ML anomaly model (isolation forest, ONNX in-process) | revm full replay |

---

## Entity intelligence

The intelligence service maintains an entity graph across all monitored chains.
An entity is a cluster of addresses believed to be controlled by the same actor.

Clustering signals: common funder · common deployer · same bytecode hash ·
shared profit receiver

Every confirmed incident enriches the graph. Every entity merge propagates
downstream to invalidate and recompute risk scores. The data flywheel:

```
entity clustering → auto-labels → better attribution → more entity links → repeat
```

Risk scores are **explainable and versioned**:

```
Score: 91 / 100   Confidence: 0.94   (model v1.4.2)

+25  183 sim-confirmed sandwich attacks (lifetime profit: $8.2M)
+20  Entity cluster: 32 linked wallets, 4 chains
+15  Prior flash-loan-adjacent incident (correlation 0.88)
+10  Funded via Tornado Cash mixer (2 hops, confidence: 0.6)
+12  Profit/incident +40% MoM, 4 new wallets in 30d
+9   Expanded to Base (7d ago)
```

`score` and `confidence` are independent axes. Score answers "how risky."
Confidence answers "how sure." Surfacing both prevents over-trusting a number
backed only by heuristic labels.

---

## ML layer

Full design: [ARCHITECTURE.md §20](./ARCHITECTURE.md#20-aiml-layer) · build-out: Sprints 18–20.

What is **built** here is classical ML — a gradient-boosted classifier and an
isolation forest, served as ONNX through an in-process inference seam. The
LLM copilot (§20.4) is **designed, not built**; it is marked as such below.
Being explicit about the line, because "AI" is doing a lot of work in most
repos and none of it is doing any here.

| §20 component | Crate | Status |
|---|---|---|
| Frozen, versioned feature schema | `ml-features` | Shipped |
| Training-set export + provenance | `dataset` | Shipped |
| ONNX inference seam (`ort`) | `inference` | Shipped |
| Isolation-forest anomaly detector | `anomaly-detector` | Shipped, Shadow-staged |
| Rollout gate · drift · governance | `backtest`, `detection` | Shipped |
| Behavioral embeddings + similarity search | `intelligence` | Shipped |
| LLM investigation copilot (SAR drafts, NL rules) | — | **Designed only** |

The platform's event-sourced core makes it an unusually good substrate for
ML, and the layer is built to exploit exactly that, under the same governance
as everything else:

**The training data is free.** Every detection is confirmed or refuted by EVM
simulation with a measured profit/loss — so the event store continuously
generates labeled ground truth, and deterministic replay makes every training
dataset reproducible byte-for-byte. No hand-labeling, no external dataset.

**ML detection rides the existing rails.** An ML detector is just another
`DetectorPlugin` (`ModelKind::ML` has been in the trait since day one):
ONNX inference in-process via `ort` behind an `InferenceEngine` seam, model
weights hash-pinned into the registry's `config_hash`, shadow-deployed and
gated by the same backtest precision/recall harness as every heuristic. A
supervised classifier sharpens confidence on known patterns; an
isolation-forest anomaly model flags attacks that *have no signature yet* —
with feature-level evidence, because unexplainable detection doesn't ship
here.

**Behavioral embeddings widen the moat.** Per-address behavior vectors +
a ClickHouse HNSW vector index answer "which addresses behave like this known
attacker" — surfacing cluster candidates a fresh-funded bot can't hide from,
via `GET /v1/address/{addr}/similar`. Scores are cosine similarity over
population-standardized vectors, and each result carries the per-feature
contributions that produced it — an exact decomposition of the score, not an
attribution laid beside it.
Similarity is a reduced-confidence clustering signal, never an auto-merge:
the graph's correctness story stays intact.

**The LLM copilot is designed to be hallucination-safe by construction —
and is not built yet.** No copilot crate exists; this paragraph describes
§20.4's design, not shipped behavior. The intended construction: SAR narrative
drafts grounded in the audit trail, every factual claim carrying the event ids
it derives from, so reviewers verify against the store rather than the model.
Natural-language rule creation ("alert when a wallet within 2 hops of a
sanctioned address moves > $10K") would emit the rule engine's existing wire
form and must compile through the existing parse boundary — so a hallucinated
rule fails compilation and can never run. LLM output stays a proposal, never a
fact: nothing it produces would enter the event store as evidence.

---

## API surface

```
POST /v1/address/{addr}/screen        synchronous allow/review/block decision (pre-tx screening)
GET  /v1/address/{addr}/risk          risk score + confidence + factor breakdown
GET  /v1/address/{addr}/labels        all labels with provenance
GET  /v1/address/{addr}/similar       behaviorally similar addresses, with the factors driving each match
GET  /v1/entity/{id}                  full entity profile
GET  /v1/entity/{id}/graph?hops=2     connected addresses (degree-capped)
GET  /v1/entity/{id}/timeline         curated milestone history
GET  /v1/incidents                    paginated incident feed
GET  /v1/audit/incident/{id}          complete event stream for one incident
GET  /v1/builders                     builder leaderboard by MEV type
POST /v1/rules                        create a custom alert rule
WS   /v1/stream                       live incident stream (provisional + confirmed + retracted)
```

WebSocket clients handle three lifecycle transitions:
`provisional_alert` → `alert_confirmed` (with sim data) → `alert_retracted`

The screening endpoint is the exception to the async model — it answers
synchronously (`allow` / `review` / `block`) over the intelligence cache, with a
customer-configurable, versioned decision policy and a hard-block-on-sanctions
override. Every decision carries the factor breakdown so a block is auditable.

### Interactive API docs (Swagger)

`api-service` above is the public, JWT-gated surface. A few internal services
also expose their own read APIs with a live Swagger UI — useful for exploring
the system by hand while developing, no Postman collection to maintain:

| Service | Run it | Swagger UI |
|---|---|---|
| `server` (public API) | `cargo run -p server` | `http://localhost:8080/swagger-ui` |
| `event-store` (audit/replay — every domain event ever published, incl. every predictive forecast) | `cargo run -p event-store` | `http://localhost:8081/swagger-ui` |
| `predictive` (live liquidation-cascade risk — §16) | `cargo run -p predictive` | `http://localhost:9466/swagger-ui` |

Each Swagger UI lets you fire a request straight from the browser ("Try it
out") — no separate client needed. `predictive`'s is the newest: `GET
/v1/positions` lists every currently tracked position's live risk, and `GET
/v1/cascade/simulate?asset=0x...&price=2180` runs the reflexivity model
on-demand against whatever the tracker currently holds ("what if this asset
drops to $X right now") without waiting for a real oracle tick. `event-store`
covers the historical side of the same feature — `GET
/v1/replay?event_type=LiquidationCascadeWarned` returns every cascade warning
ever published, since it durably stores every event type automatically.

These internal services need their `.env` configured (Kafka/Postgres/ClickHouse
per `.env.example`) to boot for real; `just up` brings up the dev stack.

---

## Tech stack

**Language:** Rust throughout — `tokio` async runtime, `rayon` for CPU-bound
parallelism (EVM simulation), `axum` for HTTP/WebSocket, `tonic` for gRPC.

**Chain integration:** `reth` ExEx (execution extension — receives blocks
inside the node before DB commit), `alloy` for types/ABI/provider, `revm`
for EVM simulation.

**Storage:**
- PostgreSQL — entity metadata, labels, rules, customer accounts (`sqlx`)
- ClickHouse — event store (append-only domain events), incident analytics
- Redis — entity/score cache, rate limiting
- S3/R2 — raw block and trace archival

**Messaging:**
- Kafka (`rdkafka`) — domain event backbone
- RabbitMQ (`lapin`) — simulation job work queue

**Observability:** `tracing` + OpenTelemetry distributed traces, `metrics` +
Prometheus, Grafana dashboards. Key SLOs: end-to-end alert latency, simulation
confirmation rate, false-positive rate.

---

## Business model

| Tier | Monthly | Key limits |
|------|---------|-----------|
| Free | $0 | Dashboard read, limited API |
| Starter | $99 | 10K API calls, 5 rules, webhook alerts |
| Pro | $499 | 50K API calls, 25 rules, full entity graph |
| Enterprise | Custom | Unlimited + SLA + SAR export |

**Counterparty Screening API — metered, per-call (billed separately from seats):**

| Tier | Price | Applies when |
|------|-------|--------------|
| Developer | $0.01 / call | first 1,000 free, no commit |
| Growth | $0.007 / call | volume ≥ 100K / mo |
| Scale | $0.004 / call | volume ≥ 1M / mo |
| Enterprise | Custom | SLA · on-prem · raw feed |

The dashboard exposes nine surfaces — Intelligence, Live Monitor, Audit Trail,
Screening API, Builders, Analytics, Alerts, Detectors, and Billing — over the
same event-sourced backbone.

Target customers: compliance teams at crypto exchanges (regulatory obligation
to file SARs, plus inline withdrawal screening), DeFi protocol risk officers
(attack attribution and blocking), and quantitative researchers (MEV landscape
data).

---

## Why Rust

- `revm` and `alloy` are Rust-native — no FFI, no bindings overhead on the
  critical simulation path
- Zero-copy `bytes::Bytes` decoding of RLP-encoded block data at chain
  throughput
- Bounded `mpsc` channels give compile-time-enforced backpressure between
  async stages and CPU workers
- The type system models the domain event hierarchy precisely — invalid state
  transitions are unrepresentable
- `proptest` property-based testing on the sandwich heuristic and entity merge
  logic covers edge cases that example-based tests miss

---

## Repository structure

One Cargo workspace; each service is a crate that ships as an independent
binary/container.

```
├── ARCHITECTURE.md              full system design and rationale
├── production_readiness.md      MVP → GA: hardening epics with exit gates
├── crates/
│   ├── events/                  locked domain-event schema + versioned envelope
│   ├── event-bus/               Kafka produce/consume seams (EventSink, run_consumer)
│   ├── event-store/             immutable audit log service (ClickHouse)
│   ├── ingestion/               reorg-aware block assembly, chain events
│   ├── ingestion-exex-node/     Reth ExEx in-process ingestion node
│   ├── detection/               fast-path detector scheduler (< 1s)
│   ├── detector-api/            the DetectorPlugin seam detector crates implement
│   ├── sandwich-detector/       │
│   ├── arb-detector/            │
│   ├── flashloan-detector/      │
│   ├── liquidation-detector/    ├─ detector plugin crates (one per attack class)
│   ├── rugpull-detector/        │
│   ├── washtrading-detector/    │
│   ├── poisoning-detector/      │
│   ├── anomaly-detector/        │  ML: isolation forest over frozen features (§20.2)
│   ├── demo-detector/           │
│   ├── cross-chain-correlator/  bridge-crossing MEV correlation (§24)
│   ├── simulation/              slow-path revm confirmation (RabbitMQ workers)
│   ├── intelligence/            labels · entities · attribution · risk · embeddings
│   ├── rule-engine/             customer rules: compiler, temporal windows, webhooks
│   ├── predictive/              pre-harm forecasts: mempool + liquidation cascade risk (§16)
│   ├── notification/            multi-channel delivery, dedup ledger, retraction re-targeting
│   ├── server/                  public API: REST · WebSocket · JWT · usage metering
│   ├── usage/                   metering sink + daily rollups (§13)
│   ├── ml-features/             frozen, versioned feature schema (§20.1)
│   ├── dataset/                 training-set export with provenance + manifests (§20.1)
│   ├── inference/               ONNX runtime seam (`ort`) behind InferenceEngine (§20.2)
│   ├── backtest/                replay ground truth → precision/recall; the CI gate
│   ├── db/ · ch-migrate/        shared Postgres pool + ClickHouse migration runner
│   ├── telemetry/               tracing + metrics boot, W3C trace propagation
│   ├── bounded-map/             bounded-memory collections for long-lived consumers
│   ├── arch-conformance/        enforces the dependency seam rules in CI
│   └── api-error/               shared API error vocabulary
├── deploy/                      docker-compose · k8s kustomize · Grafana dashboards
├── docs/                        engineering conventions
└── justfile                     `just check` reproduces the CI gate locally
```

---

## Getting started

Prerequisites: Rust (stable, via [`rustup`](https://rustup.rs)) and
[`just`](https://github.com/casey/just). Nothing else — no database, no
Kafka, no Docker. Every `sqlx::query!` verifies against a committed offline
cache (`SQLX_OFFLINE=true`, the default), so build/lint/test never need a
live service.

```bash
git clone https://github.com/KyawKyawThar/onchain_fraud_mev_detector
cd onchain_fraud_mev_detector
just check       # fmt --check · clippy -D warnings · nextest · release build
                  # · the backtest precision/recall gate — exactly what CI runs
```

Fastest way to see something run — replays labeled ground-truth incidents
through all seven detectors and prints a measured precision/recall report,
gated against a committed baseline (no infra required):

```bash
cargo run -p backtest
```

| Command | What it runs |
|---|---|
| `just test` | Unit tests (nextest) + doctests — hermetic, no infra |
| `just backtest` | Replay ground-truth fixtures; fail if any detector regressed below its committed baseline |
| `just check` | The full CI gate, locally: fmt, clippy, tests, release build, backtest gate |
| `just up` | Bring up the full dev stack (Postgres, Redis, ClickHouse, Kafka, RabbitMQ) via docker-compose |
| `just test-integration` | + `#[ignore]` tests against the real stack above (needs `just up`) |
| `just tools` | One-time install of `cargo-nextest`, `sqlx-cli`, `cargo-audit`, `cargo-deny`, etc. |

The engineering conventions behind this (seams + in-memory doubles, typed
errors, "parse don't validate," the three test layers, supply-chain policy)
are written up in [docs/engineering-conventions.md](./docs/engineering-conventions.md).

---

## Measurement: what the numbers cover

Being precise about this, because a detection claim is only as good as the set
it was measured on.

**What is enforced.** Every PR runs a precision/recall backtest
([`.github/workflows/pr.yml`](./.github/workflows/pr.yml) → *Backtest P/R
gate*). It replays ground-truth fixtures through the whole detector roster and
fails the build on either of two independent conditions: a detector dropping
below [`crates/backtest/baseline.json`](./crates/backtest/baseline.json) (the
regression gate), or an `Active` detector sitting below
[`crates/backtest/promotion_gate.json`](./crates/backtest/promotion_gate.json)
(the governance floor — no `--update` flag, on purpose). Moving a baseline is a
reviewed diff, not a side effect.

**What the current numbers are.** The committed baseline is precision 1.0 /
recall 1.0 for all seven detectors — measured over **one hand-built scenario per
detector plus one clean block**. Each scenario is mainnet-shaped, and because
every detector runs over every fixture's blocks, an unexpected alert from any
detector on any fixture counts against its precision.

**What that does *not* establish.** A perfect score on ~8 curated scenarios is a
*regression* signal, not a field accuracy measurement — with a single negative
block in the set, the sample cannot resolve a 4% false-positive rate at all.
The `< 4%` figure in the intro is the product target the gate exists to
eventually enforce, not a result this repo has demonstrated. Closing that gap
needs adversarial negatives and replayed mainnet windows — tracked under
Epic E in [production_readiness.md](./production_readiness.md).

The harness itself is the point: the fixtures are cheap to add, the gate is
already wired, and the numbers move under review rather than silently.

---

## Contact

Built by **Nicholas** — senior backend engineer, distributed systems,
Go + Rust.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/kyawkyaw-thar-210602185/)
[![Email](https://img.shields.io/badge/Email-Contact-grey?style=flat-square)](mailto:kyawkyaw.thar84@gmail.com)
