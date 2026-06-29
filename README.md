# MEVWatch

**Real-time MEV detection and blockchain threat intelligence.**

[![CI](https://github.com/KyawKyawThar/onchain_fraud_mev_detector/actions/workflows/ci.yml/badge.svg)](https://github.com/KyawKyawThar/onchain_fraud_mev_detector/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/Rust-stable-orange?logo=rust&logoColor=white)
![License](https://img.shields.io/badge/license-proprietary-red)

MEVWatch monitors Ethereum and EVM-compatible chains block by block, detects
sandwich attacks, flash loan exploits, rug pulls, wash trading, and address
poisoning — then confirms every detection through EVM simulation before
surfacing it to customers. The result is simulation-backed threat intelligence
with a false positive rate below 4%, served through a REST/WebSocket API, a
live dashboard, and a configurable alert rule engine.

---

## Demo

> *Full demo video — architecture walkthrough, live incident detection,
> entity graph, rule engine test mode.*

[![MEVWatch Demo](https://img.shields.io/badge/▶_Watch_Demo-4_minutes-teal?style=for-the-badge)](https://loom.com/placeholder)

Screenshots:

| Live Monitor | Entity Intelligence | Rule Engine |
|---|---|---|
| ![Live Monitor](./docs/live-monitor.png) | ![Intelligence](./docs/intelligence.png) | ![Rules](./docs/rule-engine.png) |

---

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

## API surface

```
POST /v1/address/{addr}/screen        synchronous allow/review/block decision (pre-tx screening)
GET  /v1/address/{addr}/risk          risk score + confidence + factor breakdown
GET  /v1/address/{addr}/labels        all labels with provenance
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

```
mevwatch/
├── README.md
├── ARCHITECTURE.md      full system design and rationale
├── ONBOARDING.md        domain knowledge guide for new contributors
└── docs/
    ├── live-monitor.png
    ├── intelligence.png
    ├── entity-graph.png
    └── rule-engine.png
```

Source code is not public. Contact for access or collaboration.

---

## Contact

Built by **Nicholas** — senior backend engineer, distributed systems,
Go + Rust.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat-square&logo=linkedin)](https://linkedin.com/in/your-profile)
[![Email](https://img.shields.io/badge/Email-Contact-grey?style=flat-square)](mailto:your@email.com)
