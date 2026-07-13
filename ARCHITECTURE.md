# MEVWatch — System Architecture

Real-time on-chain fraud & MEV detection as an event-driven Rust microservices
platform: event sourcing as the audit backbone, an address-intelligence graph
as the core asset, and a customer-configurable rule engine on top.

This document describes the system design and its rationale. Services share
one Cargo workspace; each service is a crate under [`crates/`](./crates/) and
deploys as an independent binary/container. The path from this design to a
production-grade deployment — reliability, DR, security, scale, model
governance, and compliance gates — is defined in
[production_readiness.md](./production_readiness.md).

---

## 1. Two architectural principles that govern everything

### Principle 1 — Three-layer separation

```
Evidence      →    Attribution / Entities / Labels    →    Derived Views
(immutable)        (mutable, versioned overlays)           (recomputable)
```

Detection is attribution-blind. Labels change; evidence does not. Risk scores
are pure functions of their inputs, always recomputable.

### Principle 2 — Event sourcing as the audit backbone

The system does not store only final state — it stores every domain event that
caused that state. The complete event log is the source of truth; read models
(incidents, scores, dashboards) are projections derived from it.

Customers will ask *"why did you generate this alert?"* — and that question is
sometimes a legal question. Answering it requires a complete, immutable,
replayable audit trail, not a snapshot.

Together: detection produces immutable evidence events, interpretation evolves
through mutable overlay events, and derived views are projections. Every state
change is a domain event that can be replayed, audited, and explained.

---

## 2. Domain event model

All services communicate by publishing and consuming domain events over the
event bus. The event store is the canonical record of everything that happened.

### Chain events (ingestion-service)
```
RawBlockReceived      { chain, number, hash, timestamp }
BlockAssembled        { chain, number, hash, tx_count, trace_available }
BlockCanonicalized    { chain, number, hash }
BlockReverted         { chain, number, hash, replaced_by: hash }
BlockFinalized        { chain, number, hash }
```

### Detection events (detection-service, fast path)
```
DetectorTriggered       { detector_id, detector_version, block, txs, raw_confidence, evidence }
PreliminaryAlertCreated { alert_id, detector_id, addresses, kind, confidence, provisional: true }
```

### Simulation events (simulation-service, slow path)
```
SimulationRequested   { alert_id, evidence }
SimulationCompleted   { alert_id, profit, victim_loss, confirmed: bool }
IncidentCreated       { incident_id, alert_id, kind, txs, profit, victim_loss, severity }
IncidentRetracted     { incident_id, reason }
IncidentFinalized     { incident_id, block_hash }
```

### Intelligence events (intelligence-service)
```
LabelAdded            { address, kind, value, confidence, source }
LabelUpdated          { address, label_id, old_value, new_value, source }
LabelRevoked          { address, label_id, reason }
EntityCreated         { entity_id, seed_address }
EntityMerged          { surviving_id, absorbed_id, evidence_ref }
EntitySplit           { original_id, new_ids, reason }
AttributionUpdated    { incident_id, entity_ids, labels }
RiskScoreUpdated      { address, entity_id, score, delta, factors, model_version }
SanctionHit           { address, list, entry }
```

### Rule engine events (rule-engine-service)
```
RuleCreated           { rule_id, owner, definition }
RuleTriggered         { rule_id, address, matched_events, context }
RuleAlertCreated      { alert_id, rule_id, address, explanation }
```

### System events
```
UsageRecorded         { customer_id, event_type, quantity, timestamp }
```

> **Schema evolution.** Events ride a versioned envelope with an upcasting
> seam (see [`crates/events/SCHEMA.md`](./crates/events/SCHEMA.md)): changes
> are additive, old events replay unchanged, and the wire format is pinned by
> golden tests.

> **Events vs. commands.** Everything above is a domain *event* — a fact in
> the past tense, immutable, appended to the event store, transported on
> Kafka. The system has exactly one *command* — `SimulationJob` ("run this
> simulation") — and it is deliberately **not** in this model and **not** in
> the event store. A command is an instruction, consumed once; it travels on
> the RabbitMQ work queue (§7). Only its result re-enters the event model, as
> `SimulationCompleted`. Keeping commands out of the event log is what keeps
> the audit trail a record of what *happened* rather than what was *attempted*.

---

## 3. Service topology

```
                    ┌─────────────────────────────────────────────┐
                    │              EVENT BUS (Kafka)               │
                    │     all inter-service communication          │
                    └──────────────────────┬──────────────────────┘
                                           │
        ┌──────────────────────────────────┼──────────────────────────────────┐
        │                                  │                                   │
        ▼                                  ▼                                   ▼
┌──────────────┐              ┌────────────────────┐              ┌──────────────────────┐
│  ingestion   │──────────►  │  detection-service  │──────────►  │  simulation-service  │
│  service     │  assembled  │  (FAST PATH <1s)    │  triggered  │  (SLOW PATH async)   │
└──────────────┘  blocks     └────────────────────┘  alerts     └──────────────────────┘
        │                                  │                                   │
        │                    ┌─────────────┘                                   │
        │                    ▼                                                  ▼
        │          ┌──────────────────────┐              ┌──────────────────────────────┐
        │          │  intelligence-service │◄─────────── │       event-store-service     │
        │          │  (the graph)         │  all events  │  (immutable audit log)        │
        │          └──────────────────────┘              └──────────────────────────────┘
        │                    │
        │                    ▼
        │          ┌──────────────────────┐
        │          │   rule-engine-service │
        │          └──────────────────────┘
        │                    │
        └────────────────────┼──────────────────────────────────┐
                             ▼                                   ▼
                   ┌──────────────────┐              ┌──────────────────────┐
                   │   api-service    │              │ notification-service │
                   │ REST/gRPC/WS     │              │ webhooks / alerts    │
                   └──────────────────┘              └──────────────────────┘
                             │
                             ▼
                   ┌──────────────────┐
                   │ billing-service  │
                   └──────────────────┘
```

### Inter-service communication rules

Two transports, split by **what** is being moved. The distinction is events
vs. commands:

- **Domain events → Kafka (async, default).** A domain event is a *fact*:
  something that already happened (`IncidentCreated`, `RiskScoreUpdated`).
  Facts are immutable, multi-consumer, ordered per key, replayable, and append
  to the event store. Kafka's log model is built for exactly this — retention,
  offsets, fan-out, deterministic replay for backtesting. Keyed by chain or
  address.
- **Work commands → RabbitMQ (async, simulation dispatch only).** A command is
  an *instruction*: do this unit of work (`SimulationJob`). A command is
  consumed once, by exactly one worker, and either succeeds, retries, or
  dead-letters. This is a competing-consumer work queue, not an event log —
  see §7. It does **not** append to the event store (a command is not a fact;
  only its *result*, `SimulationCompleted`, is a domain event back on Kafka).
- **Sync request/response → gRPC (exceptions only).** Where latency matters —
  the API service querying the intelligence service for a risk score.
- Services own their data stores. No cross-service database joins. No shared
  tables.

> **Why not one broker?** Kafka *can* approximate a work queue with consumer
> groups, but parallelism is capped at partition count, there is no
> per-message ack/redelivery, no dead-letter routing, and no priority. The
> simulation path needs all four. Conversely RabbitMQ is a poor event log — no
> long-horizon retention, no replay, no offset rewind for backtesting. Each
> tool carries the message shape it was designed for. The boundary is the
> events/commands seam, and it is the *only* place a second broker is
> introduced.

---

## 4. Event-store service

The immutable audit log. Every domain event from every service is appended
here. This is the system of record.

**Storage:** append-only log, partitioned by `(chain, event_type, date)`.
ClickHouse with `MergeTree` — append-only semantics, no updates, no deletes.

**API:** append (internal only, write-authenticated), query by
address/incident/time range, replay stream for a given event type and window.

**Why this is not Kafka itself:** Kafka has configurable retention and is not
designed for long-term queryable storage. The event store is queryable by
business keys (address, incident_id, block_hash) and retained indefinitely.
Kafka is the transport; this service is the permanent record.

**Audit use case:**
```
GET /audit/incident/{id}

→ RawBlockReceived(19_800_000)
→ BlockAssembled(19_800_000)
→ DetectorTriggered(sandwich-v1.2, confidence: 0.71)
→ PreliminaryAlertCreated(alert-88)
→ SimulationCompleted(profit: $12,400, victim_loss: $840, confirmed: true)
→ IncidentCreated(incident-42)
→ LabelAdded(0xabc, MevBot, "known-sandwich-bot-cluster-7", confidence: 0.9)
→ AttributionUpdated(incident-42, entity-183)
→ RiskScoreUpdated(0xabc, 87/100, model-v1.4)
→ IncidentFinalized(block 19_800_002)
```

This is the complete, reproducible answer to "why did you generate this alert?"

---

## 5. Ingestion service

**Responsibilities:** source adapters, reorg-aware block assembler, block
canonicalization and finalization tracking. Emits chain events.

**Consumed:** nothing (source of truth for chain data).

**Emits:** `RawBlockReceived`, `BlockAssembled`, `BlockCanonicalized`,
`BlockReverted`, `BlockFinalized`.

**Data store:** in-memory block tree (bounded by finalization depth). No
persistent store needed — chain data is re-fetchable; the event store has the
event log.

**Source adapters (in order of preference):**
1. reth ExEx — in-node post-execution pipeline.
2. Own node IPC/WebSocket — `newHeads` + trace APIs.
3. RPC failover pool — health-checked, circuit-broken.

**Reorg handling:** on `parent_hash` mismatch, walk to the common ancestor,
emit `BlockReverted` for orphaned blocks, emit `BlockCanonicalized` for the
new canonical chain. Services that maintain cross-block state consume these
events to roll back their own projections (§14).

---

## 6. Detection service (fast path — target < 1 second)

**Principle:** emit a preliminary alert as fast as possible using heuristics
only. No simulation. No label lookups on the hot path. Confidence is based on
on-chain facts only (attribution-blind).

**Consumed:** `BlockAssembled` · **Emits:** `DetectorTriggered`,
`PreliminaryAlertCreated`

**Data store:** none persistent. In-memory cross-block detector state,
versioned by block for reorg rollback.

### DetectorPlugin trait

```rust
pub trait DetectorPlugin: Send + Sync {
    fn id(&self) -> DetectorId;
    fn version(&self) -> SemVer;
    fn kind(&self) -> ModelKind;   // Rule | ML | Hybrid
    fn scope(&self) -> Scope;
    fn detect(&self, ctx: &DetectionCtx) -> Vec<Evidence>;
}
```

`DetectionCtx` contains the block bundle, normalized events, and enrichment
(token/pool/price — no labels). Output: `Vec<Evidence>` carrying
`(detector_id, detector_version, on_chain_confidence)`. **No attribution in
this layer.**

### Model registry

Every deployed detector is registered with `(id, name, version, kind,
config_hash, deployed_at, deprecated_at, performance)`. This supports safe
rollouts (deploy v1.3 alongside v1.2, compare results), A/B testing, and
deprecation. Every `DetectorTriggered` event carries the registry entry's
`(id, version, config_hash)` — historical evidence is always attributable to
an exact detector version.

### Detector crates (compile-time plugin registration)

No dynamic loading — Rust has no stable ABI. Each detector is an independent
crate implementing `DetectorPlugin`, registered at compile time, with
per-detector feature flags/config. Isolation, independent testing, selective
open-sourcing; premium detectors stay closed.

---

## 7. Simulation service (slow path — async, seconds to minutes)

**Principle:** receive preliminary alerts, run expensive revm simulation to
confirm or retract, then emit confirmed incidents. Runs asynchronously — never
on the alert critical path.

**Consumed:** `PreliminaryAlertCreated`, `BlockReverted` (to retract pending
simulations) · **Emits:** `SimulationCompleted`, `IncidentCreated`,
`IncidentRetracted`, `IncidentFinalized`

**Data store:** Postgres for in-flight simulation jobs and confirmed
incidents. ClickHouse for the incident analytics projection.

### Job dispatch — the RabbitMQ work queue

The simulation service is the one component that is **not** a stream consumer
at heart — it is a worker pool draining a backlog of expensive, CPU-bound
jobs. The workload is "N interchangeable workers, each pulls the next job,
runs it, acks it": a competing-consumer work queue, which is RabbitMQ's native
model and Kafka's awkward one.

```
PreliminaryAlertCreated  (Kafka, domain event)
        │
        ▼
  dispatcher  (thin Kafka consumer inside simulation-service)
        │  publishes a SimulationJob COMMAND
        ▼
  ┌─────────────────────────────┐
  │  RabbitMQ  sim.jobs queue    │   quorum queue, durable
  │  priority 0–9, x-dead-letter │
  └──────────────┬──────────────┘
                 │  competing consumers
     ┌───────────┼───────────┬───────────┐
     ▼           ▼           ▼           ▼
  worker      worker      worker      worker     (revm on rayon)
     │
     └──► result published back to Kafka as a domain event:
          SimulationCompleted / IncidentCreated / IncidentRetracted
```

Why this shape:

- **`SimulationJob` is a command, not a domain event** — an instruction,
  consumed exactly once, deliberately absent from the event model and the
  event store. The audit log records facts; "we decided to simulate" is not a
  fact worth replaying — only the outcome is.
- **Competing consumers.** Add worker instances to add throughput; no
  partition-count ceiling.
- **Per-message ack + redelivery.** A worker acks only after the simulation
  finishes. The input is hostile bytecode executing in revm, so crashes are
  part of the threat model — an unacked job is redelivered automatically.
- **Dead-letter exchange.** A job that fails N times routes to `sim.jobs.dlx`
  for inspection instead of poisoning the queue: a quarantine, not an outage.
- **Priority queue.** High-value alerts jump ahead of backlog.
- **Queue depth = backpressure signal.** The ready-message count is the single
  number that says "simulation is falling behind"; it drives worker scaling.

### Ordering & idempotency

The work queue gives up two guarantees Kafka's per-key log provides — strict
ordering and exactly-once-ish processing — and the design is safe precisely
because this workload never needed either:

- **Jobs are independent, so order does not matter.** Each `SimulationJob` is
  a self-contained `(block, tx_set)` unit with no cross-job state.
- **Redelivery is safe because processing is idempotent.** The simulation
  cache is keyed by `(block, tx_set)`, so a re-run is a cache hit; results are
  domain events keyed by `alert_id`, which downstream projections dedup like
  any replayed event.
- **Ordering is reasserted where it matters** — at the Kafka projections,
  which are commutative over their keys (`provisional → confirmed → retracted`
  is a monotonic lifecycle) — not demanded of the worker pool.

### What simulation confirms

- **Attacker profit:** simulate the bundle, diff balances.
- **Victim loss:** diff victim holdings.
- **Counterfactual:** re-simulate the victim swap without the frontrun.
- **Honeypot:** simulate buy then sell from a fresh address.

### Fast/slow path data flow

```
BlockAssembled
      │
      ▼  (< 1 second)
detection-service
      │
      ▼
PreliminaryAlertCreated ──────────────────────────────────────────► notification-service
      │                                                               (streams provisional alert)
      ▼  (async, seconds–minutes)
simulation-service   (revm worker pool drains the RabbitMQ sim.jobs queue)
      │
      ├── confirmed ──► IncidentCreated ──► intelligence-service
      │                                          │
      │                                          ▼ RiskScoreUpdated
      │                                    notification-service
      │                                    (upgrades alert to confirmed)
      │
      └── retracted ──► IncidentRetracted ──► notification-service
                                               (retracts provisional alert)
```

Subscribers receive provisional alerts immediately; they are upgraded or
retracted asynchronously. Clients must handle both transitions — this is part
of the API contract.

### Simulation hardening

Gas/step caps per simulation — honeypot bytecode runs in the simulator and is
treated as hostile input. revm is sandboxed; results are cached by
`(block, tx_set)` so replay never re-simulates the same bundle.

---

## 8. Intelligence service

The address-intelligence graph: labels, entity clustering, attribution, risk
scoring, sanctions. Raw detection commoditises; the accumulated graph does not.

**Consumed:** `IncidentCreated`, `IncidentRetracted`, `IncidentFinalized`,
`BlockCanonicalized`, `BlockReverted`, label/entity events.

**Emits:** `LabelAdded`, `LabelUpdated`, `LabelRevoked`, `EntityCreated`,
`EntityMerged`, `EntitySplit`, `AttributionUpdated`, `RiskScoreUpdated`,
`SanctionHit`.

**Data stores:** Postgres (labels with provenance, versioned entities,
attribution, sanctions lists) · Redis (hot-path label/score cache, TTL-backed,
evicted on update) · ClickHouse (address-graph adjacency for hop queries) ·
petgraph (in-memory, bounded subgraph analysis only — load a 3-hop
neighborhood, analyze, discard).

### 8.1 Wallet labels

Labels carry `kind` (CexWallet, MevBot, KnownScammer, Bridge, Protocol,
Deployer, MixerUser, SanctionedEntity, ScammerAssociate, BuilderAddress…),
`value`, `confidence` (manual 1.0 > heuristic 0.7 > external feed 0.4),
`source`, and validity. **Conflicting labels are stored, not overwritten** —
manual overrides heuristic, but both are retained for audit.

Sources: public feeds (Etherscan tags, OFAC SDN, community MEV-bot lists,
protocol registries), heuristic auto-labeling (builder feeRecipients,
code-hash matching, funding-source clustering), entity-graph derivation
(clustering with a known actor yields `ScammerAssociate` at reduced
confidence), and manual curation.

### 8.2 Entity clustering

An entity is a versioned cluster of addresses believed to share a controller.
Cluster heuristics: common funder, common deployer, same code hash, shared
profit receiver. Every merge emits `EntityMerged`; downstream scores
invalidate and recompute automatically.

**Hub-node degree cap:** never walk an unbounded multi-hop graph through a CEX
hot wallet, major bridge, or router — they connect to millions of addresses.
High-degree nodes are labeled infrastructure endpoints that stop the walk.
Getting this wrong collapses the graph into noise.

### 8.3 Risk scores

```
Score: 87 / 100   Confidence: 0.91   (model v1.4.2)

+35  2 confirmed sandwich attacks (profit: $18,400)
+20  1 flash-loan exploit (victim loss: $240,000)
+15  entity member: Entity #183 (known MEV cluster)
+10  funded by mixer-adjacent address (confidence: 0.6)
+7   co-deployed with known scammer
```

Score design rules: **explainable** (every delta carries an evidence
reference), **versioned** (model version is part of the output),
**time-decayed** (old incidents contribute less), and **nuanced about
taint-by-association** (mixer proximity is a reduced-confidence signal, not a
verdict — legally contested and documented as such).

**Score vs. confidence are independent axes.** Score answers "how risky";
confidence answers "how sure." Confidence aggregates the evidentiary strength
of the contributing factors (sim-confirmed incidents and on-chain-verified
merges weigh high; heuristic and external-feed labels weigh low), so an
address can be high-risk/low-confidence or low-risk/high-confidence — and
customers can see which. Both are computed in the same pass, cached by
`(address, model_version)`, and invalidated together on any input change.

### 8.4 Sanctions

OFAC SDN, EU, and relevant national lists are ingested; any address match
emits `SanctionHit` immediately. A hard alert — it never waits on the slow
simulation path.

### 8.5 Data flywheel

Entity clustering auto-generates labels → labels improve attribution
confidence → better attribution surfaces more entity links → repeat. This loop
is the compounding defensibility that pure detection cannot replicate.

---

## 9. Rule engine service

Customer-defined alerting on top of the intelligence graph — compliance teams,
traders, and investigators all need alerting logic beyond the built-in
detectors.

**Consumed:** `IncidentCreated`, `RiskScoreUpdated`, `EntityMerged`,
`LabelAdded`, `SanctionHit` (plus supporting streams). · **Emits:**
`RuleTriggered`, `RuleAlertCreated`.

### Rule model

A rule is a customer-owned document: a set of `Condition`s combined by a
`LogicOp` (All/Any/Not), an optional `TemporalConstraint`, and delivery
`Action`s.

```
Conditions:  TransferAmount · InteractedWith · IncidentKind · EntityLabel
             RiskScore · SanctionMatch · HopDistance · NewAddress
Temporal:    Sequence  { events, within_blocks }
             Frequency { condition, count, within_blocks }
Actions:     WebhookAlert · EmailAlert · SlackAlert · TagAddress
```

Example:
```yaml
name: "Large transfer then mixer interaction"
conditions:
  - transfer_amount: { gt: 1000000, token: USDC }
  - interacted_with: { label_kind: MixerUser }
temporal: { sequence: true, within_blocks: 100 }
actions:
  - webhook_alert: { url: "https://compliance.example.com/hook" }
```

Rules are validated at the parse boundary, compiled once per load into pure
evaluation closures (link-or-fail: a malformed stored rule stops the boot with
the rule id, never a silent skip), and evaluated against the enriched event
stream. Rules are owned by customers and **structurally isolated** — every
store operation is keyed by owner, so cross-customer reads are unrepresentable.

Temporal rules maintain a windowed state machine per `(rule_id, address)`,
persisted to Redis with TTL bounded by the rule's block window (TTL expiry ≡
window close). The event stream is partitioned by address so one worker owns
all state for a given address — single-writer ownership instead of locks. On
`BlockReverted`, in-flight windows are rewound so reverted-block events stop
counting as progress (§14).

Fired alerts are delivered through an action seam: the webhook adapter POSTs a
pinned JSON payload to the customer's endpoint with bounded retry/backoff
(4xx/redirects are permanent rejections; 5xx/transport faults retry). Alert
ids are **derived deterministically** from the fire's identity, so an
at-least-once redelivery re-emits the same alert id — a dedup key for the
customer, not an uncorrelatable duplicate.

---

## 10. API service

**Consumed:** reads projections from the intelligence service (gRPC/sync) and
the event store. · **Emits:** `UsageRecorded` (feeds billing).

### Endpoints

- `GET /v1/address/{addr}/risk` — score + confidence + factor breakdown + model version.
- `GET /v1/address/{addr}/labels` — all labels with provenance and confidence.
- `GET /v1/entity/{id}` — addresses, incidents, reputation history.
- `GET /v1/entity/{id}/graph?hops=3` — connected addresses (degree-capped).
- `GET /v1/entity/{id}/timeline` — curated milestone history.
- `GET /v1/incidents?chain=&kind=&severity=&since=` — paginated incident feed.
- `GET /v1/audit/incident/{id}` — complete event stream for an incident.
- `GET /v1/builders` — builder leaderboard by MEV type.
- `POST /v1/address/{addr}/screen` — synchronous allow/review/block decision.
- `POST /v1/rules` — create a custom rule.
- `WS  /v1/stream` — live incident stream.

### WebSocket contract

Clients must handle three lifecycle transitions: `provisional_alert` (fast
path, unconfirmed) → `alert_confirmed` (with simulation data) →
`alert_retracted` (provisional was wrong; remove from UI). Documented and
tested explicitly.

### Counterparty screening (synchronous decision API)

`POST /v1/address/{addr}/screen` is the one **synchronous, latency-critical**
surface — a pre-transaction risk decision exchanges and protocols call inline
on withdrawals and onboarding. It is a thin decision layer over the
intelligence read path (Redis hot cache): cached score, confidence, labels,
entity and sanctions status map through a **versioned, customer-configurable
decision policy** to `allow` / `review` / `block`, with a
hard-block-on-sanctions override that bypasses score thresholds entirely. The
response carries the full factor breakdown, so a blocking decision is
explainable and auditable. Every call is metered (`ScreeningCall`) and carries
its own SLO and rate limits.

---

## 11. Notification service

**Consumed:** `PreliminaryAlertCreated`, `IncidentCreated`,
`IncidentRetracted`, `IncidentFinalized`, `RuleAlertCreated`, `SanctionHit`.
· **Emits:** `UsageRecorded`.

Severity-routed delivery with retry/backoff, dedup per incident per
subscriber, delivery receipts. Webhook, email, Slack, PagerDuty channels.
Customer-configurable filters (min severity, kind, chain). Handles the
provisional → confirmed → retracted lifecycle so subscribers receive
upgrades/retractions paired to their original alert.

---

## 12. Billing service

**Consumed:** `UsageRecorded` events from every metering producer. · A sink.

**Data store:** ClickHouse for raw usage events (high volume, append-only);
Postgres for accounts, plans, billing periods, aggregates.

Usage is metered from day one — per event processed, detector run, simulation,
incident, alert delivered, API call, screening call, rule evaluated, chain and
wallet monitored. The billing service measures; payment integration is a
separate concern wired to these aggregates.

---

## 13. Storage per service

| Service | Store | Rationale |
|---|---|---|
| event-store | ClickHouse (append-only) | Immutable log, queryable by key, retained |
| ingestion | In-memory only | Block tree bounded by finality depth |
| detection | In-memory only | Cross-block state, reorg-versioned |
| simulation | Postgres + ClickHouse | In-flight jobs + incident analytics |
| intelligence | Postgres + Redis + ClickHouse | Labels/entities + cache + graph adjacency |
| rule-engine | Postgres + Redis | Rule definitions + temporal state (TTL) |
| api | No own store | Reads intelligence + event-store |
| notification | Postgres | Delivery records, subscriber config, dedup keys |
| billing | Postgres + ClickHouse | Accounts/plans + usage events |

**Cross-service data sharing rule:** no cross-service database joins, no
shared tables. A service that needs another's data subscribes to its events or
calls its API.

---

## 14. Reorg handling (cross-service)

`BlockReverted` is broadcast to all services. Each service that maintains
derived state handles it:

- **detection:** rewind cross-block detector state to the common ancestor.
- **simulation:** cancel pending simulations for reverted blocks; retract
  already-emitted incidents via `IncidentRetracted`.
- **intelligence:** roll back entity merges triggered by retracted incidents;
  invalidate affected risk scores; re-emit `RiskScoreUpdated`.
- **rule-engine:** rewind temporal rule windows that included events from
  reverted blocks.
- **event-store:** append the `BlockReverted` itself — the audit log records
  everything, including reorgs.

Reorg propagation is eventually consistent across services — acceptable
because all artifacts carry `provisional` semantics until `BlockFinalized`.

---

## 15. Concurrency model (per service)

All services use the same pattern: bounded async channels for inter-stage
backpressure, rayon/`spawn_blocking` for CPU-bound work (simulation, graph
analysis, decoding), never CPU on the async reactor.

- **ingestion:** async I/O, in-memory block tree.
- **detection:** async scheduler, per-block fan-out on rayon, bounded channels.
- **simulation:** RabbitMQ competing consumers; revm workers on rayon; queue
  depth as the backpressure signal.
- **intelligence:** async Kafka consumer, sync gRPC read API; entity merges
  serialized per entity.
- **rule-engine:** partitioned by address so one worker owns an address's
  temporal state; bounded per-worker mailboxes.

---

## 16. Replay & backtesting

- A backfill binary replays archived blocks through detection + simulation
  using the identical code path (same crates), parallelized across ranges.
- The backtest harness runs `(detector_id, version, config_hash)` triples over
  labeled historical windows → precision/recall/latency. Changes are gated on
  metric improvement.
- The event store is the replay source — any time window, deterministically.

---

## 17. Observability

`tracing` spans propagate across service boundaries via W3C trace context
(distributed tracing). Prometheus metrics per service: ingestion lag, assembly
latency, per-detector hit rate/latency, simulation queue depth, entity merge
rate, cache hit rates, score recompute latency, reorg depth/frequency, rule
evaluation and delivery counters, API p50/p99. Grafana dashboards track the
key SLOs: end-to-end alert latency (block → notification), simulation
confirmation rate, false-positive rate.

---

## 18. Deployment

Each service is a container; services deploy and scale independently — that is
the point of the topology.

```
ingestion-service      — 1 instance per chain (I/O bound)
detection-service      — scale by CPU (detector fan-out)
simulation-service     — scale aggressively (revm CPU is the bottleneck)
intelligence-service   — scale the read path; shard writes by address range
rule-engine-service    — scale by partition count
api-service            — stateless, horizontal behind a load balancer
notification-service   — scale by customer count
billing-service        — single instance or small HA pair
event-store-service    — ClickHouse cluster with replication
kafka                  — partitioned by chain, one topic per event type
rabbitmq               — sim job dispatch only: quorum queue, DLX, priority
```

Images are minimal non-root containers built from a single multi-stage
cargo-chef Dockerfile, built against the committed `.sqlx` offline cache. CI
mirrors the local `just check` gate (fmt, clippy `-D warnings`, nextest,
testcontainers-backed integration tests, `cargo audit`/`cargo deny`); the
toolchain is pinned via `rust-toolchain.toml`. See
[docs/engineering-conventions.md](./docs/engineering-conventions.md) for the
full engineering discipline.

---

## 19. Tech stack

**Runtime & chain:** `tokio`, `alloy` (types/ABI/providers), `reth` (ExEx),
`revm`, `rayon`, `petgraph`.

**Data & messaging:** `sqlx` (Postgres), ClickHouse client, Redis, `rdkafka`
(Kafka — domain events), `lapin` (RabbitMQ — simulation job queue).

**Serving:** `axum` (REST/WebSocket), `tonic` (gRPC).

**Quality & ops:** `tracing` + OpenTelemetry, `metrics` + Prometheus,
`thiserror`/`anyhow`, `criterion`, `proptest`, cargo-nextest, cargo-deny +
cargo-audit, cargo-chef, `just`, lefthook, Renovate.
