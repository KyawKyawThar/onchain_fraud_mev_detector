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

### AI events (copilot-service — §20)
```
IncidentNarrativeDrafted { incident_id, narrative_ref, model_id, prompt_version, grounded_event_ids }
RuleDraftProposed        { draft_id, owner, source_text_hash, draft_ref, definition, model_id, prompt_id, prompt_version, prompt_digest, proposed_at }
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
confidence), behavioral similarity to a directly-known actor (§20.3's
clustering signal, at a *further* reduced band than the graph-derived one),
and manual curation.

A derived label may never anchor a further derivation. Both derivation paths
above read only labels a direct source produced — a feed, a heuristic, a
curator — so an association is always exactly one hop from something known.
Allowing a second hop would let the system's own guesses become its evidence,
which is how taint-by-association (§8.3) goes from a documented, contested
signal to an unbounded one.

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
| copilot | Postgres | Draft narratives/rules, prompt versions, approval state (§20) |

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
copilot-service        — small pool (LLM calls are I/O-bound, never hot-path)
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

**AI/ML (§20):** `ort` (ONNX Runtime inference — dynamically loaded, not
linked or downloaded), `libm` (bit-identical feature extraction across
platforms), ClickHouse vector search, Claude API (Messages + Batches, via a
thin internal HTTP client — no official Rust SDK). No in-process training
stack: models — the supervised GBDT and the isolation forest alike — are
trained offline in whatever stack fits and cross the boundary as an ONNX
artifact plus its `feature_version`, so serving needs one runtime rather than
one library per model family. (The plan named `linfa` for the isolation
forest; ONNX serving made it unnecessary.)

---

## 20. AI/ML layer

Machine learning and LLMs extend the platform at three points: an ML detector
on the fast path, behavioral embeddings in the intelligence graph, and an LLM
investigation copilot. Three rules govern all of them — each one an extension
of a principle the rest of the system already enforces:

1. **The fast path stays attribution-blind and explainable.** An ML detector
   is just another `DetectorPlugin` with `ModelKind::ML` (§6): registered in
   the model registry, versioned by `(id, version, config_hash)`,
   shadow-deployed first, gated by the backtest harness (§16) like any
   rule-based detector. An ML hit flows into the same simulation confirmation
   path — it is never surfaced to customers unconfirmed.
2. **LLM output is a proposal, never a fact.** Nothing an LLM produces enters
   the event store as detection evidence or mutates the intelligence graph.
   Drafts are validated at existing parse boundaries (rules) or approved by
   humans (narratives), and every draft records the model id and prompt
   version that produced it — the same provenance discipline labels carry
   (§8.1).
3. **Training data comes from the system's own flywheel.** Every
   `SimulationCompleted` confirms or refutes a `DetectorTriggered` — a
   labeled example the platform generates for free, continuously, with an
   exact ground truth (simulated profit/loss). No hand-labeling pipeline, no
   external dataset dependency.

### 20.1 Training-data flywheel

The event store is a deterministic training-data generator. A dataset is
defined by `(time window, feature_version, label rule)` and materialized by
replaying that window (§16) — reproducible byte-for-byte, because replay is.

- **Labels:** `DetectorTriggered` joined to its `SimulationCompleted` outcome.
  `confirmed: true` with measured profit is a positive; a retraction or
  failed confirmation is a hard negative. The false-positive feedback loop
  (production-readiness Epic E) supplies corrective relabels.
- **Features:** an `ml-features` crate extracts a versioned, deterministic
  feature vector from the same `DetectionCtx` detectors see (§6) —
  transaction structure, gas dynamics, value flows, pool interactions,
  cross-block position deltas. No labels, no attribution: features obey the
  same attribution-blindness rule as the detectors that will consume them.
  `feature_version` is stamped into every dataset and every deployed model.
- **Export:** a dataset binary (same pattern as the backfill binary, §16)
  replays an event-store window through feature extraction into ClickHouse /
  Parquet. Model training itself happens offline; the contract between
  training and serving is the ONNX artifact plus its `feature_version` —
  train in whatever stack fits, serve in Rust.

  Delivered as the `dataset` crate, reading through the event store's own
  `GET /v1/replay` (the §16 seam) rather than its storage. Every run emits a
  **manifest** whose content hash covers the rows — so "reproducible by
  construction" is a comparison an operator can make, not a claim. Two joins
  in the schema are weaker than they look and are therefore *marked* rather
  than assumed: `DetectorTriggered` carries no id (so the trigger→alert edge
  is reconstructed, and ambiguity is recorded per row and excluded by
  default), and the store holds events rather than blocks (so the
  `DetectionCtx` behind a feature vector is rebuilt at a declared **fidelity**
  until an archive-backed source lands — the same deferral, and the same seam
  discipline, as simulation's `JobResolver`). A partial block reconstruction
  yields *wrong* block-relative features rather than missing ones, which is
  why fidelity gates a dataset instead of merely annotating it.

### 20.2 ML detection on the fast path

An `anomaly-detector` crate implements `DetectorPlugin` (depending on
`detector-api` only, like every detector crate) and runs two models:

- **Supervised classifier** (gradient-boosted trees, trained on flywheel
  labels): scores candidate MEV patterns the heuristic detectors already
  shape, sharpening `raw_confidence` on ambiguous structures.
- **Unsupervised anomaly model** (isolation forest over the same feature
  vectors): flags blocks/bundles that look like *nothing seen before* — the
  detector for attacks that have no signature yet. Its evidence says "this is
  anomalous and here are the top contributing features," not "this is a
  sandwich."

Serving mechanics:

- **`InferenceEngine` seam:** `infer(&self, &FeatureVector) -> Score` — a
  trait with an `ort` (ONNX Runtime) backend and an in-memory test double, the
  same seam discipline as `EventSink`. Inference is CPU work and runs inside
  the detector's rayon fan-out (§15); the model is loaded once at boot,
  link-or-fail.

  Delivered as the `inference` crate. Two shape decisions the sketch above
  leaves open: `infer` is **fallible**, because the alternative to a `Result`
  when a runtime call fails is a fabricated score, which is the one output a
  detection system must never produce; and the scored unit is a
  `FeatureVector`, never a `DetectionCtx`, so the serving side is
  attribution-blind *by construction* exactly as extraction is. `ort` is built
  to load the runtime dynamically rather than link or download it, keeping
  `cargo build` hermetic and making a missing library a typed boot error
  instead of a panic in a rayon worker. Since ONNX Runtime's `Run` is not
  thread-safe, the engine holds a pool of independently-locked sessions rather
  than funnelling a parallel fan-out through one mutex.
- **Weights are config:** the model artifact's SHA-256 is folded into the
  registry `config_hash`, so a weight change is a new `(id, version,
  config_hash)` triple — historical evidence stays attributable to the exact
  weights that produced it, and rollback is the registry's existing
  `deprecated_at` mechanism.

  The fold is one function, `ConfigHash::with_model_artifact`, over a
  `ModelDescriptor` digest that covers the artifact hash *and* the trained
  `feature_version` and its schema digest — so a feature-schema change is as
  visible in the triple as a retrain. A deployment may additionally **pin** the
  expected artifact digest, at which point a swapped weights file is a refused
  boot rather than a silent change of behaviour.
- **Rollout:** Shadow (evidence suppressed from customer surfaces, §6 rollout
  policy) → backtest gate (precision/recall ≥ committed baseline) → Live.
  Identical lifecycle to a heuristic detector change — ML gets no special
  path around the gates.
  The Python half of that boundary is a pinned **training image**
  (`deploy/training`) that reads a `dataset export` Parquet file and writes a
  serving bundle. Three of its choices are load-bearing rather than
  conventional: the feature order comes from the file (which `dataset` writes
  in schema order) rather than from a list, because a mis-ordered matrix
  produces a model that is wrong in a way nothing downstream can detect — the
  arity still matches; the train/test split is time-ordered, because several
  rows commonly describe one block and shuffling reports a precision the model
  does not have; and every export is **verified by running it** through the
  same ONNX Runtime version production serves, so a converter bug or an opset
  mismatch fails in a batch job rather than at a pod's first block.
- **Deployment:** the runtime is loaded, so it is a deployment fact. The
  detection image carries a pinned, SHA-256-verified ONNX Runtime and sets
  `ORT_DYLIB_PATH`; the model **bundle** — artifacts, baselines and the config
  naming them — is a separate immutable image whose tag *is* the model version,
  unpacked at pod start. Two artifacts, because models and code move on
  different clocks: a retrain must not require a code build, and a code deploy
  must not silently change which weights are serving. There is one detection
  image, not an ML and a non-ML variant: the detector is linked always and
  constructed only when a bundle is configured, so enabling ML detection in a
  cluster is a config change rather than a rebuild. `detection check-models`
  runs the real loader over a bundle before it is deployed and prints the
  `config_hash` those weights will stamp — so a bad bundle fails in CI, not as
  a crashloop.
- **Latency budget:** inference must fit the < 1s fast path (§6). ONNX GBDT /
  isolation-forest inference is microseconds per candidate; the budget is
  enforced by the same per-detector latency metrics (§17).

  Serving metrics are a **decorator over the seam** (`ObservedEngine`), not
  call-site instrumentation: it wraps any engine — the real backend and the
  test double alike — so no backend and no call path can ship unmeasured, and
  the backend itself stays free of metrics. Alongside latency, throughput and
  failures-by-reason it records the served **score distribution**, which is the
  cheapest §20.5 drift signal available; the per-feature population-stability
  statistics build on it rather than replacing it.
- **Explainability sits above the seam.** An anomaly finding's "top
  contributing features" is derived from the feature vector against the drift
  monitor's own distribution statistics, not from a model-specific attribution
  output. The seam returns a score and nothing else, so a model format with no
  attribution support is still explainable and one subsystem owns the answer to
  "why did this fire?".

  Delivered as the `anomaly-detector` crate. Those distribution statistics are
  a `ml_features::FeatureBaseline` — a median centre and a MAD spread per
  feature, exported by the training run beside its artifact and bound to the
  schema it was exported under, so a mismatched snapshot is a refused boot
  rather than an explanation quietly measured against the wrong distribution.
  Robust statistics, not mean/σ: on-chain features are heavy-tailed, and the
  point of a baseline is to make outliers *visible* rather than hide them
  behind one $40M block's inflated variance. A contribution states the
  observed value, the training centre and spread, the signed deviation, and
  its **share** of the block's total deviation — so a thin explanation reads
  as thin, and a finding no single feature explains reports nothing rather
  than padding itself with its five least-boring features. The baseline hash
  travels in the evidence and in the detector's `config_hash`: an explanation
  is part of what a deployment claims, so re-deriving one is a new registry
  triple like a retrain.

  Two shapes the sketch above leaves open. The novelty model claims no known
  behaviour, which no existing `AlertKind` could express — tagging an
  unexplained bundle `Sandwich` because the model saw sandwiches in training
  would put an accusation on the wire the evidence cannot support — so
  `AlertKind::Anomaly` names the one behaviour that is "structurally unusual,
  and here is what is unusual about it". And the supervised model does **not**
  rewrite another detector's `raw_confidence`: a `DetectorPlugin` is a pure
  function of the context and sees no other detector's findings, so the two
  opinions stand side by side rather than being fused by a detector that
  cannot see what it is fusing. Fusion is a composition concern above the
  seam, and needs a ranking to prove it is an improvement.

### 20.3 Behavioral embeddings (intelligence service)

A per-address **behavior vector** — activity cadence, counterparty-type
distribution, value-flow shape, incident history — computed from the
ClickHouse adjacency store on a schedule, versioned like risk-score models.

- **Similarity search:** "addresses that behave like entity #183" via
  ClickHouse vector search over the embedding column. Exposed as
  `GET /v1/address/{addr}/similar` and as an investigation surface in the
  dashboard.
- **A clustering signal, not a merge trigger:** high similarity to a known
  actor enters entity clustering as a reduced-confidence heuristic signal —
  exactly how §8.1 treats heuristic labels. It never auto-merges entities;
  merges still require the on-chain evidence heuristics (§8.2). This keeps
  the graph's correctness story intact while widening its recall.
- **Flywheel effect:** embeddings surface candidate links → confirmed links
  improve attribution → richer incident history sharpens the embeddings —
  the §8.5 loop, now with a learned component.

The vector itself is delivered as `intelligence::embedding` (the pure kernel
and its version registry), `embedding_store` (ClickHouse), `embedding_job` (the
compute core), `embedding_sweep` (the schedule) and `embedding_consumer` (the
invalidation stream), with `AddressEmbeddingUpdated` as its event. What the
sketch above leaves open turned out to be almost everything that matters.

*The schema is frozen, doubly versioned, and the freeze is survivable.* The
feature enum **is** the schema — declaration order is vector order, and one
exhaustive `match` computes it — so a reordered or unclassified feature is a
compile error rather than a silently incomparable vector. Alongside
`embedding_version` every vector carries a hash of that schema, because a
version string cannot catch an edit made *under* it, and comparing across such
an edit computes distances between two different feature spaces while looking
entirely well-formed. Crucially the versions live in a **registry**, not a
constant: the job computes every enabled version per address, so shipping a v2
is shadow → backfill → cut the read over → retire v1. A frozen schema without
that seam is just a schema you cannot change.

*The clock enters a vector at day resolution.* Three features are functions of
"now" rather than of the observations alone — recency, the trailing-window
share, and the incident decay. Evaluated at the instant, every one of them moves
on every recomputation, so a **dormant** address — precisely what a schedule
exists to notice — would produce a different vector every hour forever and
nothing could ever be skipped. Quantizing to the UTC day is also the better
statistic: sub-day precision in "days since last seen" is spurious, and ranking
on it would be ranking on when the sweep happened to run.

*Not every recomputation is worth writing down.* A vector is stored and
published when it is new, when its content moved, when its schema changed, or
when the stored one has passed a refresh floor — otherwise it is skipped and
counted. Without this an hourly sweep republishes the whole address space
forever, into a bus and an event store that keep everything. The refresh floor
is what keeps `computed_at` readable as "last verified" rather than "last
changed", which is otherwise indistinguishable from "the job stopped running".

*Everything is page-shaped.* The naive form — "for each address, load its
inputs" — is seven sequential round trips per address, which at a sweep page of
500 is 3,500 queries to embed 500 addresses. The batched loader issues a fixed
number of queries per page regardless of its size, which is why the adjacency
seam grew `edge_history_many` and the store seams grew their `*_many` siblings.
The single-address path is a thin wrapper over the batched one, so the two
cannot drift about what the kernel is fed.

*The sweep is hash-sharded, and the shard key was declared before it was
needed.* Cursor-paging over an ordered keyspace makes a hash shard nearly free:
each replica owns the addresses that hash into its index, reads only those rows,
and keeps its own cursor — no coordination, no rebalancing protocol. One pod
cannot embed mainnet, and retrofitting a shard key onto a keyspace already being
walked is a flag day, so an unsharded deployment is simply shard 0 of 1. It
deploys as a StatefulSet because the pod ordinal *is* the shard index.

*Storage diverges from its neighbours on purpose.* `block_production` is
append-only because a record legitimately evolves — incidents fold in,
retractions subtract, reorgs revert. A recomputed behavior vector instead fully
supersedes its predecessor and nothing reads the history, so this table is a
`ReplacingMergeTree`: consistency with a neighbouring table is not a reason when
the write semantics differ.

*Comparison is standardized, and that is not the kernel's job.* The feature
families have deliberately different natural ranges, so a raw distance is
dominated by the log-magnitude family and "behaviorally similar" degrades into
"similar transaction count". A population **baseline** — median and scaled MAD
per feature, robust because on-chain distributions are heavy-tailed — is
computed periodically from the stored vectors and applied at *comparison* time.
Stored vectors stay in interpretable units, a re-derived baseline changes
rankings without rewriting history, and a baseline whose schema hash does not
match is a refused comparison rather than a plausible-looking distance in the
wrong units.

Two properties the sketch does not mention and a reader should not assume.
"Value-flow shape" is shape, not magnitude: `address_adjacency` records
relations and no amounts, so the missing magnitude is an explicit
`value_magnitude_known = 0` — the same "encode, never impute" rule §20.1 applies
to unpriced tokens. And a vector is **not reorg-safe**: the incident-history
family rolls back (the consumer reads `AttributionRetracted`, §15), but the
adjacency graph has no reversal, so the cadence and flow families describe every
observation ever appended, canonical or not.

*Similarity search re-ranks what the index shortlists, and says so.* The
`vector_similarity` (HNSW) index over `address_embeddings.vector` can only
accelerate the distance function baked into it, and standardization is an
affine shift no such index expresses. So `GET /v1/address/{addr}/similar` is
the two-stage ANN shape: ClickHouse shortlists candidates by **raw** cosine
distance off the index, then `intelligence::similarity` standardizes every
candidate against the population baseline and scores it exactly in that space.
Only the shortlist is approximate, and only in recall — nothing it does can
make a returned score or explanation wrong — so the response carries
`approximate` and `candidates_considered` rather than presenting an
approximation as an exact answer, the same mark-the-fidelity rule as
`observations_truncated`. The candidate over-fetch is the knob that buys the
recall back.

*The explanation is the score's decomposition, not an attribution laid beside
it.* Cosine similarity over standardized vectors splits exactly into one signed
term per feature, `z_subject[i] * z_candidate[i] / (|z_subject| |z_candidate|)`,
and those terms sum to the score. A positive term means both addresses sit on
the same side of the population median on that feature; a negative one means
they sit on opposite sides and it is pushing them apart. Both are surfaced,
ranked by magnitude — "these two look alike *except* on X" is the sentence an
investigator needs, and an explanation that only ever agrees with its own
conclusion is not one.

*Two absences are answers, not failures.* An address at the population median
on essentially every feature has no direction to search along, and cosine
against it is 0/0; a chain whose baseline job has not run yet cannot be ranked
in the right units at all. Both come back as an explained empty result
(`no_signal` / `no_baseline`) with the address still `found` — a 500 would be
wrong and an unexplained empty list would be worse, and `no_baseline` is
counted so the one failure that looks like a normal empty answer from outside
is visible to ops from inside.

*The index locks the column to one arity.* ClickHouse rejects an insert whose
array length differs from the dimension the index declares, which collides
head-on with the property this table was built for: v1 and v2 vectors living
side by side during a shadow rollout. That is not left to be discovered in
production — a unit test pins every roster version's dimension to the
migration's, and fails the build with the required operator sequence the moment
one disagrees.

Finally, one fan-out is deliberately refused. Labelling an address also changes
the counterparty-type distribution of everyone who ever transacted with it, and
a `LabelAdded` on a router would invalidate millions of addresses off a single
event — the same collapse the §8.2 hub cap exists to prevent. That drift is left
to the sweep, and its staleness bound is one sweep interval. This is the
concrete reason the job is scheduled *as well as* event-driven rather than
either alone.

*The clustering signal proposes into a table of its own, and that separation is
the design.* `intelligence::link_signal` consumes `AddressEmbeddingUpdated`,
runs the same search, and writes a **candidate link**
(`entity_link_candidates` + `EntityLinkProposed`) whenever a strong match
lands on an address some *direct* source has identified. It never touches
`entity_addresses`. That table's primary key on `address` — one address, one
entity — is the invariant attribution, risk scoring and the rule engine are all
allowed to assume, and everything that writes it does so off facts the chain
recorded. A behavioral match is a different kind of claim: it says two addresses
look alike under one feature space, against one baseline, at one moment. It can
be right about a freshly funded bot with no graph edges at all — the recall this
whole section exists to widen — and it can equally be two unrelated arbitrage
bots running the same off-the-shelf strategy. Merging on it would let a learned
score rewrite the graph's correctness story, and the failure would be silent: a
wrong merge produces a plausible entity, not an error.

*The anchor must be directly known, and refusing the second hop is the most
important rule in the module.* Only labels a manual curator, a public feed or an
on-chain heuristic put there can anchor a proposal; a label whose source is
`EntityDerived` cannot. Without that, taint spreads transitively — A is a known
scammer, B behaves like A and earns a derived `ScammerAssociate`, C behaves like
*B* and earns one off B's derived label — and within a few hops the system is
confidently accusing addresses on the strength of its own guesses. §8.3 already
names taint-by-association as legally contested and reduced-confidence;
second-order taint is that problem squared, and no confidence discount is small
enough to make it honest. The refusal is counted, not silent: a sustained
`derived_anchor_only` rate means the derived labels are pooling into a cluster
of their own, which is worth an investigator's attention rather than a code
change.

*The confidence ladder holds numerically.* A proposal's confidence is a ceiling
(0.45 by default) scaled by the similarity that produced it, discounted again
when the neighbour's vector describes a truncated hub window — so it is always
strictly below `EntityDerived`'s 0.5 band, which is itself below the heuristic
0.7. A behavioral guess can never outrank a graph fact, at any similarity. When
the anchor is a *bad actor* specifically (not merely an identified `MevBot`, the
task's own example), the proposal also mints one reduced-confidence
`ScammerAssociate` on the other address, under its own `source_detail` so an
auditor can tell a behavioral claim from a clustering one without leaving the
row.

*The flywheel's cycle is a fixpoint, by construction.* A proposal can mint a
label; the label invalidates the subject's embedding; the recomputed embedding
returns to the signal. That loop is the §8.5 flywheel working, and it terminates
because every artifact is keyed on content rather than on time: the label id is
seeded from the claim, the proposal id from the unordered address pair and the
feature space, and the embedding job republishes only a vector that actually
moved. A rediscovered proposal *refreshes* rather than duplicating, and one an
operator already decided is left alone entirely — a rejection cannot be reopened
by a re-run, or the triage queue could never be emptied.

*The row and its announcement are two writes, and the gap between them is
closed explicitly.* The obvious rule — announce exactly what was just inserted
— is wrong under a crash: Postgres commits, the process dies before Kafka, the
consumer offset was never committed, the event redelivers, the row now exists,
and an insert-keyed rule stays silent. The announcement would be lost
permanently and invisibly. So the question the store answers is not "did I
insert this?" but **"does this row still owe an announcement?"** —
`announced_at IS NULL`, a column stamped only *after* a publish returns. That
makes delivery at-least-once rather than at-most-once, which every downstream
write already tolerates because each is keyed; a boot-time sweep drains
anything redelivery itself cannot reach (a group reset forward, a compacted
topic). It is `rule_outbox`'s trade in the cheaper shape this workload allows:
no second table to drain, because the proposal row *is* the durable record the
announcement belongs to.

*The decision is pure, and so is everything that follows from it.* `propose`
turns a search into claims; `plan` turns the store's answer into an ordered
list of effects — announce this, mint that — and a thin executor performs them.
The rule that most needed to be assertable is the one that only exists across a
whole pass: a subject matching three known actors earns three proposals and
**one** label, and as a plan that is an equality check on a `Vec` rather than a
count of events on a recording sink. The same split is why the write model and
the read model are different types: a `Proposal` has no status field to express
a decision with, so no caller can hand the store a "confirmed" proposal for it
to silently ignore.

*The expensive half is gated, and the gate is the honest reading of the task.*
The search is the most expensive read the platform serves and the sweep
recomputes the whole address space, so pairing them naively is one ANN scan per
address per lap. Three gates need no store read at all (wrong chain, wrong
feature space, an all-zero vector), and the fourth — on by default — skips any
address the entity graph has already placed. The signal is for widening recall
where evidence cannot reach; searching addresses the graph already resolved is a
merge-candidate mode an operator turns on by name.

### 20.4 LLM investigation copilot (copilot-service)

A separate service consuming `IncidentCreated` and reading the audit stream
(§4). Two capabilities, both grounded in data the system already trusts:

- **Incident narratives / SAR drafts.** Compliance teams file Suspicious
  Activity Reports by hand from raw event streams. The copilot drafts the
  narrative from the incident's complete audit trail — every factual claim in
  the draft carries the event id it derives from (`grounded_event_ids`), so a
  reviewer verifies claims against the store, not against the model. Drafts
  are `IncidentNarrativeDrafted` events: provisional forever, human-approved
  before leaving the platform. Backfill over historical incidents runs
  through the Batch API at half cost — narrative generation is never
  latency-critical.

  **The citation contract is enforced, not requested.** A narrative has no
  compiler, and "a human reads it" is a boundary that degrades with queue
  depth, so the drafted text is parsed back: its inline `[uuid, …]` citations
  are checked against the audit window the model was actually shown, the
  draft's `grounded_event_ids` is narrowed from that window to what the text
  cites, and a draft citing an event it was never shown — a fabricated
  reference, which looks verifiable until someone tries to look it up — lands
  `blocked` rather than in a reviewer's queue. That is the narrative's
  analogue of the rule parse boundary below: the same statement a refusal
  makes, for the same reason. The threshold on *how much* must be cited is
  deliberately below 100%, because the prompt itself requires uncitable
  sentences (saying plainly what the record does not establish).

  The event carries a **reference** to the draft plus the provenance triple
  (`model_id`, `prompt_version`, prompt digest) and the grounded ids — never
  the prose: an unapproved, machine-written document has no business being
  replicated into an immutable audit log as if it were evidence. It is written
  into `copilot_outbox` **in the same transaction as the landing** and drained
  onto Kafka by a flusher — the same transactional-outbox shape `rule_outbox`
  uses (§20), because a narrative reaching `ready` and the audit trail hearing
  about it are one fact, not two.

  Approval is a store-side flip over the copilot's own review API, and nothing
  auto-delivers. **The reviewer's identity comes from a verified JWT**, not a
  request field: an approval signed with a name the caller chose is not an
  audit record. Bearer verification is shared (`crates/auth`) so the platform
  has one issuer and one claim set; each service then interprets `sub` for
  itself (a billing customer for the metered API, a person for the copilot).
- **Natural-language rule creation.** "Alert me when any wallet within 2 hops
  of a sanctioned address moves more than $10K into our pools" → the model
  emits the rule engine's wire form under a structured-output schema → the
  draft compiles through the **existing rule parse boundary** (§9). A
  hallucinated condition fails compilation and returns the compiler's error —
  it can never run. The customer reviews the compiled rule (echoed back in
  plain language) before activating it. `RuleDraftProposed` is the audit
  record; activation flows through the normal `POST /v1/rules` path.

  **The safety argument is that there is only one parser.** The copilot
  re-implements none of §9's vocabulary: a drafted rule goes through
  `RuleDefinition` → `Rule::validate` → `CompiledRuleSet::compile`, the same
  path a hand-written rule takes, and the compiler — not merely the validator —
  is the gate, because "well formed" and "evaluable" are different questions
  and only the second is safe to hand somebody. A draft that fails lands
  `blocked` with the parser's own message, inside the same one landing rule the
  narrative's citation check runs in, so the cross-pod cache cannot promote a
  draft the worker would have blocked.

  **The model has no owner field to hallucinate into.** The structured-output
  schema is generated from `RuleDefinition` — a rule *minus* `id` and `owner`,
  the two fields no request body may choose — and that same type is what the
  API service's `POST /v1/rules` builds from, so a drafted definition is
  byte-for-byte a create body. The owner comes from the verified JWT twice: at
  `POST /v1/rules/draft`, and again at activation.

  The draft's subject id is **derived from `(owner, request)`**, so asking the
  same question twice resolves to the draft that already exists rather than
  buying a second, differently-worded answer to it; the hash is salted by owner
  because a key shared across customers would be a cross-tenant draft, not a
  cache hit. The event carries the **definition** where the narrative event
  carries only a reference — a definition is a closed structure that already
  passed the compiler and cannot act on anything until a customer activates it,
  which is precisely what an auditor will later want to diff against what *was*
  activated — and it carries only the **hash** of the customer's sentence,
  never the sentence. The plain-language echo is rendered from the compiled
  definition, never from what the model said about its own output: a
  model-written summary would be wrong in exactly the case that matters.

Mechanics:

- **`llm` seam crate:** an `LlmClient` trait over the Claude Messages API
  (thin `reqwest` client — there is no official Rust SDK), with an in-memory
  double for tests. Default model `claude-opus-5`; model id is config, never
  hardcoded at call sites.

  Its `CompletionCache` seam is **async**, sized for the implementation that
  isn't in the crate: the in-process map pays one boxed future per call, while
  the copilot's cross-pod cache is a database round trip that a synchronous
  trait would force to block a runtime worker. Sizing a seam for the cheap
  implementation and taxing the expensive one is backwards when the expensive
  one is the one that runs in production.

  Everything that makes a rate-limited third party survivable is a **decorator
  over the seam**, assembled in one composition root (`llm::LlmStack`) because
  the order is load-bearing and every wrong order still compiles:
  `Cached → Metered → Retrying → Breaker → Admitted → Anthropic`. A cache hit
  therefore costs no permit, no breaker signal and no bill; metering is per
  *logical* call, so three attempts are one invoice line; the breaker is
  consulted on every attempt; and an admission permit covers the HTTP call
  only, not the backoff sleep.

  Two failure classifications, deliberately distinct: `Transience` answers
  "should the queue above re-run this later?" and `retry_now` answers "would
  trying again in 200ms help?". A shed call, an open circuit, and a
  `retry-after` longer than this process will hold a worker are all *transient
  but not retriable here* — **there are two clocks**, and an in-process loop
  exists to ride out a blip, not to wait out a quota.

  The breaker and the jittered backoff are `resilience`, shared with §5's RPC
  endpoint pool rather than copied — the `db::redis` argument applied to
  concurrency state machines.

- **The copilot must not call the model from inside a consumer callback.**
  `run_consumer` awaits its handler inline before committing, so a multi-minute
  completion becomes the poll interval: the member is evicted, the partition
  rebalances, the record is redelivered, and the same expensive call starts
  again elsewhere. The copilot therefore takes the shape §7 already uses for
  the slow path — a thin consumer that records a draft job and commits in
  milliseconds, and a worker pool that drains it. The drafts table doubles as
  the cross-pod response cache, keyed by request digest.

  The queue is a **Postgres table**, not the RabbitMQ §7 uses for simulation
  jobs, and the difference is what each thing *is*: a simulation job is a
  command consumed once, while a draft is an artifact with a lifecycle
  (queued → leased → answered → approved) that has to stay auditable long
  after the work item is gone. Splitting the two across a broker and a store
  would need a distributed transaction to keep them agreed; one row needs
  none. Claims are `FOR UPDATE SKIP LOCKED` with a lease, so every pod runs
  the same query without colliding and a pod killed mid-call leaves work that
  expires back onto the queue rather than work that vanished behind a
  committed offset.

  Two invariants the lease carries. It must **outlast the worst-case call**
  (the seam's per-request timeout times its attempt budget) or a second pod
  reclaims a job that is still running and both pay — checked at boot, because
  its failure mode is a doubled bill and two documents, never an error. And a
  worker **never retries**: a transient fault releases the job to the queue's
  clock, a permanent one fails the draft. That is the same two-clocks split
  the seam draws between `Transience` and `retry_now`, applied one level up.

  A refusal or a `max_tokens` truncation is a *successful, billed* call whose
  answer is unusable, so it lands in its own terminal state rather than being
  retried — re-running a decline buys a second identical decline at full
  price — and it is **cached**, which is what stops a redelivery loop paying
  for it repeatedly.

  **A pod only claims the draft kinds it can serve.** The queue is
  kind-agnostic — narratives and rule drafts share it — but a replica carries
  only the generators it was built with, and a claim is a *durable lease*: a
  draft leased by a pod with no generator for it is a draft nobody else may
  touch until that lease expires. The generator roster is linked at boot
  (duplicate or empty is a refused rollout) and its key set *is* the claim
  filter, so leasing unservable work is impossible rather than merely
  unlikely.

  **The lease is sized from the real worst case**, which is not
  `attempts × timeout`: the seam sleeps *between* attempts, outside the
  per-request timeout, so the budget is the grounding read plus
  `attempts × timeout` plus `(attempts − 1) ×` the longest inter-attempt
  sleep. Checked at boot, because a lease that expires mid-call produces no
  error at all — a second pod reclaims a running job, both call the provider,
  and the only symptom is the bill.

- **Prompt injection is expected input, not an edge case.** Everything the
  copilot reasons over is attacker-influenced (token and ENS names, contract
  metadata, decoded calldata). Instructions live only in the versioned system
  artifact; chain-derived text is fenced as untrusted in a *user* turn and
  cannot close its own fence. Those reduce how often the architectural defence
  is needed; they do not replace it — the load-bearing control remains that
  output is a proposal, a drafted rule must survive the §9 parse boundary, a
  rule's owner comes from the JWT and never from the model, and activation is a
  human step.
- **Prompts are versioned artifacts** — checked in, hashed, and stamped into
  every draft event alongside the model id. A prompt change is a diff review,
  and every historical draft is attributable to the exact prompt that
  produced it.
- **Cost is metered:** token usage flows through `UsageRecorded` like every
  other billable quantity — in **four SKUs** (fresh input, output, cache write,
  cache read), because they are four different prices and a single "tokens"
  number cannot be turned into a bill. Per-customer spend is alarmed, never
  gated. A separate, platform-wide spend ceiling exists as a runaway-loop
  safety valve; it is not a per-customer quota.

### 20.5 Model governance

- **Drift detection:** serving-time feature distributions are monitored
  against the training snapshot (population-stability metrics per feature);
  drift past threshold raises an alert and flags the model version in the
  registry — visible before precision decays, not after.

  Delivered as a **second decorator over the serving seam** (`DriftEngine`
  outside `ObservedEngine`, so the inference-latency histogram the < 1s budget
  is checked against measures inference and not bookkeeping). It sees exactly
  the vectors a model is served, and measures them against the same
  `FeatureBaseline` the explanations are written from — one owner of "what
  normal was", or the alert and the evidence would disagree in precisely the
  situation both exist for.

  The statistic is **not** a population-stability index, and the deviation is
  the interesting part. A PSI needs the training distribution's *shape*; a
  baseline carries robust summary statistics and deliberately not a histogram,
  because the export has to stay small, comparable across versions, and
  hashable into a deployment's identity. Binning against an assumed shape
  would be worse than nothing here — §20.1 features are heavy-tailed by
  construction, so a normality assumption reports drift on the quietest
  possible day. What ships instead is the robust two-sample analogue of what
  the baseline can honestly support: over a tumbling window of served vectors,
  each feature's clamped z-scores are summarised by their own median (**shift**
  — how far the serving window has moved, in training spreads) and σ-scaled MAD
  (**spread** — whether it still varies as much as training did). One
  magnitude, `max(|shift|, |ln spread|)`, is what a threshold is set on.
  Tumbling and not sliding, so one drifted condition is one alert rather than a
  stream of identical ones. A feature that never varied in training reports
  shift alone: its spread is a floor, not an observation, and reading `ln 0`
  off it would page on the quietest possible traffic.

  Serving/training skew reappears here as its own counter rather than as a
  statistic: a vector the baseline cannot describe is *refused*, not folded in,
  because one foreign vector would corrupt every subsequent reading and the
  skew is the more urgent signal anyway. It pages — the boot-time check already
  passed, so a rejection at serving time is a wiring bug, not a data condition.

  **The durable flag is an event, not a mutable registry.** A breaching window
  publishes `ModelDriftDetected` — the model, the drifted features with their
  numbers, and the exact `(id, version, config_hash)` triple that was serving —
  into the same event store as everything else (§4). That is what §20.5's "flag
  the model version" means here, and it is stronger than a mutable flag would
  be: metrics answer "is it drifting now?" and expire with Prometheus retention,
  while the question an incident review asks months later is *which weights were
  serving when it drifted, and could anyone have known?* Keyed by the same
  triple the findings carry, the two join without a heuristic.

  The registry itself is deliberately **not** mutated at runtime. It is linked
  once at boot and immutable for the process's life (§6), which is what makes a
  triple mean the same thing for every event that process emits; a flag that
  changed mid-run would make the triple a function of *when* an event was
  emitted. The registry-level response stays the one §20.5 already prescribes:
  a new version, or `deprecated_at` on this one.

  Emission is a **block-boundary concern**, not the seam's. `inference` is
  forbidden `event-bus` by the architecture rules — a serving seam that could
  publish would be a serving seam with an opinion about topology — and a
  detector cannot publish either, being a pure function of its context. So a
  reading leaves through a plain `DriftSource` trait and the scheduler appends
  it to the events that block was publishing anyway: same producer, same retry,
  same DLQ, no second failure mode for a handful of events per hour.

  **Two bounds, because they answer different questions.** A window closes at N
  vectors *or* T elapsed, whichever comes first, never below a sample floor. The
  count bound decides how *good* a reading is; the age bound decides how *soon*
  there is one — and at one block-level vector per block, a count-only window is
  blind for roughly the first 100 minutes after a deploy, which is precisely
  when new weights are most likely to be wrong. A model too quiet to reach the
  floor within the age bound keeps accumulating rather than publishing
  statistics over a handful of samples, and its silence is visible as a flat
  window counter rather than as an absence of drift.

  **The monitor fails open, loudly.** A watcher must never be why the fast path
  stops scoring blocks, so a contended or poisoned accumulator drops the
  observation instead of blocking or panicking (and a poisoned one discards its
  partial window and resumes, rather than going silent for the process's life).
  What it does not do is drop anything quietly: every skipped observation, every
  evicted undrained reading, and every vector refused for schema skew is
  counted, because a monitor that has stopped monitoring reads exactly like a
  model with no drift.

  The breach threshold is per-model config and is **exported as a gauge**, so the
  alert rules compare against the number each model was actually judged by
  instead of restating it in PromQL — where a literal would be a second
  definition of the same policy, wrong for any model that tuned its own.
- **Retraining is a release:** a retrained model is a new registry version and
  walks the same Shadow → backtest → Live gate. There is no "hot-swap the
  weights" path.

  The gate is a **committed floor, separate from the regression baseline**, and
  the separation is load-bearing. The baseline answers "did this change make
  something worse?" and every intentional change is allowed to rewrite it; a
  promotion bar that a change could rewrite would let a detector ratchet its own
  floor down one merge at a time and arrive at `Active` with a precision of 0.2,
  each step "no regression". So `promotion_gate.json` has no `--update` flag:
  moving it is a hand edit, which is the friction a governance threshold should
  have. The gate reads the *live* rollout staging rather than restating it, and
  the asymmetry is deliberate — it can **block a release** (an `Active` detector
  below its floor, or one promoted and no longer measured, fails CI) but it can
  only **recommend a promotion** (a `Shadow` detector that clears reports as
  promotable; leaving `Shadow` stays a human edit). A detector with too few
  ground-truthed incidents reads `Unmeasured`, not `pass` — a model can be fit
  to one fixture, and a gate that promoted on it would be measuring
  memorisation. The gate prints the corpus its verdicts rest on, because at the
  shipped fixture set's size `PROMOTABLE` means "not disqualified by the
  evidence we have", not "proven" — and the number to grow is the corpus (§20.1
  replay over a production window, whose labels the flywheel already produces),
  not the thresholds.

  **Demotion is config; promotion is a merge.** `DETECTION_SHADOW_DETECTORS`
  can force any detector to `Shadow` at boot, and `DETECTION_DISABLED_DETECTORS`
  can stop one running at all. Neither can promote, and that asymmetry is the
  point: shadowing a detector that is melting down at 03:00 should need nothing
  but a config change, while making one customer-facing is a claim about
  evidence and stays a reviewed diff with a backtest run in it. A general
  per-environment override would be a path around the gate — the exact thing
  "ML gets no special path" forbids, available to every heuristic detector too.
- **The registry is the single source of truth** for what is deployed: model
  cards gain `artifact_hash` and `feature_version` fields, and the
  serving/training skew check (deployed `feature_version` == artifact's
  training `feature_version`) is enforced at boot, link-or-fail (§6).
