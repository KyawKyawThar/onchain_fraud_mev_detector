# On-Chain Fraud & MEV Detector — v2 Microservices Architecture (Rust)

A production-grade on-chain risk intelligence platform. v2 graduates from a monolithic workspace to an event-driven microservices architecture, with event sourcing as the audit backbone, an Address Intelligence Service as the core moat, and a Rule Engine as the primary commercial differentiator.

> **v1 → v2 migration principle:** the Cargo workspace crate boundaries from v1 are preserved. Each crate becomes the implementation of a deployable service. No logic is rewritten; deployment topology changes.

---

## 1. Two architectural principles that govern everything

### Principle 1 — Three-layer separation (from v1)

```
Evidence      →    Attribution / Entities / Labels    →    Derived Views
(immutable)        (mutable, versioned overlays)           (recomputable)
```

Detection is attribution-blind. Labels change; evidence does not. Risk scores are pure functions of their inputs, always recomputable.

### Principle 2 — Event sourcing as the audit backbone (new in v2)

Do not store only final state. Store every domain event that caused that state. The complete event log is the source of truth; read models (incidents, scores, dashboards) are projections derived from it.

```
WHY? Because customers will ask: "Why did you generate this alert?"
That question is sometimes a legal question.
You need a complete, immutable, replayable audit trail.
```

These two principles together mean: detection produces immutable evidence events, interpretation evolves through mutable overlay events, and derived views are projections. Every state change in the system is a domain event that can be replayed, audited, and explained.

---

## 2. Domain event model

All services communicate by publishing and consuming these events over the event bus. The event store is the canonical record of everything that happened.

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
DetectorTriggered     { detector_id, detector_version, block, txs, raw_confidence, evidence }
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

> **Events vs. commands.** Everything above is a domain *event* — a fact in the past tense, immutable, appended to the event store, transported on Kafka. The system has exactly one *command* — `SimulationJob` ("run this simulation") — and it is deliberately **not** in this model and **not** in the event store. A command is an instruction, consumed once; it travels on the RabbitMQ work queue (§7). Only its result re-enters the event model, as `SimulationCompleted`. Keeping commands out of the event log is what keeps the audit trail a record of what *happened* rather than what was *attempted*.

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
        │          │  (THE MOAT)          │  all events  │  (immutable audit log)        │
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

Two transports, split by **what** is being moved — not by team preference. The distinction is events vs. commands:

- **Domain events → Kafka (async, default).** A domain event is a *fact*: something that already happened (`IncidentCreated`, `RiskScoreUpdated`). Facts are immutable, multi-consumer, ordered per key, replayable, and append to the event store. Kafka's log model is built for exactly this — retention, offsets, fan-out, deterministic replay for backtesting. Keyed by chain or address.
- **Work commands → RabbitMQ (async, simulation dispatch only).** A command is an *instruction*: do this unit of work (`SimulationJob`). A command is consumed once, by exactly one worker, and either succeeds, retries, or dead-letters. This is a competing-consumer work queue, not an event log — see §7. It does **not** append to the event store (a command is not a fact; only its *result*, `SimulationCompleted`, is a domain event back on Kafka).
- **Sync request/response → gRPC (exceptions only).** Where latency matters — API service querying intelligence service for a risk score, for example.
- Services own their data stores. No cross-service database joins. No shared tables.

> **Why not one broker?** Kafka *can* approximate a work queue with consumer groups, but parallelism is capped at partition count, there is no per-message ack/redelivery, no dead-letter routing, and no priority. The simulation path needs all four. Conversely RabbitMQ is a poor event log — no long-horizon retention, no replay, no offset rewind for backtesting. Each tool carries the message shape it was designed for. The boundary is the events/commands seam, and it is the *only* place a second broker is introduced.

---

## 4. Event-store service

The immutable audit log. Every domain event from every service is appended here. This is the system of record.

**Storage:** append-only log, partitioned by `(chain, event_type, date)`. ClickHouse with `MergeTree` — append-only semantics, no updates, no deletes. Retention configurable.

**API:** append (internal only, write-authenticated), query by address/incident/time range, replay stream for a given event type and time window.

**Why this is not Kafka itself:** Kafka has configurable retention and is not designed for long-term queryable storage. The event store is queryable by business keys (address, incident_id, block_hash) and retained indefinitely. Kafka is the transport; this service is the permanent record.

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

**Responsibilities:** source adapters, reorg-aware block assembler, block canonicalization and finalization tracking. Emits chain events.

**Consumed:** nothing (source of truth for chain data).

**Emits:** `RawBlockReceived`, `BlockAssembled`, `BlockCanonicalized`, `BlockReverted`, `BlockFinalized`.

**Data store:** in-memory block tree (bounded by finalization depth). No persistent store needed — chain data is re-fetchable; the event store has the event log.

**Source adapters (in order of preference):**
1. reth ExEx — in-node post-execution pipeline.
2. Own node IPC/WebSocket — `newHeads` + trace APIs.
3. RPC failover pool — health-checked, circuit-broken.

**Reorg handling:** on `parent_hash` mismatch, walk to common ancestor, emit `BlockReverted` for orphaned blocks, emit `BlockCanonicalized` for the new canonical chain. Services that maintain cross-block state consume these events to roll back their own projections.

---

## 6. Detection service (fast path — target < 1 second)

**Principle:** emit a preliminary alert as fast as possible using heuristics only. No simulation. No label lookups on the hot path. Confidence is based on on-chain facts only (attribution-blind).

**Consumed:** `BlockAssembled`

**Emits:** `DetectorTriggered`, `PreliminaryAlertCreated`

**Data store:** none persistent. In-memory cross-block detector state, versioned by block for reorg rollback.

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

`DetectionCtx` contains: `BlockBundle`, normalized events, enrichment (token/pool/price — no labels). Output: `Vec<Evidence>` carrying `(detector_id, detector_version, on_chain_confidence)`. **No attribution in this layer.**

### Model registry

Every deployed detector is registered:

```rust
struct RegistryEntry {
    id:              DetectorId,
    name:            String,
    version:         SemVer,
    kind:            ModelKind,       // Rule | ML | Hybrid
    config_hash:     String,
    deployed_at:     Timestamp,
    deprecated_at:   Option<Timestamp>,
    performance:     Option<Metrics>, // precision/recall from last backtest
}
```

This supports safe rollouts (deploy v1.3 alongside v1.2, compare results), A/B testing, and deprecation. Every `DetectorTriggered` event carries the registry entry's `(id, version, config_hash)` — historical evidence is always attributable to an exact detector version.

### Feature flags per detector

```toml
[detectors.sandwich]
enabled = true
min_profit_usd = 10.0

[detectors.flash_loan]
enabled = true

[detectors.rugpull]
enabled = false          # behind paid plan

[detectors.wash_trading]
enabled = true
window_blocks = 100
```

### Detector crates (compile-time plugin registration)

No dynamic loading — Rust has no stable ABI. Each detector is an independent crate implementing `DetectorPlugin`, registered at compile time. Isolation, independent testing, selective open-sourcing, premium detectors stay closed.

```
detectors/
  sandwich-detector/     # v1.2
  arb-detector/          # v1.0
  flashloan-detector/    # v2.1
  liquidation-detector/
  rugpull-detector/
  washtrading-detector/
  poisoning-detector/
```

---

## 7. Simulation service (slow path — async, seconds to minutes)

**Principle:** receive preliminary alerts, run expensive revm simulation to confirm or retract, then emit confirmed incidents. Runs asynchronously — never on the alert critical path.

**Consumed:** `PreliminaryAlertCreated`, `BlockReverted` (to retract pending simulations)

**Emits:** `SimulationCompleted`, `IncidentCreated`, `IncidentRetracted`, `IncidentFinalized`

**Data store:** Postgres for in-flight simulation jobs and confirmed incidents. ClickHouse for the incident analytics projection.

### Job dispatch — the RabbitMQ work queue

The simulation service is the one component in the system that is **not** a stream consumer at heart — it is a worker pool draining a backlog of expensive, CPU-bound jobs. revm is the bottleneck (§20 says scale this aggressively); the workload is "N interchangeable workers, each pulls the next job, runs it, acks it." That is a competing-consumer work queue, which is RabbitMQ's native model and Kafka's awkward one.

The flow keeps the event backbone clean:

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

Why this shape, point by point:

- **`SimulationJob` is a command, not a domain event.** It is an instruction to do work, consumed exactly once. That is why it lives on RabbitMQ and is deliberately **absent from the §2 domain event model and the event store** — the audit log records facts, and "we decided to simulate" is not a fact worth replaying; only the *outcome* is. This is the single most important line to be able to defend: the event store stays a log of what happened, not a log of what we queued.
- **Competing consumers.** Add worker instances to add throughput. No partition-count ceiling on parallelism the way a Kafka consumer group would impose.
- **Per-message ack + redelivery.** A worker acks only after the simulation finishes. If it crashes mid-run — and the input is hostile honeypot bytecode executing in revm (§7 hardening), so crashes are part of the threat model — the unacked job is redelivered to another worker automatically.
- **Dead-letter exchange (DLX).** A job that fails N times routes to `sim.jobs.dlx` for inspection instead of poisoning the queue or looping forever. Operators get a quarantine, not an outage.
- **Priority queue.** Enterprise-tier alerts and high-provisional-profit alerts jump ahead of free-tier backlog. Native in RabbitMQ; effectively unavailable in a Kafka partition.
- **Queue depth = backpressure signal.** RabbitMQ `sim.jobs` ready-message count is the single number that says "simulation is falling behind"; it drives autoscaling of the worker pool.

`BlockReverted` is still consumed from **Kafka** (it is a domain event, multi-consumer), and on receipt the dispatcher cancels not-yet-started jobs for orphaned blocks (`basic.reject` without requeue, or a generation check on the consumer) and the service retracts any already-emitted incidents via `IncidentRetracted` back on Kafka.

### Ordering & idempotency

The work queue gives up two guarantees Kafka's per-key log provides — strict ordering and exactly-once-ish processing — and the design is safe precisely because the simulation workload never needed either.

- **Jobs are independent, so order does not matter.** Each `SimulationJob` is a self-contained `(block, tx_set)` unit. Worker A finishing block N+1 before worker B finishes block N is fine — there is no cross-job state, no accumulator, nothing that two sims read or write in common. This is *why* the competing-consumer / priority model is admissible here: reordering is a non-event. (Contrast the detection service, where cross-block detector state genuinely is order-sensitive — that path stays on Kafka's ordered partitions for exactly that reason.)
- **Redelivery is safe because processing is idempotent.** RabbitMQ guarantees at-least-once: a worker crash after finishing revm but before `ack` causes the same job to run twice. That is harmless. The simulation cache is keyed by `(block, tx_set)` (§7 hardening), so a re-run is a cache hit, not duplicate work. And the *result* is published as a domain event keyed by `alert_id` — a second `SimulationCompleted` for the same `alert_id` is a no-op the downstream projections deduplicate, the same way they already dedup any replayed Kafka event. No "exactly-once" machinery is required anywhere.
- **The result path reinstates ordering where it actually matters.** Out-of-order completion on the queue is invisible to consumers because results land back on Kafka keyed by `alert_id`/incident, and the intelligence and notification projections are written to be commutative over those keys (last-writer-by-event-time wins, `provisional → confirmed → retracted` is a monotonic lifecycle). Order is enforced at the projection, not the queue — which is the right place for it.

The one-line version for an interview: *the sim queue can reorder and redeliver freely because jobs are independent and processing is idempotent (`(block, tx_set)`-keyed cache, `alert_id`-keyed results); ordering is reasserted at the Kafka projection, not demanded of the worker pool.*


### What simulation confirms

- **Attacker profit:** simulate bundle, diff balances.
- **Victim loss:** diff victim contract holdings.
- **Counterfactual:** re-simulate victim swap without the frontrun.
- **Honeypot:** simulate buy then sell from fresh address.

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
simulation-service   (revm worker pool drains the RabbitMQ sim.jobs queue:
                      competing consumers · per-job ack/redelivery · DLX · priority)
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

Subscribers receive provisional alerts immediately; they are upgraded or retracted asynchronously. Clients must handle both transitions — this is documented in the API contract.

### Simulation hardening

Cap gas/steps per simulation — contract bytecode from honeypot tokens runs in your simulator and must be treated as hostile input. Sandbox revm. Cache simulation results by `(block, tx_set)` — avoid re-simulating the same bundle twice during replay.

---

## 8. Intelligence service (the moat)

This is the Address Intelligence Service. It consolidates what was `label-service`, `entity-graph`, `attribution`, and `risk-engine` into one service with a single product identity. The name matters: Arkham Intelligence, Nansen, TRM Labs — they are not "label services." They are intelligence platforms.

**The moat is not the detector. The moat is the intelligence graph.**

**Consumed:** `IncidentCreated`, `IncidentRetracted`, `IncidentFinalized`, `BlockCanonicalized`, `BlockReverted`, `LabelAdded`, `LabelUpdated`, `EntityMerged`, and all other domain events.

**Emits:** `LabelAdded`, `LabelUpdated`, `LabelRevoked`, `EntityCreated`, `EntityMerged`, `EntitySplit`, `AttributionUpdated`, `RiskScoreUpdated`, `SanctionHit`.

**Data stores:**
- Postgres: labels (with provenance), entities (versioned), attribution records, sanctions lists.
- Redis: hot-path label/score cache (TTL-backed, evicted on update).
- ClickHouse adjacency tables: full address graph for hop queries.
- petgraph: in-memory, bounded subgraph queries only (load 3-hop neighborhood, analyze, discard).

### 8.1 Wallet labels

```rust
struct Label {
    address:     Address,
    kind:        LabelKind,   // CexWallet | MevBot | KnownScammer | Bridge |
                              // Protocol | Deployer | MixerUser | SanctionedEntity |
                              // ScammerAssociate | BuilderAddress
    value:       String,
    confidence:  f32,         // 1.0 manual | 0.7 heuristic | 0.4 external feed
    source:      LabelSource,
    created_at:  Timestamp,
    valid_until: Option<Timestamp>,
}
```

Conflicting labels are stored, not overwritten. Manual overrides heuristic but both are retained for audit.

**Label sources:**
- Public: Etherscan tags, OFAC SDN list, community MEV-bot lists, protocol address registries.
- Heuristic auto-labeling: builder feeRecipient from relay data, code-hash matching, funding-source clustering.
- Entity-graph-derived: address A (known scammer) clusters with address B (unknown) → auto-label B as `ScammerAssociate` at reduced confidence.
- Manual curation via operator API.

### 8.2 Entity clustering

```rust
struct Entity {
    id:        EntityId,
    addresses: Vec<Address>,
    labels:    Vec<LabelRef>,
    version:   u64,           // increments on merge/split
}
```

Cluster heuristics: common funder, common deployer, same code hash, shared profit receiver. Every merge emits `EntityMerged`; downstream scores invalidate and recompute automatically.

**Hub-node degree cap:** never walk an unbounded 3-hop graph through a CEX hot wallet, major bridge, or router — they connect to millions of addresses. Apply degree caps; treat high-degree nodes as infrastructure endpoints that stop the walk. Getting this wrong collapses the graph into noise.

### 8.3 Risk scores

```rust
struct RiskScore {
    address:       Address,
    entity_id:     Option<EntityId>,
    score:         u8,          // 0–100
    confidence:    f32,         // 0.0–1.0, aggregate certainty in `score`
    model_version: SemVer,
    computed_at:   Timestamp,
    factors:       Vec<RiskFactor>,
}

struct RiskFactor {
    kind:         FactorKind,
    description:  String,
    delta:        i8,
    evidence_ref: Option<EvidenceId>,
}
```

Example:
```
Score: 87 / 100   Confidence: 0.91   (model v1.4.2)

+35  2 confirmed sandwich attacks (profit: $18,400)
+20  1 flash-loan exploit (victim loss: $240,000)
+15  entity member: Entity #183 (known MEV cluster)
+10  funded by mixer-adjacent address (confidence: 0.6)
+7   co-deployed with known scammer
```

Score design rules: **explainable** (every delta has an evidence reference), **versioned** (model version is part of output), **time-decayed** (old incidents contribute less), **taint-by-association nuanced** (mixer proximity is a signal at reduced confidence, not deterministic — legally contested and documented as such).

### Confidence vs. score — two different axes

`score` answers "how risky is this address?" `confidence` answers "how sure are we?" They are computed independently and must not be conflated — a address can be high-risk and low-confidence (e.g. a single heuristic label with no sim-confirmed incidents) or low-risk and high-confidence (e.g. extensively observed, consistently clean).

`confidence` is an aggregate over the `factors` that contributed to `score`, weighted by the evidentiary strength of each factor's `evidence_ref`:

- Sim-confirmed incidents (`IncidentCreated` with `confirmed: true`) → high weight
- On-chain-verified entity merges (shared deployer, shared code hash) → high weight
- Manual label curation (`Label.confidence = 1.0`) → high weight
- Heuristic auto-labels (funding-source clustering, `ScammerAssociate` derivation) → reduced weight
- External feed labels (`Label.confidence = 0.4`) → low weight

A factor with no `evidence_ref`, or one backed only by a low-confidence label, pulls the aggregate `confidence` down even if its `delta` is large. This is computed alongside `score` in the same pass — both are projections owned by intelligence-service, invalidated and recomputed together on any input change.

Scores are cache entries keyed by `(address, model_version)`, invalidated when any input changes, recomputed by the intelligence service.

### 8.4 Reputation

Track behavioral history over time: total MEV extracted by month, attack frequency, victim count, dormancy periods. Exposed as time-series on the entity profile API endpoint.

The same event history also backs `GET /v1/entity/{id}/timeline` — a small set of curated milestones (first seen, classification changes, new linked wallets, chain expansion, notable incidents) selected from the full event log for the entity. Both projections read from the same source events; the time-series is continuous/quantitative, the timeline is discrete/narrative.

### 8.5 Sanctions

Ingest OFAC SDN list, EU sanctions, and relevant national lists. Emit `SanctionHit` immediately on any address match against a new or existing label. This is a hard alert — does not go through the slow simulation path.

### 8.6 Data flywheel

Entity clustering auto-generates labels → labels improve attribution confidence → better attribution surfaces more entity links → flywheel continues. This loop is the compounding defensibility that pure detection cannot replicate.

---

## 9. Rule engine service

The largest commercial unlock. Compliance teams, traders, and investigators all want custom alerting on top of the intelligence graph. This is where you charge enterprise pricing.

**Consumed:** all `IncidentCreated`, `RiskScoreUpdated`, `EntityMerged`, `LabelAdded`, `SanctionHit`, normalized events.

**Emits:** `RuleTriggered`, `RuleAlertCreated`.

### Rule model

```rust
struct Rule {
    id:         RuleId,
    owner:      CustomerId,
    name:       String,
    enabled:    bool,
    conditions: Vec<Condition>,
    logic:      LogicOp,        // All | Any | Not
    temporal:   Option<TemporalConstraint>,
    actions:    Vec<Action>,
}

enum Condition {
    TransferAmount        { chain, token, gt: Option<Decimal>, lt: Option<Decimal> },
    InteractedWith        { address: Option<Address>, label_kind: Option<LabelKind> },
    IncidentKind          { kind: IncidentKind, min_confidence: f32 },
    EntityLabel           { kind: LabelKind, min_confidence: f32 },
    RiskScore             { gt: Option<u8>, lt: Option<u8> },
    SanctionMatch         { list: SanctionList },
    HopDistance           { from: Address, max_hops: u8 },
    NewAddress            { active_within_blocks: u64 },
}

enum TemporalConstraint {
    Sequence { events: Vec<Condition>, within_blocks: u64 },
    Frequency { condition: Box<Condition>, count: u32, within_blocks: u64 },
}

enum Action {
    WebhookAlert { url: String },
    EmailAlert   { to: String },
    SlackAlert   { channel: String },
    TagAddress   { label: String },
}
```

Example rules:
```yaml
# Compliance rule
name: "Large transfer then mixer interaction"
conditions:
  - transfer_amount: { gt: 1000000, token: USDC }
  - interacted_with: { label_kind: MixerUser }
temporal: { sequence: true, within_blocks: 100 }
actions:
  - webhook_alert: { url: "https://compliance.example.com/hook" }

# Trader protection rule
name: "Sandwich bot targeting my wallet"
conditions:
  - incident_kind: { kind: Sandwich, min_confidence: 0.8 }
  - entity_label: { kind: MevBot }
actions:
  - slack_alert: { channel: "#trading-alerts" }
```

Rules are evaluated against incoming domain events. Temporal sequence rules maintain a small per-address state machine. Rules are owned by customers and isolated — no cross-customer data leakage.

### Rule engine implementation

Parse rules from the stored definition, compile to evaluation functions, run against enriched event stream. For temporal rules, maintain windowed state per `(rule_id, address)`. Persist state to Redis (TTL-bounded, keyed by rule + address). Scale horizontally: partition the event stream by address so one worker owns all state for a given address.

---

## 10. Builder & relay analysis (within detection or intelligence service)

Track the full block production chain: `Transaction → Bundle → Block → Builder → Relay → Validator`.

**Sources:** MEV-Boost relay public APIs, block `feeRecipient`, `extraData` graffiti, coinbase transfers.

```rust
struct BlockProductionRecord {
    block:              BlockId,
    builder:            Option<BuilderLabel>,
    relay:              Option<RelayLabel>,
    mev_extracted:      Decimal,
    sandwich_count:     u32,
    arb_count:          u32,
    coinbase_transfers: Vec<Transfer>,
}
```

Builder identity is heuristic. Maintain builder/relay labels in the intelligence service — the landscape shifts and hardcoding names is a maintenance trap.

**Dashboard metrics:** top builders by sandwich volume, relay market share by MEV type, builder pattern differences (some builders accept more aggressive bundles).

---

## 11. API service

**Consumed:** reads projections from intelligence service (gRPC/sync), event store (async), incident store.

**Emits:** `UsageRecorded` (feeds billing service).

### Endpoints

- `GET /v1/address/{addr}/risk` — score + confidence + full factor breakdown + model version.
- `GET /v1/address/{addr}/labels` — all labels with provenance and confidence.
- `GET /v1/entity/{id}` — all addresses, all incidents, reputation history.
- `GET /v1/entity/{id}/graph?hops=3` — connected addresses (degree-capped).
- `GET /v1/entity/{id}/timeline` — curated milestone history (first seen, label/classification changes, new linked wallets, chain expansion, significant incidents). A projection over the event store, distinct from `/v1/audit/incident/{id}`: this is entity-level and narrative ("first seen → reclassified to MEV Bot → new funding source via mixer → expanded to Base"), while the audit endpoint is incident-level and forensic (the full event sequence behind one alert).
- `GET /v1/incidents?chain=&kind=&severity=&since=` — paginated incident feed.
- `GET /v1/audit/incident/{id}` — complete event stream for an incident (from event store).
- `GET /v1/builders` — builder leaderboard by MEV type.
- `POST /v1/address/{addr}/screen` — **synchronous** allow / review / block risk decision for a counterparty (pre-transaction screening; see below). The one latency-critical, blocking surface in the API.
- `POST /v1/rules` — create a custom rule (triggers rule engine service).
- `WS  /v1/stream` — live incident stream (provisional + confirmed + retracted + score updates).

### WebSocket contract

Clients must handle three lifecycle transitions:
1. `provisional_alert` — fast path, unconfirmed.
2. `alert_confirmed` (with simulation data) — upgrades the provisional.
3. `alert_retracted` — provisional was wrong; remove from UI.

This is documented in the API contract and tested explicitly.

### Counterparty screening (synchronous decision API)

`POST /v1/address/{addr}/screen` is the one **synchronous, latency-critical** surface in the API — a pre-transaction risk decision exchanges and protocols call inline on withdrawals, onboarding and counterparty checks. Unlike the incident stream (async fast/slow path), screening must answer in a single round-trip.

It is a thin **decision layer over the intelligence service** (gRPC read, §3): it reads the cached risk score, confidence, labels, entity and sanctions status for the address (Redis hot path, §8.3) and maps them through a **decision policy** to one of three outcomes:

```
allow   — no blocking signals          (score < 40)
review  — hold for manual compliance   (40 ≤ score < 80)
block   — reject the counterparty      (score ≥ 80, OR sanctions match → hard block)
```

The policy is customer-configurable and **versioned** (named policies: `default`, `strict`, `monitor-only`), with a hard-block-on-sanctions override that bypasses the score thresholds entirely (§8.5 — `SanctionHit` is already a hard alert). The response carries the full factor breakdown with `evidence_ref`s, so a `block` / `review` decision is **explainable and auditable** — the same discipline as the risk score itself (§8.3), and necessary because the decision is a blocking action with legal/financial weight.

Every call emits `ScreeningCall` (`UsageRecorded`) — it is a **metered, per-call product** (§13), priced separately from the subscription tiers. Because it is a blocking decision on the customer's critical path, it carries its own SLO (p50 < 100ms, §19), dedicated rate limits, and the decision itself is recorded for the access-audit trail.

---

## 12. Notification service

**Consumed:** `PreliminaryAlertCreated`, `IncidentCreated`, `IncidentRetracted`, `IncidentFinalized`, `RuleAlertCreated`, `SanctionHit`.

**Emits:** `UsageRecorded` (alert count per customer).

Severity-routed webhook delivery with retry/backoff, dedup per incident per subscriber, delivery receipts. Supports webhook, email, Slack, PagerDuty. Customer-configurable filters (min severity, kind, chain). Handles provisional → confirmed → retracted lifecycle so subscribers receive upgrade/retraction events paired to their original alert.

---

## 13. Billing service

**Consumed:** `UsageRecorded` events from API service, notification service, ingestion service.

**Emits:** nothing (sink).

**Data store:** ClickHouse for raw usage events (high volume, append-only). Postgres for customer accounts, plan definitions, billing periods, aggregated usage.

### Metrics tracked from day one

```rust
enum UsageEventType {
    EventProcessed,          // per chain
    DetectorRun,             // per detector
    SimulationRun,
    IncidentGenerated,
    AlertDelivered,
    ApiCallMade,             // per endpoint
    ScreeningCall,           // per /screen decision (metered, per-call product)
    RuleEvaluated,           // per rule
    ChainMonitored,          // daily active
    WalletMonitored,         // per customer-configured address
    EntityQueried,
}

struct UsageEvent {
    customer_id: CustomerId,
    event_type:  UsageEventType,
    quantity:    u64,
    chain:       Option<ChainId>,
    timestamp:   Timestamp,
}
```

### Tier model (design, not hardcoded)

| Tier | Chains | Wallets watched | API calls/mo | Detectors | Custom rules |
|------|--------|-----------------|--------------|-----------|--------------|
| Free | 1 | 5 | 10,000 | Core only | 0 |
| Pro | 3 | 100 | 500,000 | All | 10 |
| Enterprise | All | Unlimited | Unlimited | All + custom | Unlimited |

The billing service measures; Stripe/payment integration is a separate concern wired to these aggregates.

### Counterparty Screening API — metered, per-call pricing

The synchronous screening endpoint (§11) is **not** part of the subscription seat tiers — it is a usage-metered product billed on `ScreeningCall`, because its buyers (exchanges, custodians) drive volume on their own withdrawal/onboarding traffic, not on dashboard seats. Volume-tiered, pay-per-call:

| Tier | Price | Applies when |
|------|-------|--------------|
| Developer | $0.01 / call | first 1,000 calls free · no commit |
| Growth | $0.007 / call | volume ≥ 100K / mo |
| Scale | $0.004 / call | volume ≥ 1M / mo |
| Enterprise | Custom | SLA · on-prem deployment · raw intelligence feed |

Metering must be exact and reconcilable (a screening decision is a billable, legally-weighty event) — same accuracy bar as every other `UsageRecorded` source.

---

## 14. Storage per service

| Service | Store | Rationale |
|---|---|---|
| event-store | ClickHouse (append-only) | Immutable log, queryable by key, retained forever |
| ingestion | In-memory only | Block tree bounded by finality depth |
| detection | In-memory only | Cross-block state, reorg-versioned |
| simulation | Postgres + ClickHouse | In-flight jobs + incident analytics projection |
| intelligence | Postgres + Redis + ClickHouse | Labels/entities (relational) + cache + graph adjacency |
| rule-engine | Postgres + Redis | Rule definitions + temporal state machines (TTL) |
| api | No own store | Reads from intelligence + event-store via gRPC/API |
| notification | Postgres | Delivery records, subscriber config, dedup keys |
| billing | Postgres + ClickHouse | Account/plan (relational) + usage events (analytical) |

**Cross-service data sharing rule:** no cross-service database joins. No shared tables. Services expose read APIs (gRPC for sync, Kafka for async). A service that needs data owned by another service either subscribes to its events or calls its API.

---

## 15. Reorg handling (cross-service)

`BlockReverted` is broadcast to all services. Each service that maintains derived state must handle it:

- **detection-service:** rewind cross-block detector state to common ancestor.
- **simulation-service:** cancel pending simulations for reverted blocks; retract any `IncidentCreated` events from orphaned blocks by emitting `IncidentRetracted`.
- **intelligence-service:** roll back entity merges triggered by retracted incidents; invalidate affected risk scores; re-emit `RiskScoreUpdated`.
- **rule-engine:** rewind temporal rule state windows that included events from reverted blocks.
- **event-store:** append `BlockReverted` events; the audit log records everything including reorgs.

The reorg propagation is eventually consistent across services — this is acceptable because all artifacts carry `provisional` flags until `BlockFinalized` is received.

---

## 16. Predictive pipeline (separate deployment)

The mempool prediction pipeline is a **different product with a different latency regime** — deploy it as a separate binary and scale it independently. Target < block time (~12s L1, ~2s L2) end-to-end.

```
MempoolSource → decode → predict-engine → PredictedAlert
                              ↑ entity labels from intelligence-service (cached)
```

Coverage is limited to the public mempool — private orderflow is invisible. Publishing predictions is adversarial (searchers adapt). Treat as a premium feature.

---

## 17. Concurrency model (per service)

All services use the same pattern: bounded async channels for inter-stage backpressure, rayon/`spawn_blocking` for CPU-bound work (simulation, graph analysis, decoding), never CPU on the async reactor.

- **ingestion:** async I/O, in-memory block tree.
- **detection:** async scheduler, per-block fan-out on rayon, bounded channels.
- **simulation:** RabbitMQ work queue (competing consumers, per-job ack/redelivery, DLX, priority); simulation workers on rayon. Queue depth = backpressure signal. Results published back to Kafka as domain events.
- **intelligence:** async Kafka consumer, sync gRPC read API; entity merges serialized per entity (actor model over channels).
- **rule-engine:** partition by address so one worker owns temporal state for a given address; bounded per-address channels.

---

## 18. Replay & backtesting

- `detector-backfill` binary replays archived blocks through detection + simulation services using the identical code path (same crates). Parallelized across block ranges.
- Backtest harness runs `(detector_id, version, config_hash)` triples over labeled historical windows → precision/recall/latency. Changes gated on metric improvement.
- The event store is the replay source — replay any time window deterministically.

---

## 19. Observability

`tracing` spans propagated across service boundaries via W3C trace context headers (distributed tracing). Prometheus metrics per service: ingestion lag, assembly latency, per-detector hit/latency, simulation queue depth, entity merge rate, label cache hit rate, score recompute latency, reorg depth/frequency, rule evaluation latency, API p50/p99.

Metrics feed a Grafana dashboard with key SLO panels: end-to-end alert latency (block → notification), simulation confirmation rate, false-positive rate from feedback, billing usage by customer.

---

## 20. Deployment

Each service is a container. Services deploy and scale independently — this is the point of the microservices topology.

```
ingestion-service      — 1 instance per chain (I/O bound, scale horizontally per chain)
detection-service      — scale by CPU (detector fan-out)
simulation-service     — scale aggressively (revm CPU is the bottleneck)
intelligence-service   — scale read path (gRPC), shard write path by address range
rule-engine-service    — scale by partition count
api-service            — stateless, scale horizontally behind load balancer
notification-service   — scale by customer count
billing-service        — single instance or small HA pair
event-store-service    — ClickHouse cluster with replication
kafka                  — event backbone: partitioned by chain, one topic per domain event type
rabbitmq               — simulation job dispatch only: quorum queue, DLX, priority 0–9
```

Kafka partitioned by chain; topics for each domain event type. RabbitMQ runs a single durable `sim.jobs` quorum queue (replicated across nodes for HA) plus its dead-letter exchange `sim.jobs.dlx` — it carries commands, never domain events, so it is *not* on the event-store ingest path and its loss degrades simulation throughput without losing audit history. Service discovery via DNS in Kubernetes. Secrets via Vault or cloud secrets manager.

### Containerization

Each service ships as a minimal, non-root container built from a single multi-stage **cargo-chef** Dockerfile (`docker build --build-arg BIN=<service>`). cargo-chef caches the dependency-compile layer so only changed source recompiles; the runtime stage is `debian-slim` + `ca-certificates` running as an unprivileged user (uid 10001). Images build against the committed `.sqlx` offline cache (`SQLX_OFFLINE=1`) so no live database is needed at image-build time. Published to GHCR on merge to `main` / version tags, tagged by branch, semver, and commit SHA.

### CI/CD pipeline

Three GitHub Actions workflows; the gates mirror `just check`, so **local == CI**:

- **`pr.yml`** (pull requests) — fast feedback: `cargo fmt --check`, `clippy -D warnings`, a `--locked` build (Cargo.lock must be committed and current — the Rust analog of a `go mod tidy` check), and coverage via `cargo-llvm-cov` → Codecov.
- **`ci.yml`** (push to `main` / `v*` tags) — full gate: fmt + clippy, **nextest** unit tests + doctests, testcontainers-backed integration tests, release build, **bench-smoke** (benches must compile), supply-chain scan (`cargo audit` + `cargo deny`), then the GHCR image build. Compile time is held down by `Swatinem/rust-cache` (cross-run target + registry cache) + the **mold** linker.
- **`migrate.yml`** (manual, per-environment) — `sqlx migrate info | run | revert` against a chosen GitHub Environment, gated by that environment's protection rules.

Toolchain is pinned via `rust-toolchain.toml` (channel + `rustfmt`/`clippy` components) for reproducible builds across dev and CI (§21).

### Supply-chain & dependency automation

`cargo deny` (RUSTSEC advisories, license allow-list, banned/duplicate crates, source allow-list) and `cargo audit` run on every merge. **Renovate** opens grouped dependency PRs (minor/patch batched, majors isolated, weekly, with lockfile maintenance) — each gated by the same CI before it can land.

### Developer workflow

- **`just`** is the task runner: `just check` reproduces the CI gate locally; `just up` brings the full infra (Postgres, Redis, ClickHouse, Kafka, RabbitMQ) online via `docker-compose`.
- **cargo-nextest** is the test runner; **mold/lld** are opt-in fast linkers wired through `.cargo/config.toml`.
- **lefthook** git hooks keep failures out of CI: `rustfmt --check` on commit (fast), `clippy` + nextest on push.

---

## 21. Tech stack

**Libraries:** `tokio`, `alloy` (providers/types/ABI, `sol!`), `reth` (ExEx), `revm`, `rayon`, `bytes`, `petgraph`, `sqlx` (Postgres), ClickHouse Rust client, `rdkafka` (Kafka — domain events), `lapin` (RabbitMQ/AMQP — simulation job queue), `tonic` (gRPC), `axum` (REST), `tracing` + `tracing-subscriber`, `metrics` + Prometheus exporter, `thiserror`/`anyhow`, `clap`, `criterion`, `proptest`. *(Pin current versions; toolchain pinned via `rust-toolchain.toml`.)*

**Build & dev tooling:** `just` (task runner), `cargo-nextest` (tests), `cargo-llvm-cov` (coverage), `cargo-deny` + `cargo-audit` (supply chain), `cargo-chef` (Docker layer caching), `Swatinem/rust-cache` + `mold`/`lld` (CI build caching/linking), `sqlx-cli` (migrations, offline `.sqlx` cache), `lefthook` (git hooks), `bacon`/`cargo-watch` (live reload), Renovate (dependency updates). Infra runs locally via `docker-compose`; CI/CD on GitHub Actions, images to GHCR (§20).

---

## 22. Roadmap

| Phase | Deliverable |
|---|---|
| 1 | Ingestion + reorg-safe assembler + event store backbone (domain event schema locked) |
| 2 | Detection service: DetectorRegistry, feature flags, model registry, sandwich + arb (attribution-blind) |
| 3 | Simulation service: fast/slow path split, confirmed incidents |
| 4 | Intelligence service: label seeding (public sources), basic entity clustering, attribution, risk scores |
| 5 | API service: risk endpoint, audit trail endpoint, WebSocket with provisional/confirmed/retracted |
| 6 | Rule engine: core condition types, webhook delivery, first customer-configurable rule |
| 7 | Remaining detectors with backtesting harness and precision/recall baseline |
| 8 | Builder/relay analysis, entity graph hop queries, reth ExEx path |
| 9 | Billing service (day-one metrics), notification service hardening |
| 10 | Predictive pipeline (mempool), multi-chain (add L2), full K8s deployment |

Phase 5 is the first demonstrable intelligence platform. Phases 1–4 are the unglamorous foundation — doing them right is the senior signal.

---

## 23. Interview ammunition

- *"Core principle?"* → immutable evidence, mutable attribution overlays, recomputable views. Detection never reruns when labels change. Event sourcing makes every state transition auditable.
- *"Why event sourcing?"* → "Why did you alert on this?" is sometimes a legal question. The audit trail must be complete and replayable.
- *"Fast/slow path?"* → heuristic detectors emit provisional alerts in < 1s; revm simulation confirms or retracts asynchronously. Simulation never blocks the alert critical path.
- *"Why microservices?"* → simulation CPU, intelligence reads, and API serving have fundamentally different scaling characteristics. The event bus keeps them loosely coupled. The Cargo workspace keeps code sharing clean.
- *"Why two message brokers — isn't that over-engineering?"* → No, and the reason is the events/commands seam. Kafka carries **domain events** — facts that happened, that multiple services consume, that the event store retains forever, that backtesting replays deterministically. That is a log. The simulation path carries **commands** — "run this revm job," consumed once by one worker. That is a work queue, and it needs four things Kafka does badly: competing-consumer parallelism beyond partition count, per-message ack with redelivery on worker crash (the input is hostile honeypot bytecode, so crashes are expected), dead-letter routing so a poison job doesn't loop forever, and priority so paid tiers jump the backlog. RabbitMQ gives all four natively. I introduce the second broker at exactly one seam and nowhere else — the `SimulationJob` command never enters the event store, because it isn't a fact. If an interviewer prefers one broker, the honest fallback is "consumer-group work queue on Kafka, accept the partition-count parallelism ceiling and hand-roll retry" — I can defend either; what matters is naming what each trades away.
- *"The moat?"* → the intelligence graph. Detection algorithms are public knowledge. Proprietary entity clusters, label provenance, and the data flywheel (clustering generates labels → labels improve clustering) are not.
- *"Rule engine?"* → compliance teams want custom alerting on top of the graph. "Alert me when a wallet receives >$1M then touches a mixer" is a rule, not a detector. Rules are the enterprise pricing tier.
- *"Hub-node graph trap?"* → CEX wallets and bridges connect to millions of addresses; unbounded 3-hop walks collapse into noise. Degree caps and labeled infrastructure endpoints are required.
- *"Rust specifically?"* → embedding revm, zero-copy decoding at chain throughput, bounded-channel backpressure across CPU-heavy stages, the entire Ethereum toolchain (alloy/reth/revm) is Rust-native.
- *"Risk score vs. confidence?"* → score and confidence are independent axes computed in the same pass. Score answers "how risky"; confidence answers "how sure." A single heuristic label can drive a high score with low confidence — surfacing both prevents customers from over-trusting a number that's really a guess, and the per-factor evidence weighting (sim-confirmed > on-chain-verified > heuristic > external feed) makes the aggregate auditable, same as the score itself.
