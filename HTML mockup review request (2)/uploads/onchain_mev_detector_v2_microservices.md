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
- **Async (default):** domain events over Kafka, keyed by chain or address.
- **Sync (exceptions only):** gRPC for request/response where latency matters — API service querying intelligence service for a risk score, for example.
- Services own their data stores. No cross-service database joins. No shared tables.

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
simulation-service
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
Score: 87 / 100   (model v1.4.2)

+35  2 confirmed sandwich attacks (profit: $18,400)
+20  1 flash-loan exploit (victim loss: $240,000)
+15  entity member: Entity #183 (known MEV cluster)
+10  funded by mixer-adjacent address (confidence: 0.6)
+7   co-deployed with known scammer
```

Score design rules: **explainable** (every delta has an evidence reference), **versioned** (model version is part of output), **time-decayed** (old incidents contribute less), **taint-by-association nuanced** (mixer proximity is a signal at reduced confidence, not deterministic — legally contested and documented as such).

Scores are cache entries keyed by `(address, model_version)`, invalidated when any input changes, recomputed by the intelligence service.

### 8.4 Reputation

Track behavioral history over time: total MEV extracted by month, attack frequency, victim count, dormancy periods. Exposed as time-series on the entity profile API endpoint.

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

- `GET /v1/address/{addr}/risk` — score + full factor breakdown + model version.
- `GET /v1/address/{addr}/labels` — all labels with provenance and confidence.
- `GET /v1/entity/{id}` — all addresses, all incidents, reputation history.
- `GET /v1/entity/{id}/graph?hops=3` — connected addresses (degree-capped).
- `GET /v1/incidents?chain=&kind=&severity=&since=` — paginated incident feed.
- `GET /v1/audit/incident/{id}` — complete event stream for an incident (from event store).
- `GET /v1/builders` — builder leaderboard by MEV type.
- `POST /v1/rules` — create a custom rule (triggers rule engine service).
- `WS  /v1/stream` — live incident stream (provisional + confirmed + retracted + score updates).

### WebSocket contract

Clients must handle three lifecycle transitions:
1. `provisional_alert` — fast path, unconfirmed.
2. `alert_confirmed` (with simulation data) — upgrades the provisional.
3. `alert_retracted` — provisional was wrong; remove from UI.

This is documented in the API contract and tested explicitly.

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
- **simulation:** async job queue over Kafka; simulation workers on rayon. Queue depth = backpressure signal.
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
```

Kafka partitioned by chain; topics for each domain event type. Service discovery via DNS in Kubernetes. Secrets via Vault or cloud secrets manager. CI: per-service builds, clippy + fmt + test + bench-smoke gates.

---

## 21. Tech stack

`tokio`, `alloy` (providers/types/ABI, `sol!`), `reth` (ExEx), `revm`, `rayon`, `bytes`, `petgraph`, `sqlx` (Postgres), ClickHouse Rust client, `rdkafka` (Kafka), `tonic` (gRPC), `axum` (REST), `tracing` + `tracing-subscriber`, `metrics` + Prometheus exporter, `thiserror`/`anyhow`, `clap`, `criterion`, `proptest`. *(Pin current versions.)*

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
- *"The moat?"* → the intelligence graph. Detection algorithms are public knowledge. Proprietary entity clusters, label provenance, and the data flywheel (clustering generates labels → labels improve clustering) are not.
- *"Rule engine?"* → compliance teams want custom alerting on top of the graph. "Alert me when a wallet receives >$1M then touches a mixer" is a rule, not a detector. Rules are the enterprise pricing tier.
- *"Hub-node graph trap?"* → CEX wallets and bridges connect to millions of addresses; unbounded 3-hop walks collapse into noise. Degree caps and labeled infrastructure endpoints are required.
- *"Rust specifically?"* → embedding revm, zero-copy decoding at chain throughput, bounded-channel backpressure across CPU-heavy stages, the entire Ethereum toolchain (alloy/reth/revm) is Rust-native.
