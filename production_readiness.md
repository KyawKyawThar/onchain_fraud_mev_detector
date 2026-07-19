# Production Readiness — MVP → GA

**Companion to** [ARCHITECTURE.md](ARCHITECTURE.md). The MVP build-out delivers a *demonstrable* platform. This document defines what separates that from a **production-grade, sellable, legally-defensible** platform — and the path to get there.

**Production bar (assumed):** a commercial compliance/risk-intelligence SaaS with paying enterprise customers, where alerts and risk scores carry legal/financial weight, inputs are adversarial, and the audit trail is evidence. If the real bar is lower (internal tool, single trusted user), drop the compliance and multi-tenant epics.

---

## The core reframe

> Production-grade is **not a later phase**. For this system, certain properties must be built into every MVP increment; others are a distinct hardening effort that can only happen once the system exists end-to-end.

### Bucket 1 — Shift-left (build into the MVP increments; do NOT defer)

These are correctness properties of the data path. Retrofitting them = rewriting the path. Each is tagged with where it belongs in the build-out.

| Non-negotiable | Why it can't wait | Built with |
|---|---|---|
| **Idempotent consumers** — dedup replayed/duplicate events by key | At-least-once delivery is the baseline; a non-idempotent projection is corrupt the first time Kafka redelivers | every consumer, as it's built |
| **Reorg rollback** in any service holding derived state (§15) | A `BlockReverted` handler bolted on later means auditing state you can't trust | the same increment that adds the state |
| **revm sandbox + gas/step caps** (§7 hardening) | Honeypot bytecode is hostile input by design — an unsandboxed worker is an RCE, not a bug | the simulation service |
| **Audit completeness** — every state change is an event in the store (§2, §4) | The legal claim ("complete, replayable trail") is void if any path mutates state without emitting | every event-producing service |
| **Commands stay off the event store** (§2) | The audit log must record facts, not attempts; fixing this later means rewriting history | the simulation dispatcher |
| **`provisional` flag until finality** (§15) | Customers must distinguish unconfirmed from confirmed from day one (§11 WS contract) | every alert-producing service |
| **Deterministic replay** — replay a window → identical events (§18) | This *is* the backtest/audit guarantee; non-determinism discovered late is unfixable cheaply | the whole MVP path |
| **AuthN/Z on every endpoint**, event-store append internal-only (§4) | "Add auth later" always leaks; the append API is the integrity boundary | each public/ingest surface |

If these aren't true at the end of each increment, that increment isn't done. **This is the single most important change vs. an MVP mindset.**

### Bucket 2 — Hardening epics (gate to GA; can't be done until the system exists)

Run these *after* the MVP path is green, sequenced by the exit gates below — not by calendar.

---

## Hardening Epic A — Reliability & failure correctness

**Goal:** the system behaves correctly when infrastructure and inputs misbehave, and that's *proven*, not assumed.

- [ ] **Chaos / fault injection harness:** kill workers mid-revm, drop Kafka brokers, partition the network, replay duplicate + out-of-order events, force deep reorgs. Assert projections converge to the correct state.
- [ ] **HA for every stateful component:** Kafka replication factor ≥3, RabbitMQ quorum queues across nodes (§20), ClickHouse replicated, Postgres primary + sync replica with automated failover, Redis HA/sentinel.
- [ ] **Graceful degradation:** if simulation backlogs, provisional alerts still flow (fast path independent of slow path, §6). If intelligence is down, API serves stale-but-flagged cache.
- [ ] **Resilience primitives everywhere:** timeouts, retries with jitter, circuit breakers (already on the RPC pool §5 — extend to all gRPC/HTTP hops), bounded channels verified to apply backpressure end-to-end (§17).
- [ ] **DLQ operations:** `sim.jobs.dlx` drain + replay runbook; alert on DLQ depth (§7).
- [x] **Consumer-lag & gap detection (lag half, 2026-07-19):** every durable Kafka consumer is built through `event_bus::lag::build_reporting_consumer`, exporting the per-partition `kafka_consumer_lag` gauge; every consume loop parks unprocessable records on its own `mev.dlq.<consumer>` topic (`Handled::Skip` + poison), and every binary serves `/livez` + `/readyz` (`telemetry::health`, `HEALTH_ADDR`). The `RuleCreated` dual-write went through a transactional outbox (`rule_outbox` + `rule_engine::outbox`). The dashboards/alerts on this signal (`kafka_consumer_lag` panel + `KafkaConsumerLagHigh` alert) shipped in Sprint 13 t4, 2026-07-19. Still open: event-store sequence-gap detection — a distinct correctness feature, not an observability wire-up.

**Exit gate:** chaos suite passes; killing any single node loses no audit history and recovers within RTO.

## Hardening Epic B — Disaster recovery & data integrity

**Goal:** you can rebuild the entire system from the source of truth, and you've actually done it.

- [ ] **Backups + tested restore** for event store, Postgres, ClickHouse. Define and measure **RPO/RTO**.
- [ ] **Projection rebuild runbook:** wipe a read model (incidents, scores, dashboards), replay from the event store, confirm byte-identical result (§2 — projections are derived; prove it).
- [ ] **Event schema evolution strategy:** schema registry + compatibility rules (backward/forward), so producers and consumers can deploy independently without breaking replay of historical events. *This is the highest-ripple risk in the whole system.*
- [ ] **Multi-AZ deployment**; regional DR plan if SLA requires.

**Exit gate:** a full projection rebuild from the event store reproduces current state exactly; restore drill meets RTO.

## Hardening Epic C — Security & multi-tenancy

**Goal:** adversarial inputs and untrusted tenants can't escalate, leak, or DoS.

- [ ] **Sandbox escape testing** on revm with crafted hostile bytecode (the threat model, §7); resource limits enforced (CPU/mem/time per job).
- [ ] **Secrets via Vault** (§20) — none in images, env, or git; rotation policy.
- [ ] **mTLS between services**; authN/Z on every public endpoint; rate limiting + input validation + payload caps on the public API (DoS protection).
- [ ] **Multi-tenant isolation proof:** rule engine "no cross-customer data leakage" (§9) must be *tested*, not asserted — a tenant's rule cannot read another's data or events.
- [ ] **Tier/quota enforcement:** free/pro/enterprise gates (§13) enforced server-side, not just billed after the fact.
- [ ] **Supply chain:** `cargo audit`/`cargo deny` in CI, SBOM, pinned deps (§21).
- [ ] **Access auditing:** log who queried the audit log (the audit trail itself needs an audit trail for compliance).
- [ ] **Third-party security review / pen test** before GA.

**Exit gate:** pen test findings remediated; tenant-isolation test suite green; revm sandbox survives the hostile-bytecode corpus.

## Hardening Epic D — Scale, performance & SLOs

**Goal:** the latency budgets in the doc hold *under production load*, with headroom.

- [ ] **Define SLOs** (the doc names the panels, §19 — turn them into targets): end-to-end alert latency (block → notification), fast-path < 1s (§6) at p99 under load, API p50/p99, simulation confirmation rate, uptime. Every named panel now has a metric and a dashboard (Sprint 13 t4), and `deploy/prometheus-rules.yml` wires a first pass of alert thresholds — but they're explicitly provisional (seeded from the one hard number the source doc states, §6's <1s p99; everything else is a conservative placeholder with no production traffic to calibrate against). This item stays open until those are validated/tuned against real load, not just wired.
- [ ] **Screening API critical-path SLO:** the synchronous `/screen` decision (§11) sits inline on customer withdrawals — a hard **p50 < 100ms** / bounded p99 budget *under load*, dedicated rate limits + payload caps, and **graceful degradation** (serve a stale-but-flagged cached score rather than block the customer's path if intelligence is slow). It is the one API surface where latency is contractual, not aesthetic.
- [ ] **Load testing** at target throughput: chain tps, peak alert volume, API qps. Verify the < 1s fast path holds under load, not just in isolation.
- [ ] **Autoscaling:** simulation worker pool on `sim.jobs` queue depth (the designed backpressure signal, §7, §20); HPA on detection/api by CPU/qps.
- [ ] **Intelligence write-path sharding** by address range (§20); read-path gRPC scaling; cache hit-rate targets + stampede protection on the Redis hot path (§8).
- [ ] **Capacity plan:** partition counts, shard counts, storage growth for the append-only event store (it grows forever — model the cost).

**Exit gate:** SLOs met at 1.5× projected peak load in staging; autoscaling demonstrated; load test is a recurring CI/nightly job.

## Hardening Epic E — Model governance & data quality

**Goal:** detections and scores are accurate, regression-gated, and defensible.

- [ ] **Backtest harness as a CI gate** (§18): detector changes blocked unless precision/recall ≥ baseline for the `(id, version, config_hash)` triple.
- [ ] **Shadow / A-B detector deploys** (§6 model registry already supports this) + one-click rollback via `deprecated_at`.
- [ ] **False-positive feedback loop** wired to the FP-rate panel (§19); track it as an SLO.
- [ ] **Sanctions freshness SLA:** OFAC/EU lists ingested within a bounded window; `SanctionHit` is a hard alert (§8.5) — staleness is a compliance failure.
- [ ] **Risk-score explainability audited:** every `delta` carries an `evidence_ref` (§8.3); "taint-by-association" documented as reduced-confidence, legally-contested (§8.3).

**Exit gate:** no detector ships without a passing backtest; FP rate within SLO; sanctions freshness monitored.

## Hardening Epic F — Release engineering & operations

**Goal:** deploy any service independently, with zero downtime and automated rollback.

- [ ] **Full K8s** (production needs it before GA, not after): per-service containers, DNS service discovery (§20).
- [ ] **Infrastructure as code:** Terraform + Helm; reproducible environments.
- [ ] **Progressive delivery:** canary or blue/green per service, automated rollback on SLO breach.
- [ ] **Zero-downtime schema migrations** for Postgres/ClickHouse (expand-contract), compatible with rolling deploys.
- [ ] **Staging environment** mirroring prod, fed by replayed real traffic from the event store (§18).
- [ ] **On-call + runbooks** for each failure mode: reorg storm, DLQ fills, RPC pool degraded, simulation backlog, Kafka lag, score-recompute storm.
- [ ] **Synthetic canaries:** a known historical block replayed continuously, asserting the expected incident still fires (catches silent regressions).

**Exit gate:** a service deploys to prod via canary with automated rollback, zero downtime, while traffic flows.

## Hardening Epic G — Compliance & legal (this product specifically)

**Goal:** survive the questions a regulated customer's legal team will ask.

- [ ] **Audit-trail completeness guarantee** documented and tested — the §4 "complete, reproducible answer to *why did you alert?*" must be literally true.
- [ ] **Data retention vs. erasure tension:** an immutable, append-forever event store (§4) collides with right-to-erasure regimes (GDPR). Decide and document: is an on-chain address personal data in your jurisdictions? Crypto-shredding / pseudonymization strategy for any PII that does enter (customer accounts, webhook URLs, emails in §12/§13). **This is a genuine, easy-to-miss production blocker — resolve before selling to EU customers.**
- [ ] **Label dispute / correction workflow:** someone *will* contest a `KnownScammer` label. Conflicting labels are already retained (§8.1); add a documented dispute and override process.
- [ ] **Alert liability:** terms of service framing provisional alerts (§6) so a wrong/retracted alert isn't actionable against you.
- [ ] **Screening-decision liability & governance:** a `block` from the Screening API (§11) is a *blocking action* — a denied withdrawal — not a passive alert, so it is the highest-liability surface in the product. The decision policy must be **versioned** (record which policy + version produced each block, for dispute), every `block`/`review` must carry its `evidence_ref` factor breakdown (explainable, §8.3), there must be a documented **override / appeal path** for a contested block, and ToS must frame the decision as advisory input to the customer's own action — not our determination. Screening decisions are themselves logged to the access-audit trail.
- [ ] **Billing-meter accuracy:** you charge on `UsageRecorded` (§13) — metering must be exact and reconcilable; under/over-billing is a trust and legal issue.
- [ ] **SOC 2 readiness** if selling to enterprise (follows naturally from Epics B, C, F).

**Exit gate:** retention/erasure policy signed off by legal; audit completeness test green; metering reconciliation proven.

---

## Sequencing: how this fits the build-out

```
MVP path        ── with Bucket-1 non-negotiables baked into every increment
   │               (this is the only change to the MVP plan itself)
   ▼  MVP path green end-to-end
Feature backlog ── continue baking Bucket-1 in
   │               NOTE: pull "full K8s" (Epic F) earlier; production needs it before GA
   ▼
Hardening epics A–G  ── gated by exit criteria, not dates; some run in parallel
   │                    with the feature backlog once the path is stable
   ▼
══════════════  GO-LIVE READINESS GATE  ══════════════
```

Recommended order if strictly serial (solo): **A → B → C → F → D → E → G**. Reliability and DR first (you can't harden what falls over), security and deploy next (the boundary and the pipeline), then scale and model governance, compliance last but *started* early (Epic G's retention decision gates EU launch and influences storage design — decide it before scale).

---

## Go-live readiness gate (sign off before real customers)

A single checklist; GA only when all are true.

- [ ] All Bucket-1 non-negotiables verified across the live path.
- [ ] Chaos suite green; single-node loss recovers within RTO with zero audit loss (Epic A, B).
- [ ] Full projection rebuild from event store reproduces state exactly (Epic B).
- [ ] Pen test remediated; tenant isolation + revm sandbox proven (Epic C).
- [ ] SLOs met at 1.5× peak load; autoscaling demonstrated (Epic D).
- [ ] Backtest gate enforced; sanctions freshness + FP rate within SLO (Epic E).
- [ ] Zero-downtime canary deploy with auto-rollback demonstrated; runbooks + on-call live (Epic F).
- [ ] Retention/erasure policy signed off; audit completeness + billing reconciliation proven (Epic G).
- [ ] SLO dashboards + alerting live; every named failure mode has a runbook (§19). Dashboards + alerting shipped in Sprint 13 t4 (compose and K8s, thresholds provisional — see Epic D above); the runbook half is still open.
