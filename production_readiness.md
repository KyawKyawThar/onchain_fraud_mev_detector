# Production Readiness — MVP → GA

> **Condensed checklist.** One line per item. The full write-up behind each item is preserved verbatim in [docs/history/production-readiness-log.md](docs/history/production-readiness-log.md).

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

_Full notes: [readiness log](docs/history/production-readiness-log.md#hardening-epic-a--reliability--failure-correctness)_

**Goal:** the system behaves correctly when infrastructure and inputs misbehave, and that's *proven*, not assumed.

- [ ] **Chaos / fault injection harness:** kill workers mid-revm, drop Kafka brokers, partition the network, replay duplicate + out-of-order events, force deep reorgs. Assert projections converge to the correct state.
- [ ] **HA for every stateful component:** Kafka replication factor ≥3, RabbitMQ quorum queues across nodes (§20), ClickHouse replicated, Postgres primary + sync replica with automated failover, Redis HA/sentinel.
- [ ] **Graceful degradation:** if simulation backlogs, provisional alerts still flow (fast path independent of slow path, §6). If intelligence is down, API serves stale-but-flagged cache. *(Screening half done 2026-09-13 — see Epic D's screening SLO item: `/screen` answers from a flagged last-known-good snapshot. `/risk` and `/labels` still fail closed with a 502 when intelligence is down.)*
- [ ] **Resilience primitives everywhere:** timeouts, retries with jitter, circuit breakers (already on the RPC pool §5 — extend to all gRPC/HTTP hops), bounded channels verified to apply backpressure end-to-end (§17).
- [ ] **DLQ operations:** `sim.jobs.dlx` drain + replay runbook; alert on DLQ depth (§7).
- [x] **Consumer-lag & gap detection (lag half, 2026-07-19):** every durable Kafka consumer is built through `event_bus::lag::build_reporting_consumer`, exporting the per-partition `kafka_consumer_lag` gauge; every consume loop parks unprocessable records on its own `mev.dlq.<consumer>` topic (`Handled::Skip` + poison)…

**Exit gate:** chaos suite passes; killing any single node loses no audit history and recovers within RTO.

## Hardening Epic B — Disaster recovery & data integrity

_Full notes: [readiness log](docs/history/production-readiness-log.md#hardening-epic-b--disaster-recovery--data-integrity)_

**Goal:** you can rebuild the entire system from the source of truth, and you've actually done it.

- [x] **Backups + tested restore (2026-09-05):** `docs/runbooks/backup-restore.md`, backed by `crates/backup/` — a snapshot/restore/drill tool for Postgres and ClickHouse (the event store's `events` table included), plus the `backup serve` agent that runs both on a timer.
- [x] **Projection rebuild runbook (2026-09-04):** `docs/runbooks/projection-rebuild.md`, backed by `crates/rebuild/` (the shared procedure) and `simulation::rebuild` (the first implementation).

- [ ] **Multi-AZ deployment**; regional DR plan if SLA requires.

**Exit gate:** a full projection rebuild from the event store reproduces current state exactly; restore drill meets RTO. *(Rebuild half: the procedure exists, is proven on the simulation read model, and runs in CI — see above. Restore half: the drill exists, is proven against real Postgres and ClickHouse in CI, and measures the RTO rather than asserting one. Not met until (a) intelligence's store is wired to the rebuild seam, and (b) both drills have run once against production-scale data with the durations recorded as the RTO inputs — the numbers only mean anything at the volume they will be run at.)*

## Hardening Epic C — Security & multi-tenancy

_Full notes: [readiness log](docs/history/production-readiness-log.md#hardening-epic-c--security--multi-tenancy)_

**Goal:** adversarial inputs and untrusted tenants can't escalate, leak, or DoS.

- [ ] **Sandbox escape testing** on revm with crafted hostile bytecode (the threat model, §7); resource limits enforced (CPU/mem/time per job).
- [ ] **Secrets via Vault** (§20) — none in images, env, or git; rotation policy.
- [ ] **mTLS between services**; authN/Z on every public endpoint; rate limiting + input validation + payload caps on the public API (DoS protection).
- [ ] **Multi-tenant isolation proof:** rule engine "no cross-customer data leakage" (§9) must be *tested*, not asserted — a tenant's rule cannot read another's data or events.
- ~~**Tier/quota enforcement:** free/pro/enterprise gates (§13) enforced server-side, not just billed after the fact.~~ **WITHDRAWN (product decision 2026-07-17; struck from this ledger 2026-09-07) — not deferred, not open: there are no tiers.** Every feature goes to every user, there is no~~…
- [ ] **Supply chain:** `cargo audit`/`cargo deny` in CI, SBOM, pinned deps (§21).
- [ ] **Access auditing:** log who queried the audit log (the audit trail itself needs an audit trail for compliance).
- [ ] **Third-party security review / pen test** before GA.

**Exit gate:** pen test findings remediated; tenant-isolation test suite green; revm sandbox survives the hostile-bytecode corpus.

## Hardening Epic D — Scale, performance & SLOs

_Full notes: [readiness log](docs/history/production-readiness-log.md#hardening-epic-d--scale-performance--slos)_

**Goal:** the latency budgets in the doc hold *under production load*, with headroom.

- [ ] **Define SLOs** (the doc names the panels, §19 — turn them into targets): end-to-end alert latency (block → notification), fast-path < 1s (§6) at p99 under load, API p50/p99, simulation confirmation rate, uptime.
- [x] **Screening API critical-path SLO** (2026-09-13): the synchronous `/screen` decision (§11) sits inline on customer withdrawals — a hard **p50 < 100ms** / bounded p99 budget *under load*, dedicated rate limits + payload caps, and **graceful degradation** (serve a stale-but-flagged cached score…
- [x] **Load testing** at target throughput (2026-09-07): chain tps, peak alert volume, API qps — and, first, **an instrument capable of failing.** The < 1s claim had no series behind it: the only latency detection exported was `detector_detect_duration_seconds`, one `detect` call…
- [x] **Autoscaling:** simulation worker pool on `sim.jobs` queue depth (the designed backpressure signal, §7, §20); HPA on detection/api by CPU/qps.
- [ ] **Intelligence write-path sharding** by address range (§20); read-path gRPC scaling; cache hit-rate targets + stampede protection on the Redis hot path (§8).
- [x] **Capacity plan** (2026-09-15): partition counts, shard counts, storage growth for the append-only event store (it grows forever — model the cost). `crates/capacity` gates every ClickHouse table and the Kafka topology at 1.5× in CI. It found the daily events key refusing inserts on day 1258, and a hardening pass fixed the write path under it: idempotent batched ingest (dedup token + `ReplacingMergeTree` + deduped reads), no dropped evidence, a resumable repartition Job instead of a boot-time copy, registered Kafka partition slots, slim embedding refreshes, and storage tiering. Surfaced: eleven ClickHouse tables with no TTL, five of which pass the restore limit around year 8.3…

**Exit gate:** SLOs met at 1.5× projected peak load in staging; autoscaling demonstrated; load test is a recurring CI/nightly job.

## Hardening Epic E — Model governance & data quality

_Full notes: [readiness log](docs/history/production-readiness-log.md#hardening-epic-e--model-governance--data-quality)_

**Goal:** detections and scores are accurate, regression-gated, and defensible.

- [x] **Backtest harness as a CI gate** (§18): wired in `.github/workflows/pr.yml` (*Backtest P/R gate*). A PR fails if any detector drops below `crates/backtest/baseline.json`, or if an `Active` detector sits below the `crates/backtest/promotion_gate.json` floor. Baselines move only via `just backtest-update-baseline`, as a reviewed diff.
- [ ] **Gate keyed on the full `(id, version, config_hash)` triple** (§18): today `baseline.json` and `model_performance.json` key on detector **id alone**, so a config change that moves precision is not distinguishable from a regression of the same detector.
- [ ] **Fixture set adequate to support an FP-rate claim** (§18): the gate currently replays 8 curated fixtures (7 scenarios + 1 clean block) at precision 1.0. That is a regression signal, not a field measurement — a single negative block cannot resolve the < 4% FP target. Needs adversarial negatives and replayed mainnet windows before the README's target can be stated as a result.
- [ ] **Shadow / A-B detector deploys** (§6 model registry already supports this) + one-click rollback via `deprecated_at`.
- [ ] **False-positive feedback loop** wired to the FP-rate panel (§19); track it as an SLO.
- [ ] **Sanctions freshness SLA:** OFAC/EU lists ingested within a bounded window; `SanctionHit` is a hard alert (§8.5) — staleness is a compliance failure.
- [ ] **Risk-score explainability audited:** every `delta` carries an `evidence_ref` (§8.3); "taint-by-association" documented as reduced-confidence, legally-contested (§8.3).
- [ ] **ML model provenance (§20):** every deployed model artifact is hash-pinned in the registry (`artifact_hash`, `feature_version`); serving/training feature-version skew is a boot failure, not a silent accuracy decay; retraining walks the same Shadow → backtest → Live gate as any detector change — no weight hot-swap path exists.
- [x] **Drift monitoring as an SLO (§20.5, 2026-08-27; hardened 2026-08-28):** `inference::DriftEngine` — a second decorator over the serving seam, wrapping `ObservedEngine` so the inference-latency histogram the < 1s budget is checked against stays free of bookkeeping — folds every served `FeatureVector` into a window and measures it…
- [x] **LLM output governance (§20.4, Sprint 20 t1/t3/t4/t5, 2026-08-29 → 2026-08-31):** every clause of this item is now a mechanism with a test, not a practice.
- [x] **LLM cost containment (Sprint 20 t1/t3/t5, 2026-08-29 → 2026-08-31):** **One metering path, eight SKUs.** `llm::MeteredClient` is the single call site for both the token metrics and `UsageFact::record`, published inline through the `event-bus` seam — arch-conformance *requires* that edge precisely so no LLM-specific second…

**Exit gate:** no detector ships without a passing backtest; FP rate within SLO; sanctions freshness monitored; no ML artifact deployed outside the registry; grounding audit green.

## Hardening Epic F — Release engineering & operations

_Full notes: [readiness log](docs/history/production-readiness-log.md#hardening-epic-f--release-engineering--operations)_

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

_Full notes: [readiness log](docs/history/production-readiness-log.md#hardening-epic-g--compliance--legal-this-product-specifically)_

**Goal:** survive the questions a regulated customer's legal team will ask.

- [ ] **Audit-trail completeness guarantee** documented and tested — the §4 "complete, reproducible answer to *why did you alert?*" must be literally true.
- [ ] **Data retention vs. erasure tension:** an immutable, append-forever event store (§4) collides with right-to-erasure regimes (GDPR). Decide and document: is an on-chain address personal data in your jurisdictions? Crypto-shredding / pseudonymization strategy for any PII that does enter (customer accounts, webhook URLs, emails in §12/§13). **This is a genuine, easy-to-miss production blocker — resolve before selling to EU customers.**
- [ ] **Label dispute / correction workflow:** someone *will* contest a `KnownScammer` label. Conflicting labels are already retained (§8.1); add a documented dispute and override process.
- [ ] **Alert liability:** terms of service framing provisional alerts (§6) so a wrong/retracted alert isn't actionable against you.
- [ ] **Screening-decision liability & governance:** a `block` from the Screening API (§11) is a *blocking action* — a denied withdrawal — not a passive alert, so it is the highest-liability surface in the product.
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
