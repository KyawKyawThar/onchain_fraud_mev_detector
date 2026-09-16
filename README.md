# MEVWatch

**MEV and fraud detection for EVM chains, built in Rust.**

[![CI](https://github.com/KyawKyawThar/onchain_fraud_mev_detector/actions/workflows/ci.yml/badge.svg)](https://github.com/KyawKyawThar/onchain_fraud_mev_detector/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/Rust-stable-orange?logo=rust&logoColor=white)
![License](https://img.shields.io/badge/license-proprietary-red)

MEVWatch follows Ethereum and Base block by block. It flags MEV and fraud patterns (sandwich, arbitrage, flash-loan exploit, rug pull, wash trading, address poisoning, liquidation) and replays each one in `revm` before an incident is raised. Findings feed an entity graph, explainable risk scores, a customer rule engine, and a synchronous screening API.

## What is proven, and what is not

| | |
|---|---|
| **Measured** | The fast path (block → preliminary alert) held its < 1s p99 budget at 4 blocks/s: 250ms with the API idle, and 1.000s, on the boundary, with API load on the same laptop. That is a floor, not a capacity figure ([load test](docs/runbooks/load-test.md)). On kind, the simulation workers autoscaled on queue depth: 2 → 5 replicas in 37s and back to 2 in exact 60s steps. |
| **Enforced in CI** | A detector precision/recall gate over known incidents and near misses, a README that cannot state the false-positive target as a result, alert rules that cannot fire, dependency seams, and pods that cannot start under `runAsNonRoot` all fail the build. |
| **Not yet shown** | End to end on real mainnet transactions: the live source is header-only, and simulation's fork-from-chain is stubbed. A false-positive rate: the < 4% of simulation-refuted alerts is a target, not a result. The corpus is 8 hand-built scenarios plus 22 adversarial near misses (all quiet), and it has 0 of the 3+ replayed mainnet windows and 65+ adjudicated alerts the backtest requires before stating it. No production traffic. |

## Architecture

```
ingestion ──► Kafka (domain events: ordered, replayable, the audit log) ──► event-store
                 │
      detection (fast path) ──► RabbitMQ sim.jobs (commands) ──► simulation workers (revm)
                 │
      intelligence (entity graph · risk) ──► rule-engine · notification · API (REST · WS · screening)
```

Events are facts on Kafka; simulation jobs are commands on a bounded work queue. [Design decisions](docs/design-decisions.md) explains why, and everything else below.

## Engineering highlights

- **An alert that could not fire.** The headline latency alert watched a series a backlog could never move. Rules are now a CI gate. [→](docs/design-decisions.md#rules-in-ci-not-in-a-wiki)
- **A retry that skipped its record.** The shared Kafka loop's `Retry` moved on to the next record. It now seeks back, proven against a real broker. [→](docs/design-decisions.md#delivery-correctness)
- **A deploy where no pod could start.** A named Docker `USER` under `runAsNonRoot`, found by running the tree on kind, and now a test. [→](docs/design-decisions.md#scaling-by-structure)
- **A load test designed to be able to fail.** No coordinated omission, it drains before measuring, and it returns a three-way verdict. [→](docs/design-decisions.md#measurement)

## Quick start

Needs Rust (stable) and [`just`](https://github.com/casey/just). No database or Docker: SQL is checked against a committed offline cache.

```bash
just check              # fmt · clippy -D warnings · tests · release build · backtest gate (what CI runs)
cargo run -p backtest   # replay ground-truth incidents through every detector, print precision/recall
```

## Docs

[Design decisions](docs/design-decisions.md) · [Architecture](ARCHITECTURE.md) · [Engineering conventions](docs/engineering-conventions.md) · [Production readiness](production_readiness.md) · [Sprint plan](sprint_plan.md) · [Kubernetes](deploy/k8s/README.md) · [Runbooks](docs/runbooks/)

---

Built by **Kyaw Kyaw Thar**, senior backend engineer (distributed systems, Go + Rust) · [LinkedIn](https://www.linkedin.com/in/kyawkyaw-thar-210602185/) · [Email](mailto:kyawkyaw.thar84@gmail.com)
