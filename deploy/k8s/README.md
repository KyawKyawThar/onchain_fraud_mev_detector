# Kubernetes deployment (§20)

The full platform on K8s: the five infra services the compose stack ran
(Kafka, RabbitMQ, ClickHouse, Postgres, Redis) as StatefulSets, and every
service binary as its own independently-scaled workload. `docker-compose`
remains the laptop dev loop; this tree is the deployment.

```
base/                 # topology — no credentials, no environment specifics
  infra/              # 5 StatefulSets + headless Services
  services/           # 16 workloads (Deployments, Services, HPAs, PDBs)
overlays/dev/         # kind/laptop: generated dev secrets, :dev images, debug logs
overlays/prod/        # pinned images, HPA floors raised, secrets EXPECTED (see below)
```

## Quick start (kind)

```sh
kind create cluster
just k8s-build-images        # build all service images (:dev) + kind load
# edit overlays/dev/secrets/rpc.env → real RPC endpoints
just k8s-apply               # kubectl apply -k deploy/k8s/overlays/dev
just k8s-status
```

Postgres schema migrations are **not** applied by any pod — run them the same
way CI does (`migrate.yml` / `sqlx migrate run`, e.g. via
`kubectl -n mev port-forward svc/postgres 5432 & just migrate-up`).
ClickHouse migrations need no step: each ClickHouse consumer (event-store,
usage, intelligence, simulation-projection) applies its own at boot via
`ch-migrate`, and event-store provisions the Kafka topic topology at boot.
Boot order therefore doesn't need init-containers: a service that comes up
before its stores simply fails fast, restarts with backoff, and stays out of
rotation until `/readyz` flips.

## Health & readiness

Every binary serves `GET /livez` + `GET /readyz` on `HEALTH_ADDR`
(`telemetry::health`), set once in `app-config` to `0.0.0.0:8086`. All pods
share the same probe shape: startup probe on `/livez` (150 s boot budget —
migrations happen inside it), readiness on `/readyz` (flips 503 on drain, so
a terminating pod leaves rotation before it dies), liveness on `/livez`.
Kafka's probes run a real metadata query, not a port check — a broker JVM can
die while the container stays `Running` (the compose-era `AllBrokersDown`
lesson).

## Per-service scaling (the §20 table, made concrete)

| Workload | Replicas | Why |
|---|---|---|
| ingestion-eth / -base | 1 per chain, `Recreate` | the RPC failover pool is *in-process*; two pollers double-publish heads |
| detection-eth / -base | 1 per chain, `Recreate` | chain is the Kafka partition key → one partition per chain; scale **up** (CPU/rayon), out by adding chains |
| predictive | 1, `Recreate` | owns the mempool filter + in-process dedup ring |
| event-store | 1 → partitions | consumer group; event-id-keyed inserts make overlap safe |
| simulation-dispatcher | 1 | thin Kafka→RabbitMQ bridge |
| **simulation-worker** | **HPA 2–8 (prod 4–16) on CPU** | revm is the bottleneck; competing consumers scale linearly (§20 "scale aggressively") |
| simulation-projection | 1 | read-model projector + internal `GET /v1/incidents` |
| intelligence-attribute | 1, `Recreate` | MergeActor is single-writer and does not coordinate across processes |
| **intelligence-grpc** | **HPA 2–6 on CPU** | stateless read path over Redis cache-aside (§20 "scale read path") |
| intelligence-block-production | 1, `Recreate` | per-instance pending-writes flush queue; PBS/Ethereum-gated |
| rule-engine | 1, `Recreate` | TemporalPool is single-writer-per-address per instance |
| **api-server** | **HPA 2–6 (prod 3–10) on CPU** | stateless behind the Service; WS consumer group is **per-pod** (pod-name suffix) so every replica sees every alert |
| notification | 1 → partitions | Postgres dedup ledger absorbs redelivery, overlap-safe |
| usage | 1 → partitions | customer-keyed partitioning; batched, dedup-on-read sink |

HPAs need metrics-server (kind: `helm install metrics-server ...` or the
components.yaml with `--kubelet-insecure-tls`); without it they just stay at
minReplicas.

## Secrets

Six Secrets, referenced by fixed name from the base, **never committed with
real values**:

| Secret | Keys | Consumers |
|---|---|---|
| `postgres-credentials` | `POSTGRES_DB/USER/PASSWORD` (image), `DATABASE_URL` (apps) | postgres, projection, intelligence×3, rule-engine, api-server, notification |
| `redis-credentials` | `REDIS_PASSWORD` (image), `REDIS_URL` (apps) | redis, intelligence×3, rule-engine |
| `clickhouse-credentials` | `CLICKHOUSE_DB/USER/PASSWORD` | clickhouse, event-store, projection, intelligence×3, usage |
| `rabbitmq-credentials` | `RABBITMQ_DEFAULT_USER/PASS/VHOST` (image), `RABBITMQ_URL` (apps — vhost `/` percent-encoded `%2f`!) | rabbitmq, dispatcher, worker |
| `app-secrets` | `JWT_SECRET`, `EVENT_STORE_WRITE_TOKEN`, `SMTP_USERNAME/PASSWORD` | api-server, event-store, notification |
| `rpc-endpoints` | `ETH_RPC_URLS`, `BASE_RPC_URLS`, `MEMPOOL_RPC_URL`, `INTEL_ETH_RPC_URL` | ingestion×2, predictive, intelligence-block-production |

- **dev**: `overlays/dev` generates them from `secrets/*.env` (committed
  `changeme_*` values — the `.env.example` posture). The generator hash-suffixes
  names, so editing a secret rolls its consumers.
- **prod**: `overlays/prod` generates nothing. Provision the six names via
  External Secrets Operator / Vault agent / secrets-store CSI (§20: Vault or
  cloud secrets manager). Each pod gets only the secret keys it consumes —
  the worker never sees Postgres, ingestion never sees JWT.

## Images

CI (`ci.yml` docker matrix) publishes one image per binary to
`ghcr.io/kyawkyawthar/onchain_fraud_mev_detector/<bin>` on merge to `main`,
tagged by branch, semver, and `sha-<commit>`; prod pins tags in its
`images:` block. The detection image is built with
`FEATURES=detection/detectors` — without it the binary links **zero**
detectors and boots happily doing nothing.

Not deployed here: `backtest` (a dev/CI tool, not a service) and
`ingestion-exex-node` (embeds reth — its own node deployment with its own
lockfile, out of workspace).

## What deliberately stayed behind

- Prometheus/Grafana: the in-cluster observability rollout is Sprint 13 t4;
  pods already carry `prometheus.io/scrape` annotations and standardized
  `:9100` metrics ports for it.
- Kafka is a single-node KRaft StatefulSet (official `apache/kafka` image —
  the compose stack's wurstmeister+ZooKeeper pair was a dev-era relic).
  Replication factor rides `app-config`; growing to a quorum is a
  StatefulSet + voters change behind the same `kafka` Service name.
- ClickHouse is single-node; §20's replicated cluster is a later storage
  epic behind the same Service name.
