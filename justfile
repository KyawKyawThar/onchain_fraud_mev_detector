# onchain_fraud_mev_detector (Rust) — developer workflow.
# Run `just` (or `just --list`) to see all recipes.
#
# cargo already does build/test/run; these recipes wrap the surrounding
# workflow (migrations, lint, docker, live-reload).

set dotenv-load := true
set dotenv-required := false

migrations := "crates/db/migrations"
compose    := "docker compose --env-file .env -f deploy/docker-compose.yml"

# sqlx-cli reads DATABASE_URL. Build it from POSTGRES_* (loaded from .env) if unset.
export DATABASE_URL := env_var_or_default("DATABASE_URL",
    "postgresql://" + env_var_or_default("POSTGRES_USER", "detector") + ":" +
    env_var_or_default("POSTGRES_PASSWORD", "detector") + "@localhost:" +
    env_var_or_default("POSTGRES_PORT", "5432") + "/" +
    env_var_or_default("POSTGRES_DB", "detector") + "?sslmode=disable")

# Every `sqlx::query!`/`query_as!` verifies against the committed `.sqlx/`
# cache instead of a live Postgres connection — build/lint/test never need a
# running database, and can't silently break because someone's shell has a
# stale/unreachable DATABASE_URL exported. `cargo sqlx prepare` (the one
# recipe that *must* hit a live database to regenerate the cache) ignores
# this var for its own purpose, so it isn't affected. Override per-invocation
# with `SQLX_OFFLINE=false just <recipe>` if you deliberately want live
# verification.
export SQLX_OFFLINE := env_var_or_default("SQLX_OFFLINE", "true")

# Show available recipes (default).
_default:
    @just --list

# ── Docker Compose ───────────────────────────────────────────────

# Start all containers (detached)
up:
    {{compose}} up -d

# Start dev stack with odoo-dev profile
dev-up:
    {{compose}} --profile odoo-dev up -d

# Stop dev stack (odoo-dev profile)
dev-down:
    {{compose}} --profile odoo-dev down

# Stop and remove all containers
down:
    {{compose}} down

# Stop containers and remove volumes (fresh start)
down-v:
    {{compose}} down -v

# Restart all containers
restart: down up

# Show running containers
ps:
    {{compose}} ps

# Show container logs (last 100 lines)
logs:
    {{compose}} logs --tail=100

# Follow container logs live
logs-f:
    {{compose}} logs -f

# Open psql shell in postgres container
db-shell:
    {{compose}} exec postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"

# Open redis-cli in redis container
redis-shell:
    {{compose}} exec redis redis-cli -a "$REDIS_PASSWORD"

# Open clickhouse-client in the clickhouse container (event store, §4)
ch-shell:
    {{compose}} exec clickhouse clickhouse-client -u "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" -d "$CLICKHOUSE_DB"

# ── Observability (metrics, §19) ─────────────────────────────────
# Prometheus scrapes each service's /metrics; Grafana visualizes it (datasource +
# per-detector dashboard auto-provisioned). Services run on the host, so
# Prometheus reaches them via host.docker.internal (deploy/prometheus.yml). Run a
# service (e.g. `just run-detection`) so there's something to scrape.

# Start Prometheus + Grafana
metrics-up:
    {{compose}} up -d prometheus grafana
    @echo "📊 Prometheus → http://localhost:${PROMETHEUS_PORT:-9090}"
    @echo "📈 Grafana    → http://localhost:${GRAFANA_PORT:-3000}  (login: ${GRAFANA_ADMIN_USER:-admin} / ${GRAFANA_ADMIN_PASSWORD:-admin})"
    @echo "   Dashboard: 'Detection — per-detector metrics (§19)'"

# Stop Prometheus + Grafana (keeps their volumes)
metrics-down:
    {{compose}} stop prometheus grafana

# ── Migrations (sqlx-cli) ────────────────────────────────────────

# Create a new migration: just new-migration add_foo
new-migration name:
    sqlx migrate add --source {{migrations}} {{name}}

# Apply all pending migrations
migrate-up:
    sqlx migrate run --source {{migrations}}

# Revert the last migration
migrate-down:
    sqlx migrate revert --source {{migrations}}

# Show migration status
migrate-info:
    sqlx migrate info --source {{migrations}}

# ── ClickHouse migrations (event store, §4) ──────────────────────
# The event-store binary owns its ClickHouse schema (migrations under
# crates/event-store/migrations, applied automatically on boot). These recipes
# drive them explicitly, mirroring the sqlx ones above. Needs ClickHouse up
# (`just up`) and the CLICKHOUSE_* / EVENT_STORE_* env from .env.

# Apply all pending ClickHouse migrations
ch-migrate-up:
    cargo run -p event-store -- migrate up

# Revert the last ClickHouse migration (destructive — drops the events table)
ch-migrate-down:
    cargo run -p event-store -- migrate down

# Show ClickHouse migration status
ch-migrate-info:
    cargo run -p event-store -- migrate info

# ── ClickHouse migrations (simulation incident analytics, §7/§14) ─
# The simulation-projection binary owns its own ClickHouse schema (migrations under
# crates/simulation/migrations, applied automatically on boot). These recipes drive
# them explicitly, mirroring the event-store ones above.

# Apply all pending simulation-analytics ClickHouse migrations
sim-ch-migrate-up:
    cargo run -p simulation --bin simulation-projection -- migrate up

# Revert the last one (destructive — drops the incident_analytics table)
sim-ch-migrate-down:
    cargo run -p simulation --bin simulation-projection -- migrate down

# Show simulation-analytics ClickHouse migration status
sim-ch-migrate-info:
    cargo run -p simulation --bin simulation-projection -- migrate info

# ── ClickHouse migrations (intelligence adjacency graph, §8/§14) ──
# The intelligence binary owns its own ClickHouse schema (migrations under
# crates/intelligence/migrations). Same pattern as the two blocks above.

# Apply all pending intelligence-adjacency ClickHouse migrations
intel-ch-migrate-up:
    cargo run -p intelligence -- migrate up

# Revert the last one (destructive — drops the address_adjacency table)
intel-ch-migrate-down:
    cargo run -p intelligence -- migrate down

# Show intelligence-adjacency ClickHouse migration status
intel-ch-migrate-info:
    cargo run -p intelligence -- migrate info

# Probe all three intelligence stores (Postgres schema, Redis, ClickHouse)
intel-ping:
    cargo run -p intelligence -- ping

# ── ClickHouse migrations (usage raw events, §13/§14) ────────────
# The usage binary owns its own ClickHouse schema (migrations under
# crates/usage/migrations). Same pattern as the three blocks above.

# Apply all pending usage-events ClickHouse migrations
usage-ch-migrate-up:
    cargo run -p usage -- migrate up

# Revert the last one (destructive — drops the usage_events table)
usage-ch-migrate-down:
    cargo run -p usage -- migrate down

# Show usage-events ClickHouse migration status
usage-ch-migrate-info:
    cargo run -p usage -- migrate info

# Probe the usage service's ClickHouse
usage-ping:
    cargo run -p usage -- ping

# ── ClickHouse migrations (ML training datasets, §20.1/§14) ──────
# The dataset binary owns the ml_dataset_rows / ml_dataset_manifests tables
# (migrations under crates/dataset/migrations). Same pattern as above; an
# export with --clickhouse applies them itself, so these are for inspection
# and for reverting.

# Apply all pending dataset ClickHouse migrations
dataset-ch-migrate-up:
    cargo run -p dataset -- migrate up

# Revert the last one (destructive — drops a dataset table)
dataset-ch-migrate-down:
    cargo run -p dataset -- migrate down

# Show dataset ClickHouse migration status
dataset-ch-migrate-info:
    cargo run -p dataset -- migrate info

# ── ML dataset export (§20.1, Sprint 18 t2) ──────────────────────
# Replay an event-store window, join every DetectorTriggered to the
# SimulationCompleted that confirms or refutes it, and materialise labeled
# (features, label) rows. Reproducible by construction: the same window +
# feature_version + label rule always yields the same content_hash, printed in
# the manifest.
#
# The default is a DRY RUN — it replays, joins, extracts and prints the
# manifest without writing anywhere, which is the cheap way to see what a
# window holds before committing a table to it. Add `--clickhouse` and/or
# `--parquet <path>` to write.
#
#   from/to: RFC 3339, half-open [from, to) so adjacent windows tile.
#   Needs EVENT_STORE_URL (default http://127.0.0.1:8081).
dataset-export from to *args:
    cargo run -p dataset -- export --from {{from}} --to {{to}} {{args}}

# Export the last hour to Parquet + ClickHouse, the shape a training run takes.
# `--min-fidelity full_bundle` is the honest gate: rows built from a partial
# block reconstruction have wrong block-relative features, not missing ones.
dataset-export-hour out="target/dataset.parquet":
    cargo run -p dataset -- export \
        --from "$(date -u -v-1H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)" \
        --to "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --min-fidelity full_bundle \
        --parquet {{out}} \
        --clickhouse

# ── Label seeding from public feeds (§8.1, Sprint 7 t2) ──────────
# Import a downloaded feed file. Feeds are fetched out-of-band so an import is
# a reproducible file, not a moving URL. Re-running the same file is a no-op
# (deterministic seeded label ids); a changed claim lands as a NEW coexisting
# row — conflicting labels are stored, never overwritten.
#
#   feed:   etherscan-tags (CSV address,kind,value)
#           ofac-sdn       (plain text, one address/line; e.g.
#                           https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_ETH.txt)
#           mev-list       (JSON [{"address","name"}])
#           protocol-registry (JSON [{"address","name","kind"?}])
#   detail: optional source_detail naming the specific list/registry.
intel-seed feed file detail="":
    cargo run -p intelligence -- seed {{feed}} {{file}} {{detail}}

# ── Entity clustering (§8.2, Sprint 7 t3) ─────────────────────────
# Cluster the bounded component around one seed address: common funder,
# deployer, profit-receiver and same-code-hash edges only, degree-capped and
# hop-bounded (never bridges through a CEX/bridge hub). Idempotent — safe to
# re-run against an unchanged graph.
intel-cluster chain address:
    cargo run -p intelligence -- cluster {{chain}} {{address}}

# Print one address's current risk score (§8.3, Sprint 8 t1) — read-only.
intel-risk address:
    cargo run -p intelligence -- risk {{address}}

# ── Risk-score cache invalidation (§8.3, Sprint 8 t2) ─────────────
# Long-running consumer: on any label/entity/sanctions/attribution change,
# evicts and recomputes the affected address(es)' `(address, model_version)`
# cache entry and publishes `RiskScoreUpdated`. Its own Kafka consumer group
# (INTELLIGENCE_RISK_KAFKA_GROUP) — deploy/scale independently of the default
# `cargo run -p intelligence` attribution consumer.
intel-score:
    cargo run -p intelligence -- score

# ── Reorg rollback (§15, Sprint 8 t3) ─────────────────────────────
# Long-running consumer: on `IncidentRetracted`, withdraws the incident's
# attributions and reverses any merge it caused, publishing
# `AttributionRetracted`/`EntitySplit` for `intel-score` to recompute off. Its
# own Kafka consumer group (INTELLIGENCE_REORG_KAFKA_GROUP) — deploy/scale
# independently of `attribute`/`score`.
intel-reorg:
    cargo run -p intelligence -- reorg

# ── Block-production pipeline (§10, Sprint 11 t1) ─────────────────
# Long-running consumer: per canonical block, fetches the header + body
# (INTEL_ETH_RPC_URL), asks the configured MEV-Boost relays who delivered it
# (MEV_RELAY_ENDPOINTS), resolves/mints the builder's `BuilderAddress` label,
# and appends `BlockProductionRecord` snapshots to ClickHouse (apply the table
# first: `just intel-ch-migrate-up`). Its own Kafka consumer group
# (INTELLIGENCE_PRODUCTION_KAFKA_GROUP) — deploy/scale independently.
intel-block-production:
    cargo run -p intelligence -- block-production

# ── Behavior embeddings (§20.3, Sprint 19 t1) ─────────────────────
# Long-running job: the per-address behavior vector (activity cadence,
# counterparty-type distribution, value-flow shape, incident history) computed
# from the ClickHouse adjacency graph. Two triggers in one process — a
# scheduled sweep over recently-active addresses, and a `RiskScoreUpdated`-style
# invalidation consumer on label/entity/sanctions/attribution changes — because
# neither alone is enough (cadence drifts with time passing; a sanctions hit
# must not wait out a sweep interval). Appends to `address_embeddings` (apply
# the table first: `just intel-ch-migrate-up`) and publishes
# `AddressEmbeddingUpdated`. Its own Kafka consumer group
# (INTELLIGENCE_EMBEDDING_KAFKA_GROUP) — deploy/scale independently.
intel-embedding:
    cargo run -p intelligence -- embedding

# Print one address's behavior vector and the features that dominate it —
# read-only inspection, nothing stored and nothing published. The embedding
# analogue of `just intel-risk`.
intel-embed address:
    cargo run -p intelligence -- embed {{address}}

# Recompute the §20.3 population baseline (per-feature median + scaled MAD) a
# similarity search standardizes against — without it a raw distance is
# dominated by the log-magnitude family and "behaviorally similar" degrades
# into "similar transaction count". A periodic operator/cron action: the
# population moves on a much slower clock than individual vectors do.
intel-embedding-baseline:
    cargo run -p intelligence -- embedding-baseline

# The §20.3 clustering signal: `AddressEmbeddingUpdated` in, behavioral
# *candidate links* to directly-known actors out. It proposes; it never merges
# (§8.2) — entity membership still comes only from on-chain evidence. Needs a
# population baseline (`just intel-embedding-baseline`) or every subject is
# skipped. Drains any proposal a previous run stored without announcing before
# it takes new work. Its own Kafka consumer group
# (INTELLIGENCE_LINK_SIGNAL_KAFKA_GROUP) — deploy/scale/stop independently of
# the embedding job it reads from, which matters: the search it runs is the
# most expensive read the platform serves.
intel-link-signal:
    cargo run -p intelligence -- link-signal

# List candidate links: for one address, or — with no address — the open triage
# queue, strongest first.
intel-link-candidates address="":
    cargo run -p intelligence -- link-candidates {{address}}

# Record an operator's ruling on one proposal (`confirm` | `reject`). Store-only
# by design: confirming says the evidence for a merge now exists, it does not
# perform one — run `just intel-cluster` once the §8.2 on-chain evidence does.
intel-link-decide id decision operator note="":
    cargo run -p intelligence -- link-decide {{id}} {{decision}} {{operator}} {{note}}

# Regenerate offline query cache (.sqlx) so CI builds without a DB
sqlx-prepare:
    cargo sqlx prepare --workspace -- --all-targets

# ── Dev (live reload) ────────────────────────────────────────────
# cargo-watch = nodemon-style. bacon = .air.toml-style (jobs in bacon.toml).
# Rust recompiles+restarts; there is no true hot reload.

# Run the server with live reload
dev: dev-server

# Run server only with live reload
dev-server:
    cargo watch -x 'run -p server'

# Run the event-store service (§4). ClickHouse migrations apply on boot; needs
# ClickHouse + Kafka up (`just up`).
run-event-store:
    cargo run -p event-store

# Run the ingestion service (§5). Needs RPC_URLS set (comma-separated RPC
# endpoints; legacy ETH_RPC_URLS still works); the source adapter is the
# health-checked, circuit-broken RPC failover pool. Logs each new head
# (block-tree + event emission are Sprint 2 tasks 2–4).
run-ingestion:
    cargo run -p ingestion

# Run a second ingestion instance for Base (§5, Sprint 13 t2 — one instance
# per chain; chain is the partition key on every event). Needs BASE_RPC_URLS
# set to Base RPC endpoints. Finality depth defaults per chain (Base: 1024,
# the OP-stack unsafe-head→L1-finality lag at 2 s blocks); override with
# FINALIZATION_DEPTH. The metrics port moves off 9103 so both instances can
# run on one host (§19, Sprint 13 t4).
run-ingestion-base:
    CHAIN_ID=8453 RPC_URLS="$BASE_RPC_URLS" INGESTION_METRICS_ADDR=0.0.0.0:9104 cargo run -p ingestion

# Run the detection service (§6, §17). The fast path: consumes
# BlockAssembled/BlockReverted off Kafka, fans detectors out on rayon, and
# produces DetectorTriggered/PreliminaryAlertCreated. Needs Kafka up (`just up`)
# and ingestion producing blocks. `--features detectors` links the built-in
# sandwich + arb detectors (the lib default links none).
run-detection:
    cargo run -p detection --features detectors

# Run a second detection instance for Base (§6, Sprint 13 t2). Its own consumer
# group (defaulted to detection-8453) keeps offsets separate from the Ethereum
# instance; another chain's blocks on the shared topics are commit-skipped. The
# metrics port moves off 9100 so both instances can run on one host.
run-detection-base:
    CHAIN_ID=8453 DETECTION_METRICS_ADDR=0.0.0.0:9101 cargo run -p detection --features detectors

# Run detection with the synthetic `demo` detector linked (§19). It fires on a
# fixed schedule regardless of tx content, so the per-detector metrics (hit rate,
# findings, latency) and the emit path light up on a header-only source — for
# demoing the Grafana dashboard. Dev only; never run this against real traffic.
run-detection-demo:
    cargo run -p detection --features detectors,demo

# Run the simulation dispatcher (§7, slow-path front half). Declares the sim.jobs
# topology (quorum + DLX) at boot, then consumes PreliminaryAlertCreated off Kafka
# and publishes a SimulationJob command to RabbitMQ for each. Needs Kafka + RabbitMQ
# up (`just up`) and detection producing alerts. Queue depth shows on the
# 'Simulation — sim.jobs queue (§7)' Grafana dashboard; with no worker pool draining
# sim.jobs yet (Sprint 5 t3) the backlog grows — that's the §7 backpressure signal.
run-simulation:
    cargo run -p simulation

# Run the usage service (§13, Sprint 12 — metering sink, no billing). Drains
# mev.events.UsageRecorded into the append-only ClickHouse usage_events table.
# ClickHouse migrations apply on boot; needs ClickHouse + Kafka up (`just up`).
run-usage:
    cargo run -p usage

# Run the notification service (§11, Sprint 12 — delivery hardening).
# Consumes PreliminaryAlertCreated/IncidentCreated/IncidentRetracted/
# IncidentFinalized/RuleAlertCreated/SanctionHit off Kafka, routes each to
# severity/kind/chain-filtered subscribers over webhook/email/Slack/
# PagerDuty with retry/backoff, per-subscriber dedup and delivery receipts.
# Needs Postgres + Kafka up (`just up`) and `just migrate-up` applied; no
# subscriber-management API yet — seed via `NotificationStore::create_subscriber`.
run-notification:
    cargo run -p notification

# Probe the notification service's Postgres schema
notification-ping:
    cargo run -p notification -- ping

# Run the LLM investigation copilot (§20.4, Sprint 20). Consumes
# IncidentCreated, drafts a SAR narrative from the incident's audit stream,
# checks every claim's citations against the events the model was shown, and
# holds the draft at `ready` until a human approves it over the review API
# (COPILOT_HTTP_ADDR + COPILOT_REVIEW_TOKEN; Swagger at /swagger-ui).
# Needs Postgres + Kafka up, `just migrate-up` applied, event-store running,
# and ANTHROPIC_API_KEY set — boot verifies the credential and the model.
run-copilot:
    cargo run -p copilot

# Probe the copilot's Postgres schema AND its model credential (costs no
# tokens) — the two things a misconfigured deployment gets wrong quietly.
copilot-ping:
    cargo run -p copilot -- ping

# §20.4 historical narrative backfill, through the Batch API at HALF price.
# A job, not a service: bounded window, safe to re-run (idempotent per
# incident) and safe to interrupt (an outstanding batch is resumed from its
# stored id, never submitted — or paid for — twice). Omit the window to draft
# the whole archive.
#   just copilot-backfill 2026-01-01T00:00:00Z 2026-02-01T00:00:00Z
copilot-backfill from="" to="":
    cargo run -p copilot -- backfill \
        {{ if from == "" { "" } else { "--from " + from } }} \
        {{ if to == "" { "" } else { "--to " + to } }}

# §20.4 governance sweep (Sprint 20 t5): re-resolve every landed narrative's
# citations against event-store and report what no longer holds. Exits 1 on a
# finding (a citation the store does not have, a row that disagrees with its
# own text, or a `ready` draft the citation boundary never ran on) and 2 when
# nothing could be verified at all — so it is usable as a CronJob or a
# pre-audit gate, not just as something to read.
#   just copilot-audit --since 2026-01-01T00:00:00Z
copilot-audit *args:
    cargo run -p copilot -- audit {{args}}

# Regenerate the checked-in prompt manifest (engineering conventions §16).
# A prompt edit changes a digest here, so the change cannot merge without a
# hunk a reviewer sees. Run this after touching anything under
# crates/copilot/prompts/, and put the diff in the PR.
prompt-manifest:
    cargo run -q -p copilot -- prompts > crates/copilot/prompts/MANIFEST

# Print the current per-customer token spend against the configured budget
# (§20.4 t5). The alarm's metrics deliberately carry no customer label, so
# this is where an operator finds out *who* is over budget. Needs
# USAGE_TOKEN_BUDGET set and ClickHouse up.
usage-budget:
    cargo run -p usage -- budget

# Start bacon (TUI, jobs defined in bacon.toml)
bacon:
    bacon

# Sprint 0 deliverable: one trace span propagates end-to-end across a
# stub producer/consumer (in-process; no infra needed). Watch the two
# trace_id=… lines match.
trace-demo:
    RUST_LOG=info cargo run -p telemetry --example trace_propagation

# Run the server binary inside bacon (live reload)
run:
    bacon run

# ── Scaffolding (new crates) ─────────────────────────────────────
# Crates live under crates/ and are auto-included via the "crates/*"
# glob in the workspace Cargo.toml — no need to edit members by hand.

# New binary (runnable service) crate: just new-bin worker
new-bin name:
    cargo new crates/{{name}} --bin --name {{name}} --vcs none
    @echo "✅ created crates/{{name}} (bin) — run with: cargo run -p {{name}}"

# New library (shared code) crate: just new-lib intelligence
new-lib name:
    cargo new crates/{{name}} --lib --name {{name}} --vcs none
    @echo "✅ created crates/{{name}} (lib) — import with: use {{name}}::...;"

# ── Build ────────────────────────────────────────────────────────

# Build the whole workspace (release)
build:
    cargo build --release --workspace

# Build server binary (release)
build-server:
    cargo build --release -p server

# ── Clean (target/ disk usage) ────────────────────────────────────
# `target/` is pure build cache (gitignored, safe to delete any time — the
# only cost is recompiling). It's never pruned automatically, so it grows
# without bound across every crate × profile × incremental cache; a
# workspace this size (revm, reth-adjacent deps, per-crate test binaries)
# can reach hundreds of GB. Prefer `clean-crate` over a blanket `clean` day
# to day — a full clean forces a slow full rebuild of everything, `clean-crate`
# only forces a rebuild of the one crate (and whatever depends on it).

# Show target/'s total size and its biggest subdirectories, so you know
# what a clean would actually reclaim before running one.
target-size:
    @echo "── total ──"
    @du -sh target 2>/dev/null || echo "(no target/ yet)"
    @echo "── target/* ──"
    @du -sh target/*/ 2>/dev/null | sort -rh
    @echo "── target/debug/* (usually the bulk) ──"
    @du -sh target/debug/*/ 2>/dev/null | sort -rh

# Clean one crate's build artifacts (and anything depending on it) — the
# targeted alternative to a full `clean`. Usage: `just clean-crate detection`.
clean-crate crate:
    cargo clean -p {{crate}}

# Wipe target/debug/incremental/ only — usually the single biggest reclaim
# for the lowest cost. This is purely a compile-*speed* cache (not the
# compiled artifacts themselves, which live in deps/): deleting it just means
# the next build of whatever crate you touch recompiles that one crate from
# scratch instead of incrementally, not a full workspace rebuild. Cargo
# recreates the directory on its own.
clean-incremental:
    rm -rf target/debug/incremental target/release/incremental
    @echo "✅ incremental cache cleared — the next touched crate rebuilds non-incrementally, nothing else changes"

# Full clean — every crate, every profile. Reclaims the most disk but the
# next build recompiles the whole workspace from scratch (revm/reth-adjacent
# deps included — expect tens of minutes, not seconds).
clean:
    cargo clean

# Prune build artifacts untouched in 14+ days, keep everything still active —
# the standing habit that replaces manually reaching for `clean`/`clean-crate`.
# Safe to run any time (idempotent, only ever deletes stale artifacts); wire
# it into a weekly cron/reminder rather than running it ad hoc. Needs
# `cargo-sweep` (`just tools`, or `cargo install cargo-sweep`).
sweep:
    cargo sweep --time 14
    @echo "✅ pruned artifacts untouched in 14+ days"

# ── Format ───────────────────────────────────────────────────────

# Format code
fmt:
    cargo fmt --all

# Check formatting (CI mode)
fmt-check:
    cargo fmt --all --check

# ── Lint (mirrors CI) ────────────────────────────────────────────

# Run clippy with warnings as errors (same as CI)
lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    @echo "✅ Lint passed — safe to push"

# Run clippy with auto-fix where possible
lint-fix:
    cargo clippy --fix --workspace --all-targets --allow-dirty --allow-staged

# ── Test ─────────────────────────────────────────────────────────

# Run unit tests (nextest) + doctests
test:
    cargo nextest run --workspace --no-tests=pass
    cargo test --workspace --doc

# Run all tests incl. #[ignore] integration (needs docker for testcontainers)
test-integration:
    cargo nextest run --workspace --run-ignored all --no-tests=pass

# ── Projection rebuild (§2, readiness Epic B) ─────────────────────
#
# "Projections are derived" is a claim; these recipes are the proof, and the
# same code path is the recovery procedure for a corrupted read model.
# Full runbook: docs/runbooks/projection-rebuild.md

# The drill, hermetically: build the read model the live way in throwaway
# Postgres + ClickHouse containers, wipe it, replay it from the event store,
# and assert the result is byte-identical. Needs Docker. Runs as part of
# `just test-integration` too — this is for iterating on it.
# Prove the read model is derived: stage + replay + swap in throwaway containers.
projection-rebuild-drill:
    cargo nextest run -p simulation --test projection_rebuild --run-ignored all --no-tests=pass

# Read-only fingerprint of the LIVE read model. Take one before a risky deploy
# or migration; compare after. Never destructive.
#   just projection-fingerprint            # both stores
#   just projection-fingerprint incidents  # Postgres read model only
# Print the live read model's content hash (read-only).
projection-fingerprint model="all":
    cargo run -p simulation --bin simulation-projection -- fingerprint --model {{model}}

# The drill against the LIVE stores — NON-DESTRUCTIVE. Rebuilds into a staging
# namespace, compares it with the live model, drops the staging copy, and FAILS on
# any divergence. The live read model is never written to, so this is safe to run
# on a timer against production (and should be). Needs EVENT_STORE_URL.
# Prove the LIVE read model is derived — writes nothing, fails on divergence.
projection-rebuild-verify model="all":
    cargo run -p simulation --bin simulation-projection -- verify --model {{model}}

# The recovery: the same run, but the staged replacement is PROMOTED over the live
# model (atomically, for Postgres) and the diff is a damage report rather than a
# failure. The previous generation is kept in a `…_superseded` schema — read
# runbook §5 before accepting the result and §6 before dropping it. Stop the
# projection consumer first.
# Rebuild the LIVE read model from the event store and promote it (recovery).
projection-rebuild model="all":
    cargo run -p simulation --bin simulation-projection -- rebuild --model {{model}} --yes

# ── Backups + tested restore (readiness Epic B) ───────────────────
#
# "We have backups" is a belief; these recipes are the control. The drill
# restores the real, newest artifact into a throwaway database and compares it
# row-for-row with the fingerprint taken inside the dump's own cut — so it is
# NON-DESTRUCTIVE and belongs on a timer, not a quarterly checklist.
# Full runbook: docs/runbooks/backup-restore.md

# Where do we stand against the RPO/RTO budgets? Exits 2 on a breach — which
# includes a *stale drill*, because an unverified backup does not count.
# Measure RPO/RTO against the configured budgets (exit 2 = breached).
backup-report:
    cargo run -p backup -- report

# What is on disk, how old it is, and any notes the snapshot recorded
# (a skipped table engine, a materialized view whose data is not covered).
# List backup artifacts with their ages.
backup-list target="":
    cargo run -p backup -- list {{ if target == "" { "" } else { "--target " + target } }}

# Take one consistent snapshot now. Do this before a risky migration — and
# take a `just backup-report` reading after, so the RPO clock is visibly reset.
# Take one consistent snapshot per configured target.
backup-snapshot target="":
    cargo run -p backup -- snapshot {{ if target == "" { "" } else { "--target " + target } }}

# THE CONTROL. Restores the newest artifact into a throwaway database, verifies
# it row-for-row, drops it, and records the evidence `backup-report` reads.
# Never writes to a live database; exits 2 on any divergence.
# Prove the newest backup restores — non-destructive, exit 2 on divergence.
backup-drill target="":
    cargo run -p backup -- drill {{ if target == "" { "" } else { "--target " + target } }}

# What is in the LIVE store right now, read-only. Take one before a risky
# migration and compare after. Read-only *by construction*: the command is
# handed the narrow `StoreReader` seam, which has no restore or drop on it.
# Print the live store's per-table row counts and content digests.
backup-fingerprint target="":
    cargo run -p backup -- fingerprint {{ if target == "" { "" } else { "--target " + target } }}

# Checksums only — proves the bytes are intact, NOT that they restore. Cheap
# enough to run against an offsite copy (point BACKUP_DIR at it).
# Recompute artifact checksums (not a restore).
backup-verify target="":
    cargo run -p backup -- verify {{ if target == "" { "" } else { "--target " + target } }}

# The recovery. Restores into a database you name (create it first) and ends
# with the same fingerprint comparison, so the result is a damage report rather
# than a hope. Read runbook §5 before cutting over.
# Restore an artifact into a named database (recovery).
backup-restore target into:
    cargo run -p backup -- restore --target {{target}} --into {{into}} --yes

# Apply the retention policy. Never removes the newest artifact for a target,
# whatever the policy says — a snapshot job that has been failing quietly for a
# month would otherwise empty the store.
# Prune artifacts past BACKUP_RETENTION.
backup-prune target="":
    cargo run -p backup -- prune {{ if target == "" { "" } else { "--target " + target } }}

# The tested restore, tested: real Postgres + real ClickHouse in throwaway
# containers, backed up, restored elsewhere, compared row-for-row — including a
# write landing mid-backup and a materialized view that must not double-write.
# Needs Docker (and pg_dump on PATH). Runs in `just test-integration` too.
# Prove the backup/restore path itself against real containers.
backup-drill-test:
    cargo nextest run -p backup --test restore_drill --run-ignored all --no-tests=pass

# ── Event schema registry (§2, readiness Epic B) ──────────────────

# The compatibility gate on its own: regenerate the schema of every DomainEvent
# from the real codec, diff it against crates/events/schema/v<SCHEMA_VERSION>/,
# and replay the whole append-only archive (schema/corpus/) through today's
# reader. Runs as part of `just test` too — this is for iterating on a change.
schema-check:
    cargo test -p events --all-features --test schema_registry

# Re-commit the current version's schema after an intentional change, appending
# any new shape to the archive (never rewriting one: those bytes are in the event
# store). Refuses an incompatible change: that needs a SCHEMA_VERSION bump and an
# events::upcast step (crates/events/SCHEMA.md), after which this writes the new
# version's directory and leaves the old one frozen.
schema-bless:
    cargo test -p events --all-features --test schema_registry -- --ignored --nocapture bless

# ── Backtest / precision-recall gates (§18, §20.2) ────────────────

# Replay the ground-truth fixtures and fail on either committed gate — the CI
# merge gate. Two distinct checks (see crates/backtest/src/gate.rs):
#   regression — nothing dropped below crates/backtest/baseline.json
#   promotion  — nothing Active sits below crates/backtest/promotion_gate.json,
#                and shadowed detectors clearing it are reported as promotable
backtest:
    cargo run -p backtest --all-features --locked

# Score a real ML model bundle (§20.2) alongside the heuristics: loads the
# bundle through detection's own boot path and adds the ML fixtures, so the
# promotion gate reports whether those weights have earned their way out of
# Shadow. Needs the ONNX Runtime on ORT_DYLIB_PATH, like the service does.
#   just backtest-ml out/bundle/anomaly.json
backtest-ml config:
    cargo run -p backtest --all-features --locked -- --anomaly-config {{config}}

# Overwrite the committed baseline with this run's numbers — the deliberate
# step a detector/config change that intentionally moves precision/recall
# takes before it can merge.
backtest-update-baseline:
    cargo run -p backtest --all-features --locked -- --update-baseline

# Accept a changed full-report snapshot (tests/baseline_snapshot.rs) after
# reviewing the diff `cargo test` printed — the dev-review counterpart to
# backtest-update-baseline, using only the `insta` crate (no extra install).
backtest-accept-snapshot:
    INSTA_UPDATE=always cargo test -p backtest --all-features --test baseline_snapshot

# ── Kubernetes (deploy/k8s, §20) ─────────────────────────────────

# The deployable service binaries — one GHCR image each (matches ci.yml's
# docker matrix). Each entry is `bin[:features[:runtime]]`; detection carries
# its feature flags inline and builds on the `onnx` runtime flavour, which adds
# the pinned ONNX Runtime the ML detector loads (§20.2, deploy/Dockerfile).
k8s_bins := "server ingestion detection:detection/detectors,detection/anomaly:onnx event-store simulation simulation-worker simulation-projection intelligence rule-engine notification usage predictive copilot backup::pgclient"
k8s_image := "ghcr.io/kyawkyawthar/onchain_fraud_mev_detector"

# Build every service image locally (:dev) and load it into the kind cluster —
# the local stand-in for CI's GHCR publish. Slow the first time; cargo-chef
# caches the dependency layer after that.
k8s-build-images cluster="kind":
    #!/usr/bin/env sh
    set -eu
    for entry in {{k8s_bins}}; do
        bin="${entry%%:*}"
        rest="${entry#"$bin"}"; rest="${rest#:}"
        features="${rest%%:*}"
        runtime="${rest#"$features"}"; runtime="${runtime#:}"
        [ -n "$runtime" ] || runtime="plain"
        echo "── building ${bin}${features:+ (features: $features)} [runtime: $runtime]"
        docker build -f deploy/Dockerfile \
            --build-arg BIN="$bin" \
            --build-arg FEATURES="$features" \
            --build-arg RUNTIME="$runtime" \
            -t "{{k8s_image}}/${bin}:dev" .
        kind load docker-image "{{k8s_image}}/${bin}:dev" --name "{{cluster}}"
    done

# Build a model-bundle image for the ML detector (§20.2) and load it into kind.
# `bundle` is a directory laid out per deploy/models/README.md; the build fails
# if its anomaly.json references a file the bundle doesn't contain.
k8s-build-model-image bundle tag="dev" cluster="kind":
    docker build -f deploy/models/Dockerfile --build-arg BUNDLE=. \
        -t "{{k8s_image}}/detection-models:{{tag}}" "{{bundle}}"
    kind load docker-image "{{k8s_image}}/detection-models:{{tag}}" --name "{{cluster}}"

# ── ML model training (§20.1/§20.2, deploy/training) ─────────────

train_image := "mev-training"

# Build the pinned training image (Python + scikit-learn + skl2onnx + the same
# onnxruntime version production serves, so an export verifies against it).
train-build:
    docker build -f deploy/training/Dockerfile -t "{{train_image}}" deploy/training

# Train one role from a `dataset export` Parquet file into a bundle directory.
# Run it twice — supervised from a tx export, novelty from a block export — into
# the same `out` to compose one bundle.
#
#   just train supervised out/tx-rows.parquet out/bundle
train role dataset out="out/bundle" *ARGS:
    mkdir -p "{{out}}"
    docker run --rm --user "$(id -u):$(id -g)" \
        -v "$(cd $(dirname {{dataset}}) && pwd)":/data:ro \
        -v "$(cd {{out}} && pwd)":/bundle \
        "{{train_image}}" \
        --role "{{role}}" --dataset "/data/$(basename {{dataset}})" --out /bundle {{ARGS}}

# End-to-end check of the training image on synthetic rows carrying the real
# frozen v1 feature names — no dataset, no cluster. The bundle it writes is
# servable, so `check-models-image` accepts it.
train-self-test out="out/self-test":
    mkdir -p "{{out}}"
    docker run --rm --user "$(id -u):$(id -g)" -v "$(cd {{out}} && pwd)":/bundle \
        "{{train_image}}" self-test --out /bundle

# Validate a bundle with the *real* loader, inside the detection image — the
# gate a bundle must pass before it is packaged. Needs the ML detection image
# (`just k8s-build-images`).
check-models-image bundle="out/bundle" tag="dev":
    docker run --rm -v "$(cd {{bundle}} && pwd)":/models:ro \
        "{{k8s_image}}/detection:{{tag}}" check-models /models/anomaly.json

# Pre-flight a model bundle against the *real* loader before it is deployed —
# artifact digests, pinned-digest check, feature-version skew, graph
# conformance, the probe inference, and the baseline/schema pairing. Prints the
# `config_hash` the bundle will stamp on every event, which is what you record
# when promoting a model and paste into `expected_artifact` to pin it.
#
# Needs the ONNX Runtime locally (the image ships it, your laptop doesn't):
#   macOS  brew install onnxruntime && export ORT_DYLIB_PATH="$(brew --prefix onnxruntime)/lib/libonnxruntime.dylib"
#   Linux  download the release tarball pinned in deploy/Dockerfile and point
#          ORT_DYLIB_PATH at its lib/libonnxruntime.so
check-models config:
    cargo run -p detection --features detectors,anomaly -- check-models {{config}}

# The Grafana dashboards/datasources configMapGenerator (§19, Sprint 13 t4)
# reads deploy/grafana/... directly, outside deploy/k8s/base's own tree — one
# source of truth shared with the compose stack, at the cost of needing
# kustomize's file-access sandbox relaxed. `kubectl apply/diff/delete -k`
# don't expose --load-restrictor, so every k8s-* recipe below builds through
# the standalone `kustomize` CLI and pipes into kubectl instead.
k8s_kustomize := "kustomize build --load-restrictor LoadRestrictionsNone"

# Render the dev overlay (review what would apply)
k8s-render overlay="dev":
    {{k8s_kustomize}} deploy/k8s/overlays/{{overlay}}

# Apply the dev overlay to the current kubectl context
k8s-apply overlay="dev":
    {{k8s_kustomize}} deploy/k8s/overlays/{{overlay}} | kubectl apply -f -

# Diff the dev overlay against the live cluster
k8s-diff overlay="dev":
    {{k8s_kustomize}} deploy/k8s/overlays/{{overlay}} | kubectl diff -f - || true

# Tear the stack down (keeps PVCs; delete the namespace's pvc objects to wipe data)
k8s-delete overlay="dev":
    {{k8s_kustomize}} deploy/k8s/overlays/{{overlay}} | kubectl delete -f -

# Watch the whole namespace converge
k8s-status:
    kubectl -n mev get pods,statefulsets,deployments,hpa

# ── Security / supply chain ──────────────────────────────────────

# Check for vulnerable dependencies (cargo-audit)
audit:
    cargo audit

# Check licenses, advisories, banned crates (cargo-deny)
deny:
    cargo deny check

# Full pre-push check (mirrors CI)

check: fmt-check lint test build backtest
    @echo "════════════════════════════════════════"
    @echo "  ✅ All checks passed — safe to push"
    @echo "════════════════════════════════════════"

# ── Git hooks (lefthook) ─────────────────────────────────────────

# Install pre-commit/pre-push hooks (needs: brew install lefthook)
hooks:
    lefthook install
    @echo "✅ Git hooks installed (fmt on commit; clippy + tests on push)"

# ── Pre-push check (everything CI checks) ────────────────────────

# Full pre-push check (mirrors CI)


# ── Install / Setup ──────────────────────────────────────────────

# Install dev tools (sqlx-cli, cargo-watch, bacon, nextest, audit, deny, machete, sweep)
tools:
    cargo install sqlx-cli --no-default-features --features rustls,postgres
    # nextest refuses to install without --locked, so it's a separate line.
    cargo install cargo-nextest --locked
    cargo install cargo-watch bacon cargo-audit cargo-deny cargo-machete cargo-sweep
    @echo "ℹ️  Also install lefthook for git hooks: brew install lefthook && just hooks"
    @echo "ℹ️  The event-store crate builds librdkafka from source — needs a C toolchain + make (Xcode CLT on macOS; build-essential on Linux)"