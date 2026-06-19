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

# ── Security / supply chain ──────────────────────────────────────

# Check for vulnerable dependencies (cargo-audit)
audit:
    cargo audit

# Check licenses, advisories, banned crates (cargo-deny)
deny:
    cargo deny check

# Full pre-push check (mirrors CI)

check: fmt-check lint test build
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

# Install dev tools (sqlx-cli, cargo-watch, bacon, nextest, audit, deny, machete)
tools:
    cargo install sqlx-cli --no-default-features --features rustls,postgres
    # nextest refuses to install without --locked, so it's a separate line.
    cargo install cargo-nextest --locked
    cargo install cargo-watch bacon cargo-audit cargo-deny cargo-machete
    @echo "ℹ️  Also install lefthook for git hooks: brew install lefthook && just hooks"
    @echo "ℹ️  The event-store crate builds librdkafka from source — needs cmake + a C toolchain: brew install cmake"