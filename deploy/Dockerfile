# syntax=docker/dockerfile:1
#
# Multi-stage build with cargo-chef so the dependency-compile layer is cached
# and only re-runs when Cargo.toml / Cargo.lock change. Build a specific service
# binary with:  docker build -f deploy/Dockerfile --build-arg BIN=server .
#
# This is the standard real-world way to containerize a Rust workspace.

ARG RUST_VERSION=1
FROM lukemathwalker/cargo-chef:latest-rust-${RUST_VERSION} AS chef
WORKDIR /app

# ── Plan: compute the dependency recipe ──────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Build: cook deps (cached), then build the requested binary ───
FROM chef AS builder
ARG BIN=server
COPY --from=planner /app/recipe.json recipe.json
# Heavy, cached layer — only invalidated when dependencies change.
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
# Build against the committed .sqlx cache (no live DB at image-build time).
ENV SQLX_OFFLINE=true
RUN cargo build --release --locked --bin "${BIN}" \
    && cp "target/release/${BIN}" /app/service

# ── Runtime: minimal, non-root ───────────────────────────────────
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 appuser
WORKDIR /app
COPY --from=builder /app/service /usr/local/bin/service
USER appuser
ENTRYPOINT ["/usr/local/bin/service"]
