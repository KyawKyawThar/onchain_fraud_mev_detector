# syntax=docker/dockerfile:1
#
# Multi-stage build with cargo-chef so the dependency-compile layer is cached
# and only re-runs when Cargo.toml / Cargo.lock change. Build a specific service
# binary with:  docker build -f deploy/Dockerfile --build-arg BIN=server .
#
# This is the standard real-world way to containerize a Rust workspace.

ARG RUST_VERSION=1

# The Debian release **both** the builder and the runtime are pinned to.
#
# One variable because they must agree: glibc is forward- but not
# backward-compatible, so a binary linked against the builder's glibc will not
# start on an older runtime — `version 'GLIBC_2.xx' not found`, at exec time, in
# every image. That is not hypothetical: upstream's `latest-rust-1` moved to
# Debian 13 (glibc 2.41) while this runtime stayed on bookworm (2.36), and every
# published image stopped running. Naming the release once makes the pairing
# impossible to break by upgrading one side.
ARG DEBIAN_RELEASE=bookworm

# Which runtime flavour the final image is: `plain` (the default — nothing but
# the binary and CA certs), `onnx`, which additionally carries the ONNX Runtime
# shared library the ML detector loads (§20.2), or `pgclient`, which carries
# the PostgreSQL client binaries the backup agent shells out to (Epic B).
# Selected by the last `FROM` in this file, so a `plain` build never even
# *resolves* the other stages — BuildKit prunes stages the target doesn't
# depend on.
ARG RUNTIME=plain

# The PostgreSQL client major version for the `pgclient` flavour. It must be
# **>= the server's**: pg_dump refuses outright to dump a newer server
# ("server version 18.0; pg_dump version 16.2 — aborting"), so a client that
# drifts behind an upgraded database turns every backup into a hard failure.
# Keep this in step with deploy/k8s/base/infra/postgres.yaml.
ARG PG_MAJOR=18

# The pinned ONNX Runtime release (see the `onnxruntime` stage below).
# Upgrading means bumping this *and* both digests together.
# renovate: datasource=github-releases depName=microsoft/onnxruntime extractVersion=^v(?<version>.*)$
ARG ONNXRUNTIME_VERSION=1.29.0

FROM lukemathwalker/cargo-chef:latest-rust-${RUST_VERSION}-${DEBIAN_RELEASE} AS chef
WORKDIR /app

# ── Plan: compute the dependency recipe ──────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Build: cook deps (cached), then build the requested binary ───
FROM chef AS builder
ARG BIN=server
# Optional cargo features in package/feature form (virtual workspace), e.g.
# FEATURES=detection/detectors — the detection image MUST set this or it
# links no built-in detectors (the lib default leaves the roster to the
# composing binary). A build that enables `detection/anomaly` must also set
# RUNTIME=onnx, or the ML detector has no runtime to load at boot.
ARG FEATURES=""
COPY --from=planner /app/recipe.json recipe.json
# Heavy, cached layer — only invalidated when dependencies change.
RUN cargo chef cook --release --recipe-path recipe.json ${FEATURES:+--features "${FEATURES}"}
COPY . .
# Build against the committed .sqlx cache (no live DB at image-build time).
ENV SQLX_OFFLINE=true
RUN cargo build --release --locked --bin "${BIN}" ${FEATURES:+--features "${FEATURES}"} \
    && cp "target/release/${BIN}" /app/service

# ── ONNX Runtime: pinned, checksum-verified, fetched once ────────
#
# `ort` is built `load-dynamic` (see the workspace manifest): the library is
# resolved at *boot* via ORT_DYLIB_PATH rather than linked or downloaded during
# `cargo build`. That keeps `cargo build` hermetic and needs no C++ toolchain —
# the price is that the library becomes a **deployment** fact, and this stage is
# where that fact is stated.
#
# Fetching a prebuilt binary here is not what conventions §10 rejected. What was
# rejected is `ort`'s `download-binaries` feature: an unreviewed, unpinned,
# unverified fetch inside build.rs on *every* build, including every CI job and
# every developer's laptop. This is the opposite on each count — an explicit
# version, a SHA-256 checked before the bytes are used, once per image build,
# visible in the diff when it changes. A tampered or truncated download fails
# the build instead of shipping.
#
# `ort` 2.0.0-rc.13 is compiled against ORT **API 17** here (no `api-NN` feature
# is enabled), and ONNX Runtime keeps `GetApi(n)` answering for every n up to
# its own version — so any release >= 1.17 can serve this build. Pinning an
# exact one is for reproducibility, not compatibility.
#
# Get the digests for a new version with:
#   shasum -a 256 onnxruntime-linux-{x64,aarch64}-<version>.tgz
FROM debian:${DEBIAN_RELEASE}-slim AS onnxruntime
ARG ONNXRUNTIME_VERSION
# Set by BuildKit from the requested platform — so a linux/arm64 build picks the
# aarch64 slice and its own digest instead of silently installing an x86 library.
ARG TARGETARCH
ARG ONNXRUNTIME_SHA256_AMD64=c3fddc4f139a045b0c4902c57410f0694f1c2fdf9b6939fbe38b1aeae7cd14ba
ARG ONNXRUNTIME_SHA256_ARM64=e1799098ebc054b370f6176a450f158720f297818c613e5dc99b92e2ec82346f
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
# `cp -L` resolves the versioned symlink chain (libonnxruntime.so →
# .so.1 → .so.<version>), so the image carries the real object under a stable
# name and ORT_DYLIB_PATH does not move on an upgrade.
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) slice=x64;     sha="${ONNXRUNTIME_SHA256_AMD64}" ;; \
      arm64) slice=aarch64; sha="${ONNXRUNTIME_SHA256_ARM64}" ;; \
      *) echo "no pinned ONNX Runtime for TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    release="onnxruntime-linux-${slice}-${ONNXRUNTIME_VERSION}"; \
    curl -fsSL --retry 3 --retry-delay 2 -o /tmp/ort.tgz \
      "https://github.com/microsoft/onnxruntime/releases/download/v${ONNXRUNTIME_VERSION}/${release}.tgz"; \
    echo "${sha}  /tmp/ort.tgz" | sha256sum -c -; \
    tar -xzf /tmp/ort.tgz -C /tmp; \
    mkdir -p /out; \
    cp -L "/tmp/${release}/lib/libonnxruntime.so" /out/libonnxruntime.so; \
    cp "/tmp/${release}/LICENSE" /out/ONNXRUNTIME-LICENSE; \
    rm -rf /tmp/ort.tgz "/tmp/${release}"

# ── Runtime: minimal, non-root ───────────────────────────────────
FROM debian:${DEBIAN_RELEASE}-slim AS runtime-base
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 appuser
WORKDIR /app
COPY --from=builder /app/service /usr/local/bin/service
USER appuser
ENTRYPOINT ["/usr/local/bin/service"]

# The default flavour: nothing extra.
FROM runtime-base AS runtime-plain

# The ML flavour (§20.2): + ~28 MB of ONNX Runtime, and the env var that tells
# `ort` where to find it — so no pod, chart or overlay has to carry the path.
# The library is world-readable and never written to, so this stays compatible
# with `readOnlyRootFilesystem: true`.
FROM runtime-base AS runtime-onnx
COPY --from=onnxruntime /out/libonnxruntime.so /usr/local/lib/libonnxruntime.so
# Upstream is MIT; the image redistributes the binary, so it carries the licence.
COPY --from=onnxruntime /out/ONNXRUNTIME-LICENSE /usr/local/share/licenses/ONNXRUNTIME-LICENSE
ENV ORT_DYLIB_PATH=/usr/local/lib/libonnxruntime.so

# The backup flavour (readiness Epic B): + the PostgreSQL client binaries.
#
# The backup agent orchestrates and verifies; it does not reimplement pg_dump,
# so the image has to carry the real client. It comes from the PGDG apt
# repository rather than Debian's, because Debian's tracks one major version
# per release and the pairing that matters is client >= server — see PG_MAJOR.
#
# Root filesystem is writable for this flavour: pg_dump writes its output, and
# the artifact volume is the workload's whole purpose.
FROM runtime-base AS runtime-pgclient
ARG DEBIAN_RELEASE
ARG PG_MAJOR
USER root
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl gnupg; \
    curl -fsSL --retry 3 https://www.postgresql.org/media/keys/ACCC4CF8.asc \
      | gpg --dearmor -o /usr/share/keyrings/pgdg.gpg; \
    echo "deb [signed-by=/usr/share/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt ${DEBIAN_RELEASE}-pgdg main" \
      > /etc/apt/sources.list.d/pgdg.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends "postgresql-client-${PG_MAJOR}"; \
    apt-get purge -y gnupg; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*; \
    pg_dump --version; \
    pg_restore --version
USER appuser

FROM runtime-${RUNTIME} AS runtime
