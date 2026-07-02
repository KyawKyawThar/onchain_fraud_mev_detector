//! Database access layer for the on-chain fraud/MEV detector.
//!
//! This crate owns only the **shared** Postgres plumbing — the connection-pool
//! builder — so every service that needs the OLTP store ([`simulation`], and later
//! intelligence/rule-engine/notification/billing, §14) constructs its pool the same
//! way. The per-service tables and repositories live in the owning service crate:
//! §14's rule is *no shared tables and no cross-service joins*, so this crate
//! deliberately holds no schema or query — just the pool.
//!
//! Migrations live in `crates/db/migrations` and are applied out-of-band by
//! `sqlx-cli` (the `just migrate-*` recipes / the `migrate.yml` workflow), not at
//! service boot — the same split the ClickHouse event store uses (schema is an
//! operational step, distinct from running the service).

use std::time::Duration;

use anyhow::{Context, Result};
use sqlx::postgres::{PgPool, PgPoolOptions};

/// Default ceiling on pooled connections. Sized for a single service replica; a
/// hot service can raise it via [`connect_with`]. Kept modest so N replicas don't
/// exhaust Postgres's own `max_connections`.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 10;

/// How long [`connect`] waits for the first connection to succeed before giving up,
/// so a service fails fast at boot on an unreachable/misconfigured database rather
/// than hanging.
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(10);

/// Build a Postgres connection pool from a `postgres://…` URL, eagerly opening one
/// connection so a bad URL or an unreachable database fails **at boot**, not at the
/// first query. Uses [`DEFAULT_MAX_CONNECTIONS`]; see [`connect_with`] to override.
pub async fn connect(url: &str) -> Result<PgPool> {
    connect_with(url, DEFAULT_MAX_CONNECTIONS).await
}

/// [`connect`] with an explicit connection ceiling, for a service that has profiled
/// its concurrency and needs more (or fewer) than the default.
pub async fn connect_with(url: &str, max_connections: u32) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(ACQUIRE_TIMEOUT)
        .connect(url)
        .await
        .context("connecting to Postgres")?;
    tracing::info!(max_connections, "Postgres connection pool ready");
    Ok(pool)
}
