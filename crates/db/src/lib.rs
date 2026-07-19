//! Database access layer for the on-chain fraud/MEV detector.
//!
//! This crate owns only the **shared** Postgres plumbing — the connection-pool
//! builder — so every service that needs the OLTP store ([`simulation`], and later
//! intelligence/rule-engine/notification/billing, §14) constructs its pool the same
//! way. The per-service tables and repositories live in the owning service crate:
//! §14's rule is *no shared tables and no cross-service joins*, so this crate
//! deliberately holds no schema or query — just the pool. [`redis`] is the same
//! idea for the workspace's other shared datastore (§8/§9's hot-path Redis).
//!
//! Migrations live in `crates/db/migrations` and are applied out-of-band by
//! `sqlx-cli` (the `just migrate-*` recipes / the `migrate.yml` workflow), not at
//! service boot — the same split the ClickHouse event store uses (schema is an
//! operational step, distinct from running the service).

use std::time::Duration;

use anyhow::{Context, Result};
use sqlx::postgres::{PgPool, PgPoolOptions};

pub mod redis;

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

/// Whether a Postgres error is a **permanent** (never-succeeds-on-retry) fault
/// rather than a transient one — the shared half of every service's
/// retry-vs-skip decision (`is_transient()` on its typed store error), kept
/// here so the classification cannot drift between services: the same fault
/// must not wedge one consumer's stream while another skips it (§4).
///
/// Permanent means an our-side bug that fails identically on every retry — a
/// value that can't be encoded, a column/type the query names that the schema
/// doesn't have, or a protocol/argument/configuration error. Everything else
/// (I/O, pool timeouts, a closed pool, a server-side `Database` error) is
/// transient and retried. A new `sqlx::Error` variant defaults to transient
/// (retry), the safe choice for at-least-once durability.
pub fn is_permanent(err: &sqlx::Error) -> bool {
    matches!(
        err,
        sqlx::Error::Encode(_)
            | sqlx::Error::Decode(_)
            | sqlx::Error::ColumnDecode { .. }
            | sqlx::Error::TypeNotFound { .. }
            | sqlx::Error::ColumnNotFound(_)
            | sqlx::Error::ColumnIndexOutOfBounds { .. }
            | sqlx::Error::Protocol(_)
            | sqlx::Error::InvalidArgument(_)
            | sqlx::Error::Configuration(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The retry/skip contract every service's `is_transient()` leans on:
    /// I/O/pool/server faults retry; our-side encode/decode/schema bugs don't.
    #[test]
    fn classifies_permanent_vs_transient() {
        assert!(!is_permanent(&sqlx::Error::PoolClosed));
        assert!(!is_permanent(&sqlx::Error::PoolTimedOut));
        assert!(!is_permanent(&sqlx::Error::WorkerCrashed));

        assert!(is_permanent(&sqlx::Error::Decode("bad".into())));
        assert!(is_permanent(&sqlx::Error::Encode("bad".into())));
        assert!(is_permanent(&sqlx::Error::ColumnNotFound("nope".into())));
        assert!(is_permanent(&sqlx::Error::TypeNotFound {
            type_name: "x".into()
        }));
        assert!(is_permanent(&sqlx::Error::Protocol("bad".into())));
    }
}
