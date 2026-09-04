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

/// [`connect`], but every connection in the pool resolves unqualified table
/// names in `schema` first.
///
/// The one use is a **projection rebuild** (`crates/rebuild`): a rebuild writes
/// its replacement into a staging schema beside the live tables and swaps it in.
/// Pointing the pool's `search_path` at that schema is what lets the *unmodified*
/// production write path — the same store impl, the same SQL — target it. The
/// alternative, threading a schema name through every query, would mean the
/// rebuild exercised different SQL than production runs, which defeats the
/// purpose of rebuilding through the live path at all.
///
/// `public` stays on the path after `schema`, so shared types and extensions
/// still resolve. `schema` must be a bare identifier (this is checked): it is
/// interpolated into a `SET` that cannot be parameterised.
pub async fn connect_in_schema(url: &str, schema: &str) -> Result<PgPool> {
    if schema.is_empty()
        || !schema
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        anyhow::bail!("schema {schema:?} is not a bare identifier");
    }
    // `SET search_path` is per-session, so it must run on *every* connection the
    // pool opens — including ones opened later to grow the pool, which is why
    // this is `after_connect` and not a one-off statement after `connect`.
    let schema = schema.to_owned();
    let pool = PgPoolOptions::new()
        .max_connections(DEFAULT_MAX_CONNECTIONS)
        .acquire_timeout(ACQUIRE_TIMEOUT)
        .after_connect(move |conn, _meta| {
            let schema = schema.clone();
            Box::pin(async move {
                // `AssertSqlSafe` is sqlx 0.9's explicit escape hatch for SQL
                // built at runtime. It is honest here and nowhere else in this
                // statement: `schema` was checked above to be a bare
                // identifier, and `SET search_path` takes no bind parameters.
                sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                    "SET search_path TO {schema}, public"
                )))
                .execute(conn)
                .await?;
                Ok(())
            })
        })
        .connect(url)
        .await
        .context("connecting to Postgres")?;
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
