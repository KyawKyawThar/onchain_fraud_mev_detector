//! Shared Redis plumbing (§8/§9): the connection builder and the transient/
//! permanent classification every Redis-backed store's error type leans on —
//! mirrors this crate's Postgres half ([`crate::connect`]/[`crate::is_permanent`])
//! so the two datastores this workspace treats as "hot path, not the sole
//! record" share one place their connectivity and retry semantics are
//! decided, rather than each service re-deriving byte-identical logic
//! (`intelligence::cache::RedisHotCache` and
//! `rule_engine::state_store::RedisTemporalStore` both did, until this
//! module existed).

use anyhow::{Context, Result};
use redis::aio::ConnectionManager;

/// Connect to Redis and prove it is reachable — fail-fast at boot (the
/// manager performs the initial connect + `PING`), the same posture as
/// [`crate::connect`] for Postgres. [`ConnectionManager`] is a
/// self-reconnecting handle over one multiplexed connection, cheap to clone.
pub async fn connect(url: &str) -> Result<ConnectionManager> {
    let client = redis::Client::open(url).context("parsing the Redis URL")?;
    let conn = ConnectionManager::new(client)
        .await
        .context("connecting to Redis")?;
    tracing::info!("Redis connection manager ready");
    Ok(conn)
}

/// Whether a Redis error is worth retrying — the shared half of every
/// Redis-backed store's `is_transient()` (mirrors [`crate::is_permanent`]'s
/// role for `sqlx::Error`, kept here so the classification cannot drift
/// between services: the same fault must not retry in one store and give up
/// in another).
///
/// A `Parse`/`UnexpectedReturnType` error means the command or the stored
/// value's shape is wrong — retrying re-reads the same bytes and fails
/// identically, so it's permanent for the caller (though the fix is usually
/// "treat this entry as malformed and discard it", not "retry"). Everything
/// else (connection reset, timeout, a server-side error reply) is a
/// plausible blip and defaults to transient — the safe choice for
/// at-least-once durability.
pub fn is_transient(err: &redis::RedisError) -> bool {
    !matches!(
        err.kind(),
        redis::ErrorKind::UnexpectedReturnType | redis::ErrorKind::Parse
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The retry/skip contract every Redis-backed store's `is_transient()`
    /// leans on: a malformed reply/value doesn't retry; everything else does.
    #[test]
    fn classifies_transient_vs_permanent() {
        let parse_err = redis::RedisError::from((redis::ErrorKind::Parse, "bad value"));
        assert!(!is_transient(&parse_err));

        let shape_err =
            redis::RedisError::from((redis::ErrorKind::UnexpectedReturnType, "wrong shape"));
        assert!(!is_transient(&shape_err));

        let io_err = redis::RedisError::from((redis::ErrorKind::Io, "connection reset"));
        assert!(is_transient(&io_err));

        let client_err = redis::RedisError::from((redis::ErrorKind::Client, "client-side fault"));
        assert!(is_transient(&client_err));
    }
}
