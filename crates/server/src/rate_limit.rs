//! Dedicated rate limiting for `POST /v1/address/{addr}/screen` (§19,
//! Sprint 14 t4) — one ceiling scoped ONLY to the screening endpoint, kept
//! separate from general `/v1` traffic (there is no general limiter yet) so
//! a burst against any other route can never eat into the capacity the
//! endpoint's p50 < 100ms SLO needs. Same ceiling for every customer: this
//! is a capacity/SLO protection, not a pricing-tier gate — §13's per-call
//! volume pricing (Developer/Growth/Scale/Enterprise) is metering-only (see
//! `crate::usage`'s `ScreeningCall` recording), never request-time
//! enforcement, so this limiter deliberately does not resolve a customer's
//! tier at all.
//!
//! Behind the object-safe [`ScreeningRateLimiter`] seam (mirrors
//! `PolicyStore`/`RuleStore`) so `screen_address`'s middleware is tested
//! against an in-memory double with no Redis.
//!
//! **Fixed-window counter, one pipelined round-trip**: `INCR` the per-customer
//! key, plus a `PEXPIRE ... NX` on the same key in the same pipeline (sets
//! the TTL only if the key doesn't already have one — i.e. only on the
//! window's first hit; every later increment inside the window leaves the
//! existing expiry alone, so the window never slides). `NX` makes the
//! "expire exactly once" property hold even under concurrent requests from
//! one customer without needing a Lua script or a `MULTI`/`EXEC`
//! transaction — cheap enough to sit in front of a sub-100ms handler. The
//! standard fixed-window tradeoff applies (a burst can straddle a window
//! boundary and briefly admit close to 2x the limit) — not worth a
//! sliding-window log's extra round-trips against this SLO.
//!
//! Requires Redis >= 7.0 (`EXPIRE`-family `NX`/`XX`/`GT`/`LT` flags); this
//! workspace's Redis is 8.6 (`deploy/docker-compose.yml`), well past that —
//! but `testcontainers_modules::redis::Redis`'s *default* image tag is
//! `5.0`, which rejects the extra `NX` arg outright ("wrong number of
//! arguments"). `tests/rate_limit_redis.rs` pins a newer tag explicitly;
//! don't drop that pin back to `Redis::default()`.
//!
//! **Fails open on a Redis fault** (logged + metered via
//! [`SCREENING_RATE_LIMIT_ERRORS_TOTAL`]) — unlike the intelligence/policy-
//! store dependencies on the same request path (which fail *closed*, §11
//! Sprint 14 t1/t2, because losing them loses the ability to render a
//! correct verdict), losing the rate limiter only loses a protective
//! measure. Taking screening down because Redis blipped would trade a
//! correctness-neutral capacity risk for a worse, customer-visible outage.

use std::sync::Arc;
use std::time::Duration;

use api_error::ApiError;
use async_trait::async_trait;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use events::primitives::CustomerId;
use redis::aio::ConnectionManager;

/// Counter: requests rejected with 429. Emitted at the decision seam
/// ([`enforce_screening_rate_limit`]), not inside any [`ScreeningRateLimiter`]
/// impl — so the count is identical whichever adapter (Redis / in-memory
/// double) is behind the trait, and swapping them can't silently change what
/// ops sees. No `customer` label on purpose (unbounded cardinality).
pub const SCREENING_RATE_LIMITED_TOTAL: &str = "screening_rate_limited_total";
/// The fixed window every [`RedisScreeningRateLimiter`] counts against — a
/// per-minute ceiling (`SCREENING_RATE_LIMIT_PER_MINUTE`) is the unit §19's
/// SLO is framed in, so the window itself isn't a separate config knob.
pub const SCREENING_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Counter: Redis faults while checking the limit — every one of these means
/// the request that triggered it was admitted anyway (fail-open, see module
/// docs). A non-zero rate is a Redis health signal, not a billing gap.
pub const SCREENING_RATE_LIMIT_ERRORS_TOTAL: &str = "screening_rate_limit_errors_total";

/// The outcome of a rate-limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Allowed,
    Limited,
}

/// The dedicated screening-endpoint limiter. Object-safe so `AppState` holds
/// it as `Arc<dyn ScreeningRateLimiter>`, same shape as `PolicyStore`/`RuleStore`.
#[async_trait]
pub trait ScreeningRateLimiter: Send + Sync {
    /// Count one request for `customer` against the window; `Limited` means
    /// the caller must not proceed to the handler this call.
    async fn admit(&self, customer: CustomerId) -> Admission;

    /// How long a rejected caller should wait before retrying — the value the
    /// middleware puts in the `Retry-After` header on a 429. A fixed-window
    /// limiter's safe, standards-compliant answer is the window length (the
    /// active window resets at most one window from now); reading the exact
    /// remaining TTL would cost a second Redis round-trip on the p50-critical
    /// path, which isn't worth it. Defaults to [`SCREENING_RATE_LIMIT_WINDOW`]
    /// so the in-memory double and any future adapter inherit a sane value;
    /// [`RedisScreeningRateLimiter`] overrides it with its configured window.
    fn retry_after(&self) -> Duration {
        SCREENING_RATE_LIMIT_WINDOW
    }
}

/// Redis-backed [`ScreeningRateLimiter`]. Cheap to clone — [`ConnectionManager`]
/// is a self-reconnecting multiplexed handle, the same one `intelligence`'s
/// `RedisHotCache` and `rule_engine`'s `RedisTemporalStore` hold.
#[derive(Clone)]
pub struct RedisScreeningRateLimiter {
    conn: ConnectionManager,
    limit: u32,
    window: Duration,
}

impl RedisScreeningRateLimiter {
    /// `limit` requests per `window`, per customer.
    pub fn new(conn: ConnectionManager, limit: u32, window: Duration) -> Self {
        Self {
            conn,
            limit,
            window,
        }
    }

    fn key(customer: CustomerId) -> String {
        format!("screen_rl:{customer}")
    }
}

#[async_trait]
impl ScreeningRateLimiter for RedisScreeningRateLimiter {
    async fn admit(&self, customer: CustomerId) -> Admission {
        let mut conn = self.conn.clone();
        let key = Self::key(customer);

        // One pipelined round-trip (not a transaction — see module docs on
        // why `PEXPIRE ... NX` needs no atomicity with the `INCR` to be
        // correct): bump the counter, and set its expiry only if it doesn't
        // have one yet. The `PEXPIRE` reply is dropped (`.ignore()`); only
        // the `INCR` count is read back.
        let mut pipe = redis::pipe();
        pipe.cmd("INCR").arg(&key);
        pipe.cmd("PEXPIRE")
            .arg(&key)
            .arg(self.window.as_millis() as i64)
            .arg("NX")
            .ignore();

        let result: redis::RedisResult<(u64,)> = pipe.query_async(&mut conn).await;

        match result.map(|(count,)| count) {
            // The 429 counter is emitted by the middleware, not here — see
            // `SCREENING_RATE_LIMITED_TOTAL`'s docs on why the decision metric
            // lives at the seam, not in the adapter.
            Ok(count) if count > u64::from(self.limit) => Admission::Limited,
            Ok(_) => Admission::Allowed,
            Err(err) => {
                metrics::counter!(SCREENING_RATE_LIMIT_ERRORS_TOTAL).increment(1);
                tracing::warn!(
                    %customer,
                    error = %err,
                    "screening rate limiter unreachable; failing open"
                );
                Admission::Allowed
            }
        }
    }

    fn retry_after(&self) -> Duration {
        self.window
    }
}

/// Layered only on `POST /v1/address/{addr}/screen` (see `http::build_router`)
/// — never the whole router — and only inside the JWT gate, so `customer` is
/// always present. A rejection is returned before the handler runs, saving
/// the intelligence/policy-store round-trips the p50 budget would otherwise
/// have spent on a call that was never going to be admitted.
pub async fn enforce_screening_rate_limit(
    State(limiter): State<Arc<dyn ScreeningRateLimiter>>,
    Extension(customer): Extension<CustomerId>,
    req: Request,
    next: Next,
) -> Response {
    match limiter.admit(customer).await {
        Admission::Allowed => next.run(req).await,
        Admission::Limited => {
            metrics::counter!(SCREENING_RATE_LIMITED_TOTAL).increment(1);
            too_many_requests_response(limiter.retry_after())
        }
    }
}

/// Build the 429 with a `Retry-After` header (seconds). Clients and SDKs honour
/// it to back off correctly instead of hot-looping into the same rejection —
/// a bare 429 leaves them guessing. `max(1)` so a sub-second window (tests) or
/// a rounding-to-zero can never advertise `Retry-After: 0`.
fn too_many_requests_response(retry_after: Duration) -> Response {
    let seconds = retry_after.as_secs().max(1);
    let mut response =
        ApiError::too_many_requests("screening rate limit exceeded; retry later").into_response();
    response.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from(seconds),
    );
    response
}

/// In-memory [`ScreeningRateLimiter`] double — same fixed-window counting
/// semantics as the Redis implementation (minus the wall-clock expiry, which
/// no test in this crate needs), so a test that passes here means the
/// consumer logic is right. Compiled for this crate's own unit tests and,
/// behind the `test-util` feature, for its integration tests — mirrors
/// `policy_store::test_util`.
#[cfg(any(test, feature = "test-util"))]
pub mod test_util {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    pub struct InMemoryRateLimiter {
        limit: u32,
        counts: Mutex<HashMap<CustomerId, u32>>,
    }

    impl InMemoryRateLimiter {
        pub fn new(limit: u32) -> Self {
            Self {
                limit,
                counts: Mutex::new(HashMap::new()),
            }
        }

        /// Never limits — the default for handler tests that aren't
        /// exercising rate-limiting behaviour, so the limit can't interfere.
        pub fn unbounded() -> Self {
            Self::new(u32::MAX)
        }
    }

    #[async_trait]
    impl ScreeningRateLimiter for InMemoryRateLimiter {
        async fn admit(&self, customer: CustomerId) -> Admission {
            let mut counts = self.counts.lock().expect("rate limiter lock");
            let count = counts.entry(customer).or_insert(0);
            *count += 1;
            if *count > self.limit {
                Admission::Limited
            } else {
                Admission::Allowed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::InMemoryRateLimiter;
    use super::*;

    fn customer(n: u128) -> CustomerId {
        CustomerId(uuid::Uuid::from_u128(n))
    }

    #[tokio::test]
    async fn admits_up_to_the_limit_then_rejects() {
        let limiter = InMemoryRateLimiter::new(2);
        let who = customer(1);

        assert_eq!(limiter.admit(who).await, Admission::Allowed);
        assert_eq!(limiter.admit(who).await, Admission::Allowed);
        assert_eq!(limiter.admit(who).await, Admission::Limited);
    }

    #[tokio::test]
    async fn limits_are_isolated_per_customer() {
        let limiter = InMemoryRateLimiter::new(1);

        assert_eq!(limiter.admit(customer(1)).await, Admission::Allowed);
        // A different customer's own budget is untouched by customer 1's use.
        assert_eq!(limiter.admit(customer(2)).await, Admission::Allowed);
        assert_eq!(limiter.admit(customer(1)).await, Admission::Limited);
    }

    #[tokio::test]
    async fn unbounded_never_limits() {
        let limiter = InMemoryRateLimiter::unbounded();
        let who = customer(1);
        for _ in 0..1000 {
            assert_eq!(limiter.admit(who).await, Admission::Allowed);
        }
    }
}
