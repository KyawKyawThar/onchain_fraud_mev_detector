//! [`RedisScreeningRateLimiter`]'s contract against real Redis (§19,
//! Sprint 14 t4) — the same discipline as `rule-engine`'s/`intelligence`'s
//! Redis-backed store tests: the in-memory double's unit tests (`rate_limit.rs`)
//! only mean anything because the real implementation provably honours the
//! same semantics, proved here via testcontainers (`#[ignore]`,
//! `just test-integration`).

use std::time::Duration;

use events::primitives::CustomerId;
use server::rate_limit::{scope, Admission, RedisScreeningRateLimiter, ScreeningRateLimiter};
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerRequest;
use testcontainers::ImageExt;
use testcontainers_modules::redis::{Redis, REDIS_PORT};
use uuid::Uuid;

fn customer(n: u128) -> CustomerId {
    CustomerId(Uuid::from_u128(n))
}

/// `testcontainers_modules::redis::Redis`'s *default* tag is `5.0`, which
/// doesn't understand `PEXPIRE key ms NX` (added in Redis 7.0 — see
/// `rate_limit.rs`'s module docs on why the limiter needs it). Pinned to the
/// exact tag production runs (`deploy/docker-compose.yml`'s `redis:8.6-alpine`).
fn redis_image() -> ContainerRequest<Redis> {
    Redis::default().with_tag("8.6-alpine")
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Redis)"]
async fn admits_up_to_the_limit_then_rejects_and_isolates_per_customer() {
    let container = redis_image().start().await.expect("start Redis");
    let port = container
        .get_host_port_ipv4(REDIS_PORT)
        .await
        .expect("Redis port");
    let url = format!("redis://127.0.0.1:{port}");
    let conn = db::redis::connect(&url).await.expect("connect");
    let limiter = RedisScreeningRateLimiter::new(conn, 2, Duration::from_secs(60));

    let alice = customer(1);
    let bob = customer(2);

    assert_eq!(
        limiter.admit(scope::SCREEN, alice).await,
        Admission::Allowed
    );
    assert_eq!(
        limiter.admit(scope::SCREEN, alice).await,
        Admission::Allowed
    );
    assert_eq!(
        limiter.admit(scope::SCREEN, alice).await,
        Admission::Limited
    );

    // Bob's own budget is untouched by Alice exhausting hers — separate keys.
    assert_eq!(limiter.admit(scope::SCREEN, bob).await, Admission::Allowed);
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Redis)"]
async fn the_window_expires_and_admits_again() {
    let container = redis_image().start().await.expect("start Redis");
    let port = container
        .get_host_port_ipv4(REDIS_PORT)
        .await
        .expect("Redis port");
    let url = format!("redis://127.0.0.1:{port}");
    let conn = db::redis::connect(&url).await.expect("connect");
    let limiter = RedisScreeningRateLimiter::new(conn, 1, Duration::from_millis(200));

    let who = customer(1);
    assert_eq!(limiter.admit(scope::SCREEN, who).await, Admission::Allowed);
    assert_eq!(limiter.admit(scope::SCREEN, who).await, Admission::Limited);

    tokio::time::sleep(Duration::from_millis(350)).await;

    // A fresh window: the earlier rejection didn't leave a stuck counter.
    assert_eq!(limiter.admit(scope::SCREEN, who).await, Admission::Allowed);
}
