//! [`RedisSnapshotStore`]'s contract against real Redis (§11 graceful
//! degradation, readiness Epic D) — the same discipline as
//! `rate_limit_redis.rs`: `degrade.rs`'s paused-clock tests run against the
//! in-memory double, which only means something if the real store provably
//! honours the same semantics (`#[ignore]`, `just test-integration`).

use std::time::Duration;

use chrono::DateTime;
use intelligence::pb::{SanctionMatch, ScreeningFactsReply};
use server::degrade::{FactsSnapshot, RedisSnapshotStore, SnapshotStore};
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerRequest;
use testcontainers::ImageExt;
use testcontainers_modules::redis::{Redis, REDIS_PORT};

/// Pinned to the tag production runs (`deploy/docker-compose.yml`), never the
/// module's `5.0` default — see `rate_limit_redis.rs` for the trap that caused.
fn redis_image() -> ContainerRequest<Redis> {
    Redis::default().with_tag("8.6-alpine")
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Redis)"]
async fn snapshots_replace_expire_and_refuse_corrupt_bytes() {
    let container = redis_image().start().await.expect("start Redis");
    let port = container
        .get_host_port_ipv4(REDIS_PORT)
        .await
        .expect("Redis port");
    let conn = db::redis::connect(&format!("redis://127.0.0.1:{port}"))
        .await
        .expect("connect");
    let ttl = Duration::from_secs(900);
    let store = RedisSnapshotStore::new(conn.clone(), ttl);
    let address = alloy_primitives::Address::repeat_byte(0xAB);

    assert!(
        store.get(&address).await.unwrap().is_none(),
        "an address never screened has no snapshot"
    );

    let first = FactsSnapshot {
        facts: ScreeningFactsReply {
            score: 87,
            confidence: 0.7,
            model_version: "risk-v1".into(),
            sanctions: vec![SanctionMatch {
                list: "ofac_sdn".into(),
                entry: "Evil Corp".into(),
            }],
            ..Default::default()
        },
        observed_at: DateTime::from_timestamp_millis(1_700_000_000_123).unwrap(),
    };
    let newer = FactsSnapshot {
        facts: ScreeningFactsReply {
            score: 12,
            sanctions: vec![],
            ..first.facts.clone()
        },
        observed_at: first.observed_at + chrono::Duration::seconds(5),
    };
    store.put_many(vec![(address, first)]).await.unwrap();
    store
        .put_many(vec![(address, newer.clone())])
        .await
        .unwrap();
    assert_eq!(
        store.get(&address).await.unwrap(),
        Some(newer),
        "a write replaces the snapshot whole — a stale sanctions list must never survive a newer observation"
    );

    // The TTL is the max stale age: a snapshot too old to serve is also gone.
    let key = format!("screen_lkg:{}", intelligence::model::address_key(&address));
    let mut raw = conn.clone();
    let pttl: i64 = redis::cmd("PTTL")
        .arg(&key)
        .query_async(&mut raw)
        .await
        .unwrap();
    assert!(
        pttl > 0 && pttl <= ttl.as_millis() as i64,
        "snapshot TTL must be set to the max stale age, got PTTL {pttl}"
    );

    // Bytes that are not a snapshot are an error, never a zero-score "clean"
    // answer that would decide a withdrawal as `allow`.
    let () = redis::cmd("SET")
        .arg(&key)
        .arg(&b"\xff\xff\xff"[..])
        .query_async(&mut raw)
        .await
        .unwrap();
    assert!(store.get(&address).await.is_err());
}
