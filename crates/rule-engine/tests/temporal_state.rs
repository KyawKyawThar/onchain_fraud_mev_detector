//! The [`TemporalStateStore`] contract (Sprint 9 t3), run twice — the same
//! discipline as `rule_store.rs`: once against the in-memory double (every
//! `cargo test`), once against real Redis via testcontainers (`#[ignore]`,
//! `just test-integration`). A test passing on the double only means anything
//! because the real store provably honours the same semantics.

use event_bus::Transience;
use std::time::Duration;

use alloy_primitives::Address;
use events::primitives::RuleId;
use rule_engine::state_store::{RedisTemporalStore, StateKey, TemporalStateStore};
use rule_engine::temporal::TemporalState;
use rule_engine::test_util::InMemoryTemporalStore;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::redis::{Redis, REDIS_PORT};
use uuid::Uuid;

fn key(rule_byte: u128, addr_byte: u8) -> StateKey {
    StateKey {
        rule_id: RuleId(Uuid::from_u128(rule_byte)),
        address: Address::repeat_byte(addr_byte),
    }
}

const TTL: Duration = Duration::from_secs(600);

/// The semantics every implementation must honour: absent reads as `None`,
/// save replaces whole, keys are independent per (rule, address), clear is
/// idempotent, and `in_flight_keys` lists exactly the live machines.
async fn store_contract(store: &dyn TemporalStateStore) {
    let seq_key = key(1, 0xAA);
    let freq_key = key(2, 0xAA); // same address, different rule
    let other_addr = key(1, 0xBB); // same rule, different address

    // Idle machines read as None; nothing is in flight.
    assert_eq!(store.load(&seq_key).await.expect("cold load"), None);
    assert!(store.in_flight_keys().await.expect("scan").is_empty());

    // Save → load round-trips exactly (the Redis form is JSON — pinned by
    // temporal.rs's serde test; here we prove the store preserves it).
    let seq = TemporalState::Sequence {
        matched: vec![100, 150],
    };
    let freq = TemporalState::Frequency { hits: vec![90] };
    store.save(&seq_key, &seq, TTL).await.expect("save seq");
    store.save(&freq_key, &freq, TTL).await.expect("save freq");
    assert_eq!(
        store.load(&seq_key).await.expect("load seq"),
        Some(seq.clone())
    );
    assert_eq!(store.load(&freq_key).await.expect("load freq"), Some(freq));
    // Keys are per (rule, address): the third combination is untouched.
    assert_eq!(store.load(&other_addr).await.expect("other addr"), None);

    // Replace-whole: a re-save is the new truth, not a merge.
    let advanced = TemporalState::Sequence {
        matched: vec![100, 150, 180],
    };
    store
        .save(&seq_key, &advanced, TTL)
        .await
        .expect("overwrite");
    assert_eq!(
        store.load(&seq_key).await.expect("reload"),
        Some(advanced.clone())
    );

    // The rewind work list is exactly the live machines.
    let mut in_flight = store.in_flight_keys().await.expect("scan");
    in_flight.sort_by_key(|k| (k.rule_id.0, k.address));
    assert_eq!(in_flight, vec![seq_key, freq_key]);

    // Clear drops one machine, leaves the rest, and is idempotent.
    store.clear(&seq_key).await.expect("clear");
    assert_eq!(store.load(&seq_key).await.expect("cleared"), None);
    store.clear(&seq_key).await.expect("clear again");
    assert_eq!(
        store.in_flight_keys().await.expect("scan after clear"),
        vec![freq_key]
    );
}

#[tokio::test]
async fn in_memory_store_honours_the_contract() {
    store_contract(&InMemoryTemporalStore::new()).await;
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Redis)"]
async fn redis_store_honours_the_contract() {
    let container = Redis::default().start().await.expect("start Redis");
    let port = container
        .get_host_port_ipv4(REDIS_PORT)
        .await
        .expect("Redis port");
    let url = format!("redis://127.0.0.1:{port}");
    let store = RedisTemporalStore::connect(&url).await.expect("connect");

    store_contract(&store).await;
}

/// Redis-only semantics the double can't prove: every key lands with its TTL
/// (the §9 boundedness guarantee), a malformed value is a permanent fault,
/// and foreign junk under our prefix doesn't break the rewind scan.
#[tokio::test]
#[ignore = "requires Docker (testcontainers Redis)"]
async fn redis_store_bounds_keys_and_survives_junk() {
    let container = Redis::default().start().await.expect("start Redis");
    let port = container
        .get_host_port_ipv4(REDIS_PORT)
        .await
        .expect("Redis port");
    let url = format!("redis://127.0.0.1:{port}");
    let store = RedisTemporalStore::connect(&url).await.expect("connect");

    let machine = key(7, 0xAB);
    let state = TemporalState::Sequence { matched: vec![100] };
    store.save(&machine, &state, TTL).await.expect("save");

    // Raw client to inspect what actually landed. The key layout is a pinned
    // contract (state_store.rs's unit tests), so the test may name it.
    let raw_key = format!("rules:temporal:{}:{:#x}", machine.rule_id, machine.address);
    let client = redis::Client::open(url.as_str()).expect("client");
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("raw conn");

    // SETEX landed value and bound atomically: TTL is set, ≤ requested.
    let ttl: i64 = redis::cmd("TTL")
        .arg(&raw_key)
        .query_async(&mut conn)
        .await
        .expect("ttl");
    assert!(
        ttl > 0 && ttl <= TTL.as_secs() as i64,
        "key must be TTL-bounded, got {ttl}"
    );

    // A value another build can't have written: load is a *permanent* fault
    // (retrying re-reads the same bytes) — the worker discards, never spins.
    let _: () = redis::cmd("SET")
        .arg(&raw_key)
        .arg("{not temporal state}")
        .query_async(&mut conn)
        .await
        .expect("corrupt");
    let err = store.load(&machine).await.expect_err("malformed must fail");
    assert!(!err.is_transient());

    // Foreign junk under the scan prefix is skipped, not fatal (§15 rewind
    // must survive a shared Redis).
    let _: () = redis::cmd("SET")
        .arg("rules:temporal:not-a-uuid:junk")
        .arg("x")
        .query_async(&mut conn)
        .await
        .expect("junk key");
    let keys = store.in_flight_keys().await.expect("scan with junk");
    assert_eq!(keys, vec![machine]);
}
