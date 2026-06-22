//! Hermetic failover + circuit-breaking tests for the RPC pool (§5, adapter #3).
//!
//! Each "endpoint" is a tiny in-process axum JSON-RPC server on an ephemeral
//! 127.0.0.1 port — no real node, no external network — so the pool's failover,
//! breaker-trip and wrong-chain quarantine behaviour is exercised against real
//! HTTP through the real alloy provider, deterministically.

use std::time::{Duration, Instant};

use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use events::primitives::Chain;
use ingestion::source::circuit::BreakerConfig;
use ingestion::source::rpc::RpcFailoverPool;
use ingestion::source::{ChainSource, SourceError};
use serde_json::{json, Value};
use url::Url;

/// How a mock endpoint behaves.
enum Mock {
    /// Healthy: answers `eth_chainId` / `eth_blockNumber` with these values.
    Up { chain_id: u64, block_number: u64 },
    /// Always returns HTTP 500 — a transport error the breaker counts.
    Down,
}

/// Spawn a mock endpoint and return its base URL.
async fn spawn(mock: Mock) -> Url {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let app = match mock {
        Mock::Down => {
            Router::new().route("/", post(|| async { StatusCode::INTERNAL_SERVER_ERROR }))
        }
        Mock::Up {
            chain_id,
            block_number,
        } => Router::new().route(
            "/",
            post(move |Json(req): Json<Value>| async move {
                let id = req.get("id").cloned().unwrap_or_else(|| json!(1));
                let result = match req.get("method").and_then(Value::as_str) {
                    Some("eth_chainId") => json!(format!("0x{chain_id:x}")),
                    Some("eth_blockNumber") => json!(format!("0x{block_number:x}")),
                    _ => Value::Null,
                };
                Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
            }),
        ),
    };

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Url::parse(&format!("http://{addr}/")).unwrap()
}

fn timeout() -> Duration {
    Duration::from_secs(2)
}

#[tokio::test]
async fn fails_over_to_a_healthy_endpoint_and_trips_the_bad_one() {
    let bad = spawn(Mock::Down).await;
    let good = spawn(Mock::Up {
        chain_id: 1,
        block_number: 100,
    })
    .await;

    let breaker = BreakerConfig {
        failure_threshold: 3,
        open_cooldown: Duration::from_secs(30),
        success_threshold: 1,
    };
    // Bad is first in preference order, so every call hits it before failing over.
    let pool = RpcFailoverPool::new(&[bad, good], Chain::ETHEREUM, timeout(), breaker);

    // Both endpoints routable to begin with.
    assert_eq!(pool.routable_count(Instant::now()), 2);

    // Each call fails over from the dead endpoint to the healthy one.
    for _ in 0..3 {
        assert_eq!(pool.latest_block_number().await.unwrap(), 100);
    }

    // Three consecutive failures trip the bad endpoint's breaker open: only the
    // healthy endpoint remains routable, yet calls still succeed.
    assert_eq!(pool.routable_count(Instant::now()), 1);
    assert_eq!(pool.latest_block_number().await.unwrap(), 100);
}

#[tokio::test]
async fn errors_when_every_endpoint_is_down() {
    let bad = spawn(Mock::Down).await;
    let breaker = BreakerConfig {
        failure_threshold: 2,
        open_cooldown: Duration::from_secs(30),
        success_threshold: 1,
    };
    let pool = RpcFailoverPool::new(&[bad], Chain::ETHEREUM, timeout(), breaker);

    // First failure: still closed but the call fails (the only endpoint is down).
    assert!(matches!(
        pool.latest_block_number().await,
        Err(SourceError::AllEndpointsDown { routable: 1, .. })
    ));
    // Second failure trips the breaker; now nothing is routable.
    let _ = pool.latest_block_number().await;
    assert_eq!(pool.routable_count(Instant::now()), 0);

    match pool.latest_block_number().await {
        Err(SourceError::AllEndpointsDown {
            routable, total, ..
        }) => {
            assert_eq!(routable, 0, "circuit-broken endpoint must not be attempted");
            assert_eq!(total, 1);
        }
        other => panic!("expected AllEndpointsDown, got {other:?}"),
    }
}

#[tokio::test]
async fn quarantines_an_endpoint_on_the_wrong_chain() {
    let wrong = spawn(Mock::Up {
        chain_id: 999,
        block_number: 5,
    })
    .await;
    let right = spawn(Mock::Up {
        chain_id: 1,
        block_number: 100,
    })
    .await;

    // Wrong-chain endpoint is first in preference order.
    let pool = RpcFailoverPool::new(
        &[wrong, right],
        Chain::ETHEREUM,
        timeout(),
        BreakerConfig::default(),
    );

    pool.health_check_once().await;
    assert!(!pool.all_quarantined(), "the right-chain endpoint survives");
    assert_eq!(
        pool.routable_count(Instant::now()),
        1,
        "the wrong-chain endpoint is quarantined out of rotation"
    );

    // Calls must reach the right-chain endpoint (100), never the wrong one (5).
    assert_eq!(pool.latest_block_number().await.unwrap(), 100);
}
