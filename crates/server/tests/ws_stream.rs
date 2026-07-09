//! `WS /v1/stream` lifecycle (§11) — explicit end-to-end coverage of the
//! contract documented in `src/http.rs`: a client that upgrades with a valid
//! bearer token receives the `provisional_alert` → `alert_confirmed` →
//! `alert_retracted` sequence, in order, as tagged JSON frames; a client
//! without a valid token never gets the upgrade.
//!
//! Drives a real `TcpListener` + `axum::serve` (not `ServiceExt::oneshot` —
//! that can't exercise an HTTP `Upgrade`) and a real `tokio-tungstenite`
//! client. Alerts are injected straight onto `AppState::alerts` rather than
//! through a live Kafka broker: `src/stream.rs`'s `Broadcaster` unit tests
//! already cover the envelope → `WsMessage` mapping, so this file's job is
//! purely the WS transport contract.

use std::net::SocketAddr;
use std::time::Duration;

use futures_util::StreamExt;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use secrecy::{ExposeSecret, SecretString};
use server::auth::Claims;
use server::config::JwtConfig;
use server::http::{self, AppState};
use server::intelligence_client::IntelligenceClient;
use server::stream::{AlertConfirmed, AlertRetracted, ProvisionalAlert, WsMessage};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

const TEST_SECRET: &str = "ws-stream-test-secret";
const TEST_ISSUER: &str = "mev";
const RECV_TIMEOUT: Duration = Duration::from_secs(5);

fn jwt_config() -> JwtConfig {
    JwtConfig {
        secret: SecretString::from(TEST_SECRET),
        issuer: TEST_ISSUER.to_owned(),
    }
}

fn valid_bearer() -> String {
    let claims = Claims {
        sub: "test-caller".to_owned(),
        exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
        iss: TEST_ISSUER.to_owned(),
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(jwt_config().secret.expose_secret().as_bytes()),
    )
    .expect("mint test token");
    format!("Bearer {token}")
}

/// Boot the real router on an ephemeral port, returning its address and the
/// broadcast sender the test injects alerts through (the same one
/// `crate::stream::run` would feed from Kafka in production).
async fn spawn_server() -> (SocketAddr, tokio::sync::broadcast::Sender<WsMessage>) {
    let (alerts_tx, _) = tokio::sync::broadcast::channel(16);

    let state = AppState {
        intelligence: IntelligenceClient::connect_lazy("http://127.0.0.1:50051".to_owned())
            .expect("lazy channel never fails to construct"),
        http_client: reqwest::Client::new(),
        event_store_url: "http://127.0.0.1:8081".to_owned(),
        simulation_url: "http://127.0.0.1:8082".to_owned(),
        jwt: jwt_config(),
        alerts: alerts_tx.clone(),
    };

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        axum::serve(listener, http::router(state))
            .await
            .expect("test server");
    });

    (addr, alerts_tx)
}

fn sample_provisional_alert() -> WsMessage {
    WsMessage::ProvisionalAlert(ProvisionalAlert {
        alert_id: events::primitives::AlertId::new(),
        kind: events::primitives::AlertKind::Sandwich,
        addresses: vec![alloy_primitives::Address::repeat_byte(0x11)],
        confidence: 0.7,
        chain: 1,
        occurred_at_unix_millis: 1_700_000_000_000,
    })
}

fn sample_alert_confirmed() -> WsMessage {
    WsMessage::AlertConfirmed(AlertConfirmed {
        incident_id: events::primitives::IncidentId::new(),
        alert_id: events::primitives::AlertId::new(),
        kind: events::primitives::AlertKind::Sandwich,
        txs: vec![alloy_primitives::B256::repeat_byte(0x22)],
        profit: 12.5,
        victim_loss: 9.0,
        severity: events::primitives::Severity::High,
        chain: 1,
        occurred_at_unix_millis: 1_700_000_001_000,
    })
}

fn sample_alert_retracted() -> WsMessage {
    WsMessage::AlertRetracted(AlertRetracted {
        incident_id: events::primitives::IncidentId::new(),
        reason: "block reverted".to_owned(),
        chain: 1,
        occurred_at_unix_millis: 1_700_000_002_000,
    })
}

#[tokio::test]
async fn lifecycle_is_delivered_in_order_provisional_confirmed_retracted() {
    let (addr, alerts_tx) = spawn_server().await;

    let mut request = format!("ws://{addr}/v1/stream")
        .into_client_request()
        .expect("build WS request");
    request
        .headers_mut()
        .insert("Authorization", valid_bearer().parse().expect("header"));

    let (mut ws, response) = tokio_tungstenite::connect_async(request)
        .await
        .expect("authorized client must be able to upgrade");
    assert_eq!(response.status(), 101, "must be a successful WS upgrade");

    let provisional = sample_provisional_alert();
    let confirmed = sample_alert_confirmed();
    let retracted = sample_alert_retracted();

    for expected in [&provisional, &confirmed, &retracted] {
        // Send after connecting so the broadcast has at least one subscriber;
        // a send before any client has subscribed would just be dropped.
        alerts_tx.send(expected.clone()).expect("broadcast alert");

        let frame = timeout(RECV_TIMEOUT, ws.next())
            .await
            .expect("no alert received before timeout")
            .expect("stream ended unexpectedly")
            .expect("WS transport error");

        let Message::Text(text) = frame else {
            panic!("expected a text frame, got {frame:?}");
        };
        let received: WsMessage = serde_json::from_str(&text).expect("valid WsMessage JSON");
        assert_eq!(&received, expected);
    }

    // The three lifecycle tags, explicitly, in the order the §11 contract
    // documents — the point of this test, not just structural equality above.
    let value = serde_json::to_value(&provisional).unwrap();
    assert_eq!(value["type"], "provisional_alert");
    let value = serde_json::to_value(&confirmed).unwrap();
    assert_eq!(value["type"], "alert_confirmed");
    let value = serde_json::to_value(&retracted).unwrap();
    assert_eq!(value["type"], "alert_retracted");

    ws.close(None).await.ok();
}

#[tokio::test]
async fn missing_bearer_token_is_rejected_before_the_upgrade() {
    let (addr, _alerts_tx) = spawn_server().await;

    let request = format!("ws://{addr}/v1/stream")
        .into_client_request()
        .expect("build WS request");
    // No Authorization header attached.

    let err = tokio_tungstenite::connect_async(request)
        .await
        .expect_err("unauthenticated client must not be upgraded");

    match err {
        tokio_tungstenite::tungstenite::Error::Http(response) => {
            assert_eq!(response.status(), 401);
        }
        other => panic!("expected an HTTP 401 rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn a_lagging_client_is_dropped_from_the_channel_not_the_connection() {
    // A client that never reads still holds its socket open even once its
    // receiver falls behind the broadcast channel's capacity — `RecvError::
    // Lagged` (handled in `http::stream_socket`) must not tear the connection
    // down, only skip the alerts it missed.
    let (addr, alerts_tx) = spawn_server().await;

    let mut request = format!("ws://{addr}/v1/stream")
        .into_client_request()
        .expect("build WS request");
    request
        .headers_mut()
        .insert("Authorization", valid_bearer().parse().expect("header"));
    let (mut ws, _response) = tokio_tungstenite::connect_async(request)
        .await
        .expect("authorized client must be able to upgrade");

    // Flood past the server's channel capacity (16, see `spawn_server`) before
    // reading anything back.
    for _ in 0..64 {
        let _ = alerts_tx.send(sample_provisional_alert());
    }

    let latest = sample_alert_retracted();
    alerts_tx.send(latest.clone()).expect("broadcast alert");

    // The connection must still be alive and eventually deliver *something*
    // (not necessarily `latest` itself, since more sends can race ahead of the
    // subscriber, but the socket must not have been closed by the lag).
    let frame = timeout(RECV_TIMEOUT, ws.next())
        .await
        .expect("connection must survive a lagging receiver")
        .expect("stream ended unexpectedly")
        .expect("WS transport error");
    assert!(matches!(frame, Message::Text(_)));

    ws.close(None).await.ok();
}
