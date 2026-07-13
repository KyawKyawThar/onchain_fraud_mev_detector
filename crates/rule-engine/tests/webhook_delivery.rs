//! The t5 webhook adapter against a real (loopback) HTTP endpoint: the
//! delivery-policy contract from `webhook.rs`'s module docs, pinned —
//! 2xx delivers the documented payload, 4xx/redirects reject without retry,
//! 5xx/transport faults retry with backoff up to the attempt bound, and the
//! §12 channels log instead of speaking HTTP.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use events::primitives::{AccountAddress, AlertId, CustomerId, RuleId};
use rule_engine::action::{ActionSink, DeliveryError, RuleAlert};
use rule_engine::model::Action;
use rule_engine::webhook::{WebhookActionSink, WebhookConfig};
use tokio_util::sync::CancellationToken;

/// What the throwaway endpoint saw and what it should answer. Statuses are
/// consumed per request, oldest first; when they run out it answers 200 — so
/// a test states only the interesting prefix.
struct Hook {
    bodies: Mutex<Vec<serde_json::Value>>,
    statuses: Mutex<VecDeque<u16>>,
}

impl Hook {
    fn requests(&self) -> Vec<serde_json::Value> {
        self.bodies.lock().expect("bodies lock").clone()
    }
}

async fn receive(State(hook): State<Arc<Hook>>, Json(body): Json<serde_json::Value>) -> StatusCode {
    hook.bodies.lock().expect("bodies lock").push(body);
    let status = hook
        .statuses
        .lock()
        .expect("statuses lock")
        .pop_front()
        .unwrap_or(200);
    StatusCode::from_u16(status).expect("test status code")
}

/// Bind a loopback endpoint answering `statuses` in order (then 200).
async fn spawn_hook(statuses: &[u16]) -> (String, Arc<Hook>) {
    let hook = Arc::new(Hook {
        bodies: Mutex::new(Vec::new()),
        statuses: Mutex::new(statuses.iter().copied().collect()),
    });
    let app = Router::new()
        .route("/hook", post(receive))
        .with_state(Arc::clone(&hook));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve hook");
    });
    (format!("http://{addr}/hook"), hook)
}

/// A sink tuned for tests: real policy, millisecond backoff, live token.
fn sink(attempts: u32) -> WebhookActionSink {
    sink_with(attempts, Duration::from_millis(1), CancellationToken::new())
}

fn sink_with(
    attempts: u32,
    retry_backoff: Duration,
    shutdown: CancellationToken,
) -> WebhookActionSink {
    WebhookActionSink::new(
        WebhookConfig {
            timeout: Duration::from_secs(2),
            attempts,
            retry_backoff,
        },
        shutdown,
    )
    .expect("build sink")
}

fn alert() -> RuleAlert {
    RuleAlert {
        alert_id: AlertId(uuid::Uuid::from_u128(1)),
        rule_id: RuleId(uuid::Uuid::from_u128(2)),
        owner: CustomerId(uuid::Uuid::from_u128(3)),
        address: AccountAddress::repeat_byte(0xAB),
        rule_name: "Large transfer then mixer".into(),
        explanation: "rule matched over blocks [100, 150]".into(),
        matched_blocks: vec![100, 150],
    }
}

fn webhook(url: &str) -> Action {
    Action::WebhookAlert { url: url.into() }
}

/// The happy path: one POST, the documented JSON payload — and no `owner`
/// field (routing already isolated the delivery; see webhook.rs's docs).
#[tokio::test]
async fn delivers_the_alert_payload_once() {
    let (url, hook) = spawn_hook(&[]).await;
    sink(3)
        .deliver(&alert(), &webhook(&url))
        .await
        .expect("delivered");

    let requests = hook.requests();
    assert_eq!(requests.len(), 1, "a 2xx is not retried");
    let body = &requests[0];
    assert_eq!(body["alert_id"], "00000000-0000-0000-0000-000000000001");
    assert_eq!(body["rule_id"], "00000000-0000-0000-0000-000000000002");
    assert_eq!(body["rule_name"], "Large transfer then mixer");
    assert_eq!(
        body["address"],
        "0xabababababababababababababababababababab"
    );
    assert_eq!(body["explanation"], "rule matched over blocks [100, 150]");
    assert_eq!(body["matched_blocks"], serde_json::json!([100, 150]));
    assert!(body.get("owner").is_none(), "owner never goes on the wire");
}

/// A 4xx is the endpoint refusing the alert: permanent, attempted once.
#[tokio::test]
async fn client_error_rejects_without_retry() {
    let (url, hook) = spawn_hook(&[410]).await;
    let err = sink(3)
        .deliver(&alert(), &webhook(&url))
        .await
        .expect_err("rejected");
    assert!(matches!(err, DeliveryError::Rejected { .. }), "{err}");
    assert!(!err.is_transient());
    assert_eq!(hook.requests().len(), 1, "rejections are not retried");
}

/// Redirects are never followed — a redirecting endpoint is a rejection (the
/// module docs' anti-lure policy).
#[tokio::test]
async fn redirect_rejects_without_retry() {
    let (url, hook) = spawn_hook(&[302]).await;
    let err = sink(3)
        .deliver(&alert(), &webhook(&url))
        .await
        .expect_err("rejected");
    assert!(matches!(err, DeliveryError::Rejected { .. }), "{err}");
    assert_eq!(hook.requests().len(), 1);
}

/// 5xx is transient: retried with backoff until the endpoint recovers.
#[tokio::test]
async fn server_errors_retry_until_success() {
    let (url, hook) = spawn_hook(&[500, 503]).await;
    sink(3)
        .deliver(&alert(), &webhook(&url))
        .await
        .expect("third attempt lands");
    assert_eq!(hook.requests().len(), 3, "two retries then success");
}

/// The retry bound holds: a persistently failing endpoint surfaces a
/// transient error after exactly `attempts` tries (the emitter logs it; §12
/// owns durable receipts).
#[tokio::test]
async fn exhausted_retries_surface_a_transport_error() {
    let (url, hook) = spawn_hook(&[500, 500]).await;
    let err = sink(2)
        .deliver(&alert(), &webhook(&url))
        .await
        .expect_err("exhausted");
    assert!(matches!(err, DeliveryError::Transport { .. }), "{err}");
    assert!(err.is_transient());
    assert_eq!(hook.requests().len(), 2, "bounded by the attempt budget");
}

/// Shutdown races the retry backoff: a cancelled token surfaces the last
/// transport error immediately instead of holding the fire-drain task
/// through the remaining backoff budget.
#[tokio::test]
async fn shutdown_cuts_the_retry_backoff_short() {
    let (url, hook) = spawn_hook(&[500, 500]).await;
    let shutdown = CancellationToken::new();
    shutdown.cancel();
    // A 60s backoff that is never slept: cancellation wins the race.
    let sink = sink_with(3, Duration::from_secs(60), shutdown);

    let started = std::time::Instant::now();
    let err = sink
        .deliver(&alert(), &webhook(&url))
        .await
        .expect_err("cancelled mid-retry");
    assert!(matches!(err, DeliveryError::Transport { .. }), "{err}");
    assert_eq!(hook.requests().len(), 1, "no retry after the stop signal");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "returned without sleeping the backoff"
    );
}

/// A dead endpoint (connection refused) is a transport fault, not a panic.
#[tokio::test]
async fn unreachable_endpoint_is_a_transport_error() {
    // Bind then drop: the port is real but nothing listens on it.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);

    let err = sink(1)
        .deliver(&alert(), &webhook(&format!("http://{addr}/hook")))
        .await
        .expect_err("unreachable");
    assert!(matches!(err, DeliveryError::Transport { .. }), "{err}");
    assert!(err.is_transient());
}

/// The §12 channels (email/Slack/tagging) log the would-be delivery and
/// succeed — no HTTP is spoken for them.
#[tokio::test]
async fn non_webhook_channels_log_and_succeed() {
    let sink = sink(1);
    for action in [
        Action::EmailAlert {
            to: "ops@example.com".into(),
        },
        Action::SlackAlert {
            channel: "#compliance".into(),
        },
        Action::TagAddress {
            label: "watched".into(),
        },
    ] {
        sink.deliver(&alert(), &action)
            .await
            .expect("logged, not failed");
    }
}
