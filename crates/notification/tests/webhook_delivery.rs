//! The webhook/Slack HTTP delivery policy against a real (loopback) HTTP
//! endpoint — the same shape as `rule-engine/tests/webhook_delivery.rs`: 2xx
//! delivers, 4xx rejects without retry, 5xx retries with backoff then
//! surfaces, and (the §12 addition this service closes) the SSRF guard
//! refuses a loopback/private target unless explicitly allowed.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use event_bus::Transience;
use events::primitives::{AlertId, AlertKind, Chain, CustomerId, Severity};
use notification::delivery::{DeliveryConfig, DeliveryError};
use notification::http_delivery::HttpDelivery;
use notification::model::LifecycleStage;
use notification::notice::Notice;
use tokio_util::sync::CancellationToken;

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
        axum::serve(listener, app).await.expect("serve");
    });
    (format!("http://{addr}/hook"), hook)
}

fn notice() -> Notice {
    Notice {
        dedup_key: AlertId::new().to_string(),
        stage: LifecycleStage::Confirmed,
        kind: Some(AlertKind::Sandwich),
        severity: Some(Severity::Critical),
        chain: Chain::ETHEREUM,
        addresses: vec![],
        owner: Some(CustomerId::new()),
        summary: "confirmed sandwich".into(),
        occurred_at: chrono::Utc::now(),
    }
}

fn fast_config() -> DeliveryConfig {
    DeliveryConfig {
        timeout: Duration::from_secs(2),
        attempts: 3,
        retry_backoff: Duration::from_millis(5),
    }
}

fn delivery(allow_private: bool) -> HttpDelivery {
    let sink = HttpDelivery::new(fast_config(), CancellationToken::new()).expect("build client");
    if allow_private {
        sink.allow_private_targets()
    } else {
        sink
    }
}

#[tokio::test]
async fn a_2xx_response_delivers_the_notice_payload() {
    let (url, hook) = spawn_hook(&[200]).await;
    let sink = delivery(true);
    sink.deliver_webhook(&notice(), &url)
        .await
        .expect("delivered");
    let requests = hook.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["stage"], "confirmed");
}

#[tokio::test]
async fn a_4xx_response_rejects_without_retrying() {
    let (url, hook) = spawn_hook(&[404, 200]).await;
    let sink = delivery(true);
    let err = sink.deliver_webhook(&notice(), &url).await.unwrap_err();
    assert!(matches!(err, DeliveryError::Rejected { .. }));
    assert!(!err.is_transient());
    assert_eq!(
        hook.requests().len(),
        1,
        "no retry on a permanent rejection"
    );
}

#[tokio::test]
async fn a_5xx_response_retries_then_surfaces_if_still_failing() {
    let (url, hook) = spawn_hook(&[500, 500, 500]).await;
    let sink = delivery(true);
    let err = sink.deliver_webhook(&notice(), &url).await.unwrap_err();
    assert!(matches!(err, DeliveryError::Transport { .. }));
    assert_eq!(hook.requests().len(), 3, "retried up to the attempt bound");
}

#[tokio::test]
async fn a_5xx_response_that_recovers_within_the_attempt_bound_delivers() {
    let (url, hook) = spawn_hook(&[500, 200]).await;
    let sink = delivery(true);
    sink.deliver_webhook(&notice(), &url)
        .await
        .expect("delivered on retry");
    assert_eq!(hook.requests().len(), 2);
}

#[tokio::test]
async fn slack_delivers_a_text_payload_to_its_own_webhook_url() {
    let (url, hook) = spawn_hook(&[200]).await;
    let sink = delivery(true);
    sink.deliver_slack(&notice(), &url)
        .await
        .expect("delivered");
    let requests = hook.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0]["text"]
        .as_str()
        .expect("text field")
        .contains("confirmed"));
}

/// The §12 hardening: a loopback/private target is refused *before* any
/// request is attempted, unless a test explicitly opts out via
/// `allow_private_targets()`.
#[tokio::test]
async fn a_loopback_target_is_refused_by_the_ssrf_guard() {
    let (url, hook) = spawn_hook(&[200]).await;
    let sink = delivery(false);
    let err = sink.deliver_webhook(&notice(), &url).await.unwrap_err();
    assert!(matches!(err, DeliveryError::Rejected { .. }));
    assert!(!err.is_transient());
    assert!(
        hook.requests().is_empty(),
        "refused before any request landed"
    );
}
