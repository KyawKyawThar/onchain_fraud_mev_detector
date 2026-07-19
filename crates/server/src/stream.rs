//! `WS /v1/stream` (§11) — fans the alert lifecycle out to connected clients:
//! `provisional_alert` → `alert_confirmed` → `alert_retracted`.
//!
//! This module owns the whole WS side end to end: [`WsMessage`] is the wire
//! contract the frontend consumes, [`WsMessage::from_envelope`] is the single
//! place a domain event is mapped onto it, [`Broadcaster`] is the
//! [`EventHandler`] that feeds a [`broadcast::Sender`] from the shared
//! `event_bus::run_consumer` loop (the same consume seam event-store's Kafka
//! ingest uses), and [`stream_ws`]/[`stream_socket`] are the axum handler that
//! subscribes one connection to the channel and pushes each message to its
//! socket. `src/http.rs` only wires the route in; it owns no WS-specific code.
//!
//! Only three of the schema's topics matter here — the confirm/retract result
//! path (§7) is exactly the lifecycle the WebSocket contract documents;
//! everything else on the bus is ignored by [`WsMessage::from_envelope`]
//! returning `None`.

use std::time::Duration;

use alloy_primitives::B256;
use anyhow::{Context, Result};
use async_trait::async_trait;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use event_bus::{run_consumer, EventHandler, Handled};
use events::primitives::{AccountAddress, AlertId, AlertKind, IncidentId, Severity};
use events::{topic_for, DomainEvent, EventEnvelope};
use futures_util::{SinkExt, StreamExt};
use rdkafka::consumer::StreamConsumer;
use rdkafka::ClientConfig;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::config::KafkaConfig;
use crate::http::AppState;

/// Back-off before the consumer retries after a transient fault. There is no
/// downstream store to fail against here (see [`Broadcaster::handle`]), so in
/// practice this only matters if the loop itself hits a broker blip.
const RETRY_BACKOFF: Duration = Duration::from_secs(1);

/// The three lifecycle event types the WebSocket contract documents, in the
/// order they occur. Kept as event *type names* (not [`DomainEvent::VARIANTS`])
/// because this is deliberately a **closed subset** of the schema, not "every
/// topic" — unlike event-store's ingest, which drains everything.
const LIFECYCLE_EVENT_TYPES: [&str; 3] = [
    "PreliminaryAlertCreated",
    "IncidentCreated",
    "IncidentRetracted",
];

/// Build the consumer. Its own group id (distinct from event-store's) means
/// this service's offsets advance independently — a restart resumes the
/// stream from where it left off rather than replaying from the beginning, and
/// a lagging client only ever misses what a *live* broadcast channel drops,
/// not what Kafka retains.
pub fn build_consumer(cfg: &KafkaConfig) -> Result<StreamConsumer> {
    ClientConfig::new()
        .set("bootstrap.servers", &cfg.brokers)
        .set("group.id", &cfg.group_id)
        .set("enable.auto.commit", "false")
        .set("auto.offset.reset", "latest")
        .create()
        .context("creating Kafka consumer for /v1/stream")
}

/// Drain the lifecycle topics and broadcast every mapped event until
/// `shutdown` fires. Topics are provisioned by event-store's `ensure_topics`
/// (§20) — this consumer only ever reads.
pub async fn run(
    consumer: StreamConsumer,
    sender: broadcast::Sender<WsMessage>,
    shutdown: CancellationToken,
) -> Result<()> {
    let topics: Vec<String> = LIFECYCLE_EVENT_TYPES.iter().map(|t| topic_for(t)).collect();
    let topic_refs: Vec<&str> = topics.iter().map(String::as_str).collect();
    tracing::info!(
        topics = ?topic_refs,
        "server /v1/stream consuming the alert lifecycle"
    );
    run_consumer(
        consumer,
        &topic_refs,
        "server-ws-stream",
        RETRY_BACKOFF,
        // Live-tail fan-out: no DLQ — the handler only maps + broadcasts, and
        // every record is already durably owned by the event store.
        None,
        Broadcaster { sender },
        &shutdown,
    )
    .await
}

/// The per-record decision for the WS consumer: map the event and broadcast
/// it. There is no store to fail against, so unlike event-store's `Ingest`
/// this always commits — a mapping miss (an event outside the lifecycle
/// subset) and a "no active receivers" send failure are both expected, not
/// errors.
struct Broadcaster {
    sender: broadcast::Sender<WsMessage>,
}

#[async_trait]
impl EventHandler for Broadcaster {
    async fn handle(&self, envelope: EventEnvelope) -> Handled {
        if let Some(msg) = WsMessage::from_envelope(&envelope) {
            // `Err` here only means no client is currently connected — the
            // broadcast is fire-and-forget, not a delivery guarantee (§11 is a
            // live stream, not a replay log; `/v1/audit/incident/{id}` is the
            // durable trail for a client that connects late). Logged at
            // `debug` (not `warn`) since "nobody's watching right now" is
            // routine, not a fault — but still worth a breadcrumb for "is
            // this stream actually reaching anyone".
            if self.sender.send(msg).is_err() {
                tracing::debug!(
                    event_type = envelope.event_type(),
                    "no active /v1/stream subscribers; alert dropped"
                );
            }
        }
        Handled::Commit
    }
}

/// `WS /v1/stream` (§11) — upgrades to a WebSocket and pushes the live alert
/// lifecycle (`provisional_alert` → `alert_confirmed` → `alert_retracted`) to
/// this one connection. Gated by `require_jwt` the same as every other route
/// in `http::build_router`'s `protected` router (the upgrade request is a
/// plain HTTP `GET`, so the bearer check runs before the connection is ever
/// accepted).
pub(crate) async fn stream_ws(State(state): State<AppState>, ws: WebSocketUpgrade) -> Response {
    let alerts = state.alerts.subscribe();
    ws.on_upgrade(move |socket| stream_socket(socket, alerts))
}

/// Encode one alert as a WS text frame — the pure half of the connection
/// loop, split out from [`stream_socket`] so "does this produce the wire JSON
/// a client expects" is unit-testable with no socket involved at all.
fn encode(msg: &WsMessage) -> serde_json::Result<Message> {
    serde_json::to_string(msg).map(|text| Message::Text(text.into()))
}

/// Drive one client connection until it disconnects or the process is
/// shutting down: forward every broadcast alert as a JSON text frame. The
/// socket is split so the receive half can notice a client-initiated close
/// (or a dead TCP connection) *between* alerts rather than only on the next
/// failed send — otherwise a quiet client could linger as a phantom
/// subscriber.
async fn stream_socket(socket: WebSocket, mut alerts: broadcast::Receiver<WsMessage>) {
    let (mut sink, mut source) = socket.split();
    loop {
        tokio::select! {
            alert = alerts.recv() => match alert {
                Ok(msg) => {
                    let frame = match encode(&msg) {
                        Ok(frame) => frame,
                        Err(err) => {
                            tracing::error!(error = %err, "failed to encode WS alert; skipping");
                            continue;
                        }
                    };
                    if sink.send(frame).await.is_err() {
                        return; // client gone
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    // The channel dropped alerts this client couldn't keep up
                    // with; `/v1/audit/incident/{id}` is the durable trail
                    // for what was missed (§11 — the stream itself is not a
                    // replay log).
                    tracing::warn!(skipped, "WS client lagged; alerts dropped");
                }
                Err(broadcast::error::RecvError::Closed) => return,
            },
            incoming = source.next() => match incoming {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
                Some(Ok(_)) => {} // no client-to-server protocol; ignore anything sent
            },
        }
    }
}

/// The `WS /v1/stream` wire message (§11). Internally tagged on `type` so a
/// client routes on one field without a nested `payload` — the tag values are
/// exactly the three the contract names.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsMessage {
    ProvisionalAlert(ProvisionalAlert),
    AlertConfirmed(AlertConfirmed),
    AlertRetracted(AlertRetracted),
}

impl WsMessage {
    /// Map a decoded envelope onto the WS wire contract, or `None` for
    /// anything outside the three-event lifecycle. Reuses the domain events'
    /// own field types (`AccountAddress`, `B256`, `AlertKind`, …) rather than
    /// re-deriving a wire shape, so this stays byte-for-byte consistent with
    /// how the same fields already serialize on `/v1/audit/incident/{id}`.
    pub fn from_envelope(envelope: &EventEnvelope) -> Option<Self> {
        let chain = envelope.chain.id();
        let occurred_at_unix_millis = envelope.occurred_at.timestamp_millis();

        match &envelope.payload {
            DomainEvent::PreliminaryAlertCreated(e) => {
                Some(WsMessage::ProvisionalAlert(ProvisionalAlert {
                    alert_id: e.alert_id,
                    kind: e.kind,
                    addresses: e.addresses.clone(),
                    confidence: e.confidence.get(),
                    chain,
                    occurred_at_unix_millis,
                }))
            }
            DomainEvent::IncidentCreated(e) => Some(WsMessage::AlertConfirmed(AlertConfirmed {
                incident_id: e.incident_id,
                alert_id: e.alert_id,
                kind: e.kind,
                txs: e.txs.clone(),
                profit: e.profit,
                victim_loss: e.victim_loss,
                severity: e.severity,
                chain,
                occurred_at_unix_millis,
            })),
            DomainEvent::IncidentRetracted(e) => Some(WsMessage::AlertRetracted(AlertRetracted {
                incident_id: e.incident_id,
                reason: e.reason.clone(),
                chain,
                occurred_at_unix_millis,
            })),
            _ => None,
        }
    }
}

/// Fast path, unconfirmed (§6/§11). Mirrors
/// [`events::detection::PreliminaryAlertCreated`] plus envelope metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvisionalAlert {
    pub alert_id: AlertId,
    pub kind: AlertKind,
    pub addresses: Vec<AccountAddress>,
    pub confidence: f64,
    pub chain: u64,
    pub occurred_at_unix_millis: i64,
}

/// Simulation confirmed the provisional alert (§7/§11) — upgrades it. Mirrors
/// [`events::simulation::IncidentCreated`] plus envelope metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertConfirmed {
    pub incident_id: IncidentId,
    pub alert_id: AlertId,
    pub kind: AlertKind,
    pub txs: Vec<B256>,
    pub profit: f64,
    pub victim_loss: f64,
    pub severity: Severity,
    pub chain: u64,
    pub occurred_at_unix_millis: i64,
}

/// The provisional alert was wrong — remove it from the UI (§7/§11). Mirrors
/// [`events::simulation::IncidentRetracted`] plus envelope metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertRetracted {
    pub incident_id: IncidentId,
    pub reason: String,
    pub chain: u64,
    pub occurred_at_unix_millis: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use events::detection::PreliminaryAlertCreated;
    use events::primitives::{Chain, Confidence, DetectorRef};
    use events::simulation::{IncidentCreated, IncidentRetracted};
    use serde_json::json;

    fn detector() -> DetectorRef {
        DetectorRef {
            id: "sandwich".to_owned(),
            version: "1".to_owned(),
            config_hash: "abc".to_owned(),
        }
    }

    #[test]
    fn maps_preliminary_alert_created_to_provisional_alert() {
        let alert_id = AlertId::new();
        let envelope = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::PreliminaryAlertCreated(PreliminaryAlertCreated {
                alert_id,
                detector: detector(),
                addresses: vec![AccountAddress::repeat_byte(0x11)],
                kind: AlertKind::Sandwich,
                confidence: Confidence::new(0.8),
                provisional: true,
            }),
        );

        let msg = WsMessage::from_envelope(&envelope).expect("mapped");
        let value = serde_json::to_value(&msg).unwrap();

        assert_eq!(value["type"], "provisional_alert");
        assert_eq!(value["alert_id"], json!(alert_id.to_string()));
        assert_eq!(value["kind"], "sandwich");
        assert_eq!(value["confidence"], 0.8);
        assert_eq!(value["chain"], 1);
    }

    #[test]
    fn maps_incident_created_to_alert_confirmed() {
        let incident_id = IncidentId::new();
        let alert_id = AlertId::new();
        let envelope = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::IncidentCreated(IncidentCreated {
                incident_id,
                alert_id,
                kind: AlertKind::Sandwich,
                txs: vec![B256::repeat_byte(0x22)],
                profit: 12.5,
                victim_loss: 9.0,
                severity: Severity::High,
            }),
        );

        let msg = WsMessage::from_envelope(&envelope).expect("mapped");
        let value = serde_json::to_value(&msg).unwrap();

        assert_eq!(value["type"], "alert_confirmed");
        assert_eq!(value["incident_id"], json!(incident_id.to_string()));
        assert_eq!(value["alert_id"], json!(alert_id.to_string()));
        assert_eq!(value["severity"], "high");
        assert_eq!(value["profit"], 12.5);
        assert_eq!(value["victim_loss"], 9.0);
    }

    #[test]
    fn maps_incident_retracted_to_alert_retracted() {
        let incident_id = IncidentId::new();
        let envelope = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::IncidentRetracted(IncidentRetracted {
                incident_id,
                reason: "block reverted".to_owned(),
            }),
        );

        let msg = WsMessage::from_envelope(&envelope).expect("mapped");
        let value = serde_json::to_value(&msg).unwrap();

        assert_eq!(value["type"], "alert_retracted");
        assert_eq!(value["incident_id"], json!(incident_id.to_string()));
        assert_eq!(value["reason"], "block reverted");
    }

    #[test]
    fn ignores_events_outside_the_lifecycle() {
        let envelope = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::BlockFinalized(events::chain::BlockFinalized {
                block: events::primitives::BlockRef::new(1, Default::default()),
            }),
        );
        assert_eq!(WsMessage::from_envelope(&envelope), None);
    }

    #[tokio::test]
    async fn broadcaster_forwards_mapped_events_and_always_commits() {
        let (sender, mut receiver) = broadcast::channel(4);
        let broadcaster = Broadcaster { sender };

        let envelope = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::IncidentRetracted(IncidentRetracted {
                incident_id: IncidentId::new(),
                reason: "reorg".to_owned(),
            }),
        );
        let handled = broadcaster.handle(envelope.clone()).await;

        assert_eq!(handled, Handled::Commit);
        let received = receiver.recv().await.expect("broadcast delivered");
        assert_eq!(received, WsMessage::from_envelope(&envelope).unwrap());
    }

    #[tokio::test]
    async fn broadcaster_commits_even_with_no_active_receivers() {
        // No `receiver` held — `send` errors (no subscribers), which must not
        // be treated as a fault: a live stream with nobody connected is normal.
        let (sender, receiver) = broadcast::channel(4);
        drop(receiver);
        let broadcaster = Broadcaster { sender };

        let envelope = EventEnvelope::new(
            Chain::ETHEREUM,
            DomainEvent::IncidentRetracted(IncidentRetracted {
                incident_id: IncidentId::new(),
                reason: "reorg".to_owned(),
            }),
        );
        assert_eq!(broadcaster.handle(envelope).await, Handled::Commit);
    }

    #[test]
    fn encode_produces_the_type_tagged_json_text_frame() {
        let msg = WsMessage::AlertRetracted(AlertRetracted {
            incident_id: IncidentId::new(),
            reason: "reorg".to_owned(),
            chain: 1,
            occurred_at_unix_millis: 0,
        });

        let frame = encode(&msg).expect("encodes");
        let Message::Text(text) = frame else {
            panic!("expected a text frame, got {frame:?}");
        };
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        assert_eq!(value["type"], "alert_retracted");
    }
}
