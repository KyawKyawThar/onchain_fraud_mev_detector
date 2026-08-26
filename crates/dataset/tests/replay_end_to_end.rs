//! End-to-end: append real events to a real event store, then export a dataset
//! through its real `GET /v1/replay` API.
//!
//! Every other test in this crate feeds the pipeline from `VecEventSource`,
//! which proves the *logic* but stubs the one thing a stub cannot prove: that
//! [`HttpEventSource`] and the event-store handler agree on query-parameter
//! names, cursor-token format, and page JSON. That contract is checked here by
//! serving the store's own `http::router` in-process over a real socket.
//!
//! Marked `#[ignore]` (Docker required); CI's `integration-test` job runs it
//! with `--run-ignored all`.

use std::net::SocketAddr;

use alloy_primitives::B256;
use chrono::{DateTime, Utc};
use dataset::ctx::{Fidelity, ReplayCtxFactory, ReplayCtxSource};
use dataset::sink::CollectingSink;
use dataset::source::{replay_window_types, HttpEventSource};
use dataset::spec::DatasetSpec;
use dataset::{run_export, ExportOptions};
use event_store::http::AppState;
use event_store::store::{build_client, EventStore};
use ml_features::Granularity;
use secrecy::SecretString;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::clickhouse::{ClickHouse, CLICKHOUSE_PORT};
use uuid::Uuid;

use events::chain::{BlockAssembled, BlockReverted};
use events::detection::{DetectorTriggered, PreliminaryAlertCreated};
use events::primitives::{
    AlertId, AlertKind, BlockRef, Chain, Confidence, DetectorRef, IncidentId, Severity,
    SuggestedAction,
};
use events::simulation::{IncidentCreated, IncidentRetracted, SimulationCompleted};
use events::{DomainEvent, EventEnvelope};

const CHAIN: Chain = Chain::ETHEREUM;

fn at(millis: i64) -> DateTime<Utc> {
    // Millisecond precision: the store's `DateTime64(3)` column keeps exactly
    // that, so a coarser fixture would read back shifted.
    DateTime::from_timestamp_millis(1_700_000_000_000 + millis).expect("valid timestamp")
}

fn detector(id: &str) -> DetectorRef {
    DetectorRef {
        id: id.to_owned(),
        version: "1.0.0".to_owned(),
        config_hash: "cafe".to_owned(),
    }
}

fn block(n: u64) -> BlockRef {
    BlockRef::new(n, B256::repeat_byte(n as u8))
}

fn tx(b: u8) -> B256 {
    B256::repeat_byte(b)
}

fn envelope(seq: u32, payload: DomainEvent) -> EventEnvelope {
    EventEnvelope::with_metadata(
        Uuid::from_u128(u128::from(seq)),
        at(i64::from(seq) * 1_000),
        CHAIN,
        payload,
    )
}

/// A window spanning two blocks, exercising every outcome the label rule can
/// reach plus two it must exclude:
///
/// - block 1: a **confirmed** finding (tx 1, tx 2) and a **refuted** one (tx 3)
/// - block 2: a **retracted** finding (tx 4) and a `Shadow`-style trigger with
///   no alert (tx 5)
/// - block 3: a confirmed finding on a block that is then **reverted**
fn window() -> Vec<EventEnvelope> {
    let confirmed = AlertId(Uuid::from_u128(0xa1));
    let refuted = AlertId(Uuid::from_u128(0xa2));
    let retracted = AlertId(Uuid::from_u128(0xa3));
    let reorged = AlertId(Uuid::from_u128(0xa4));
    let retracted_incident = IncidentId(Uuid::from_u128(0xc3));

    fn trigger(id: &str, b: BlockRef, txs: Vec<B256>, confidence: f64) -> DomainEvent {
        DomainEvent::DetectorTriggered(DetectorTriggered {
            detector: detector(id),
            block: b,
            txs,
            raw_confidence: Confidence::new(confidence),
            evidence: serde_json::json!({ "note": "fixture" }),
        })
    }
    fn alert(id: &str, alert_id: AlertId, confidence: f64) -> DomainEvent {
        DomainEvent::PreliminaryAlertCreated(PreliminaryAlertCreated {
            alert_id,
            detector: detector(id),
            addresses: vec![],
            kind: AlertKind::Sandwich,
            confidence: Confidence::new(confidence),
            provisional: true,
            impact_usd: None,
            severity: Severity::Low,
            suggested_action: SuggestedAction::Monitor,
        })
    }
    fn completed(alert_id: AlertId, ok: bool) -> DomainEvent {
        DomainEvent::SimulationCompleted(SimulationCompleted {
            alert_id,
            profit: if ok { 500.0 } else { 0.0 },
            victim_loss: if ok { 120.0 } else { 0.0 },
            confirmed: ok,
        })
    }
    fn incident(incident_id: IncidentId, alert_id: AlertId, txs: Vec<B256>) -> DomainEvent {
        DomainEvent::IncidentCreated(IncidentCreated {
            incident_id,
            alert_id,
            kind: AlertKind::Sandwich,
            txs,
            profit: 500.0,
            victim_loss: 120.0,
            impact_usd: None,
            severity: Severity::High,
            suggested_action: SuggestedAction::Investigate,
            victim_address: None,
            victim_loss_usd: None,
        })
    }

    vec![
        envelope(
            0,
            DomainEvent::BlockAssembled(BlockAssembled {
                block: block(1),
                tx_count: 3,
                trace_available: false,
            }),
        ),
        envelope(1, trigger("sandwich", block(1), vec![tx(1), tx(2)], 0.9)),
        envelope(2, alert("sandwich", confirmed, 0.9)),
        envelope(3, trigger("arb", block(1), vec![tx(3)], 0.4)),
        envelope(4, alert("arb", refuted, 0.4)),
        envelope(5, completed(confirmed, true)),
        envelope(
            6,
            incident(
                IncidentId(Uuid::from_u128(0xc1)),
                confirmed,
                vec![tx(1), tx(2)],
            ),
        ),
        envelope(7, completed(refuted, false)),
        envelope(
            8,
            DomainEvent::BlockAssembled(BlockAssembled {
                block: block(2),
                tx_count: 2,
                trace_available: false,
            }),
        ),
        envelope(9, trigger("sandwich", block(2), vec![tx(4)], 0.7)),
        envelope(10, alert("sandwich", retracted, 0.7)),
        // No alert for this one — a Shadow build's trigger.
        envelope(11, trigger("shadow", block(2), vec![tx(5)], 0.6)),
        envelope(12, completed(retracted, true)),
        envelope(13, incident(retracted_incident, retracted, vec![tx(4)])),
        envelope(
            14,
            DomainEvent::IncidentRetracted(IncidentRetracted {
                incident_id: retracted_incident,
                reason: "superseded by a later run".to_owned(),
            }),
        ),
        envelope(
            15,
            DomainEvent::BlockAssembled(BlockAssembled {
                block: block(3),
                tx_count: 1,
                trace_available: false,
            }),
        ),
        envelope(16, trigger("sandwich", block(3), vec![tx(6)], 0.8)),
        envelope(17, alert("sandwich", reorged, 0.8)),
        envelope(18, completed(reorged, true)),
        envelope(
            19,
            DomainEvent::BlockReverted(BlockReverted {
                block: block(3),
                replaced_by: B256::repeat_byte(0xfe),
            }),
        ),
    ]
}

fn spec() -> DatasetSpec {
    DatasetSpec {
        chain: CHAIN,
        from: at(-1_000),
        to: at(100_000),
        feature_version: ml_features::FEATURE_VERSION,
        granularity: Granularity::Tx,
        min_fidelity: Fidelity::HeaderOnly,
        include_ambiguous: false,
        lookahead_secs: dataset::DEFAULT_LOOKAHEAD_SECS,
    }
}

/// Serve the event store's own router on an ephemeral port.
async fn serve(store: EventStore) -> SocketAddr {
    let app = event_store::http::router(AppState {
        store,
        write_token: SecretString::from("test-token".to_owned()),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn a_dataset_is_exported_through_the_real_replay_api() {
    let container = ClickHouse::default()
        .start()
        .await
        .expect("start clickhouse");
    let port = container
        .get_host_port_ipv4(CLICKHOUSE_PORT)
        .await
        .expect("map port");

    let client = build_client(&event_store::config::ClickhouseConfig {
        url: format!("http://127.0.0.1:{port}"),
        user: "default".to_owned(),
        password: SecretString::from(String::new()),
        database: "default".to_owned(),
    });
    event_store::migrate::MIGRATOR
        .run(&client)
        .await
        .expect("event-store migrations apply");

    let store = EventStore::new(client);
    store
        .append_batch(&window())
        .await
        .expect("append the window");

    let addr = serve(store).await;
    let http = HttpEventSource::new(reqwest::Client::new(), format!("http://{addr}"));

    // The context source reads the same window — the binary's own two-pass
    // shape, driven here through the real HTTP client.
    let replayed = replay_window_types(&http, &spec(), 10_000)
        .await
        .expect("replay through the real API");
    assert!(
        replayed
            .windows(2)
            .all(|w| (w[0].occurred_at, w[0].event_id) < (w[1].occurred_at, w[1].event_id)),
        "the merged per-type passes reproduce the store's total order"
    );
    let ctx_source = ReplayCtxSource::from_events(&replayed);
    assert_eq!(ctx_source.len(), 3, "three blocks named by the window");

    let mut sink = CollectingSink::new();
    let manifest = run_export(
        &spec(),
        &http,
        &ReplayCtxFactory,
        &mut sink,
        ExportOptions::default(),
    )
    .await
    .expect("export through the real replay API");

    // ── the labels the window was built to produce ────────────────────
    assert_eq!(
        manifest.join.triggers, 5,
        "every DetectorTriggered in the window was seen"
    );
    assert_eq!(manifest.rows.by_outcome.get("confirmed"), Some(&1));
    assert_eq!(manifest.rows.by_outcome.get("refuted"), Some(&1));
    assert_eq!(manifest.rows.by_outcome.get("retracted"), Some(&1));
    assert_eq!(
        manifest.rows.by_outcome.get("unalerted"),
        Some(&1),
        "the Shadow trigger has no ground truth"
    );
    assert_eq!(
        manifest.rows.by_outcome.get("reverted"),
        Some(&1),
        "a confirmation on an orphaned block is dropped (§15)"
    );
    assert_eq!(manifest.join.reverted_blocks, 1);

    // Rows: tx 1 + tx 2 positive, tx 3 negative (refuted), tx 4 negative
    // (retracted). The Shadow and reverted findings contribute none.
    assert_eq!(manifest.rows.written, 4);
    assert_eq!(manifest.rows.by_label.get("positive"), Some(&2));
    assert_eq!(manifest.rows.by_label.get("negative"), Some(&2));
    assert_eq!(manifest.rows.unlabeled, 2);
    assert_eq!(sink.rows.len(), 4);

    // Every row is bound exactly (no two findings share a detector build and a
    // confidence here), and carries a full-width finite vector.
    assert!(sink.rows.iter().all(|r| r.binding.is_trusted()));
    assert!(sink
        .rows
        .iter()
        .all(|r| r.features.len() == manifest.feature_names.len()));
    assert!(sink
        .rows
        .iter()
        .all(|r| r.features.iter().all(|v| v.is_finite())));

    // ── reproducible by construction, over the real store ─────────────
    let mut again = CollectingSink::new();
    let second = run_export(
        &spec(),
        &http,
        &ReplayCtxFactory,
        &mut again,
        ExportOptions::default(),
    )
    .await
    .expect("second export");
    assert_eq!(sink.rows, again.rows);
    assert!(
        manifest.describes_same_dataset(&second),
        "same window + same feature_version + same label rule ⇒ same dataset"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn the_replay_client_follows_cursors_across_pages_of_the_real_api() {
    let container = ClickHouse::default()
        .start()
        .await
        .expect("start clickhouse");
    let port = container
        .get_host_port_ipv4(CLICKHOUSE_PORT)
        .await
        .expect("map port");

    let client = build_client(&event_store::config::ClickhouseConfig {
        url: format!("http://127.0.0.1:{port}"),
        user: "default".to_owned(),
        password: SecretString::from(String::new()),
        database: "default".to_owned(),
    });
    event_store::migrate::MIGRATOR
        .run(&client)
        .await
        .expect("migrations apply");

    // More events than one page holds, so the export must round-trip the
    // store's own opaque cursor token — the part of the contract a stubbed
    // source cannot exercise.
    let mut events = Vec::new();
    for seq in 0..250u32 {
        events.push(envelope(
            seq,
            DomainEvent::BlockAssembled(BlockAssembled {
                block: block(u64::from(seq)),
                tx_count: 1,
                trace_available: false,
            }),
        ));
    }
    let store = EventStore::new(client);
    store.append_batch(&events).await.expect("append");

    let addr = serve(store).await;
    let http = HttpEventSource::new(reqwest::Client::new(), format!("http://{addr}"));

    let replayed = dataset::source::replay_window(
        &http,
        CHAIN,
        at(-1_000),
        at(1_000_000),
        &["BlockAssembled"],
        10_000,
    )
    .await
    .expect("replay");

    assert_eq!(
        replayed.len(),
        250,
        "every page was followed — a truncated window would be a silently wrong dataset"
    );
    let ids: Vec<Uuid> = replayed.iter().map(|e| e.event_id).collect();
    let unique: std::collections::BTreeSet<Uuid> = ids.iter().copied().collect();
    assert_eq!(
        unique.len(),
        250,
        "no event was returned twice by the cursor"
    );
}
