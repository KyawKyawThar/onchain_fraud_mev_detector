//! Integration tests for the ClickHouse sink against a *real* ClickHouse, spun
//! up on demand via testcontainers. Marked `#[ignore]` so the default `cargo
//! test` stays hermetic; CI's `integration-test` job (and `just
//! test-integration`) run them with `--run-ignored all`.
//!
//! Three things are proven here, none of which a unit test can:
//!
//! 1. The migrations apply, and a batch of rows written through the sink reads
//!    back with its features, label and provenance intact — including the
//!    `Array(Float64)` column, whose RowBinary encoding is exactly the kind of
//!    thing that only fails against a real server.
//! 2. **Re-exporting the same spec converges rather than doubles.** This is the
//!    operational payoff of the whole determinism story: a deterministic
//!    pipeline produces identical `ORDER BY` keys, and the ReplacingMergeTree
//!    collapses them — so "re-run the window after a schema fix" is safe.
//! 3. The manifest table answers the reproducibility question directly: two
//!    runs of one spec land two manifest rows carrying **one** distinct
//!    `content_hash`.

use chrono::{DateTime, Utc};
use dataset::config::ClickhouseConfig;
use dataset::ctx::{Fidelity, MapCtxSource, StaticCtxFactory};
use dataset::sink::clickhouse::{build_client, ClickHouseSink, DatasetRowRecord};
use dataset::sink::FanOutSink;
use dataset::source::VecEventSource;
use dataset::spec::DatasetSpec;
use dataset::{run_export, ExportOptions};
use secrecy::SecretString;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::clickhouse::{ClickHouse, CLICKHOUSE_PORT};

use alloy_primitives::B256;
use detector_api::test_util::{addr, transfer, CtxBuilder};
use detector_api::DetectionCtx;
use events::chain::BlockAssembled;
use events::detection::{DetectorTriggered, PreliminaryAlertCreated};
use events::primitives::{
    AlertId, AlertKind, BlockRef, Chain, Confidence, DetectorRef, Severity, SuggestedAction,
};
use events::simulation::SimulationCompleted;
use events::{DomainEvent, EventEnvelope};
use ml_features::Granularity;
use uuid::Uuid;

const CHAIN: Chain = Chain::ETHEREUM;
const CONFIRMED: AlertId = AlertId(Uuid::from_u128(0xa1));
const REFUTED: AlertId = AlertId(Uuid::from_u128(0xa2));

fn client_for(http_port: u16) -> clickhouse::Client {
    build_client(&ClickhouseConfig {
        url: format!("http://127.0.0.1:{http_port}"),
        user: "default".to_owned(),
        password: SecretString::from(String::new()),
        database: "default".to_owned(),
    })
}

fn at(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(secs, 0).expect("valid timestamp")
}

fn detector() -> DetectorRef {
    DetectorRef {
        id: "sandwich".into(),
        version: "1.2.0".into(),
        config_hash: "deadbeef".into(),
    }
}

fn block() -> BlockRef {
    BlockRef::new(19_800_000, B256::repeat_byte(0xab))
}

fn tx(b: u8) -> B256 {
    B256::repeat_byte(b)
}

fn envelope(seq: u32, payload: DomainEvent) -> EventEnvelope {
    EventEnvelope::with_metadata(
        Uuid::from_u128(u128::from(seq)),
        at(1_700_000_000 + i64::from(seq)),
        CHAIN,
        payload,
    )
}

fn spec() -> DatasetSpec {
    DatasetSpec {
        chain: CHAIN,
        from: at(1_700_000_000),
        to: at(1_700_001_000),
        feature_version: ml_features::FEATURE_VERSION,
        granularity: Granularity::Tx,
        min_fidelity: Fidelity::HeaderOnly,
        include_ambiguous: false,
        lookahead_secs: dataset::DEFAULT_LOOKAHEAD_SECS,
    }
}

/// One confirmed finding (tx 1 + tx 2) and one refuted finding (tx 3).
fn window() -> Vec<EventEnvelope> {
    fn alert(id: AlertId, confidence: f64) -> DomainEvent {
        DomainEvent::PreliminaryAlertCreated(PreliminaryAlertCreated {
            alert_id: id,
            detector: detector(),
            addresses: vec![],
            kind: AlertKind::Sandwich,
            confidence: Confidence::new(confidence),
            provisional: true,
            impact_usd: None,
            severity: Severity::Low,
            suggested_action: SuggestedAction::Monitor,
        })
    }
    fn trigger(txs: Vec<B256>, confidence: f64) -> DomainEvent {
        DomainEvent::DetectorTriggered(DetectorTriggered {
            detector: detector(),
            block: block(),
            txs,
            raw_confidence: Confidence::new(confidence),
            evidence: serde_json::json!({}),
        })
    }

    vec![
        envelope(
            0,
            DomainEvent::BlockAssembled(BlockAssembled {
                block: block(),
                tx_count: 3,
                trace_available: false,
            }),
        ),
        envelope(1, trigger(vec![tx(1), tx(2)], 0.9)),
        envelope(2, alert(CONFIRMED, 0.9)),
        envelope(3, trigger(vec![tx(3)], 0.4)),
        envelope(4, alert(REFUTED, 0.4)),
        envelope(
            5,
            DomainEvent::SimulationCompleted(SimulationCompleted {
                alert_id: CONFIRMED,
                profit: 250.0,
                victim_loss: 90.0,
                confirmed: true,
            }),
        ),
        envelope(
            6,
            DomainEvent::SimulationCompleted(SimulationCompleted {
                alert_id: REFUTED,
                profit: 0.0,
                victim_loss: 0.0,
                confirmed: false,
            }),
        ),
    ]
}

fn enriched_ctx() -> DetectionCtx {
    let token = addr(0x77);
    let pool = addr(0xee);
    let mut builder = CtxBuilder::new()
        .at(CHAIN, block())
        .priced_token(token, 18, 2.0);
    for (i, hash) in [tx(1), tx(2), tx(3)].into_iter().enumerate() {
        let sender = addr(i as u8 + 1);
        builder = builder.transfer_tx(
            hash,
            sender,
            vec![transfer(token, sender, pool, 1_000 * (i as u128 + 1))],
        );
    }
    builder.build()
}

/// Run one full export into ClickHouse, returning the manifest.
async fn export_into(client: &clickhouse::Client) -> dataset::DatasetManifest {
    let mut sinks = FanOutSink::new();
    sinks.push(Box::new(ClickHouseSink::new(client.clone())));
    let ctx_factory = StaticCtxFactory::new(std::sync::Arc::new(
        MapCtxSource::new().with(enriched_ctx(), Fidelity::Enriched),
    ));

    run_export(
        &spec(),
        &VecEventSource::new(window()),
        &ctx_factory,
        &mut sinks,
        ExportOptions::default(),
    )
    .await
    .expect("export succeeds")
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn rows_land_in_clickhouse_and_a_re_export_converges_instead_of_doubling() {
    let container = ClickHouse::default()
        .start()
        .await
        .expect("start clickhouse");
    let port = container
        .get_host_port_ipv4(CLICKHOUSE_PORT)
        .await
        .expect("map port");
    let client = client_for(port);

    dataset::migrate::MIGRATOR
        .run(&client)
        .await
        .expect("migrations apply");

    // ── first export ──────────────────────────────────────────────────
    let first = export_into(&client).await;
    assert_eq!(first.rows.written, 3);

    let rows: Vec<DatasetRowRecord> = client
        .query("SELECT ?fields FROM ml_dataset_rows ORDER BY block_number, tx_hash")
        .fetch_all()
        .await
        .expect("read rows back");
    assert_eq!(rows.len(), 3);

    // The Array(Float64) column survives the RowBinary round trip intact, and
    // its width matches the schema the manifest names.
    assert!(rows
        .iter()
        .all(|r| r.features.len() == first.feature_names.len()));
    assert!(rows
        .iter()
        .all(|r| r.features.iter().all(|v| v.is_finite())));

    // Labels and their simulated figures came through.
    let positives: Vec<&DatasetRowRecord> = rows.iter().filter(|r| r.label == 1).collect();
    assert_eq!(positives.len(), 2, "tx 1 and tx 2 of the confirmed finding");
    assert!(positives.iter().all(|r| r.profit == 250.0));
    assert!(positives.iter().all(|r| r.outcome == "confirmed"));

    let negative = rows.iter().find(|r| r.label == 0).expect("the refuted row");
    assert_eq!(negative.outcome, "refuted");
    assert_eq!((negative.profit, negative.victim_loss), (0.0, 0.0));
    assert_eq!(negative.fidelity, "enriched");
    assert_eq!(negative.binding, "exact");
    assert_eq!(negative.dataset_id, first.dataset_id);

    // ── re-export the same spec ───────────────────────────────────────
    let second = export_into(&client).await;
    assert_eq!(
        second.content_hash, first.content_hash,
        "a deterministic pipeline over immutable events re-produces the dataset"
    );

    // The physical rows may be duplicated until merges run, but the *logical*
    // dataset is unchanged: the ORDER BY key is identical, so a de-duplicating
    // count is stable. This is what makes re-running a window safe.
    let distinct: u64 = client
        .query(
            "SELECT count() FROM (
               SELECT DISTINCT dataset_id, block_number, detector_id, trigger_event_id, tx_hash
               FROM ml_dataset_rows
             )",
        )
        .fetch_one()
        .await
        .expect("count distinct keys");
    assert_eq!(
        distinct, 3,
        "re-exporting a spec must converge onto the same rows, not double the dataset"
    );

    // ── the manifest table answers the reproducibility question ───────
    let (runs, distinct_hashes): (u64, u64) = client
        .query(
            "SELECT count(), uniqExact(content_hash) FROM ml_dataset_manifests
             WHERE dataset_id = ?",
        )
        .bind(&first.dataset_id)
        .fetch_one()
        .await
        .expect("read manifests");
    assert_eq!(runs, 2, "every run is recorded — that is the evidence");
    assert_eq!(
        distinct_hashes, 1,
        "and both runs agreed on the dataset's content hash"
    );

    // The feature names live once, on the manifest — the key to reading the
    // rows' bare Array(Float64).
    let names: Vec<String> = client
        .query("SELECT feature_names FROM ml_dataset_manifests LIMIT 1")
        .fetch_one()
        .await
        .expect("read feature names");
    assert_eq!(names, first.feature_names);
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn migrations_are_idempotent_and_reversible() {
    let container = ClickHouse::default()
        .start()
        .await
        .expect("start clickhouse");
    let port = container
        .get_host_port_ipv4(CLICKHOUSE_PORT)
        .await
        .expect("map port");
    let client = client_for(port);

    let applied = dataset::migrate::MIGRATOR
        .run(&client)
        .await
        .expect("first run");
    assert_eq!(applied.len(), 2);

    let again = dataset::migrate::MIGRATOR
        .run(&client)
        .await
        .expect("second run");
    assert!(again.is_empty(), "re-running applies nothing");

    let status = dataset::migrate::MIGRATOR
        .status(&client)
        .await
        .expect("status");
    assert!(status.iter().all(|s| s.applied));

    // Down reverts the most recent one only.
    let reverted = dataset::migrate::MIGRATOR
        .revert_last(&client)
        .await
        .expect("revert");
    assert_eq!(reverted, Some("0002_create_ml_dataset_manifests"));
    let status = dataset::migrate::MIGRATOR
        .status(&client)
        .await
        .expect("status");
    assert!(status.iter().any(|s| !s.applied));
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn the_sink_refuses_before_a_replay_when_clickhouse_is_unreachable() {
    // A deliberately dead port: `ping` is what the binary calls before
    // spending minutes on a replay it could not write.
    let sink = ClickHouseSink::new(client_for(1));
    assert!(
        sink.ping().await.is_err(),
        "an unreachable server must fail the probe, not the export's last step"
    );
}
