//! Integration tests for the event store against *real* ClickHouse and Kafka,
//! spun up on demand via testcontainers. Marked `#[ignore]` so the default
//! `cargo test` stays hermetic; CI's `integration-test` job (and
//! `just test-integration`) run them with `--run-ignored all`.
//!
//! Two things are proven here:
//!   1. an appended batch lands immutably and reconstructs byte-for-byte, and
//!   2. an event published to Kafka is consumed and persisted end-to-end — the
//!      Sprint-1 deliverable ("any event on Kafka lands in the store").

use std::time::{Duration, Instant};

use alloy_primitives::B256;
use ch_migrate::swap::SwapOutcome;
use chrono::{DateTime, Utc};
use event_store::config::{ClickhouseConfig, KafkaConfig};
use event_store::query::Filters;
use event_store::repartition::{self, RunOutcome};
use event_store::retention::{self as store_retention, Reconciliation, TtlState};
use event_store::store::{build_client, EventRow, EventStore, StoredEvent, STORED_EVENT_COLUMNS};
use event_store::tiering::{self, TieringConfig, TieringPlan};
use event_store::{kafka, migrate};
use events::chain::{BlockAssembled, BlockFinalized};
use events::intelligence::{AttributionUpdated, SanctionHit};
use events::primitives::{
    AccountAddress, AlertId, AlertKind, BlockRef, Chain, EntityId, IncidentId, Severity,
};
use events::simulation::IncidentCreated;
use events::{DomainEvent, EventEnvelope};
use rdkafka::admin::{AdminClient, AdminOptions, ResourceSpecifier};
use rdkafka::consumer::Consumer;
use rdkafka::message::{Header, OwnedHeaders};
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::ClientConfig;
use secrecy::SecretString;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::clickhouse::{ClickHouse, CLICKHOUSE_PORT};
use testcontainers_modules::kafka::apache::{Kafka, KAFKA_PORT};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// A handful of events spanning two chains and two event types, so a successful
/// insert also exercises the ordering key's leading columns. Built
/// with millisecond-precise timestamps because the `DateTime64(3)` column stores
/// only milliseconds (an arbitrary `now()` wouldn't survive the round trip).
fn sample_events() -> Vec<EventEnvelope> {
    let at = |ms: i64| DateTime::<Utc>::from_timestamp_millis(ms).unwrap();
    vec![
        EventEnvelope::with_metadata(
            Uuid::from_u128(1),
            at(1_700_000_000_001),
            Chain::ETHEREUM,
            DomainEvent::BlockAssembled(BlockAssembled {
                block: BlockRef::new(19_800_000, B256::repeat_byte(0xab)),
                tx_count: 142,
                trace_available: true,
            }),
        ),
        EventEnvelope::with_metadata(
            Uuid::from_u128(2),
            at(1_700_000_000_002),
            Chain::ETHEREUM,
            DomainEvent::BlockFinalized(BlockFinalized {
                block: BlockRef::new(19_799_936, B256::repeat_byte(0xcd)),
            }),
        ),
        EventEnvelope::with_metadata(
            Uuid::from_u128(3),
            at(1_700_000_000_003),
            Chain(8453), // Base — a different partition
            DomainEvent::BlockAssembled(BlockAssembled {
                block: BlockRef::new(12_000_000, B256::repeat_byte(0xef)),
                tx_count: 7,
                trace_available: false,
            }),
        ),
    ]
}

/// Every fixture this suite appends must still sit inside the store's retention
/// window. Since migration `0003_events_retention` the `events` table deletes
/// rows older than the policy floor, and it does so *in the background while a
/// test runs* — so a stale fixture does not fail as "bad timestamp", it fails as
/// rows vanishing from a query result, at a different assertion on every run.
///
/// This check needs no Docker, so it fails in the fast gate with an explanation
/// instead of leaving the `#[ignore]`d suite to fail mysteriously. It matters
/// because [`sample_events`] is anchored to a hard-coded 2023 date, which will
/// drift out of the window on its own — the point is to be told when.
#[test]
fn every_fixture_is_inside_the_retention_window() {
    let floor_days =
        i64::from(retention::STATUTORY_ARTIFACT_DAYS + retention::EVIDENCE_MARGIN_DAYS);
    let cutoff = Utc::now() - chrono::TimeDelta::days(floor_days);
    for event in sample_events() {
        assert!(
            event.occurred_at > cutoff,
            "fixture {} is dated {}, older than the {floor_days}-day retention floor: \
             ClickHouse will delete it mid-test. Re-anchor the fixture clock.",
            event.event_id,
            event.occurred_at,
        );
    }
}

/// The schema the service boots into: migrations, then the table swap that
/// completes when it moves no data (a fresh container always qualifies).
async fn migrate_like_boot(store: &EventStore) {
    migrate::MIGRATOR
        .run(store.client())
        .await
        .expect("migrate");
    let outcome = repartition::reconcile_safe(store.client())
        .await
        .expect("boot swap");
    assert_eq!(outcome, SwapOutcome::Swapped, "a fresh store swaps at boot");
}

async fn engine_full(store: &EventStore, table: &str) -> String {
    store
        .client()
        .query(
            "SELECT engine_full FROM system.tables WHERE database = currentDatabase() AND name = ?",
        )
        .bind(table)
        .fetch_one()
        .await
        .expect("engine_full")
}

async fn count(store: &EventStore, sql: &str) -> u64 {
    store.client().query(sql).fetch_one().await.expect(sql)
}

/// Connect an [`EventStore`] to a testcontainer ClickHouse (default user, no
/// password, `default` database).
fn store_for(http_port: u16) -> EventStore {
    EventStore::new(build_client(&ClickhouseConfig {
        url: format!("http://127.0.0.1:{http_port}"),
        user: "default".to_owned(),
        password: SecretString::from(String::new()),
        database: "default".to_owned(),
    }))
}

/// A [`KafkaConfig`] pointing at a testcontainer broker, with a small topology
/// (3 partitions, replication 1 — one broker, 1h retention) matching the defaults.
fn kafka_config(brokers: &str, group_id: &str) -> KafkaConfig {
    KafkaConfig {
        brokers: brokers.to_owned(),
        group_id: group_id.to_owned(),
        topic_partitions: 3,
        topic_replication: 1,
        retention_ms: 60 * 60 * 1_000,
    }
}

async fn fetch_all_envelopes(store: &EventStore) -> Vec<EventEnvelope> {
    // The canonical read projection (`StoredEvent`), shared with the production
    // query path — RowBinary maps by position, so the SELECT lists exactly its
    // fields, in order.
    let sql = format!("SELECT {STORED_EVENT_COLUMNS} FROM events");
    let rows: Vec<StoredEvent> = store
        .client()
        .query(&sql)
        .fetch_all()
        .await
        .expect("query events");
    let mut envelopes: Vec<EventEnvelope> = rows
        .into_iter()
        .map(|row| EventEnvelope::try_from(row).expect("reconstruct"))
        .collect();
    envelopes.sort_by_key(|e| e.event_id);
    envelopes
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers ClickHouse)"]
async fn append_persists_and_round_trips_every_event() {
    let node = ClickHouse::default()
        .start()
        .await
        .expect("start clickhouse");
    let port = node
        .get_host_port_ipv4(CLICKHOUSE_PORT)
        .await
        .expect("clickhouse port");

    let store = store_for(port);
    migrate_like_boot(&store).await;

    let mut want = sample_events();
    store.append_batch(&want).await.expect("append");

    let count: u64 = store
        .client()
        .query("SELECT count() FROM events")
        .fetch_one()
        .await
        .expect("count");
    assert_eq!(count, want.len() as u64);

    let got = fetch_all_envelopes(&store).await;
    want.sort_by_key(|e| e.event_id);
    assert_eq!(got, want, "stored events must reconstruct byte-for-byte");
}

/// The capacity plan's table replacement, the way a deployed store meets it: a
/// daily-partitioned `events` with history, a new build that migrates, and the
/// repartition Job.
///
/// Proves each claim the design makes. Boot moves no data. The Job carries
/// every row across byte-for-byte and keeps the old table. A bulk insert that
/// **throws** under the daily key (one block over
/// `max_partitions_per_insert_block`, as a backup restore produces) lands under
/// the monthly one — checked against the daily table first, so the test fails
/// if the hazard stops being real. A row a writer lands in the old table late is
/// carried across by a re-run. And finalize refuses until the old table is
/// provably contained.
#[tokio::test]
#[ignore = "requires Docker (testcontainers ClickHouse)"]
async fn the_repartition_job_upgrades_a_daily_store_in_place() {
    let node = ClickHouse::default()
        .start()
        .await
        .expect("start clickhouse");
    let port = node
        .get_host_port_ipv4(CLICKHOUSE_PORT)
        .await
        .expect("clickhouse port");
    let store = store_for(port);
    let client = store.client();

    // The new build's migrations ran; its boot swap has not, because the store
    // it meets already holds history.
    migrate::MIGRATOR.run(client).await.expect("migrate");

    // 150 days x 2 chains x 2 event types = 600 daily partitions of history,
    // dated inside the retention window so the TTL cannot race the assertions.
    let epoch = Utc::now().timestamp_millis() - 200 * 86_400_000;
    let history = spread_events(epoch, 150, 0);
    // The daily key caps one insert at 100 partitions: 2 days x 4 pairs = 8.
    for chunk in history.chunks(4 * 2) {
        store.append_batch(chunk).await.expect("append history");
    }

    // The hazard is real on the daily table: 30 days x 4 pairs = 120 partitions.
    let bulk = spread_events(epoch, 30, 1_000_000);
    assert!(
        store.append_batch(&bulk).await.is_err(),
        "the daily key must refuse a bulk insert over max_partitions_per_insert_block — \
         if it stops, this test no longer proves the repartition is needed"
    );

    // Boot with data: reports, moves nothing.
    let boot = repartition::reconcile_safe(client).await.expect("boot");
    assert_eq!(
        boot,
        SwapOutcome::Pending {
            live_rows: history.len() as u64,
            staged_rows: 0
        }
    );
    let plan = repartition::plan(client).await.expect("plan");
    let to_move: u64 = plan.gaps.iter().map(|g| g.missing).sum();
    assert_eq!(to_move, history.len() as u64, "{plan}");

    // The Job.
    let outcome = repartition::run(client).await.expect("run");
    assert!(
        matches!(outcome, RunOutcome::Repartitioned { .. }),
        "{outcome}"
    );

    let live = engine_full(&store, "events").await;
    assert!(live.starts_with("ReplacingMergeTree"), "{live}");
    assert!(
        live.contains("PARTITION BY toYYYYMM(occurred_at)"),
        "{live}"
    );
    assert_eq!(store_retention::read_ttl(&live), TtlState::Days(2192));
    assert_eq!(
        count(&store, "SELECT count() FROM events__retired").await,
        history.len() as u64,
        "the daily table is kept, retired"
    );

    let mut want = history.clone();
    want.sort_by_key(|e| e.event_id);
    assert_eq!(
        fetch_all_envelopes(&store).await,
        want,
        "every historical row must survive the move byte-for-byte"
    );

    // The same bulk insert now lands.
    store
        .append_batch(&bulk)
        .await
        .expect("a bulk insert spanning a month must land under the monthly key");

    // A writer still on the old table lands one more event there.
    let late = spread_events(epoch, 1, 5_000_000).remove(0);
    let mut insert = client
        .insert::<EventRow>("events__retired")
        .await
        .expect("insert into retired");
    insert
        .write(&EventRow::try_from(&late).unwrap())
        .await
        .unwrap();
    insert.end().await.unwrap();

    // Finalize refuses while the retired table holds an event the live one lacks…
    let refused =
        repartition::finalize(client, repartition::DropRetiredIntent::from_operator_flag()).await;
    assert!(
        matches!(
            refused,
            Err(repartition::RepartitionError::RetiredNotSubsumed { missing: 1, .. })
        ),
        "{refused:?}"
    );

    // …a re-run carries it across, and then finalize drops the old table.
    let rerun = repartition::run(client).await.expect("rerun");
    assert!(matches!(rerun, RunOutcome::CaughtUp { .. }), "{rerun}");
    let dropped =
        repartition::finalize(client, repartition::DropRetiredIntent::from_operator_flag())
            .await
            .expect("finalize");
    assert_eq!(dropped, history.len() as u64 + 1);
    assert!(
        !ch_migrate::swap::TableSwap::exists(client, "events__retired")
            .await
            .unwrap()
    );
    assert_eq!(
        count(&store, "SELECT uniqExact(event_id) FROM events").await,
        (history.len() + bulk.len() + 1) as u64
    );
}

/// At-least-once ingest, made idempotent by the store: an exact batch retry is
/// refused at insert time, a redelivery that forms a *different* batch is
/// collapsed by the engine, and a read never shows a duplicate in between.
#[tokio::test]
#[ignore = "requires Docker (testcontainers ClickHouse)"]
async fn a_retried_or_redelivered_batch_is_stored_and_read_once() {
    let node = ClickHouse::default()
        .start()
        .await
        .expect("start clickhouse");
    let port = node
        .get_host_port_ipv4(CLICKHOUSE_PORT)
        .await
        .expect("clickhouse port");
    let store = store_for(port);
    migrate_like_boot(&store).await;

    let epoch = Utc::now().timestamp_millis() - 86_400_000;
    let events = spread_events(epoch, 3, 0);

    // The batch loop's transient-failure path re-sends the identical batch.
    store.append_batch(&events).await.expect("first");
    store.append_batch(&events).await.expect("retry");
    assert_eq!(
        count(&store, "SELECT count() FROM events").await,
        events.len() as u64,
        "an identical batch is deduplicated at insert time"
    );

    // A redelivery after a restart forms a different batch around the same events.
    let mut overlapping = events[..4].to_vec();
    overlapping.extend(spread_events(epoch, 1, 9_000_000));
    store.append_batch(&overlapping).await.expect("redelivery");

    let unique = (events.len() + 4) as u64;
    let replay = store
        .replay(&Filters {
            from: Some(DateTime::<Utc>::from_timestamp_millis(epoch - 1).unwrap()),
            limit: Some(10_000),
            ..Filters::default()
        })
        .await
        .expect("replay");
    assert_eq!(
        replay.events.len() as u64,
        unique,
        "reads dedupe before merges run"
    );
    assert_eq!(
        count(&store, "SELECT count() FROM events FINAL").await,
        unique,
        "the engine collapses the redelivered copies"
    );
}

/// Storage tiering on a server with a hot/cold policy. The trap it closes: the
/// old TTL reader took a move rule for the retention window, so a tiered table
/// made boot refuse to start.
#[tokio::test]
#[ignore = "requires Docker (testcontainers ClickHouse)"]
async fn tiering_adds_a_move_rule_and_retention_still_reads_its_window() {
    use testcontainers::ImageExt;
    const STORAGE: &str = r#"<clickhouse>
  <storage_configuration>
    <disks>
      <cold><path>/var/lib/clickhouse/cold/</path></cold>
    </disks>
    <policies>
      <tiered>
        <volumes>
          <default><disk>default</disk></default>
          <cold><disk>cold</disk></cold>
        </volumes>
      </tiered>
    </policies>
  </storage_configuration>
</clickhouse>"#;
    let node = ClickHouse::default()
        .with_copy_to(
            "/etc/clickhouse-server/config.d/storage.xml",
            STORAGE.as_bytes().to_vec(),
        )
        .start()
        .await
        .expect("start clickhouse");
    let port = node
        .get_host_port_ipv4(CLICKHOUSE_PORT)
        .await
        .expect("clickhouse port");
    let store = store_for(port);
    let client = store.client();
    migrate_like_boot(&store).await;

    let cfg = TieringConfig::new("tiered".into(), "cold".into(), 90).unwrap();
    let applied = tiering::reconcile(client, &cfg).await.expect("tier");
    assert!(
        matches!(
            applied,
            TieringPlan::Apply {
                set_policy: Some(_),
                ..
            }
        ),
        "{applied:?}"
    );
    let tiered = engine_full(&store, "events").await;
    assert!(tiered.contains("TO VOLUME"), "{tiered}");
    assert_eq!(
        tiering::reconcile(client, &cfg).await.expect("again"),
        TieringPlan::Unchanged,
        "reconciliation is idempotent"
    );

    // Boot's retention reconcile on a tiered table: in line, not a refusal.
    let policies = ::retention::PolicySet::default();
    let decision = store_retention::reconcile_safe(client, "default", &policies, Utc::now())
        .await
        .expect("retention on a tiered table");
    assert!(
        matches!(decision, Reconciliation::Unchanged { .. }),
        "{decision}"
    );

    // Widening the window keeps the move rule.
    let wider = ::retention::PolicySet::uniform(
        ::retention::Policy::new(
            ::retention::STATUTORY_ARTIFACT_DAYS,
            ::retention::EVIDENCE_MARGIN_DAYS + 30,
        )
        .unwrap(),
    );
    let widened = store_retention::reconcile_safe(client, "default", &wider, Utc::now())
        .await
        .expect("widen");
    assert!(matches!(widened, Reconciliation::Extend(_)), "{widened}");
    let rules = store_retention::observe_rules_current(client)
        .await
        .unwrap();
    assert_eq!(rules.delete, TtlState::Days(2222));
    assert_eq!(rules.moves, vec![cfg.move_rule()]);

    // And evidence still lands.
    store
        .append_batch(&sample_events())
        .await
        .expect("append under the tiered policy");
}

/// One event per day for `days` days, for each of two chains and two event
/// types, starting at `epoch_ms`. `id_base` keeps two calls' ids disjoint.
fn spread_events(epoch_ms: i64, days: i64, id_base: u128) -> Vec<EventEnvelope> {
    let mut out = Vec::new();
    for day in 0..days {
        let at = DateTime::<Utc>::from_timestamp_millis(epoch_ms + day * 86_400_000).unwrap();
        for (c, chain) in [Chain::ETHEREUM, Chain::BASE].into_iter().enumerate() {
            let id =
                |kind: u128| Uuid::from_u128(id_base + (day as u128) * 4 + (c as u128) * 2 + kind);
            let block = BlockRef::new(day as u64, B256::repeat_byte(0xab));
            out.push(EventEnvelope::with_metadata(
                id(0),
                at,
                chain,
                DomainEvent::BlockAssembled(BlockAssembled {
                    block,
                    tx_count: 1,
                    trace_available: false,
                }),
            ));
            out.push(EventEnvelope::with_metadata(
                id(1),
                at,
                chain,
                DomainEvent::BlockFinalized(BlockFinalized { block }),
            ));
        }
    }
    out
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers ClickHouse)"]
async fn query_api_finds_events_by_incident_address_and_window() {
    let node = ClickHouse::default()
        .start()
        .await
        .expect("start clickhouse");
    let port = node
        .get_host_port_ipv4(CLICKHOUSE_PORT)
        .await
        .expect("clickhouse port");

    let store = store_for(port);
    migrate_like_boot(&store).await;

    // Fixture timestamps are offsets from a *recent* epoch, deliberately not
    // from 1970. The events table now carries a retention TTL (migration
    // `0003_events_retention`: occurred_at + 2192 days), so a bare
    // `from_timestamp_millis(1_000)` dates these rows 1970-01-01 — expired by
    // half a century. ClickHouse then deletes them in the background *while the
    // test is running*, and (under the original daily `(chain, event_type,
    // date)` partitioning, before the 0004 repartition) it dropped them one
    // event type at a time. The symptom is an arbitrary-looking subset of a query result
    // going missing, at a *different assertion on each run* (the trail on a
    // slow run, the replay window on a fast one) — which reads like a
    // write-path bug rather than like retention.
    //
    // Anchored to `now` rather than to a fixed recent date so it cannot rot
    // back out of the window: a hard-coded 2023 base would start failing this
    // same way in 2029. Whole milliseconds because the `DateTime64(3)` column
    // stores no more, and these values must survive the round trip.
    let epoch = Utc::now().timestamp_millis();
    let at = |ms: i64| DateTime::<Utc>::from_timestamp_millis(epoch + ms).unwrap();
    let incident = IncidentId(Uuid::from_u128(0x5151));
    let address = AccountAddress::repeat_byte(0x42);

    // A noise block, two events for one incident (created, then attributed), and
    // a sanction hit naming `address` — spanning a 1s→4s window.
    let events = vec![
        EventEnvelope::with_metadata(
            Uuid::from_u128(10),
            at(1_000),
            Chain::ETHEREUM,
            DomainEvent::BlockAssembled(BlockAssembled {
                block: BlockRef::new(19_800_000, B256::repeat_byte(0xab)),
                tx_count: 1,
                trace_available: true,
            }),
        ),
        EventEnvelope::with_metadata(
            Uuid::from_u128(11),
            at(2_000),
            Chain::ETHEREUM,
            DomainEvent::IncidentCreated(IncidentCreated {
                incident_id: incident,
                alert_id: AlertId::new(),
                kind: AlertKind::Sandwich,
                txs: vec![B256::repeat_byte(0x01)],
                profit: 12_400.0,
                victim_loss: 840.0,
                impact_usd: None,
                severity: Severity::High,
                suggested_action: events::primitives::SuggestedAction::Escalate,
                victim_address: None,
                victim_loss_usd: None,
            }),
        ),
        EventEnvelope::with_metadata(
            Uuid::from_u128(12),
            at(3_000),
            Chain::ETHEREUM,
            DomainEvent::AttributionUpdated(AttributionUpdated {
                incident_id: incident,
                entity_ids: vec![EntityId::new()],
                labels: vec!["MevBot".to_owned()],
            }),
        ),
        EventEnvelope::with_metadata(
            Uuid::from_u128(13),
            at(4_000),
            Chain::ETHEREUM,
            DomainEvent::SanctionHit(SanctionHit {
                address,
                list: "OFAC".to_owned(),
                entry: "SDN-1".to_owned(),
            }),
        ),
    ];
    store.append_batch(&events).await.expect("append");

    // by incident (§4 audit): only the two incident-keyed events, oldest first.
    let trail = store
        .audit_incident(incident, &Filters::default())
        .await
        .expect("audit");
    assert!(trail.next_cursor.is_none(), "small trail fits in one page");
    let trail_types: Vec<_> = trail.events.iter().map(|e| e.event_type()).collect();
    assert_eq!(trail_types, vec!["IncidentCreated", "AttributionUpdated"]);

    // by address: only the sanction hit references it.
    let by_addr = store
        .events_by_address(address, &Filters::default())
        .await
        .expect("by address");
    assert_eq!(by_addr.events.len(), 1);
    assert_eq!(by_addr.events[0].event_type(), "SanctionHit");
    // An unrelated address finds nothing.
    let none = store
        .events_by_address(AccountAddress::repeat_byte(0x99), &Filters::default())
        .await
        .expect("by address");
    assert!(none.events.is_empty());

    // replay over a half-open window [2s, 4s): the incident pair, excluding the
    // block at 1s and the sanction at exactly 4s (upper bound is exclusive).
    let window = store
        .replay(&Filters {
            from: Some(at(2_000)),
            to: Some(at(4_000)),
            ..Default::default()
        })
        .await
        .expect("replay window");
    let window_types: Vec<_> = window.events.iter().map(|e| e.event_type()).collect();
    assert_eq!(window_types, vec!["IncidentCreated", "AttributionUpdated"]);

    // replay narrowed to one event type (the §4 replay-by-event-type stream).
    let blocks = store
        .replay(&Filters {
            event_type: Some("BlockAssembled".to_owned()),
            ..Default::default()
        })
        .await
        .expect("replay by type");
    assert_eq!(blocks.events.len(), 1);
    assert_eq!(blocks.events[0].event_type(), "BlockAssembled");

    // An unbounded replay (no narrowing) is refused, not silently full-scanned.
    assert!(store.replay(&Filters::default()).await.is_err());

    // Keyset pagination: page size 1 over the whole [1s, 5s) window walks all
    // four events in order, following next_cursor, with the last page closing
    // the stream (next_cursor == None).
    let mut paged = Vec::new();
    let mut cursor = None;
    loop {
        let page = store
            .replay(&Filters {
                from: Some(at(0)),
                to: Some(at(5_000)),
                limit: Some(1),
                cursor,
                ..Default::default()
            })
            .await
            .expect("replay page");
        paged.extend(page.events.iter().map(|e| e.event_type().to_owned()));
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(
        paged,
        vec![
            "BlockAssembled",
            "IncidentCreated",
            "AttributionUpdated",
            "SanctionHit"
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Docker (testcontainers Kafka)"]
async fn ensure_topics_provisions_one_topic_per_event_type() {
    let kafka_node = Kafka::default().start().await.expect("start kafka");
    let brokers = format!(
        "127.0.0.1:{}",
        kafka_node
            .get_host_port_ipv4(KAFKA_PORT)
            .await
            .expect("kafka port")
    );
    let cfg = kafka_config(&brokers, "event-store-provision-test");

    // Idempotent: provisioning twice succeeds — the second run is a no-op over
    // already-existing topics (TopicAlreadyExists is swallowed, not an error).
    kafka::ensure_topics(&cfg).await.expect("provision topics");
    kafka::ensure_topics(&cfg)
        .await
        .expect("re-provisioning is idempotent");

    // Every event type now has its `mev.events.<EventType>` topic, each with the
    // configured partition count (§20 — topic-per-event-type, partitioned by chain).
    let consumer = kafka::build_consumer(&cfg).expect("build consumer");
    let metadata = consumer
        .fetch_metadata(None, Duration::from_secs(10))
        .expect("fetch metadata");
    let partitions_by_topic: std::collections::HashMap<&str, usize> = metadata
        .topics()
        .iter()
        .map(|t| (t.name(), t.partitions().len()))
        .collect();

    for expected in events::all_topics() {
        let partitions = partitions_by_topic
            .get(expected.as_str())
            .unwrap_or_else(|| panic!("topic {expected} was not provisioned"));
        assert_eq!(
            *partitions, cfg.topic_partitions as usize,
            "{expected} should have {} partitions",
            cfg.topic_partitions
        );
    }

    // Retention/cleanup policy must actually land on the broker — Kafka is the
    // *bounded wire* (§2/§4); an unbounded topic would be a silent second record.
    let admin: AdminClient<_> = ClientConfig::new()
        .set("bootstrap.servers", &brokers)
        .create()
        .expect("admin client");
    let described = admin
        .describe_configs(
            &[ResourceSpecifier::Topic("mev.events.BlockAssembled")],
            &AdminOptions::new().request_timeout(Some(Duration::from_secs(10))),
        )
        .await
        .expect("describe configs");
    let resource = described
        .into_iter()
        .next()
        .expect("one resource described")
        .expect("describe ok");
    let want_retention = cfg.retention_ms.to_string();
    assert_eq!(
        resource
            .get("retention.ms")
            .and_then(|e| e.value.as_deref()),
        Some(want_retention.as_str()),
        "topic retention must match config (bounded wire)"
    );
    assert_eq!(
        resource
            .get("cleanup.policy")
            .and_then(|e| e.value.as_deref()),
        Some("delete"),
        "event topics delete on retention, never compact"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Docker (testcontainers ClickHouse + Kafka)"]
async fn event_published_to_kafka_lands_in_store() {
    let ch = ClickHouse::default()
        .start()
        .await
        .expect("start clickhouse");
    let ch_port = ch
        .get_host_port_ipv4(CLICKHOUSE_PORT)
        .await
        .expect("clickhouse port");
    let kafka_node = Kafka::default().start().await.expect("start kafka");
    let brokers = format!(
        "127.0.0.1:{}",
        kafka_node
            .get_host_port_ipv4(KAFKA_PORT)
            .await
            .expect("kafka port")
    );

    let store = store_for(ch_port);
    migrate_like_boot(&store).await;

    // Mirror production boot order: provision the topology first, so the topics
    // exist before either the producer sends or the consumer's explicit
    // subscription resolves.
    let cfg = kafka_config(&brokers, "event-store-test");
    kafka::ensure_topics(&cfg).await.expect("provision topics");

    let envelope = sample_events().remove(0);
    let producer: FutureProducer = ClientConfig::new()
        .set("bootstrap.servers", &brokers)
        .set("message.timeout.ms", "5000")
        .create()
        .expect("create producer");

    let topic = envelope.topic();
    let key = envelope.chain.id().to_string();
    let payload = envelope.to_json_vec().expect("serialize envelope");
    // A W3C traceparent header, the same shape a real producer injects.
    let headers = OwnedHeaders::new().insert(Header {
        key: "traceparent",
        value: Some("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"),
    });
    producer
        .send(
            FutureRecord::to(&topic)
                .payload(&payload)
                .key(&key)
                .headers(headers),
            Duration::from_secs(5),
        )
        .await
        .expect("produce");

    // Run the real consumer.
    let consumer = kafka::build_consumer(&cfg).expect("build consumer");
    let consumer_store = store.clone();
    let shutdown = CancellationToken::new();
    let consumer_task = tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            // Small batches with a short wait: the production defaults would
            // hold one record for a full second before the poll below sees it.
            let batch = event_store::config::ingest_config(100, 100).expect("batch config");
            kafka::run(consumer, consumer_store, batch, None, shutdown).await
        }
    });

    // Poll until it lands (or time out).
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let count: u64 = store
            .client()
            .query("SELECT count() FROM events")
            .fetch_one()
            .await
            .expect("count");
        if count >= 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "event never reached the store within 30s"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // Exercise the graceful path: cancel and let the consumer drain & exit.
    shutdown.cancel();
    consumer_task
        .await
        .expect("consumer task")
        .expect("consumer run");

    let got = fetch_all_envelopes(&store).await;
    assert_eq!(got, vec![envelope], "the consumed event must match exactly");
}
