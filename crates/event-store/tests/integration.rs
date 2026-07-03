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
use chrono::{DateTime, Utc};
use event_store::config::{ClickhouseConfig, KafkaConfig};
use event_store::query::Filters;
use event_store::store::{build_client, EventStore, StoredEvent, STORED_EVENT_COLUMNS};
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
/// insert also exercises the `(chain, event_type, date)` partitioning. Built
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
    migrate::MIGRATOR
        .run(store.client())
        .await
        .expect("migrate");

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
    migrate::MIGRATOR
        .run(store.client())
        .await
        .expect("migrate");

    let at = |ms: i64| DateTime::<Utc>::from_timestamp_millis(ms).unwrap();
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
                severity: Severity::High,
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
    migrate::MIGRATOR
        .run(store.client())
        .await
        .expect("migrate");

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
        async move { kafka::run(consumer, consumer_store, shutdown).await }
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
