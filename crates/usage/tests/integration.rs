//! Integration tests for the usage sink against *real* ClickHouse and Kafka,
//! spun up on demand via testcontainers. Marked `#[ignore]` so the default
//! `cargo test` stays hermetic; CI's `integration-test` job (and
//! `just test-integration`) run them with `--run-ignored all`.
//!
//! Three things are proven here:
//!   1. an inserted batch lands and reads back exactly, a redelivered
//!      duplicate converges to one logical row in the raw table (the
//!      ReplacingMergeTree + `count(DISTINCT event_id)` posture), **and** the
//!      rollup double-counts that duplicate — locking the documented
//!      "rollup is approximate, raw is exact" accuracy split;
//!   2. `UsageRecorded`s published to Kafka land as rows end-to-end through
//!      the *batching* loop (one flush, offsets committed after it), and feed
//!      the daily rollup; and
//!   3. a misrouted non-usage event on the topic is parked on the
//!      `mev.dlq.usage` dead-letter topic — byte-for-byte, with the skip
//!      reason in headers — without wedging the records around it.

use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use event_bus::batch::BatchConfig;
use event_bus::dlq::DeadLetterQueue;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::message::{Header, Headers, OwnedHeaders};
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::{ClientConfig, Message};
use secrecy::SecretString;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::clickhouse::{ClickHouse, CLICKHOUSE_PORT};
use testcontainers_modules::kafka::apache::{Kafka, KAFKA_PORT};
use tokio_util::sync::CancellationToken;
use usage::config::{ClickhouseConfig, KafkaConfig};
use usage::store::{build_client, UsageRow, UsageStore};
use usage::{kafka, migrate};
use uuid::Uuid;

use events::primitives::{Chain, CustomerId};
use events::system::{UsageEventType, UsageRecorded};
use events::{DomainEvent, EventEnvelope};

/// Connect a [`UsageStore`] to a testcontainer ClickHouse (default user, no
/// password, `default` database).
fn store_for(http_port: u16) -> UsageStore {
    UsageStore::new(build_client(&ClickhouseConfig {
        url: format!("http://127.0.0.1:{http_port}"),
        user: "default".to_owned(),
        password: SecretString::from(String::new()),
        database: "default".to_owned(),
    }))
}

/// A `UsageRecorded` envelope with deterministic identity, so assertions can
/// key on exact values. Millisecond-precise timestamp because the
/// `DateTime64(3)` column stores only milliseconds.
fn usage_envelope(id: u128, customer: u128, quantity: u64) -> EventEnvelope {
    let at = DateTime::<Utc>::from_timestamp_millis(1_700_000_000_000 + id as i64).unwrap();
    EventEnvelope::with_metadata(
        Uuid::from_u128(id),
        at,
        Chain::ETHEREUM,
        DomainEvent::UsageRecorded(UsageRecorded {
            customer_id: Some(CustomerId(Uuid::from_u128(customer))),
            event_type: UsageEventType::ApiCallMade.as_wire_str().to_owned(),
            quantity,
            timestamp: at,
        }),
    )
}

/// A tight test batch shape: small size trigger, short wait, fast retries.
fn test_batch_config() -> BatchConfig {
    BatchConfig {
        max_items: 100,
        max_wait: Duration::from_millis(200),
        retry_backoff: Duration::from_millis(50),
        shutdown_flush_grace: Duration::from_secs(5),
    }
}

async fn fetch_all_rows(store: &UsageStore) -> Vec<UsageRow> {
    let mut rows: Vec<UsageRow> = store
        .client()
        .query(
            "SELECT event_id, customer_id, event_type, quantity, chain, occurred_at \
             FROM usage_events",
        )
        .fetch_all()
        .await
        .expect("query usage_events");
    rows.sort_by_key(|r| r.event_id);
    rows
}

/// The rollup read discipline from the 0002 migration header: SummingMergeTree
/// holds partial sums until merges run, so readers always aggregate.
async fn rollup_totals(store: &UsageStore) -> (u64, u64) {
    store
        .client()
        .query(
            "SELECT toUInt64(sum(total_quantity)), toUInt64(sum(events)) \
             FROM usage_rollup_daily",
        )
        .fetch_one::<(u64, u64)>()
        .await
        .expect("query usage_rollup_daily")
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers ClickHouse)"]
async fn batch_insert_lands_duplicates_converge_and_the_rollup_is_honest() {
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

    let env = usage_envelope(1, 7, 3);
    let row = UsageRow::try_from(&env).expect("map");
    store
        .insert_batch(std::slice::from_ref(&row))
        .await
        .expect("insert");
    // The at-least-once redelivery: the same batch flushed again (a crash
    // between flush and offset commit).
    store
        .insert_batch(std::slice::from_ref(&row))
        .await
        .expect("insert duplicate");

    // Exact reconciliation never depends on merge timing: DISTINCT event_id
    // is 1 whether or not the background merge has run yet.
    let distinct: u64 = store
        .client()
        .query("SELECT count(DISTINCT event_id) FROM usage_events")
        .fetch_one()
        .await
        .expect("distinct count");
    assert_eq!(distinct, 1, "a redelivered event is one logical event");

    // And the ReplacingMergeTree key does converge the physical duplicates:
    // FINAL forces the merge view.
    let merged: u64 = store
        .client()
        .query("SELECT count() FROM usage_events FINAL")
        .fetch_one()
        .await
        .expect("final count");
    assert_eq!(merged, 1, "duplicates converge under the engine key");

    let got = fetch_all_rows(&store).await;
    assert_eq!(got.first(), Some(&row), "the row must read back exactly");

    // The documented accuracy split: the rollup MV fired on BOTH raw inserts
    // (raw-table dedup does not propagate), so it double-counts the redelivery
    // — which is exactly why exact numbers read the raw table and the rollup
    // is the dashboard surface.
    let (total_quantity, events) = rollup_totals(&store).await;
    assert_eq!(total_quantity, 6, "rollup counts the duplicate (3 + 3)");
    assert_eq!(events, 2, "rollup saw two raw inserts");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Docker (testcontainers ClickHouse + Kafka)"]
async fn usage_published_to_kafka_lands_via_batching_and_poison_parks_on_the_dlq() {
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

    // In production event-store's `ensure_topics` owns the source topology
    // (§20); the DLQ's own `ensure` also provisions the source topic's broker
    // here via auto-creation being off — so create the source topic through
    // the same admin path the DLQ uses, then the DLQ topic itself.
    let dlq = DeadLetterQueue::ensure(&brokers, "usage", 1, 60 * 60 * 1_000)
        .await
        .expect("provision DLQ");
    // Stand in for event-store's ensure_topics for the source topic.
    {
        use rdkafka::admin::{AdminClient, AdminOptions, NewTopic, TopicReplication};
        let admin: AdminClient<_> = ClientConfig::new()
            .set("bootstrap.servers", &brokers)
            .create()
            .expect("admin client");
        admin
            .create_topics(
                &[NewTopic::new(
                    &kafka::topic(),
                    3,
                    TopicReplication::Fixed(1),
                )],
                &AdminOptions::new().request_timeout(Some(Duration::from_secs(10))),
            )
            .await
            .expect("create source topic");
    }

    // Two usage events for different customers, plus a misrouted non-usage
    // event that must be parked, not stall the two around it.
    let first = usage_envelope(1, 7, 1);
    let misrouted = EventEnvelope::new(
        Chain::ETHEREUM,
        DomainEvent::SanctionHit(events::intelligence::SanctionHit {
            address: events::primitives::AccountAddress::repeat_byte(0x42),
            list: "OFAC".to_owned(),
            entry: "SDN-1".to_owned(),
        }),
    );
    let second = usage_envelope(2, 8, 5);

    let producer: FutureProducer = ClientConfig::new()
        .set("bootstrap.servers", &brokers)
        .set("message.timeout.ms", "5000")
        .create()
        .expect("create producer");
    let misrouted_bytes = misrouted.to_json_vec().expect("serialize misrouted");
    for envelope in [&first, &misrouted, &second] {
        // The real producer keying: customer for usage, chain for the rest
        // (the §13 partition-spread decision, via the schema's PartitionKey).
        let key = envelope.partition_key().to_string();
        let payload = envelope.to_json_vec().expect("serialize envelope");
        // A W3C traceparent header, the same shape a real producer injects.
        let headers = OwnedHeaders::new().insert(Header {
            key: "traceparent",
            value: Some("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"),
        });
        producer
            .send(
                FutureRecord::to(&kafka::topic())
                    .payload(&payload)
                    .key(&key)
                    .headers(headers),
                Duration::from_secs(5),
            )
            .await
            .expect("produce");
    }

    // Run the real batching consumer.
    let cfg = KafkaConfig {
        brokers: brokers.clone(),
        group_id: "usage-test".to_owned(),
        dlq_replication: 1,
        dlq_retention_ms: 60 * 60 * 1_000,
    };
    let consumer = kafka::build_consumer(&cfg).expect("build consumer");
    let consumer_store = store.clone();
    let shutdown = CancellationToken::new();
    let consumer_task = tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            kafka::run(
                consumer,
                consumer_store,
                test_batch_config(),
                Some(&dlq),
                shutdown,
            )
            .await
        }
    });

    // Poll until both usage rows land (or time out) — the misrouted event
    // sits between them, so both landing proves it was skipped, not wedged on.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let count: u64 = store
            .client()
            .query("SELECT count(DISTINCT event_id) FROM usage_events")
            .fetch_one()
            .await
            .expect("count");
        if count >= 2 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "usage rows never reached the sink within 30s"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // Exercise the graceful path: cancel and let the consumer drain & exit.
    shutdown.cancel();
    consumer_task
        .await
        .expect("consumer task")
        .expect("consumer run");

    let got = fetch_all_rows(&store).await;
    let want = vec![
        UsageRow::try_from(&first).expect("map"),
        UsageRow::try_from(&second).expect("map"),
    ];
    assert_eq!(got, want, "exactly the two usage events, mapped exactly");

    // The rollup MV fed off the same batch insert.
    let (total_quantity, events) = rollup_totals(&store).await;
    assert_eq!(total_quantity, 6, "1 + 5 across the two customers");
    assert_eq!(events, 2);

    // The misrouted record was parked on the DLQ byte-for-byte, with the skip
    // reason and source coordinates in headers.
    let dlq_consumer: StreamConsumer = ClientConfig::new()
        .set("bootstrap.servers", &brokers)
        .set("group.id", "dlq-check")
        .set("enable.auto.commit", "false")
        .set("auto.offset.reset", "earliest")
        .create()
        .expect("dlq consumer");
    dlq_consumer
        .subscribe(&[&DeadLetterQueue::topic_for("usage")])
        .expect("subscribe dlq");
    let parked = tokio::time::timeout(Duration::from_secs(30), dlq_consumer.recv())
        .await
        .expect("a record must reach the DLQ within 30s")
        .expect("dlq receive");
    assert_eq!(
        parked.payload(),
        Some(misrouted_bytes.as_slice()),
        "the original bytes, untouched"
    );
    let headers = parked.headers().expect("dlq headers");
    let header = |name: &str| -> String {
        headers
            .iter()
            .find(|h| h.key == name)
            .and_then(|h| h.value)
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_else(|| panic!("missing DLQ header {name}"))
    };
    assert!(
        header("dlq.error").contains("SanctionHit"),
        "names the poison"
    );
    assert_eq!(header("dlq.consumer"), "usage");
    assert_eq!(header("dlq.source.topic"), kafka::topic());
    // The producer's trace context survived onto the parked copy.
    assert!(header("traceparent").starts_with("00-"));
}
