//! `KafkaEventSink` sends every record to the partition
//! `events::partitioning::partition_for_key` names, proven against a real broker.
//!
//! The sink cannot hand the choice to librdkafka: under its default CRC-32
//! partitioner Ethereum's and Base's chain keys shared one partition, and
//! rdkafka 0.39's `FutureProducer` cannot carry a custom partitioner. So the
//! sink reads each topic's partition count from broker metadata and sets the
//! partition explicitly. A unit test can check the function; only a broker can
//! show that the metadata read, the cache and the explicit send agree with it —
//! and that nothing silently fell back to the hash.
//!
//! Marked `#[ignore]` (Docker); CI's integration job runs it.

use std::collections::BTreeMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use event_bus::{EventSink, KafkaEventSink};
use events::chain::BlockFinalized;
use events::partitioning::{crc32, partition_for_key};
use events::primitives::{BlockRef, Chain, CustomerId};
use events::system::UsageRecorded;
use events::{DomainEvent, EventEnvelope};
use rdkafka::admin::{AdminClient, AdminOptions, NewTopic, TopicReplication};
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::{ClientConfig, Message};
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::kafka::apache::{Kafka, KAFKA_PORT};
use uuid::Uuid;

/// The deployed default, and large enough that a hash placement and a slot
/// placement disagree for the chains under test.
const PARTITIONS: i32 = 12;

fn at(n: u64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp_millis(1_700_000_000_000 + n as i64).unwrap()
}

fn finalized(n: u64, chain: Chain) -> EventEnvelope {
    EventEnvelope::with_metadata(
        Uuid::from_u128(u128::from(n)),
        at(n),
        chain,
        DomainEvent::BlockFinalized(BlockFinalized {
            block: BlockRef::new(n, Default::default()),
        }),
    )
}

fn usage(n: u64, customer: CustomerId) -> EventEnvelope {
    EventEnvelope::with_metadata(
        Uuid::from_u128(1_000 + u128::from(n)),
        at(n),
        Chain::ETHEREUM,
        DomainEvent::UsageRecorded(UsageRecorded {
            customer_id: Some(customer),
            event_type: "api_call_made".into(),
            quantity: 1,
            timestamp: at(n),
        }),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Docker (testcontainers Kafka)"]
async fn the_sink_places_chain_keys_on_their_slots_and_business_keys_by_hash() {
    let node = Kafka::default().start().await.expect("start kafka");
    let brokers = format!(
        "127.0.0.1:{}",
        node.get_host_port_ipv4(KAFKA_PORT)
            .await
            .expect("kafka port")
    );

    // Provisioned first, as event-store does at boot: the sink reads the
    // partition count from metadata and must see the real one.
    let finalized_topic = finalized(0, Chain::ETHEREUM).topic();
    let usage_topic = usage(0, CustomerId(Uuid::nil())).topic();
    let admin: AdminClient<_> = ClientConfig::new()
        .set("bootstrap.servers", &brokers)
        .create()
        .expect("admin client");
    for result in admin
        .create_topics(
            &[
                NewTopic::new(&finalized_topic, PARTITIONS, TopicReplication::Fixed(1)),
                NewTopic::new(&usage_topic, PARTITIONS, TopicReplication::Fixed(1)),
            ],
            &AdminOptions::new().operation_timeout(Some(Duration::from_secs(30))),
        )
        .await
        .expect("create topics")
    {
        result.expect("topic created");
    }

    // Three events per chain (the second and third publish read the cached
    // count), and customers chosen so their hash placement is spread out.
    let customers: Vec<CustomerId> = (0..4u128)
        .map(|i| CustomerId(Uuid::from_u128(0xC0FFEE + i)))
        .collect();
    let sink = KafkaEventSink::new(&brokers).expect("sink");
    let mut expected: BTreeMap<String, i32> = BTreeMap::new();
    let mut n = 0;
    for chain in [Chain::ETHEREUM, Chain::BASE] {
        for _ in 0..3 {
            n += 1;
            sink.publish(finalized(n, chain))
                .await
                .expect("publish block");
        }
        let slot = chain.partition_slot().expect("known chain") as i32;
        expected.insert(chain.id().to_string(), slot);
    }
    for customer in &customers {
        n += 1;
        sink.publish(usage(n, *customer))
            .await
            .expect("publish usage");
        let key = customer.to_string();
        expected.insert(
            key.clone(),
            partition_for_key(key.as_bytes(), PARTITIONS as u32) as i32,
        );
    }
    let published = n;

    // Read everything back and record which partition each key landed on.
    let consumer: StreamConsumer = ClientConfig::new()
        .set("bootstrap.servers", &brokers)
        .set("group.id", "partition-placement")
        .set("auto.offset.reset", "earliest")
        .create()
        .expect("consumer");
    consumer
        .subscribe(&[finalized_topic.as_str(), usage_topic.as_str()])
        .expect("subscribe");
    let mut landed: BTreeMap<String, Vec<i32>> = BTreeMap::new();
    let mut received = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while received < published {
        let message = tokio::time::timeout_at(deadline, consumer.recv())
            .await
            .unwrap_or_else(|_| {
                panic!("only {received} of {published} records arrived: {landed:?}")
            })
            .expect("receive");
        let key = String::from_utf8(message.key().expect("keyed").to_vec()).expect("utf-8 key");
        landed.entry(key).or_default().push(message.partition());
        received += 1;
    }

    for (key, want) in &expected {
        let got = &landed[key];
        assert!(
            got.iter().all(|p| p == want),
            "key {key} must land on partition {want}, landed on {got:?}"
        );
    }
    assert_eq!(landed["1"], vec![0, 0, 0], "Ethereum occupies slot 0");
    assert_eq!(landed["8453"], vec![1, 1, 1], "Base occupies slot 1");

    // The regression this replaced: under librdkafka's hash the two chains
    // would have shared a partition at the old count of three. Pin that the
    // placement above is the slot, not a hash that happened to agree.
    assert_eq!(crc32(b"1") % 3, crc32(b"8453") % 3);
}
