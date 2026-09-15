//! `Handled::Retry` re-fetches the record, proven against a real broker.
//!
//! The shared consume loop used to back off and go straight back to `recv()`.
//! librdkafka never redelivers an uncommitted record within a session, so
//! `recv()` handed the NEXT record, and the next `Commit` on the partition
//! committed past the one being "retried". Every consumer on `run_consumer`
//! inherited that silent skip. `run_consumer` now seeks the partition back
//! to the record before backing off.
//!
//! A unit test cannot show this: it lives in librdkafka's fetch position, not in
//! our code. Marked `#[ignore]` (Docker); CI's integration job runs it.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use event_bus::{run_consumer, EventHandler, Handled};
use events::chain::BlockFinalized;
use events::primitives::{BlockRef, Chain};
use events::{DomainEvent, EventEnvelope};
use rdkafka::admin::{AdminClient, AdminOptions, NewTopic, TopicReplication};
use rdkafka::consumer::StreamConsumer;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::ClientConfig;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::kafka::apache::{Kafka, KAFKA_PORT};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const TOPIC: &str = "retry-refetch";

fn envelope(n: u64) -> EventEnvelope {
    let at = DateTime::<Utc>::from_timestamp_millis(1_700_000_000_000 + n as i64).unwrap();
    EventEnvelope::with_metadata(
        Uuid::from_u128(u128::from(n)),
        at,
        Chain::ETHEREUM,
        DomainEvent::BlockFinalized(BlockFinalized {
            block: BlockRef::new(n, Default::default()),
        }),
    )
}

/// Records every block number it is handed. Returns `Retry` the first time it
/// sees block 1, and `Commit` otherwise. Cancels `shutdown` once it has handled
/// `stop_after` records, so the loop ends whether or not the retry re-fetched.
struct RetryOnceHandler {
    seen: Arc<Mutex<Vec<u64>>>,
    stop_after: usize,
    shutdown: CancellationToken,
}

#[async_trait]
impl EventHandler for RetryOnceHandler {
    async fn handle(&self, envelope: EventEnvelope) -> Handled {
        let DomainEvent::BlockFinalized(finalized) = envelope.payload else {
            return Handled::Commit;
        };
        let n = finalized.block.number;
        let mut seen = self.seen.lock().unwrap();
        let first_sight_of_one = n == 1 && !seen.contains(&1);
        seen.push(n);
        if seen.len() >= self.stop_after {
            self.shutdown.cancel();
        }
        if first_sight_of_one {
            Handled::Retry
        } else {
            Handled::Commit
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Docker (testcontainers Kafka)"]
async fn a_retried_record_is_handled_again_before_the_records_after_it() {
    let node = Kafka::default().start().await.expect("start kafka");
    let brokers = format!(
        "127.0.0.1:{}",
        node.get_host_port_ipv4(KAFKA_PORT)
            .await
            .expect("kafka port")
    );

    // One partition, so order is total and "the record after it" is unambiguous.
    let admin: AdminClient<_> = ClientConfig::new()
        .set("bootstrap.servers", &brokers)
        .create()
        .expect("admin client");
    admin
        .create_topics(
            &[NewTopic::new(TOPIC, 1, TopicReplication::Fixed(1))],
            &AdminOptions::new().request_timeout(Some(Duration::from_secs(10))),
        )
        .await
        .expect("create topic");

    let producer: FutureProducer = ClientConfig::new()
        .set("bootstrap.servers", &brokers)
        .set("message.timeout.ms", "5000")
        .create()
        .expect("producer");
    for n in 1..=3 {
        let payload = envelope(n).to_json_vec().expect("serialize");
        producer
            .send(
                FutureRecord::<(), _>::to(TOPIC).payload(&payload),
                Duration::from_secs(5),
            )
            .await
            .expect("produce");
    }

    let consumer: StreamConsumer = ClientConfig::new()
        .set("bootstrap.servers", &brokers)
        .set("group.id", "retry-refetch")
        .set("enable.auto.commit", "false")
        .set("auto.offset.reset", "earliest")
        .create()
        .expect("consumer");

    let seen = Arc::new(Mutex::new(Vec::new()));
    let shutdown = CancellationToken::new();
    let handler = RetryOnceHandler {
        seen: seen.clone(),
        stop_after: 4,
        shutdown: shutdown.clone(),
    };

    // Without the seek the handler sees only [1, 2, 3] and never reaches four
    // records; the timeout turns that into a clear failure instead of a hang.
    let run = run_consumer(
        consumer,
        &[TOPIC],
        "retry-refetch-test",
        Duration::from_millis(50),
        None,
        handler,
        &shutdown,
    );
    let finished = tokio::time::timeout(Duration::from_secs(60), run).await;
    let seen = seen.lock().unwrap().clone();

    assert!(
        finished.is_ok(),
        "the consumer never handled four records; seen {seen:?}. A retried record \
         was skipped rather than re-fetched."
    );
    assert_eq!(
        seen,
        vec![1, 1, 2, 3],
        "record 1 must be handled again, before record 2, after its Retry"
    );
}
