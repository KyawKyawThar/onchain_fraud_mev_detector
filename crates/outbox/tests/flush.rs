//! The outbox against real Postgres (§20). Marked `#[ignore]` so the default
//! `cargo test` stays hermetic; CI's integration job runs them.
//!
//! Three properties that only a real database can show, and each one is a way
//! the seam could be wrong while every unit test stayed green:
//!
//! * the **idempotency key** dedups at the database, under the real unique
//!   constraint rather than an in-memory set;
//! * the **lease** stops two flushers publishing the same row, which is what
//!   happens the moment the API service scales past one replica;
//! * a **failed publish leaves the row pending**, so the verdict survives a
//!   broker outage rather than being marked done and lost.

use std::sync::Mutex;

use async_trait::async_trait;
use event_bus::{EventSink, PublishError};
use events::{DomainEvent, EventEnvelope};
use outbox::{Enqueued, Outbox};
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

const FEEDBACK: Outbox = Outbox::new("feedback_outbox", "feedback_outbox");

/// Records what it was asked to publish, and can be told to refuse.
#[derive(Default)]
struct RecordingSink {
    published: Mutex<Vec<EventEnvelope>>,
    refuse: bool,
}

#[async_trait]
impl EventSink for RecordingSink {
    async fn publish(&self, envelope: EventEnvelope) -> Result<(), PublishError> {
        if self.refuse {
            return Err(PublishError::Delivery("broker down".into()));
        }
        self.published.lock().expect("lock").push(envelope);
        Ok(())
    }
}

async fn pool() -> (sqlx::PgPool, testcontainers::ContainerAsync<Postgres>) {
    let container = Postgres::default()
        .start()
        .await
        .expect("start Postgres container");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("Postgres port");
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let pool = db::connect(&url).await.expect("connect");
    sqlx::migrate!("../db/migrations")
        .run(&pool)
        .await
        .expect("apply migrations");
    (pool, container)
}

fn envelope() -> serde_json::Value {
    let event = EventEnvelope::new(
        events::primitives::Chain::ETHEREUM,
        DomainEvent::AlertFeedbackRecorded(events::feedback::AlertFeedbackRecorded {
            incident_id: events::primitives::IncidentId::new(),
            customer_id: events::primitives::CustomerId::new(),
            verdict: events::feedback::FeedbackVerdict::FalsePositive,
            reason_code: events::feedback::FeedbackReason::OurOwnActivity,
            reason: None,
            cohort: events::feedback::FeedbackCohort::Solicited,
            submitted_at: chrono::Utc::now(),
        }),
    );
    serde_json::to_value(event).expect("serialize")
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn an_enqueued_envelope_publishes_once_and_is_stamped() {
    let (pool, _pg) = pool().await;
    let sink = RecordingSink::default();

    assert_eq!(
        FEEDBACK
            .enqueue(&pool, &envelope(), Some("key-1"), chrono::Utc::now())
            .await
            .expect("enqueue"),
        Enqueued::Queued
    );

    assert_eq!(FEEDBACK.flush_once(&pool, &sink).await.expect("flush"), 1);
    assert_eq!(sink.published.lock().unwrap().len(), 1);

    // A second pass has nothing to do: the row is stamped, not re-read.
    assert_eq!(FEEDBACK.flush_once(&pool, &sink).await.expect("flush"), 0);
    assert_eq!(sink.published.lock().unwrap().len(), 1);
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn a_repeated_idempotency_key_is_not_a_second_event() {
    let (pool, _pg) = pool().await;
    let sink = RecordingSink::default();

    for _ in 0..3 {
        FEEDBACK
            .enqueue(&pool, &envelope(), Some("same-key"), chrono::Utc::now())
            .await
            .expect("enqueue");
    }

    assert_eq!(
        FEEDBACK.flush_once(&pool, &sink).await.expect("flush"),
        1,
        "three submissions of one verdict must reach the ledger once"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn a_leased_batch_is_invisible_to_a_second_flusher() {
    // What happens the moment the API service scales past one replica. The
    // lease is claimed by the first flusher's pass; the second finds nothing
    // to do rather than publishing every row a second time.
    let (pool, _pg) = pool().await;
    FEEDBACK
        .enqueue(&pool, &envelope(), Some("leased"), chrono::Utc::now())
        .await
        .expect("enqueue");

    // The first flusher's sink refuses, so the row stays *pending* — but its
    // lease is held, which is precisely the window a second replica would
    // otherwise race into.
    let refusing = RecordingSink {
        refuse: true,
        ..RecordingSink::default()
    };
    assert_eq!(
        FEEDBACK.flush_once(&pool, &refusing).await.expect("flush"),
        0
    );

    let second_replica = RecordingSink::default();
    assert_eq!(
        FEEDBACK
            .flush_once(&pool, &second_replica)
            .await
            .expect("flush"),
        0,
        "a claimed row must not be picked up by a second flusher inside its lease"
    );

    // And the row is not lost: it is pending, waiting for the lease to lapse.
    let pending: i64 =
        sqlx::query_scalar("SELECT count(*) FROM feedback_outbox WHERE published_at IS NULL")
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(
        pending, 1,
        "a failed publish must leave the verdict pending"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn the_rule_outbox_shares_the_shape() {
    // The generalization's real claim: one flusher, two tables. If the
    // migration that added `claimed_until`/`idempotency_key` to `rule_outbox`
    // ever diverges, this fails here rather than in rule-engine at runtime.
    let (pool, _pg) = pool().await;
    let rules = Outbox::new("rule_outbox", "rule_outbox");
    let sink = RecordingSink::default();

    assert_eq!(
        rules
            .enqueue(&pool, &envelope(), None, chrono::Utc::now())
            .await
            .expect("enqueue"),
        Enqueued::Queued
    );
    assert_eq!(rules.flush_once(&pool, &sink).await.expect("flush"), 1);
}
