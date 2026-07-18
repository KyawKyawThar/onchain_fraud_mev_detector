//! The [`NotificationStore`] contract, exercised twice: against the
//! in-memory double (every `cargo test` run) and against real Postgres via
//! testcontainers (`#[ignore]`, run by `just test-integration`) — proving
//! `PgNotificationStore` honours the same dedup/claim/correlation semantics
//! the in-memory double does. Mirrors `rule-engine/tests/rule_store.rs`.

use chrono::{DateTime, Utc};
use events::primitives::{AlertId, CustomerId, IncidentId, Severity};
use notification::model::{
    Channel, ChannelKind, LifecycleStage, Subscriber, SubscriberId, SubscriptionFilter,
};
use notification::store::{ClaimOutcome, DeliveryOutcome, NotificationStore, PgNotificationStore};
use notification::test_util::InMemoryNotificationStore;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

fn at(secs: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(secs, 0).expect("valid timestamp")
}

fn subscriber(owner: CustomerId) -> Subscriber {
    Subscriber {
        id: SubscriberId::new(),
        owner,
        channels: vec![Channel::Webhook {
            url: "https://example.com/hook".into(),
        }],
        filter: SubscriptionFilter {
            min_severity: Some(Severity::Low),
            kinds: None,
            chains: None,
        },
        enabled: true,
    }
}

// ── The contract, backend-agnostic ───────────────────────────────

/// Claiming the same `(subscriber, dedup_key, stage, channel)` key twice
/// before an outcome is recorded resumes the same row — a redelivered
/// record that crashed mid-attempt retries, it doesn't silently vanish.
async fn contract_claim_resumes_an_undelivered_row(store: &dyn NotificationStore) {
    let sub = subscriber(CustomerId::new());
    store.create_subscriber(&sub, at(1)).await.expect("create");
    let dedup_key = AlertId::new().to_string();

    let first = store
        .claim_delivery(
            sub.id,
            &dedup_key,
            LifecycleStage::Provisional,
            ChannelKind::Webhook,
            at(2),
        )
        .await
        .expect("claim");
    let ClaimOutcome::Proceed(id1) = first else {
        panic!("expected Proceed on a fresh claim");
    };

    let second = store
        .claim_delivery(
            sub.id,
            &dedup_key,
            LifecycleStage::Provisional,
            ChannelKind::Webhook,
            at(3),
        )
        .await
        .expect("claim again");
    let ClaimOutcome::Proceed(id2) = second else {
        panic!("expected Proceed to resume the same undelivered row, not AlreadyDelivered");
    };
    assert_eq!(id1, id2, "the same row is resumed, not a new one minted");
}

/// Once a claim's outcome is `Delivered`, re-claiming the same key is a true
/// dedup — the redelivered-record contract `notice_deliveries`'s unique
/// index backs.
async fn contract_delivered_claim_is_true_dedup(store: &dyn NotificationStore) {
    let sub = subscriber(CustomerId::new());
    store.create_subscriber(&sub, at(1)).await.expect("create");
    let dedup_key = AlertId::new().to_string();

    let ClaimOutcome::Proceed(id) = store
        .claim_delivery(
            sub.id,
            &dedup_key,
            LifecycleStage::Confirmed,
            ChannelKind::Webhook,
            at(2),
        )
        .await
        .expect("claim")
    else {
        panic!("expected Proceed");
    };
    store
        .record_outcome(id, DeliveryOutcome::Delivered, at(3))
        .await
        .expect("record delivered");

    let redelivered = store
        .claim_delivery(
            sub.id,
            &dedup_key,
            LifecycleStage::Confirmed,
            ChannelKind::Webhook,
            at(4),
        )
        .await
        .expect("claim redelivered");
    assert_eq!(redelivered, ClaimOutcome::AlreadyDelivered);
}

/// A confirmed upgrade shares the provisional's `dedup_key` (§11 lineage)
/// but is claimed as a *distinct* delivery — one stage's `Delivered` status
/// never dedups the other's.
async fn contract_confirmed_upgrade_is_a_distinct_delivery(store: &dyn NotificationStore) {
    let sub = subscriber(CustomerId::new());
    store.create_subscriber(&sub, at(1)).await.expect("create");
    let dedup_key = AlertId::new().to_string();

    let ClaimOutcome::Proceed(provisional_id) = store
        .claim_delivery(
            sub.id,
            &dedup_key,
            LifecycleStage::Provisional,
            ChannelKind::Webhook,
            at(2),
        )
        .await
        .expect("claim provisional")
    else {
        panic!("expected Proceed");
    };
    store
        .record_outcome(provisional_id, DeliveryOutcome::Delivered, at(3))
        .await
        .expect("record delivered");

    let confirmed = store
        .claim_delivery(
            sub.id,
            &dedup_key,
            LifecycleStage::Confirmed,
            ChannelKind::Webhook,
            at(4),
        )
        .await
        .expect("claim confirmed");
    assert!(
        matches!(confirmed, ClaimOutcome::Proceed(id) if id != provisional_id),
        "the confirmed stage is a distinct, undelivered row"
    );
}

/// `delivered_targets_for` returns exactly the prior recipients of a
/// `dedup_key`, deduped across stages — the retraction re-targeting path.
async fn contract_delivered_targets_for_returns_prior_recipients(store: &dyn NotificationStore) {
    let sub = subscriber(CustomerId::new());
    store.create_subscriber(&sub, at(1)).await.expect("create");
    let dedup_key = AlertId::new().to_string();

    for stage in [LifecycleStage::Provisional, LifecycleStage::Confirmed] {
        let ClaimOutcome::Proceed(id) = store
            .claim_delivery(sub.id, &dedup_key, stage, ChannelKind::Webhook, at(2))
            .await
            .expect("claim")
        else {
            panic!("expected Proceed");
        };
        store
            .record_outcome(id, DeliveryOutcome::Delivered, at(3))
            .await
            .expect("record delivered");
    }

    let targets = store
        .delivered_targets_for(&dedup_key)
        .await
        .expect("targets");
    assert_eq!(targets.len(), 1, "deduped across the two delivered stages");
    assert_eq!(targets[0].0, sub.id);
    assert_eq!(targets[0].1, sub.owner);

    // A rejected/failed delivery never appears as a retargetable recipient.
    let other_key = AlertId::new().to_string();
    let ClaimOutcome::Proceed(id) = store
        .claim_delivery(
            sub.id,
            &other_key,
            LifecycleStage::Provisional,
            ChannelKind::Webhook,
            at(4),
        )
        .await
        .expect("claim")
    else {
        panic!("expected Proceed");
    };
    store
        .record_outcome(id, DeliveryOutcome::Failed("timeout".into()), at(5))
        .await
        .expect("record failed");
    assert!(store
        .delivered_targets_for(&other_key)
        .await
        .expect("targets")
        .is_empty());
}

/// The incident↔alert correlation: recorded once, idempotent, absent until
/// recorded.
async fn contract_incident_alert_correlation(store: &dyn NotificationStore) {
    let incident_id = IncidentId::new();
    let alert_id = AlertId::new();

    assert_eq!(
        store.alert_for_incident(incident_id).await.expect("lookup"),
        None
    );

    store
        .record_incident_alert(incident_id, alert_id, at(1))
        .await
        .expect("record");
    assert_eq!(
        store.alert_for_incident(incident_id).await.expect("lookup"),
        Some(alert_id)
    );

    // Idempotent: recording again (e.g. a redelivered IncidentCreated) does
    // not error and keeps the original mapping.
    store
        .record_incident_alert(incident_id, AlertId::new(), at(2))
        .await
        .expect("re-record");
    assert_eq!(
        store.alert_for_incident(incident_id).await.expect("lookup"),
        Some(alert_id),
        "the first-recorded mapping wins"
    );
}

/// `subscribers_for` scopes to `owner` when given, and returns every
/// enabled subscriber platform-wide when `None`.
async fn contract_subscribers_for_scoping(store: &dyn NotificationStore) {
    let alice = CustomerId::new();
    let bob = CustomerId::new();
    let alices_sub = subscriber(alice);
    let bobs_sub = subscriber(bob);
    store
        .create_subscriber(&alices_sub, at(1))
        .await
        .expect("create");
    store
        .create_subscriber(&bobs_sub, at(1))
        .await
        .expect("create");

    let alices = store.subscribers_for(Some(alice)).await.expect("scoped");
    assert_eq!(alices.len(), 1);
    assert_eq!(alices[0].id, alices_sub.id);

    let everyone = store.subscribers_for(None).await.expect("platform-wide");
    assert!(everyone.iter().any(|s| s.id == alices_sub.id));
    assert!(everyone.iter().any(|s| s.id == bobs_sub.id));
}

// ── In-memory double (every test run) ────────────────────────────

#[tokio::test]
async fn in_memory_claim_resumes_an_undelivered_row() {
    contract_claim_resumes_an_undelivered_row(&InMemoryNotificationStore::new()).await;
}

#[tokio::test]
async fn in_memory_delivered_claim_is_true_dedup() {
    contract_delivered_claim_is_true_dedup(&InMemoryNotificationStore::new()).await;
}

#[tokio::test]
async fn in_memory_confirmed_upgrade_is_a_distinct_delivery() {
    contract_confirmed_upgrade_is_a_distinct_delivery(&InMemoryNotificationStore::new()).await;
}

#[tokio::test]
async fn in_memory_delivered_targets_for_returns_prior_recipients() {
    contract_delivered_targets_for_returns_prior_recipients(&InMemoryNotificationStore::new())
        .await;
}

#[tokio::test]
async fn in_memory_incident_alert_correlation() {
    contract_incident_alert_correlation(&InMemoryNotificationStore::new()).await;
}

#[tokio::test]
async fn in_memory_subscribers_for_scoping() {
    contract_subscribers_for_scoping(&InMemoryNotificationStore::new()).await;
}

// ── Real Postgres (`just test-integration`) ──────────────────────

/// Start a Postgres container, apply the workspace migrations, hand back the
/// store (plus the container guard — dropping it kills the database).
async fn pg_store() -> (
    PgNotificationStore,
    testcontainers::ContainerAsync<Postgres>,
) {
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
    (PgNotificationStore::new(pool), container)
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn pg_claim_resumes_an_undelivered_row() {
    let (store, _pg) = pg_store().await;
    store.ping().await.expect("schema applied");
    contract_claim_resumes_an_undelivered_row(&store).await;
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn pg_delivered_claim_is_true_dedup() {
    let (store, _pg) = pg_store().await;
    contract_delivered_claim_is_true_dedup(&store).await;
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn pg_confirmed_upgrade_is_a_distinct_delivery() {
    let (store, _pg) = pg_store().await;
    contract_confirmed_upgrade_is_a_distinct_delivery(&store).await;
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn pg_delivered_targets_for_returns_prior_recipients() {
    let (store, _pg) = pg_store().await;
    contract_delivered_targets_for_returns_prior_recipients(&store).await;
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn pg_incident_alert_correlation() {
    let (store, _pg) = pg_store().await;
    contract_incident_alert_correlation(&store).await;
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn pg_subscribers_for_scoping() {
    let (store, _pg) = pg_store().await;
    contract_subscribers_for_scoping(&store).await;
}
