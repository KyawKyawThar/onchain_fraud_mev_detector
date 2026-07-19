//! The [`RuleStore`] contract, exercised twice: against the in-memory double
//! (every `cargo test` run — proving the semantics the t2–t5 consumers lean
//! on) and against *real* Postgres via testcontainers (`#[ignore]`, run by
//! `just test-integration` — proving `PgRuleStore` honours the same contract,
//! including the §9 isolation guarantee).

use chrono::{DateTime, Utc};
use event_bus::Transience;
use events::primitives::{AccountAddress, Chain, CustomerId, LabelKind};
use rule_engine::model::{Action, Condition, Rule, TemporalConstraint};
use rule_engine::store::{CreateRuleOutcome, PgRuleStore, RuleStore, StoreError};
use rule_engine::test_util::{InMemoryRuleStore, RuleBuilder};
use rust_decimal::Decimal;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

fn at(secs: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(secs, 0).expect("valid timestamp")
}

/// A valid §9 rule owned by `owner` — the compliance example, temporal clause
/// included, so the Pg round-trip covers every column shape.
fn rule(owner: CustomerId, name: &str) -> Rule {
    let large_usdc = Condition::TransferAmount {
        chain: Chain::ETHEREUM,
        token: Some(AccountAddress::repeat_byte(0xAA)),
        gt: Some(Decimal::new(1_000_000, 0)),
        lt: None,
    };
    let touches_mixer = Condition::InteractedWith {
        address: None,
        label_kind: Some(LabelKind::MixerUser),
    };
    RuleBuilder::new(owner)
        .name(name)
        .condition(large_usdc.clone())
        .condition(touches_mixer.clone())
        .temporal(TemporalConstraint::Sequence {
            events: vec![large_usdc, touches_mixer],
            within_blocks: 100,
        })
        .action(Action::WebhookAlert {
            url: "https://compliance.example.com/hook".into(),
        })
        .build()
}

// ── The contract, backend-agnostic ───────────────────────────────

/// Create writes once, redelivery is a no-op, and the stored definition reads
/// back exactly (Decimal thresholds, temporal clause, actions — the whole
/// document).
async fn contract_create_and_read_back(store: &dyn RuleStore) {
    let owner = CustomerId::new();
    let rule = rule(owner, "compliance");

    assert_eq!(
        store.create_rule(&rule, at(100)).await.expect("create"),
        CreateRuleOutcome::Created
    );
    // Redelivered create (same rule_id): idempotent no-op.
    assert_eq!(
        store.create_rule(&rule, at(101)).await.expect("redeliver"),
        CreateRuleOutcome::AlreadyExists
    );

    let read = store
        .rule(owner, rule.id)
        .await
        .expect("read")
        .expect("stored rule");
    assert_eq!(read, rule);

    let listed = store.rules_for_owner(owner).await.expect("list");
    assert_eq!(listed, vec![rule]);
}

/// An invalid definition is rejected before any write — it can never land in
/// the store — and the rejection is permanent (never retried).
async fn contract_invalid_rule_rejected(store: &dyn RuleStore) {
    let owner = CustomerId::new();
    let mut bad = rule(owner, "bad");
    bad.actions.clear();

    let err = store
        .create_rule(&bad, at(100))
        .await
        .expect_err("must reject");
    assert!(matches!(err, StoreError::Invalid(_)));
    assert!(!err.is_transient());
    assert!(store.rules_for_owner(owner).await.expect("list").is_empty());
}

/// One live rule name per customer; the same name is fine for a *different*
/// customer, and reusable after the original is deleted.
async fn contract_name_unique_per_owner(store: &dyn RuleStore) {
    let owner = CustomerId::new();
    let other = CustomerId::new();
    let first = rule(owner, "compliance");
    store.create_rule(&first, at(100)).await.expect("create");

    // Same owner, same name, different id → NameTaken, nothing written.
    let dup = rule(owner, "compliance");
    assert_eq!(
        store.create_rule(&dup, at(101)).await.expect("dup"),
        CreateRuleOutcome::NameTaken
    );
    assert_eq!(store.rules_for_owner(owner).await.expect("list").len(), 1);

    // Another customer freely uses the same name — names are scoped, not global.
    assert_eq!(
        store
            .create_rule(&rule(other, "compliance"), at(102))
            .await
            .expect("other owner"),
        CreateRuleOutcome::Created
    );

    // Deleting frees the name for its owner.
    assert!(store
        .delete_rule(owner, first.id, at(103))
        .await
        .expect("delete"));
    assert_eq!(
        store
            .create_rule(&rule(owner, "compliance"), at(104))
            .await
            .expect("recreate"),
        CreateRuleOutcome::Created
    );
}

/// §9's isolation guarantee: another customer's rules are invisible and
/// untouchable — a cross-customer probe is indistinguishable from "no such
/// rule", and cross-customer toggles/deletes write nothing.
async fn contract_customer_isolation(store: &dyn RuleStore) {
    let alice = CustomerId::new();
    let mallory = CustomerId::new();
    let alices = rule(alice, "compliance");
    store.create_rule(&alices, at(100)).await.expect("create");

    // Read probe with the right rule_id but the wrong owner: absent.
    assert_eq!(store.rule(mallory, alices.id).await.expect("probe"), None);
    assert!(store
        .rules_for_owner(mallory)
        .await
        .expect("list")
        .is_empty());

    // Mutation probes: nothing written, alice's rule untouched.
    assert!(!store
        .set_enabled(mallory, alices.id, false, at(101))
        .await
        .expect("toggle probe"));
    assert!(!store
        .delete_rule(mallory, alices.id, at(102))
        .await
        .expect("delete probe"));
    let still = store
        .rule(alice, alices.id)
        .await
        .expect("read")
        .expect("still stored");
    assert!(still.enabled);
}

/// Enable/disable is owner-scoped and visible in the engine's evaluation set;
/// soft delete removes from every read path.
async fn contract_toggle_delete_and_evaluation_set(store: &dyn RuleStore) {
    let owner = CustomerId::new();
    let keep = rule(owner, "keep");
    let toggle = rule(owner, "toggle");
    let drop_ = rule(owner, "drop");
    for (r, t) in [(&keep, 100), (&toggle, 101), (&drop_, 102)] {
        store.create_rule(r, at(t)).await.expect("create");
    }

    // The evaluation set crosses owners but sees only enabled, live rules.
    let enabled_ids = |rules: Vec<Rule>| rules.into_iter().map(|r| r.id).collect::<Vec<_>>();
    let all = store.enabled_rules().await.expect("enabled");
    for r in [&keep, &toggle, &drop_] {
        assert!(enabled_ids(all.clone()).contains(&r.id));
    }

    // Disable one; toggling to the state it already has reports no-op.
    assert!(store
        .set_enabled(owner, toggle.id, false, at(110))
        .await
        .expect("disable"));
    assert!(!store
        .set_enabled(owner, toggle.id, false, at(111))
        .await
        .expect("re-disable"));
    // Disabled rules stay in the customer's management view…
    assert_eq!(store.rules_for_owner(owner).await.expect("list").len(), 3);
    // …but leave the evaluation set.
    let now_enabled = enabled_ids(store.enabled_rules().await.expect("enabled"));
    assert!(!now_enabled.contains(&toggle.id));

    // Soft delete: gone from every read path; idempotent.
    assert!(store
        .delete_rule(owner, drop_.id, at(120))
        .await
        .expect("delete"));
    assert!(!store
        .delete_rule(owner, drop_.id, at(121))
        .await
        .expect("re-delete"));
    assert_eq!(store.rule(owner, drop_.id).await.expect("read"), None);
    assert_eq!(store.rules_for_owner(owner).await.expect("list").len(), 2);
    let now_enabled = enabled_ids(store.enabled_rules().await.expect("enabled"));
    assert!(!now_enabled.contains(&drop_.id));
}

// ── In-memory double (every test run) ────────────────────────────

#[tokio::test]
async fn in_memory_create_and_read_back() {
    contract_create_and_read_back(&InMemoryRuleStore::new()).await;
}

#[tokio::test]
async fn in_memory_invalid_rule_rejected() {
    contract_invalid_rule_rejected(&InMemoryRuleStore::new()).await;
}

#[tokio::test]
async fn in_memory_name_unique_per_owner() {
    contract_name_unique_per_owner(&InMemoryRuleStore::new()).await;
}

#[tokio::test]
async fn in_memory_customer_isolation() {
    contract_customer_isolation(&InMemoryRuleStore::new()).await;
}

#[tokio::test]
async fn in_memory_toggle_delete_and_evaluation_set() {
    contract_toggle_delete_and_evaluation_set(&InMemoryRuleStore::new()).await;
}

// ── Real Postgres (`just test-integration`) ──────────────────────

/// Start a Postgres container, apply the workspace migrations, hand back the
/// store (plus the pool, for outbox-table assertions, and the container guard
/// — dropping it kills the database).
async fn pg_store() -> (
    PgRuleStore,
    sqlx::PgPool,
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
    // The same migrations the `just migrate-*` recipes apply.
    sqlx::migrate!("../db/migrations")
        .run(&pool)
        .await
        .expect("apply migrations");
    (PgRuleStore::new(pool.clone()), pool, container)
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn pg_create_and_read_back() {
    let (store, _pool, _pg) = pg_store().await;
    store.ping().await.expect("schema applied");
    contract_create_and_read_back(&store).await;
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn pg_invalid_rule_rejected() {
    let (store, _pool, _pg) = pg_store().await;
    contract_invalid_rule_rejected(&store).await;
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn pg_name_unique_per_owner() {
    let (store, _pool, _pg) = pg_store().await;
    contract_name_unique_per_owner(&store).await;
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn pg_customer_isolation() {
    let (store, _pool, _pg) = pg_store().await;
    contract_customer_isolation(&store).await;
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn pg_toggle_delete_and_evaluation_set() {
    let (store, _pool, _pg) = pg_store().await;
    contract_toggle_delete_and_evaluation_set(&store).await;
}

// ── The transactional outbox (§20) ───────────────────────────────

/// A `RuleCreated` announcement in wire-envelope form, as `POST /v1/rules`
/// composes it.
fn announcement(rule: &Rule) -> serde_json::Value {
    let event = events::DomainEvent::RuleCreated(events::rule_engine::RuleCreated {
        rule_id: rule.id,
        owner: rule.owner,
        definition: serde_json::to_value(rule).expect("rule encodes"),
    });
    serde_json::to_value(events::EventEnvelope::new(Chain::ETHEREUM, event))
        .expect("envelope encodes")
}

/// `create_rule_announced` enqueues exactly one announcement per *created*
/// rule — a redelivered create (AlreadyExists) and a name conflict enqueue
/// nothing, mirroring what actually got stored.
#[tokio::test]
async fn in_memory_announced_create_enqueues_only_on_created() {
    let store = InMemoryRuleStore::new();
    let owner = CustomerId::new();
    let r = rule(owner, "compliance");
    let ann = announcement(&r);

    assert_eq!(
        store
            .create_rule_announced(&r, &ann, at(100))
            .await
            .expect("create"),
        CreateRuleOutcome::Created
    );
    // Redelivery: no second announcement.
    assert_eq!(
        store
            .create_rule_announced(&r, &ann, at(101))
            .await
            .expect("redeliver"),
        CreateRuleOutcome::AlreadyExists
    );
    assert_eq!(store.announcements().len(), 1);
    assert_eq!(store.announcements()[0], ann);
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn pg_announced_create_is_transactional_and_flushes_to_the_sink() {
    use event_bus::test_util::RecordingSink;

    let (store, pool, _pg) = pg_store().await;
    let owner = CustomerId::new();
    let r = rule(owner, "compliance");
    let ann = announcement(&r);

    assert_eq!(
        store
            .create_rule_announced(&r, &ann, at(100))
            .await
            .expect("create"),
        CreateRuleOutcome::Created
    );
    // Redelivery enqueues nothing.
    assert_eq!(
        store
            .create_rule_announced(&r, &ann, at(101))
            .await
            .expect("redeliver"),
        CreateRuleOutcome::AlreadyExists
    );
    let pending: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rule_outbox WHERE published_at IS NULL")
            .fetch_one(&pool)
            .await
            .expect("count pending");
    assert_eq!(pending, 1, "exactly one announcement pending");

    // The flusher publishes it and stamps it published.
    let sink = RecordingSink::default();
    let published = rule_engine::outbox::flush_once(&pool, &sink)
        .await
        .expect("flush");
    assert_eq!(published, 1);
    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], events::DomainEvent::RuleCreated(_)));

    let pending: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rule_outbox WHERE published_at IS NULL")
            .fetch_one(&pool)
            .await
            .expect("count pending");
    assert_eq!(pending, 0, "flushed row is stamped, not re-published");

    // A second flush is a no-op — the outbox drains exactly once per row.
    let published = rule_engine::outbox::flush_once(&pool, &sink)
        .await
        .expect("flush again");
    assert_eq!(published, 0);
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn pg_outbox_row_stays_pending_when_the_sink_fails() {
    use async_trait::async_trait;
    use event_bus::{EventSink, PublishError};
    use events::EventEnvelope;

    /// A sink whose broker is down: every publish fails retriably.
    struct DownSink;
    #[async_trait]
    impl EventSink for DownSink {
        async fn publish(&self, _envelope: EventEnvelope) -> Result<(), PublishError> {
            Err(PublishError::Delivery("broker down".into()))
        }
    }

    let (store, pool, _pg) = pg_store().await;
    let owner = CustomerId::new();
    let r = rule(owner, "compliance");
    store
        .create_rule_announced(&r, &announcement(&r), at(100))
        .await
        .expect("create");

    let published = rule_engine::outbox::flush_once(&pool, &DownSink)
        .await
        .expect("flush survives a publish failure");
    assert_eq!(published, 0);
    let pending: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rule_outbox WHERE published_at IS NULL")
            .fetch_one(&pool)
            .await
            .expect("count pending");
    assert_eq!(
        pending, 1,
        "the failed row is still pending for the next tick"
    );
}
