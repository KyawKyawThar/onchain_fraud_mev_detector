//! **The projection-rebuild drill** (production readiness Epic B), against real
//! Postgres and ClickHouse in throwaway containers.
//!
//! §2 says projections are derived: the event store is the system of record and
//! every read model is a fold over it that could be thrown away and recomputed.
//! This file is the test of that claim, and the same code path is the recovery
//! procedure for a corrupted read model
//! (`docs/runbooks/projection-rebuild.md`).
//!
//! Each test does what the runbook does:
//!
//! 1. drive the **live** path — the real [`ProjectionConsumer`] over the real
//!    stores — with a stream of result-path events, including the duplicates
//!    and cross-partition reordering Kafka actually delivers;
//! 2. fingerprint the resulting rows;
//! 3. replay the same events into a **staging namespace** through
//!    [`SimulationReadModel`] (which drives that *same* consumer type against a
//!    `search_path`-scoped pool / a staging ClickHouse database);
//! 4. assert the fingerprints match — byte-identical over every derived column;
//! 5. promote or discard, and assert the live tables ended up as claimed.
//!
//! Two properties get their own tests because they are the ones staging exists
//! for: `verify` never writes to the live model, and a fault mid-replay leaves
//! production untouched rather than wiped and half-filled.
//!
//! Marked `#[ignore]` so the default `cargo test` stays hermetic; CI's
//! integration job and `just test-integration` run them, and
//! `just projection-rebuild-drill` runs this file alone.
//!
//! The replay source is a canned in-memory [`ReplaySource`] rather than a live
//! event-store container: what is under test is the *fold and the stores*, and
//! the store's own ordering/pagination is already covered by
//! `event-store/tests/integration.rs`. The canned source returns events in the
//! event store's `(occurred_at, event_id)` order, which is what the real one
//! guarantees.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use clickhouse::Client;
use event_bus::{EventHandler, Handled};
use events::primitives::{
    AccountAddress, AlertId, AlertKind, Chain, IncidentId, Severity, SuggestedAction, UsdAmount,
};
use events::simulation::{
    IncidentCreated, IncidentFinalized, IncidentRetracted, SimulationCompleted, SimulationRequested,
};
use events::{DomainEvent, EventEnvelope};
use rebuild::source::{PageRequest, ReplayError, ReplayPage, ReplaySource, Watermark};
use rebuild::{Outcome, RebuildPlan, Scope, Snapshotter, VerifyFailure};
use revm::primitives::B256;
use simulation::projection_consumer::ProjectionConsumer;
use simulation::rebuild::{PostgresStore, SimulationReadModel, Stores};
use simulation::store::{
    ClickhouseAnalytics, CrossChainFindingStore, IncidentAnalytics, IncidentStore, PgIncidentStore,
};
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::clickhouse::{ClickHouse, CLICKHOUSE_PORT};
use testcontainers_modules::postgres::Postgres;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

// ── fixtures ────────────────────────────────────────────────────────

fn at(secs: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(secs, 0).expect("valid timestamp")
}

/// An envelope with a *deterministic* id, so a rerun of the test replays the
/// identical stream — the same property §18 demands of the real replay.
fn env(seq: u8, payload: DomainEvent, occurred_at: DateTime<Utc>) -> EventEnvelope {
    EventEnvelope::with_metadata(
        Uuid::from_bytes([seq; 16]),
        occurred_at,
        Chain::ETHEREUM,
        payload,
    )
}

fn alert(byte: u8) -> AlertId {
    AlertId(Uuid::from_bytes([byte; 16]))
}

fn incident(byte: u8) -> IncidentId {
    IncidentId(Uuid::from_bytes([byte; 16]))
}

fn requested(alert_id: AlertId) -> DomainEvent {
    DomainEvent::SimulationRequested(SimulationRequested {
        alert_id,
        evidence: serde_json::json!({ "kind": "sandwich" }),
    })
}

fn completed(alert_id: AlertId, profit: f64, confirmed: bool) -> DomainEvent {
    DomainEvent::SimulationCompleted(SimulationCompleted {
        alert_id,
        profit,
        victim_loss: profit / 2.0,
        confirmed,
    })
}

fn created(alert_id: AlertId, incident_id: IncidentId) -> DomainEvent {
    DomainEvent::IncidentCreated(IncidentCreated {
        incident_id,
        alert_id,
        kind: AlertKind::Sandwich,
        txs: vec![B256::repeat_byte(0x01), B256::repeat_byte(0x02)],
        profit: 5.0,
        victim_loss: 2.5,
        impact_usd: None,
        severity: Severity::High,
        suggested_action: SuggestedAction::Escalate,
        victim_address: Some(AccountAddress::from(
            alloy_primitives::Address::repeat_byte(0x11),
        )),
        victim_loss_usd: Some(UsdAmount::new(2.5)),
    })
}

fn retracted(incident_id: IncidentId) -> DomainEvent {
    DomainEvent::IncidentRetracted(IncidentRetracted {
        incident_id,
        reason: "reorg orphaned the block".to_string(),
    })
}

fn finalized(incident_id: IncidentId) -> DomainEvent {
    DomainEvent::IncidentFinalized(IncidentFinalized {
        incident_id,
        block_hash: B256::repeat_byte(0x33),
    })
}

/// A history that exercises every branch of the fold *and* the delivery
/// pathologies the projection exists to absorb:
///
/// * a full confirm → finalize lifecycle (alert `0xa1`);
/// * a confirm → retract lifecycle where the terminal arrives **before** the
///   `IncidentCreated` that links it — the cross-partition reorder the fold
///   buffers as an orphan (alert `0xb1`);
/// * a **duplicate** `SimulationCompleted` carrying identical figures — the
///   at-least-once redelivery that must fold to a no-op (alert `0xa1`);
/// * a re-simulation with *newer* figures, which must win by event time;
/// * an unconfirmed alert that never becomes an incident (alert `0xc1`);
/// * a bare `SimulationRequested` whose job row exists with no incident.
///
/// Returned in `(occurred_at, event_id)` order — the order the event store
/// hands back, and therefore the order the rebuild sees.
fn history() -> Vec<EventEnvelope> {
    let (a, b, c, d) = (alert(0xa1), alert(0xb1), alert(0xc1), alert(0xd1));
    let (ia, ib) = (incident(0xa2), incident(0xb2));

    let mut events = vec![
        env(0x01, requested(a), at(100)),
        env(0x02, requested(b), at(101)),
        env(0x03, requested(c), at(102)),
        env(0x04, requested(d), at(103)),
        env(0x05, completed(a, 10.0, true), at(110)),
        env(0x06, created(a, ia), at(111)),
        // Redelivery of 0x05's content under a fresh event id (a worker
        // crash-rerun): identical figures, so the fold reports no change.
        env(0x07, completed(a, 10.0, true), at(112)),
        // The terminal for `b` lands before its creation (different partition
        // key) — the fold buffers it and replays it on 0x0a.
        env(0x08, retracted(ib), at(120)),
        env(0x09, completed(b, 4.0, true), at(121)),
        env(0x0a, created(b, ib), at(122)),
        // `c` was simulated and dropped: an audit outcome, no incident.
        env(0x0b, completed(c, 0.0, false), at(130)),
        // A re-simulation of `a` with newer figures — must win by event time.
        env(0x0c, completed(a, 12.0, true), at(140)),
        env(0x0d, finalized(ia), at(150)),
    ];
    events.sort_by_key(|e| (e.occurred_at, e.event_id));
    events
}

/// The canned replay source: hands back the history in store order, paging so
/// the driver's cursor loop is exercised rather than short-circuited.
struct CannedStore {
    events: Vec<EventEnvelope>,
    page: usize,
}

#[async_trait]
impl ReplaySource for CannedStore {
    /// The double models `appended_at == occurred_at` (nothing here arrives
    /// late), so a watermark past the last event includes the whole history —
    /// and the bound is still exercised, since every page must carry it.
    async fn watermark(&self) -> Result<Watermark, ReplayError> {
        Ok(Watermark::at(at(1_000_000)))
    }

    async fn page(&self, request: &PageRequest) -> Result<ReplayPage, ReplayError> {
        // Mirror the store's narrowing: a lane asks for one event type.
        let matching: Vec<&EventEnvelope> = self
            .events
            .iter()
            .filter(|event| {
                request
                    .event_type
                    .as_deref()
                    .is_none_or(|wanted| event.event_type() == wanted)
                    && event.occurred_at >= request.from
                    && request.to.is_none_or(|to| event.occurred_at < to)
                    && request.chain.is_none_or(|chain| event.chain.id() == chain)
                    // The ingest-time cut. Modelled as `occurred_at` here (see
                    // `watermark`), but honoured, so a driver that forgot to
                    // push the bound down would not silently pass.
                    && request
                        .appended_before
                        .is_none_or(|w| event.occurred_at < w.as_datetime())
            })
            .collect();

        // Keyset resume, exactly as the store's `Cursor` does.
        let start = match &request.cursor {
            None => 0,
            Some(token) => {
                let (millis, id) = token.split_once(':').expect("well-formed cursor");
                let key = (
                    millis.parse::<i64>().expect("millis"),
                    id.parse::<Uuid>().expect("uuid"),
                );
                matching
                    .iter()
                    .position(|e| (e.occurred_at.timestamp_millis(), e.event_id) > key)
                    .unwrap_or(matching.len())
            }
        };

        let slice: Vec<EventEnvelope> = matching
            .iter()
            .skip(start)
            .take(self.page)
            .map(|e| (*e).clone())
            .collect();
        let has_more = matching.len() > start + slice.len();
        let next_cursor = has_more.then(|| {
            let last = slice.last().expect("a full page is non-empty");
            format!("{}:{}", last.occurred_at.timestamp_millis(), last.event_id)
        });
        Ok(ReplayPage {
            events: slice,
            next_cursor,
        })
    }
}

// ── infrastructure ──────────────────────────────────────────────────

struct Stack {
    pool: sqlx::PgPool,
    /// Staging opens a *second* pool pointed at the staging schema, which needs
    /// the URL — a pool cannot be re-pointed once built.
    url: String,
    clickhouse: Client,
    // Held so the containers outlive the test.
    _postgres: testcontainers::ContainerAsync<Postgres>,
    _clickhouse: testcontainers::ContainerAsync<ClickHouse>,
}

async fn stack() -> Stack {
    let postgres = Postgres::default()
        .start()
        .await
        .expect("start Postgres container");
    let pg_port = postgres
        .get_host_port_ipv4(5432)
        .await
        .expect("Postgres port");
    let url = format!("postgres://postgres:postgres@127.0.0.1:{pg_port}/postgres");
    let pool = db::connect(&url).await.expect("connect Postgres");
    sqlx::migrate!("../db/migrations")
        .run(&pool)
        .await
        .expect("apply Postgres migrations");

    let ch = ClickHouse::default()
        .start()
        .await
        .expect("start ClickHouse container");
    let ch_port = ch
        .get_host_port_ipv4(CLICKHOUSE_PORT)
        .await
        .expect("ClickHouse port");
    let clickhouse = Client::default()
        .with_url(format!("http://127.0.0.1:{ch_port}"))
        .with_database("default");
    simulation::ch_migrate::MIGRATOR
        .run(&clickhouse)
        .await
        .expect("apply ClickHouse migrations");

    Stack {
        pool,
        url,
        clickhouse,
        _postgres: postgres,
        _clickhouse: ch,
    }
}

/// Drive the **live** path: the real consumer over the real stores, exactly as
/// the Kafka loop would, one event at a time.
async fn run_live(stack: &Stack, events: &[EventEnvelope]) {
    let pg = PgIncidentStore::new(stack.pool.clone());
    let store: Arc<dyn IncidentStore> = Arc::new(pg.clone());
    let cross_chain: Arc<dyn CrossChainFindingStore> = Arc::new(pg);
    let analytics: Arc<dyn IncidentAnalytics> =
        Arc::new(ClickhouseAnalytics::new(stack.clickhouse.clone()));
    let consumer = ProjectionConsumer::new(store, analytics, cross_chain);

    for event in events {
        match consumer.handle(event.clone()).await {
            Handled::Commit => {}
            other => panic!("the live path did not commit {}: {other:?}", event.event_id),
        }
    }
}

impl Stack {
    /// The Postgres read model target.
    fn postgres(&self) -> Stores {
        Stores::Postgres(PostgresStore::new(
            self.pool.clone(),
            secrecy::SecretString::from(self.url.clone()),
        ))
    }

    /// The ClickHouse analytics target.
    fn clickhouse(&self) -> Stores {
        Stores::Clickhouse(self.clickhouse.clone())
    }

    /// Both, from one replay.
    fn both(&self) -> Stores {
        Stores::Both {
            postgres: PostgresStore::new(
                self.pool.clone(),
                secrecy::SecretString::from(self.url.clone()),
            ),
            clickhouse: self.clickhouse.clone(),
        }
    }

    /// Schemas this test has created besides the built-ins — used to assert
    /// that staging areas are cleaned up rather than leaked.
    async fn rebuild_schemas(&self) -> Vec<String> {
        sqlx::query_scalar::<_, String>(
            "SELECT schema_name FROM information_schema.schemata
             WHERE schema_name LIKE 'rebuild%' ORDER BY schema_name",
        )
        .fetch_all(&self.pool)
        .await
        .expect("list schemas")
    }
}

fn token() -> CancellationToken {
    CancellationToken::new()
}

// ── the drill ───────────────────────────────────────────────────────

/// **The claim.** Build the Postgres read model the live way, rebuild it from
/// the event store into staging, and get byte-identical rows back.
#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres + ClickHouse)"]
async fn the_incident_read_model_rebuilds_byte_identically_from_the_event_store() {
    let stack = stack().await;
    let events = history();
    run_live(&stack, &events).await;

    let model = SimulationReadModel::new(stack.postgres());
    let source = CannedStore {
        events: events.clone(),
        // Deliberately smaller than any single event type's count, so the
        // driver's cursor loop and the lane merge are both exercised.
        page: 2,
    };

    let report = rebuild::verify(&model, &source, &RebuildPlan::full(), &token())
        .await
        .unwrap_or_else(|err| panic!("the read model is not purely derived:\n{err}"));

    // A matching pair of *empty* fingerprints would also be "identical", so pin
    // what the drill actually had to prove: the fixture's four alerts each get a
    // `sim_jobs` row, and three reach the incident read model — `0xd1` was only
    // ever requested, so it has a job and no incident. That asymmetry is
    // deliberate; it is the row whose absence a rebuild could most easily get
    // wrong in the friendly direction.
    let incidents: i64 = sqlx::query_scalar("SELECT count(*) FROM incidents")
        .fetch_one(&stack.pool)
        .await
        .expect("count incidents");
    let jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM sim_jobs")
        .fetch_one(&stack.pool)
        .await
        .expect("count sim_jobs");
    assert_eq!((incidents, jobs), (3, 4));
    assert_eq!(report.live_rows, 7, "3 incidents + 4 jobs");
    assert_eq!(report.staged_rows, 7);
    assert_eq!(report.events_replayed, events.len() as u64);
    assert_eq!(report.live_root, report.staged_root);
}

/// The property that makes the drill schedulable rather than an outage: `verify`
/// builds the replacement, compares it, and **never writes to the live model**.
#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres + ClickHouse)"]
async fn verify_never_touches_the_live_tables_and_cleans_up_after_itself() {
    let stack = stack().await;
    let events = history();
    run_live(&stack, &events).await;

    // The live rows, byte for byte, before the drill.
    let model = SimulationReadModel::new(stack.postgres());
    let before = model
        .digest(&Scope::everything())
        .await
        .expect("fingerprint live");
    // `updated_at` is excluded from the digest, so compare it separately — it is
    // the column a stray write would move even when the values matched.
    let touched_before: Vec<(Uuid, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as("SELECT alert_id, updated_at FROM incidents ORDER BY alert_id")
            .fetch_all(&stack.pool)
            .await
            .expect("read updated_at");

    let source = CannedStore { events, page: 3 };
    let report = rebuild::verify(&model, &source, &RebuildPlan::full(), &token())
        .await
        .expect("a derived model passes the drill");
    assert_eq!(report.outcome, Outcome::Discarded);

    let after = model
        .digest(&Scope::everything())
        .await
        .expect("fingerprint live again");
    assert_eq!(before.root(), after.root(), "live model must be untouched");

    let touched_after: Vec<(Uuid, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as("SELECT alert_id, updated_at FROM incidents ORDER BY alert_id")
            .fetch_all(&stack.pool)
            .await
            .expect("read updated_at");
    assert_eq!(
        touched_before, touched_after,
        "not even `updated_at` may move: a verify writes nothing to the live tables"
    );

    assert!(
        stack.rebuild_schemas().await.is_empty(),
        "the staging schema must be dropped"
    );
}

/// The recovery: the staged replacement is promoted over the live tables, and
/// the previous generation is retained for inspection and rollback.
#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres + ClickHouse)"]
async fn a_promotion_swaps_the_tables_and_keeps_the_previous_generation() {
    let stack = stack().await;
    let events = history();
    run_live(&stack, &events).await;

    // Corrupt one row so the promotion demonstrably changes something.
    let corrupted = alert(0xa1).0;
    sqlx::query("UPDATE incidents SET profit = 999999 WHERE alert_id = $1")
        .bind(corrupted)
        .execute(&stack.pool)
        .await
        .expect("corrupt one row");

    let model = SimulationReadModel::new(stack.postgres());
    let source = CannedStore { events, page: 4 };
    let report = rebuild::rebuild(&model, &source, &RebuildPlan::full().confirm(), &token())
        .await
        .expect("the recovery completes");

    assert_eq!(report.outcome, Outcome::Promoted);
    assert_eq!(
        report.divergence.changed,
        vec![format!("incidents/{corrupted}")],
        "the damage report must name the corrupted row"
    );

    // The live table now holds the value the events imply.
    let profit: f64 = sqlx::query_scalar("SELECT profit FROM incidents WHERE alert_id = $1")
        .bind(corrupted)
        .fetch_one(&stack.pool)
        .await
        .expect("read the promoted row");
    assert_eq!(profit, 12.0, "the newest simulation's figures win");

    // The superseded generation survives — the only copy of anything the
    // rebuild could not derive, and the rollback if this was a mistake.
    let schemas = stack.rebuild_schemas().await;
    assert_eq!(
        schemas.len(),
        1,
        "exactly the superseded schema: {schemas:?}"
    );
    assert!(schemas[0].ends_with("_superseded"), "{schemas:?}");
    let superseded: f64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT profit FROM \"{}\".incidents WHERE alert_id = $1",
        schemas[0]
    )))
    .bind(corrupted)
    .fetch_one(&stack.pool)
    .await
    .expect("read the superseded row");
    assert_eq!(
        superseded, 999999.0,
        "the pre-promotion value is recoverable"
    );
}

/// A row nothing in the log produced is the shape §2 forbids. The drill must
/// classify it as `lost` — and, being non-destructive, must leave it in place.
#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres + ClickHouse)"]
async fn a_row_with_no_events_behind_it_is_reported_but_not_silently_deleted() {
    let stack = stack().await;
    let events = history();
    run_live(&stack, &events).await;

    let orphan = Uuid::from_bytes([0xee; 16]);
    sqlx::query(
        "INSERT INTO incidents (alert_id, status, profit, victim_loss, figures_at)
         VALUES ($1, 'confirmed', 1.0, 1.0, now())",
    )
    .bind(orphan)
    .execute(&stack.pool)
    .await
    .expect("insert an underived row");

    let model = SimulationReadModel::new(stack.postgres());
    let source = CannedStore { events, page: 100 };

    let failure = rebuild::verify(&model, &source, &RebuildPlan::full(), &token())
        .await
        .expect_err("an underived row must fail the drill");
    let VerifyFailure::Diverged(report) = failure else {
        panic!("expected a divergence");
    };
    assert_eq!(report.divergence.lost, vec![format!("incidents/{orphan}")]);

    // The drill reports; it does not delete. An operator decides whether that
    // row was an audit-completeness hole worth investigating before a promotion
    // removes the evidence.
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM incidents WHERE alert_id = $1")
        .bind(orphan)
        .fetch_one(&stack.pool)
        .await
        .expect("count");
    assert_eq!(remaining, 1, "verify must not mutate the live model");
}

/// The ClickHouse analytics firehose and its materialized-view rollup.
#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres + ClickHouse)"]
async fn the_analytics_projection_and_its_rollup_rebuild_identically() {
    let stack = stack().await;
    let events = history();
    run_live(&stack, &events).await;

    let model = SimulationReadModel::new(stack.clickhouse());
    let source = CannedStore { events, page: 3 };

    let report = rebuild::verify(&model, &source, &RebuildPlan::full(), &token())
        .await
        .unwrap_or_else(|err| panic!("the analytics projection is not purely derived:\n{err}"));

    assert!(
        report.live_rows > 0,
        "the live run should have appended analytics rows"
    );
    // The rollup is fed by a materialized view on inserts into
    // `incident_analytics`; staging builds its own, so a mismatch here would
    // mean the staged MV had not fired or had double-counted.
    assert_eq!(
        report.live_root,
        report.staged_root,
        "{}",
        report.summarize(20)
    );
}

/// Both stores from one replay — the `--model all` an operator actually runs.
#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres + ClickHouse)"]
async fn both_stores_rebuild_and_promote_from_a_single_replay() {
    let stack = stack().await;
    let events = history();
    run_live(&stack, &events).await;

    let model = SimulationReadModel::new(stack.both());
    let source = CannedStore {
        events: events.clone(),
        page: 5,
    };

    let report = rebuild::rebuild(&model, &source, &RebuildPlan::full().confirm(), &token())
        .await
        .expect("a combined rebuild completes");
    assert_eq!(report.events_replayed, events.len() as u64);
    assert!(report.is_identical(), "{}", report.summarize(20));
    assert_eq!(report.outcome, Outcome::Promoted);

    // Both live surfaces still answer after the swap.
    let incidents: i64 = sqlx::query_scalar("SELECT count(*) FROM incidents")
        .fetch_one(&stack.pool)
        .await
        .expect("count incidents");
    assert_eq!(incidents, 3);
    let analytics: u64 = stack
        .clickhouse
        .query("SELECT count() FROM incident_analytics")
        .fetch_one()
        .await
        .expect("count analytics");
    assert!(analytics > 0);
}

/// The safety interlock: promotion needs explicit authorization, and refusing it
/// happens before any staging area is created.
#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres + ClickHouse)"]
async fn an_unconfirmed_rebuild_touches_nothing() {
    let stack = stack().await;
    run_live(&stack, &history()).await;

    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM incidents")
        .fetch_one(&stack.pool)
        .await
        .expect("count");
    assert!(before > 0);

    let model = SimulationReadModel::new(stack.postgres());
    let source = CannedStore {
        events: history(),
        page: 10,
    };

    rebuild::rebuild(&model, &source, &RebuildPlan::full(), &token())
        .await
        .expect_err("an unconfirmed plan must refuse to promote");

    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM incidents")
        .fetch_one(&stack.pool)
        .await
        .expect("count");
    assert_eq!(before, after);
    assert!(
        stack.rebuild_schemas().await.is_empty(),
        "nothing may be created before the refusal"
    );
}

/// A rebuild is total by construction: a narrowed scope is refused rather than
/// approximated, because promoting a staged table built from a window would
/// promote one missing everything outside it.
#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres + ClickHouse)"]
async fn a_scoped_rebuild_is_refused_rather_than_approximated() {
    let stack = stack().await;
    run_live(&stack, &history()).await;

    let model = SimulationReadModel::new(stack.postgres());
    let source = CannedStore {
        events: history(),
        page: 10,
    };
    let plan = RebuildPlan::full()
        .scoped(Scope::everything().for_chain(Chain::ETHEREUM.id()))
        .confirm();

    let err = rebuild::rebuild(&model, &source, &plan, &token())
        .await
        .expect_err("a narrowed scope is not expressible for this model");
    assert!(err.to_string().contains("full rebuild"), "{err}");

    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM incidents")
        .fetch_one(&stack.pool)
        .await
        .expect("count");
    assert!(remaining > 0, "the refusal must precede any change");
}

/// Cancellation: a rebuild that runs for hours must stop when asked, discard its
/// staging area, and leave production exactly as it was.
#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres + ClickHouse)"]
async fn a_cancelled_rebuild_discards_staging_and_leaves_production_intact() {
    let stack = stack().await;
    run_live(&stack, &history()).await;

    let model = SimulationReadModel::new(stack.postgres());
    let before = model
        .digest(&Scope::everything())
        .await
        .expect("fingerprint live");
    let source = CannedStore {
        events: history(),
        page: 1,
    };

    let shutdown = CancellationToken::new();
    shutdown.cancel();
    let err = rebuild::rebuild(&model, &source, &RebuildPlan::full().confirm(), &shutdown)
        .await
        .expect_err("a cancelled run must not report success");
    assert!(err.to_string().contains("UNCHANGED"), "{err}");

    let after = model
        .digest(&Scope::everything())
        .await
        .expect("fingerprint live again");
    assert_eq!(before.root(), after.root());
    assert!(
        stack.rebuild_schemas().await.is_empty(),
        "a cancelled run must not leak its staging area"
    );
}
