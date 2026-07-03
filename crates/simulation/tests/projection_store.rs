//! Integration tests for the incident/job persistence stores (Sprint 6 t5) against
//! *real* Postgres and ClickHouse, spun up on demand via testcontainers. Marked
//! `#[ignore]` so the default `cargo test` stays hermetic; CI's integration job (and
//! `just test-integration`) run them with `--run-ignored all`.
//!
//! Three things are proven here:
//!   1. the confirmed-incident read-model upsert is idempotent (re-applying a folded
//!      event overwrites the one row with identical values — the §7 no-op, persisted),
//!   2. the in-flight `sim_jobs` row is monotonic (a finished job never regresses to
//!      `requested` on a reordered/redelivered event), and
//!   3. the ClickHouse analytics firehose appends immutable rows that aggregate by kind.
//!
//! Records are built the way production builds them — by folding events through the pure
//! [`IncidentProjection`] — since its watermark fields are crate-private. Read-back uses
//! sqlx's runtime query API (not the `query!` macro) so these tests need no compile-time
//! database or `.sqlx` cache entry.

use chrono::{DateTime, Utc};
use events::primitives::{AlertId, AlertKind, Chain, IncidentId, Severity};
use events::simulation::{IncidentCreated, SimulationCompleted};
use events::{DomainEvent, EventEnvelope};
use revm::primitives::B256;
use simulation::projection::IncidentProjection;
use simulation::store::{
    AnalyticsRow, ClickhouseAnalytics, IncidentAnalytics, IncidentStore, JobState, JobUpdate,
    PgIncidentStore,
};
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::clickhouse::{ClickHouse, CLICKHOUSE_PORT};
use testcontainers_modules::postgres::Postgres;
use uuid::Uuid;

fn at(secs: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(secs, 0).expect("valid timestamp")
}

fn env(payload: DomainEvent, occurred_at: DateTime<Utc>) -> EventEnvelope {
    EventEnvelope::with_metadata(Uuid::new_v4(), occurred_at, Chain::ETHEREUM, payload)
}

fn completed(alert: AlertId, profit: f64) -> DomainEvent {
    DomainEvent::SimulationCompleted(SimulationCompleted {
        alert_id: alert,
        profit,
        victim_loss: profit / 2.0,
        confirmed: true,
    })
}

fn created(alert: AlertId, incident: IncidentId) -> DomainEvent {
    DomainEvent::IncidentCreated(IncidentCreated {
        incident_id: incident,
        alert_id: alert,
        kind: AlertKind::Sandwich,
        txs: vec![B256::repeat_byte(0x01), B256::repeat_byte(0x02)],
        profit: 5.0,
        victim_loss: 2.5,
        severity: Severity::High,
    })
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn incident_upsert_is_idempotent_and_job_status_is_monotonic() {
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
    // Apply the same migration the `just migrate-*` recipes run.
    sqlx::migrate!("../db/migrations")
        .run(&pool)
        .await
        .expect("apply migrations");

    let store = PgIncidentStore::new(pool.clone());

    // Fold a confirmed incident, then persist it twice — the second write is the §7 no-op.
    let alert = AlertId::new();
    let incident = IncidentId::new();
    let mut proj = IncidentProjection::new();
    proj.apply(&env(completed(alert, 5.0), at(10)));
    proj.apply(&env(created(alert, incident), at(11)));
    let record = proj.record(&alert).expect("folded row");

    store.upsert_incident(record).await.expect("first upsert");
    store
        .upsert_incident(record)
        .await
        .expect("idempotent upsert");

    // Exactly one incident row, with the folded identity + figures.
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM incidents")
        .fetch_one(&pool)
        .await
        .expect("count incidents");
    assert_eq!(count, 1, "idempotent: one alert → one row");

    let row: (Uuid, Option<Uuid>, String, Option<String>, f64, Vec<String>) = sqlx::query_as(
        "SELECT alert_id, incident_id, status, kind, profit, txs FROM incidents WHERE alert_id = $1",
    )
    .bind(alert.0)
    .fetch_one(&pool)
    .await
    .expect("read incident row");
    assert_eq!(row.0, alert.0);
    assert_eq!(row.1, Some(incident.0));
    assert_eq!(row.2, "confirmed");
    assert_eq!(row.3.as_deref(), Some("sandwich"));
    assert_eq!(row.4, 5.0);
    assert_eq!(row.5.len(), 2, "both tx hashes stored");
    assert!(row.5[0].starts_with("0x"));

    // Job tracking: a completed job must not regress to `requested` when an older/
    // reordered SimulationRequested lands afterwards.
    store
        .record_job(&JobUpdate {
            alert_id: alert,
            chain: Chain::ETHEREUM,
            state: JobState::Completed,
            at: at(20),
        })
        .await
        .expect("record completed");
    store
        .record_job(&JobUpdate {
            alert_id: alert,
            chain: Chain::ETHEREUM,
            state: JobState::Requested,
            at: at(10),
        })
        .await
        .expect("record (late) requested");

    let (status, requested_at, completed_at): (
        String,
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
    ) = sqlx::query_as(
        "SELECT status, requested_at, completed_at FROM sim_jobs WHERE alert_id = $1",
    )
    .bind(alert.0)
    .fetch_one(&pool)
    .await
    .expect("read job row");
    assert_eq!(
        status, "completed",
        "completed job never regresses to requested"
    );
    // The late `requested` still backfills its timestamp (COALESCE keeps first-seen).
    assert_eq!(requested_at, Some(at(10)));
    assert_eq!(completed_at, Some(at(20)));
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers ClickHouse)"]
async fn analytics_rows_append_and_aggregate_by_kind() {
    let container = ClickHouse::default()
        .start()
        .await
        .expect("start ClickHouse container");
    let http_port = container
        .get_host_port_ipv4(CLICKHOUSE_PORT)
        .await
        .expect("ClickHouse port");

    let client = clickhouse::Client::default()
        .with_url(format!("http://127.0.0.1:{http_port}"))
        .with_user("default")
        .with_database("default");

    // Apply the analytics migration, then append a few immutable rows.
    simulation::ch_migrate::MIGRATOR
        .run(&client)
        .await
        .expect("apply ClickHouse migrations");
    let analytics = ClickhouseAnalytics::new(client.clone());

    let mut proj = IncidentProjection::new();
    for profit in [3.0_f64, 7.0, 11.0] {
        let alert = AlertId::new();
        let incident = IncidentId::new();
        // The confirmed incident carries the run's profit (it is the newest event, so its
        // figures win the last-writer-by-event-time fold).
        let created_env = env(
            DomainEvent::IncidentCreated(IncidentCreated {
                incident_id: incident,
                alert_id: alert,
                kind: AlertKind::Sandwich,
                txs: vec![B256::repeat_byte(0x01)],
                profit,
                victim_loss: profit / 2.0,
                severity: Severity::High,
            }),
            at(100),
        );
        proj.apply(&env(completed(alert, profit), at(99)));
        proj.apply(&created_env);
        let record = proj.record(&alert).expect("row");
        analytics
            .append(&AnalyticsRow::from_event(&created_env, record))
            .await
            .expect("append analytics");
    }

    // Wide-scan aggregation: count + total profit by kind (all sandwiches here).
    let (kind, n, total_profit): (String, u64, f64) = client
        .query(
            "SELECT kind, count() AS n, sum(profit) AS total \
             FROM incident_analytics GROUP BY kind",
        )
        .fetch_one()
        .await
        .expect("aggregate analytics");
    assert_eq!(kind, "sandwich");
    assert_eq!(n, 3);
    assert_eq!(total_profit, 21.0);
}
