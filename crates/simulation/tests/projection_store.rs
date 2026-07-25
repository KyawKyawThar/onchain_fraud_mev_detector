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
use events::primitives::{
    AccountAddress, AlertId, AlertKind, Chain, IncidentId, Severity, UsdAmount,
};
use events::simulation::{
    IncidentCreated, IncidentFinalized, IncidentRetracted, SimulationCompleted,
};
use events::{DomainEvent, EventEnvelope};
use revm::primitives::B256;
use simulation::projection::{IncidentProjection, IncidentStatus};
use simulation::store::{
    AnalyticsRow, ClickhouseAnalytics, IncidentAnalytics, IncidentFilters, IncidentStore, JobState,
    JobUpdate, PgIncidentStore, WalletExposureStore,
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
        impact_usd: None,
        severity: Severity::High,
        suggested_action: events::primitives::SuggestedAction::Escalate,
        victim_address: None,
        victim_loss_usd: None,
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
                impact_usd: None,
                severity: Severity::High,
                suggested_action: events::primitives::SuggestedAction::Escalate,
                victim_address: None,
                victim_loss_usd: None,
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

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn list_incidents_filters_by_status_and_paginates() {
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
    let store = PgIncidentStore::new(pool);

    // Two confirmed incidents, written oldest-first, plus one unconfirmed
    // (SimulationCompleted with confirmed = false, no IncidentCreated) — the
    // §11 audit outcome that never becomes a live incident.
    let mut confirmed_alerts = Vec::new();
    for (secs, profit) in [(10, 5.0), (20, 9.0)] {
        let alert = AlertId::new();
        let incident = IncidentId::new();
        let mut proj = IncidentProjection::new();
        proj.apply(&env(completed(alert, profit), at(secs)));
        proj.apply(&env(created(alert, incident), at(secs + 1)));
        store
            .upsert_incident(proj.record(&alert).expect("folded row"))
            .await
            .expect("upsert confirmed");
        confirmed_alerts.push(alert);
    }

    let unconfirmed_alert = AlertId::new();
    let mut proj = IncidentProjection::new();
    proj.apply(&env(
        DomainEvent::SimulationCompleted(SimulationCompleted {
            alert_id: unconfirmed_alert,
            profit: 0.0,
            victim_loss: 0.0,
            confirmed: false,
        }),
        at(30),
    ));
    store
        .upsert_incident(proj.record(&unconfirmed_alert).expect("folded row"))
        .await
        .expect("upsert unconfirmed");

    // Unfiltered: all three, newest-updated (i.e. most-recently-written) first.
    let page = store
        .list_incidents(&IncidentFilters::default())
        .await
        .expect("list all");
    assert_eq!(page.incidents.len(), 3);
    assert_eq!(page.incidents[0].alert_id, unconfirmed_alert);
    assert!(page.next_cursor.is_none());

    // Status filter: only the two confirmed rows.
    let page = store
        .list_incidents(&IncidentFilters {
            status: Some(IncidentStatus::Confirmed),
            ..Default::default()
        })
        .await
        .expect("list confirmed");
    assert_eq!(page.incidents.len(), 2);
    assert!(page
        .incidents
        .iter()
        .all(|record| confirmed_alerts.contains(&record.alert_id)));

    // Pagination: a page of 1 reports a cursor; following it exhausts the rest.
    let first_page = store
        .list_incidents(&IncidentFilters {
            limit: Some(1),
            ..Default::default()
        })
        .await
        .expect("first page");
    assert_eq!(first_page.incidents.len(), 1);
    let cursor = first_page.next_cursor.expect("more rows follow");

    let second_page = store
        .list_incidents(&IncidentFilters {
            limit: Some(1),
            cursor: Some(cursor),
            ..Default::default()
        })
        .await
        .expect("second page");
    assert_eq!(second_page.incidents.len(), 1);
    assert_ne!(
        first_page.incidents[0].alert_id,
        second_page.incidents[0].alert_id
    );
}

/// A confirmed incident naming `victim` as its victim, valued at `usd_lost`.
fn created_with_victim(
    alert: AlertId,
    incident: IncidentId,
    kind: AlertKind,
    usd_lost: f64,
    victim: AccountAddress,
) -> DomainEvent {
    DomainEvent::IncidentCreated(IncidentCreated {
        incident_id: incident,
        alert_id: alert,
        kind,
        txs: vec![B256::repeat_byte(0x01)],
        profit: usd_lost,
        victim_loss: usd_lost,
        impact_usd: Some(UsdAmount::new(usd_lost)),
        severity: Severity::High,
        suggested_action: events::primitives::SuggestedAction::Escalate,
        victim_address: Some(victim),
        victim_loss_usd: Some(UsdAmount::new(usd_lost)),
    })
}

/// Fold one event through the projection and append the resulting snapshot to the
/// analytics table exactly as the production consumer does (append per real change,
/// with the triggering event's `event_type`). The snapshot carries the victim
/// business key once `IncidentCreated` has stamped it — including on a later
/// retraction row, which is what the exposure query must learn to exclude.
async fn fold_and_append(
    proj: &mut IncidentProjection,
    analytics: &ClickhouseAnalytics,
    alert: AlertId,
    envelope: EventEnvelope,
) {
    proj.apply(&envelope);
    let row = {
        let record = proj.record(&alert).expect("row after fold");
        AnalyticsRow::from_event(&envelope, record)
    };
    analytics.append(&row).await.expect("append analytics");
}

/// The §11 wallet MEV-exposure read against real ClickHouse: a created-then-
/// **retracted** incident (its retraction snapshot still carries the victim key)
/// must be excluded from the wallet's losses, while a created-then-finalized one
/// stays counted. Exercises the `argMax`-latest-confirmed dedup that no unit test
/// can reach, end to end through [`WalletExposureStore::mev_exposure`].
#[tokio::test]
#[ignore = "requires Docker (testcontainers ClickHouse)"]
async fn mev_exposure_excludes_retracted_incidents_and_totals_by_kind() {
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
    simulation::ch_migrate::MIGRATOR
        .run(&client)
        .await
        .expect("apply ClickHouse migrations");
    let analytics = ClickhouseAnalytics::new(client);

    let victim = AccountAddress::repeat_byte(0x55);
    let other_victim = AccountAddress::repeat_byte(0x66);
    let mut proj = IncidentProjection::new();

    // Incident A — created only (sandwich, $100), created at t=1000. Counted.
    let a_alert = AlertId::new();
    let a_incident = IncidentId::new();
    fold_and_append(
        &mut proj,
        &analytics,
        a_alert,
        env(
            created_with_victim(a_alert, a_incident, AlertKind::Sandwich, 100.0, victim),
            at(1_000),
        ),
    )
    .await;

    // Incident B — created (arbitrage, $200) then finalized. Still confirmed → counted.
    let b_alert = AlertId::new();
    let b_incident = IncidentId::new();
    fold_and_append(
        &mut proj,
        &analytics,
        b_alert,
        env(
            created_with_victim(b_alert, b_incident, AlertKind::Arbitrage, 200.0, victim),
            at(2_000),
        ),
    )
    .await;
    fold_and_append(
        &mut proj,
        &analytics,
        b_alert,
        env(
            DomainEvent::IncidentFinalized(IncidentFinalized {
                incident_id: b_incident,
                block_hash: B256::repeat_byte(0xbb),
            }),
            at(2_500),
        ),
    )
    .await;

    // Incident C — created (liquidation, $999) then retracted. Excluded: the money
    // never moved, even though the retraction snapshot still carries the victim key.
    let c_alert = AlertId::new();
    let c_incident = IncidentId::new();
    fold_and_append(
        &mut proj,
        &analytics,
        c_alert,
        env(
            created_with_victim(c_alert, c_incident, AlertKind::Liquidation, 999.0, victim),
            at(3_000),
        ),
    )
    .await;
    fold_and_append(
        &mut proj,
        &analytics,
        c_alert,
        env(
            DomainEvent::IncidentRetracted(IncidentRetracted {
                incident_id: c_incident,
                reason: "block reverted".to_owned(),
            }),
            at(3_500),
        ),
    )
    .await;

    // A different wallet's incident must never leak into this wallet's exposure.
    let d_alert = AlertId::new();
    let d_incident = IncidentId::new();
    fold_and_append(
        &mut proj,
        &analytics,
        d_alert,
        env(
            created_with_victim(
                d_alert,
                d_incident,
                AlertKind::Sandwich,
                500.0,
                other_victim,
            ),
            at(2_100),
        ),
    )
    .await;

    // Unfiltered: A + B only — C retracted, D is another wallet's.
    let summary = simulation::exposure::summarize(
        analytics
            .mev_exposure(&victim, None)
            .await
            .expect("exposure query"),
    );
    assert_eq!(summary.incident_count, 2, "retracted C is excluded");
    assert_eq!(summary.total_usd_lost, 300.0, "$100 + $200, not C's $999");
    assert_eq!(summary.worst_usd_lost, 200.0);
    assert!(
        summary.by_kind.iter().all(|k| k.kind != "liquidation"),
        "the retracted liquidation must not appear in any breakdown"
    );
    // The finalized incident reports its *creation* time, not its finalization time.
    let b = summary
        .incidents
        .iter()
        .find(|i| i.incident_id == b_incident.0)
        .expect("finalized incident B is present");
    assert_eq!(b.occurred_at, at(2_000));

    // `since` = t=1500 drops A (created t=1000), keeps B (created t=2000).
    let since = simulation::exposure::summarize(
        analytics
            .mev_exposure(&victim, Some(at(1_500)))
            .await
            .expect("exposure query with since"),
    );
    assert_eq!(since.incident_count, 1);
    assert_eq!(since.incidents[0].incident_id, b_incident.0);
}
