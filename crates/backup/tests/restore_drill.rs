//! The tested restore, tested. `#[ignore]`d testcontainers suites against real
//! Postgres and real ClickHouse; CI's `integration-test` job runs them with
//! `--run-ignored all` (and `just backup-drill-test` locally).
//!
//! This file is the reason the readiness item can be checked off. Everything
//! else in the crate is machinery for producing a claim; these tests are the
//! ones that take a live database, back it up, restore it somewhere else, and
//! assert the rows came back — including the cases a green backup job would
//! sail past:
//!
//! * **a write lands mid-backup** — the artifact must be the consistent cut,
//!   not a smear across it, and the drill must still pass;
//! * **a table added after the last release** — discovery, not a hard-coded
//!   list, so the new table is in the artifact nobody remembered to update;
//! * **an artifact whose bytes rotted** — caught before a restore is attempted
//!   and blamed on the artifact rather than the restore;
//! * **a materialized view** — created after the data lands, so the restore
//!   does not double-write the rollup it also restored;
//! * **a merging engine** — the raw rows collapse in the background, so both
//!   sides read `FINAL` or the drill fails at random.
//!
//! The Postgres suite pins the container to the **same major version as the
//! local `pg_dump`**: a `pg_dump` older than its server refuses to run at all,
//! and pinning here means the test proves the real client/server pair on
//! whatever machine it runs on rather than only the one in CI.

use std::path::Path;

use backup::artifact::ArtifactStore;
use backup::clickhouse::ClickHouseTarget;
use backup::manifest::{Cut, Derivation};
use backup::postgres::PostgresTarget;
use backup::target::{BackupTarget, Database, StoreReader};
use backup::{drill, snapshot};
use secrecy::SecretString;
use testcontainers::runners::AsyncRunner;
use testcontainers::ImageExt;
use testcontainers_modules::clickhouse::{ClickHouse, CLICKHOUSE_PORT};
use testcontainers_modules::postgres::Postgres;
use tokio_util::sync::CancellationToken;

const CLICKHOUSE_TAG: &str = "25.6";

/// Every call site takes a token; these tests never cancel.
fn cancel() -> CancellationToken {
    CancellationToken::new()
}

/// A scratch artifact root unique to each test.
fn artifact_root(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "backup-it-{}-{}-{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("create artifact root");
    root
}

// ── Postgres ─────────────────────────────────────────────────────

/// The major version of the `pg_dump` on this machine, so the container can be
/// matched to it.
fn pg_dump_major() -> Option<u32> {
    let output = std::process::Command::new("pg_dump")
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.split_whitespace()
        .find_map(|token| token.split('.').next()?.parse::<u32>().ok())
}

async fn start_postgres() -> (
    testcontainers::ContainerAsync<Postgres>,
    String,
    PostgresTarget,
) {
    let major = pg_dump_major().expect(
        "pg_dump is not on PATH — the Postgres backup path shells out to the real client, \
         so this suite needs postgresql-client installed",
    );
    let container = Postgres::default()
        .with_tag(format!("{major}-alpine"))
        .start()
        .await
        .expect("start Postgres container");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("Postgres port");
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let target =
        PostgresTarget::new("postgres", SecretString::from(url.clone())).expect("build target");
    (container, url, target)
}

/// A schema with the value shapes whose text rendering is server-setting
/// dependent — the ones an unpinned session would round-trip differently on
/// the verifying server.
async fn seed_postgres(pool: &sqlx::PgPool) {
    sqlx::query(
        "CREATE TABLE rules (
             id           uuid PRIMARY KEY,
             owner        text NOT NULL,
             created_at   timestamptz NOT NULL,
             threshold    double precision NOT NULL,
             payload      jsonb NOT NULL,
             signature    bytea,
             tags         text[] NOT NULL DEFAULT '{}'
         )",
    )
    .execute(pool)
    .await
    .expect("create rules");

    // A table with exact duplicate rows: an XOR-combined digest would cancel
    // these in pairs and call a table that lost both of them identical.
    sqlx::query("CREATE TABLE deliveries (recipient text NOT NULL, stage text NOT NULL)")
        .execute(pool)
        .await
        .expect("create deliveries");

    for i in 0..250_i32 {
        sqlx::query(
            "INSERT INTO rules (id, owner, created_at, threshold, payload, signature, tags)
             VALUES ($1, $2, now() - ($3 || ' hours')::interval, $4, $5, $6, $7)",
        )
        .bind(uuid::Uuid::from_u128(i as u128))
        .bind(format!("customer-{}", i % 7))
        .bind(i.to_string())
        .bind(f64::from(i) / 3.0)
        .bind(serde_json::json!({ "n": i, "nested": { "on": i % 2 == 0 } }))
        .bind(if i % 5 == 0 {
            None
        } else {
            Some(vec![i as u8, 0xff, 0x00])
        })
        .bind(vec![format!("t{}", i % 3), "shared".to_owned()])
        .execute(pool)
        .await
        .expect("insert rule");
    }
    for _ in 0..4 {
        sqlx::query(
            "INSERT INTO deliveries (recipient, stage) VALUES ('ops@example.com', 'confirmed')",
        )
        .execute(pool)
        .await
        .expect("insert delivery");
    }
}

#[tokio::test]
#[ignore = "requires docker + pg_dump"]
async fn postgres_backup_restores_row_for_row() {
    let (_container, url, target) = start_postgres().await;
    let pool = db::connect(&url).await.expect("connect");
    seed_postgres(&pool).await;

    let store = ArtifactStore::new(artifact_root("pg-roundtrip"));
    let manifest = snapshot(&target, &store, &cancel())
        .await
        .expect("snapshot");

    // Discovery, not a list: both seeded tables are in the artifact without
    // anything naming them.
    assert!(
        manifest.tables.contains_key("public.rules"),
        "{:?}",
        manifest.tables
    );
    assert!(manifest.tables.contains_key("public.deliveries"));
    assert_eq!(manifest.tables["public.rules"].rows, 250);
    assert_eq!(manifest.tables["public.deliveries"].rows, 4);
    assert_eq!(
        manifest.tables["public.rules"].cut,
        Cut::TransactionSnapshot
    );
    // Nothing re-derives a customer's rules — the manifest must say so, since
    // that is what tells an operator this artifact is the only copy.
    assert_eq!(
        manifest.tables["public.rules"].derivation,
        Derivation::SystemOfRecord
    );

    let artifact = store
        .newest("postgres")
        .await
        .expect("list")
        .expect("an artifact");
    let report = drill::run(&target, &artifact, false, &cancel())
        .await
        .expect("drill");
    assert!(report.passed(), "{}", report.summarize(20));
    assert!(report.elapsed.as_secs_f64() > 0.0);
}

#[tokio::test]
#[ignore = "requires docker + pg_dump"]
async fn a_write_during_the_backup_is_outside_the_cut_and_the_drill_still_passes() {
    // The failure this crate's central mechanism exists to prevent: fingerprint
    // and dump as two reads of a moving database. Here rows land *while* the
    // snapshot runs; because pg_dump joins the same exported snapshot the
    // fingerprint was taken in, the artifact and its manifest agree, and the
    // restore of it verifies exactly.
    let (_container, url, target) = start_postgres().await;
    let pool = db::connect(&url).await.expect("connect");
    seed_postgres(&pool).await;

    let writer = pool.clone();
    let churn = tokio::spawn(async move {
        for i in 1_000..1_400_i32 {
            let _ = sqlx::query(
                "INSERT INTO rules (id, owner, created_at, threshold, payload, tags)
                 VALUES ($1, 'late', now(), 1.5, '{}'::jsonb, '{}')",
            )
            .bind(uuid::Uuid::from_u128(i as u128))
            .execute(&writer)
            .await;
        }
    });

    let store = ArtifactStore::new(artifact_root("pg-concurrent"));
    let manifest = snapshot(&target, &store, &cancel())
        .await
        .expect("snapshot");
    churn.await.expect("writer");

    let artifact = store
        .newest("postgres")
        .await
        .expect("list")
        .expect("an artifact");
    let report = drill::run(&target, &artifact, false, &cancel())
        .await
        .expect("drill");
    assert!(report.passed(), "{}", report.summarize(20));

    // The live table has grown past the artifact — which is exactly right, and
    // is the difference between "the backup is stale" (fine, that is the RPO)
    // and "the backup is torn" (not fine, and would have failed above).
    let live: i64 = sqlx::query_scalar("SELECT count(*) FROM rules")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert!(
        live as u64 >= manifest.tables["public.rules"].rows,
        "live {live} < artifact {}",
        manifest.tables["public.rules"].rows
    );
}

#[tokio::test]
#[ignore = "requires docker + pg_dump"]
async fn a_table_added_after_the_last_release_is_still_backed_up() {
    // The silent-coverage-loss failure: a hand-maintained table list keeps
    // passing for months while the newest table is in no artifact at all.
    let (_container, url, target) = start_postgres().await;
    let pool = db::connect(&url).await.expect("connect");
    seed_postgres(&pool).await;
    sqlx::query("CREATE TABLE brand_new (id int PRIMARY KEY, note text)")
        .execute(&pool)
        .await
        .expect("create");
    sqlx::query("INSERT INTO brand_new VALUES (1, 'nobody updated a list for this')")
        .execute(&pool)
        .await
        .expect("insert");

    let store = ArtifactStore::new(artifact_root("pg-newtable"));
    let manifest = snapshot(&target, &store, &cancel())
        .await
        .expect("snapshot");
    assert_eq!(manifest.tables["public.brand_new"].rows, 1);

    let artifact = store.newest("postgres").await.expect("list").expect("some");
    assert!(drill::run(&target, &artifact, false, &cancel())
        .await
        .expect("drill")
        .passed());
}

#[tokio::test]
#[ignore = "requires docker + pg_dump"]
async fn a_rotted_artifact_fails_the_drill_and_is_blamed_on_the_artifact() {
    let (_container, url, target) = start_postgres().await;
    let pool = db::connect(&url).await.expect("connect");
    seed_postgres(&pool).await;

    let store = ArtifactStore::new(artifact_root("pg-rot"));
    snapshot(&target, &store, &cancel())
        .await
        .expect("snapshot");
    let artifact = store.newest("postgres").await.expect("list").expect("some");

    // Flip bytes in the middle of the dump, keeping its length — the bit-rot
    // shape that a size check alone would miss.
    let path = artifact.dir.join("dump.pgc");
    let mut bytes = tokio::fs::read(&path).await.expect("read");
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0xff;
    tokio::fs::write(&path, &bytes).await.expect("write");

    let artifact = store.newest("postgres").await.expect("list").expect("some");
    let report = drill::run(&target, &artifact, false, &cancel())
        .await
        .expect("drill");
    assert!(!report.passed());
    assert!(
        report.failures()[0].contains("artifact integrity"),
        "{:?}",
        report.failures()
    );
}

#[tokio::test]
#[ignore = "requires docker + pg_dump"]
async fn a_restore_that_silently_loses_rows_fails_the_drill() {
    // Proves the drill is a fingerprint comparison and not an exit-code check:
    // the artifact is intact and pg_restore succeeds, but the manifest is made
    // to claim one more row than the dump holds.
    let (_container, url, target) = start_postgres().await;
    let pool = db::connect(&url).await.expect("connect");
    seed_postgres(&pool).await;

    let store = ArtifactStore::new(artifact_root("pg-lossy"));
    snapshot(&target, &store, &cancel())
        .await
        .expect("snapshot");
    let artifact = store.newest("postgres").await.expect("list").expect("some");

    let manifest_path = artifact.dir.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(&manifest_path).await.expect("read"))
            .expect("parse");
    manifest["tables"]["public.rules"]["rows"] = serde_json::json!(251);
    tokio::fs::write(
        &manifest_path,
        serde_json::to_vec(&manifest).expect("encode"),
    )
    .await
    .expect("write");

    let artifact = store.newest("postgres").await.expect("list").expect("some");
    let report = drill::run(&target, &artifact, false, &cancel())
        .await
        .expect("drill");
    assert!(!report.passed());
    assert!(
        report.failures()[0].contains("251 row(s) expected, 250 restored"),
        "{:?}",
        report.failures()
    );
}

#[tokio::test]
#[ignore = "requires docker + pg_dump"]
async fn the_drill_leaves_nothing_behind() {
    // The property that lets this run on a timer against production.
    let (_container, url, target) = start_postgres().await;
    let pool = db::connect(&url).await.expect("connect");
    seed_postgres(&pool).await;

    let store = ArtifactStore::new(artifact_root("pg-clean"));
    snapshot(&target, &store, &cancel())
        .await
        .expect("snapshot");
    let artifact = store.newest("postgres").await.expect("list").expect("some");
    assert!(drill::run(&target, &artifact, false, &cancel())
        .await
        .expect("drill")
        .passed());

    let leftovers: i64 =
        sqlx::query_scalar("SELECT count(*) FROM pg_database WHERE datname LIKE '%\\_drill\\_%'")
            .fetch_one(&pool)
            .await
            .expect("count databases");
    assert_eq!(leftovers, 0, "the drill left a scratch database behind");

    // And production is untouched: same rows, same fingerprint.
    let live: i64 = sqlx::query_scalar("SELECT count(*) FROM rules")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(live, 250);
}

// ── ClickHouse ───────────────────────────────────────────────────

async fn start_clickhouse() -> (
    testcontainers::ContainerAsync<ClickHouse>,
    ClickHouseTarget,
    reqwest::Client,
    String,
) {
    let container = ClickHouse::default()
        .with_tag(CLICKHOUSE_TAG)
        .with_env_var("CLICKHOUSE_SKIP_USER_SETUP", "1")
        .start()
        .await
        .expect("start ClickHouse container");
    let port = container
        .get_host_port_ipv4(CLICKHOUSE_PORT)
        .await
        .expect("ClickHouse port");
    let url = format!("http://127.0.0.1:{port}");
    let target = ClickHouseTarget::new(
        "clickhouse",
        url.clone(),
        "default",
        SecretString::from(String::new()),
        Database::new("default").expect("database"),
    );
    (container, target, reqwest::Client::new(), url)
}

async fn ch(client: &reqwest::Client, url: &str, sql: &str) -> String {
    let response = client
        .post(url)
        .header("X-ClickHouse-User", "default")
        .header("X-ClickHouse-Key", "")
        .body(sql.to_owned())
        .send()
        .await
        .expect("send");
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    assert!(status.is_success(), "{sql}\n{status}: {body}");
    body
}

/// The event log plus a derived rollup fed by a materialized view — the two
/// ClickHouse shapes with different guarantees, and the MV ordering trap.
async fn seed_clickhouse(client: &reqwest::Client, url: &str) {
    ch(
        client,
        url,
        "CREATE TABLE default.events (
             event_id UUID, schema_version UInt16, chain UInt64, event_type String,
             occurred_at DateTime64(3, 'UTC'), payload String,
             appended_at DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC'),
             incident_id Nullable(UUID), addresses Array(String)
         ) ENGINE = MergeTree ORDER BY (chain, event_type, occurred_at, event_id)",
    )
    .await;
    ch(
        client,
        url,
        "CREATE TABLE default.usage_rollup_daily (
             day Date, customer String, events UInt64
         ) ENGINE = SummingMergeTree(events) ORDER BY (day, customer)",
    )
    .await;
    ch(
        client,
        url,
        "CREATE MATERIALIZED VIEW default.usage_rollup_daily_mv TO default.usage_rollup_daily AS
         SELECT toDate(occurred_at) AS day, event_type AS customer, count() AS events
         FROM default.events GROUP BY day, customer",
    )
    .await;

    ch(
        client,
        url,
        "INSERT INTO default.events (event_id, schema_version, chain, event_type, occurred_at, payload, incident_id, addresses)
         SELECT generateUUIDv4(), 1, 1, ['BlockAssembled', 'IncidentCreated'][(number % 2) + 1],
                toDateTime64('2026-09-01 00:00:00.000', 3, 'UTC') + toIntervalSecond(number),
                concat('{\"n\":', toString(number), '}'),
                if(number % 3 = 0, NULL, generateUUIDv4()),
                ['0xabc', '0xdef']
         FROM numbers(500)",
    )
    .await;
}

#[tokio::test]
#[ignore = "requires docker"]
async fn clickhouse_backup_restores_the_log_and_its_rollup() {
    let (_container, target, client, url) = start_clickhouse().await;
    seed_clickhouse(&client, &url).await;

    let store = ArtifactStore::new(artifact_root("ch-roundtrip"));
    let manifest = snapshot(&target, &store, &cancel())
        .await
        .expect("snapshot");

    // The log is the system of record and gets a real watermark cut; the
    // rollup is derived and gets the weaker, honestly-labelled one.
    assert_eq!(manifest.tables["events"].rows, 500);
    assert_eq!(manifest.tables["events"].cut, Cut::IngestWatermark);
    assert_eq!(
        manifest.tables["events"].derivation,
        Derivation::SystemOfRecord
    );
    assert_eq!(
        manifest.tables["usage_rollup_daily"].derivation,
        Derivation::Derived
    );
    // The MV is schema, not data: restoring it as data would be restoring the
    // rollup twice.
    assert!(!manifest.tables.contains_key("usage_rollup_daily_mv"));
    assert!(manifest
        .schema
        .iter()
        .any(|o| o.name == "usage_rollup_daily_mv"));

    let artifact = store
        .newest("clickhouse")
        .await
        .expect("list")
        .expect("an artifact");
    let report = drill::run(&target, &artifact, false, &cancel())
        .await
        .expect("drill");
    assert!(report.passed(), "{}", report.summarize(20));
}

#[tokio::test]
#[ignore = "requires docker"]
async fn restoring_does_not_double_write_through_a_materialized_view() {
    // The trap in the ClickHouse module docs, as an assertion. A ClickHouse MV
    // is an insert trigger: restore `events` while the MV exists and every
    // restored row fires it, writing a second copy of the rollup on top of the
    // rollup that was also restored. The result is a restore that "succeeds"
    // with doubled aggregates — so the restore creates tables, loads data, and
    // only then creates views.
    let (_container, target, client, url) = start_clickhouse().await;
    seed_clickhouse(&client, &url).await;

    let store = ArtifactStore::new(artifact_root("ch-mv"));
    snapshot(&target, &store, &cancel())
        .await
        .expect("snapshot");
    let artifact = store
        .newest("clickhouse")
        .await
        .expect("list")
        .expect("some");

    let scratch = target.provision_scratch().await.expect("provision");
    let scratch_db = scratch.database().clone();
    target
        .restore(&artifact.dir, &artifact.manifest, &scratch_db, &cancel())
        .await
        .expect("restore");

    let live_total = ch(
        &client,
        &url,
        "SELECT sum(events) FROM default.usage_rollup_daily FINAL FORMAT TabSeparated",
    )
    .await;
    let restored_total = ch(
        &client,
        &url,
        &format!(
            "SELECT sum(events) FROM `{}`.usage_rollup_daily FINAL FORMAT TabSeparated",
            scratch_db
        ),
    )
    .await;
    assert_eq!(
        live_total.trim(),
        restored_total.trim(),
        "the rollup was written twice — the materialized view fired during the restore"
    );

    target.drop_scratch(scratch).await.expect("drop");
}

#[tokio::test]
#[ignore = "requires docker"]
async fn a_merging_engine_is_compared_on_its_logical_content() {
    // A SummingMergeTree's raw rows collapse in background merges, so a drill
    // that compared raw reads would pass or fail depending on when a merge
    // happened to run. Forcing a merge between the backup and the verification
    // is that race, made deterministic.
    let (_container, target, client, url) = start_clickhouse().await;
    seed_clickhouse(&client, &url).await;

    let store = ArtifactStore::new(artifact_root("ch-merge"));
    snapshot(&target, &store, &cancel())
        .await
        .expect("snapshot");

    ch(
        &client,
        &url,
        "OPTIMIZE TABLE default.usage_rollup_daily FINAL",
    )
    .await;

    let artifact = store
        .newest("clickhouse")
        .await
        .expect("list")
        .expect("some");
    let report = drill::run(&target, &artifact, false, &cancel())
        .await
        .expect("drill");
    assert!(report.passed(), "{}", report.summarize(20));
}

#[tokio::test]
#[ignore = "requires docker"]
async fn events_appended_after_the_watermark_are_outside_the_cut() {
    // The log grows during and after a backup. The artifact is a clean cut at
    // W, so it must not contain the later rows — and must not be reported as
    // torn because of them.
    let (_container, target, client, url) = start_clickhouse().await;
    seed_clickhouse(&client, &url).await;

    let store = ArtifactStore::new(artifact_root("ch-watermark"));
    let manifest = snapshot(&target, &store, &cancel())
        .await
        .expect("snapshot");
    assert_eq!(manifest.tables["events"].rows, 500);

    ch(
        &client,
        &url,
        "INSERT INTO default.events (event_id, schema_version, chain, event_type, occurred_at, payload, addresses)
         SELECT generateUUIDv4(), 1, 1, 'BlockAssembled', now64(3, 'UTC'), '{}', []
         FROM numbers(25)",
    )
    .await;

    let artifact = store
        .newest("clickhouse")
        .await
        .expect("list")
        .expect("some");
    let report = drill::run(&target, &artifact, false, &cancel())
        .await
        .expect("drill");
    assert!(report.passed(), "{}", report.summarize(20));

    let live = ch(
        &client,
        &url,
        "SELECT count() FROM default.events FORMAT TabSeparated",
    )
    .await;
    assert_eq!(live.trim(), "525");
}

#[tokio::test]
#[ignore = "requires docker"]
async fn a_restore_into_a_named_database_is_verifiable_the_same_way() {
    // The recovery path, not the drill path: `backup restore --into`. Same
    // fingerprint comparison, so an operator gets a damage report rather than
    // a hope.
    let (_container, target, client, url) = start_clickhouse().await;
    seed_clickhouse(&client, &url).await;

    let store = ArtifactStore::new(artifact_root("ch-recovery"));
    snapshot(&target, &store, &cancel())
        .await
        .expect("snapshot");
    let artifact = store
        .newest("clickhouse")
        .await
        .expect("list")
        .expect("some");

    ch(&client, &url, "CREATE DATABASE recovered").await;
    let destination = Database::new("recovered").expect("database");
    target
        .restore(&artifact.dir, &artifact.manifest, &destination, &cancel())
        .await
        .expect("restore");
    let fingerprints = target.fingerprint(&destination).await.expect("fingerprint");
    let diff = artifact.manifest.diff(&fingerprints);
    assert!(diff.is_clean(), "{}", diff.summarize(20));
}

/// The runtime guard this replaced is gone, and its absence is the upgrade.
///
/// The previous shape took a `Destination { database, scratch: bool }` and
/// checked the flag inside `drop_scratch`, so "do not drop production" was a
/// runtime `ensure!` protecting the most dangerous call in the crate. Now a
/// `Scratch` is only constructible by `provision_scratch` and is consumed by
/// value, so the mistake is **unspellable**: there is no way to write
/// `drop_scratch(live_database)` that compiles, and no way to drop the same
/// one twice. The compiler is the test; this comment exists so a future author
/// does not "restore the missing check".
#[tokio::test]
#[ignore = "requires docker"]
async fn a_scratch_database_round_trips_through_provision_and_drop() {
    let (_container, target, client, url) = start_clickhouse().await;
    let scratch = target.provision_scratch().await.expect("provision");
    let name = scratch.database().clone();
    let before = ch(
        &client,
        &url,
        &format!("SELECT count() FROM system.databases WHERE name = '{name}' FORMAT TabSeparated"),
    )
    .await;
    assert_eq!(before.trim(), "1");

    target.drop_scratch(scratch).await.expect("drop");
    let after = ch(
        &client,
        &url,
        &format!("SELECT count() FROM system.databases WHERE name = '{name}' FORMAT TabSeparated"),
    )
    .await;
    assert_eq!(after.trim(), "0");
}

#[tokio::test]
#[ignore = "requires docker"]
async fn the_sweep_removes_a_leaked_scratch_database() {
    // The leak guarantee, end to end. A `Drop` impl cannot provide this —
    // async destructors do not exist and a SIGKILL runs none at all — so
    // cleanup happens on the NEXT run, driven by the timestamp in the name.
    let (_container, target, client, url) = start_clickhouse().await;
    seed_clickhouse(&client, &url).await;

    // A database shaped exactly like one a crashed drill would have left,
    // stamped well in the past.
    ch(
        &client,
        &url,
        "CREATE DATABASE default_drill_20260101000000_1",
    )
    .await;
    // ...and one a *running* drill might own right now.
    let fresh = format!(
        "default_drill_{}_2",
        chrono::Utc::now().format("%Y%m%d%H%M%S")
    );
    ch(&client, &url, &format!("CREATE DATABASE {fresh}")).await;

    let swept = target
        .sweep_scratch(std::time::Duration::from_secs(3_600))
        .await
        .expect("sweep");
    assert_eq!(swept, vec!["default_drill_20260101000000_1".to_owned()]);

    let left = ch(
        &client,
        &url,
        "SELECT name FROM system.databases WHERE name LIKE '%_drill_%' ORDER BY name FORMAT TabSeparated",
    )
    .await;
    // The in-flight one survives; production was never a candidate.
    assert_eq!(left.trim(), fresh);
    let production = ch(
        &client,
        &url,
        "SELECT count() FROM system.databases WHERE name = 'default' FORMAT TabSeparated",
    )
    .await;
    assert_eq!(production.trim(), "1");
}

#[tokio::test]
#[ignore = "requires docker"]
async fn a_materialized_view_without_a_to_target_makes_the_artifact_incomplete() {
    // A view declared without `TO` keeps its data in `.inner_id.<uuid>`, whose
    // name cannot be recreated in another database — so the artifact does not
    // contain that data. The snapshot must say so as a *typed* fact, and the
    // drill must refuse to call such an artifact a pass however well the rest
    // of it restores. As a `Vec<String>` note this was a log line nobody read.
    let (_container, target, client, url) = start_clickhouse().await;
    seed_clickhouse(&client, &url).await;
    ch(
        &client,
        &url,
        "CREATE MATERIALIZED VIEW default.orphan_mv ENGINE = MergeTree ORDER BY day AS
         SELECT toDate(occurred_at) AS day, count() AS n FROM default.events GROUP BY day",
    )
    .await;

    let store = ArtifactStore::new(artifact_root("ch-incomplete"));
    let manifest = snapshot(&target, &store, &cancel())
        .await
        .expect("snapshot");
    assert!(
        !manifest.is_complete(),
        "an inner-storage table was silently treated as covered: {:?}",
        manifest.notes
    );
    assert!(manifest
        .incompleteness()
        .iter()
        .any(|note| note.object().starts_with(".inner")));

    let artifact = store
        .newest("clickhouse")
        .await
        .expect("list")
        .expect("some");
    let report = drill::run(&target, &artifact, false, &cancel())
        .await
        .expect("drill");
    assert!(
        report.diff.is_clean(),
        "everything the artifact DID hold restored exactly"
    );
    assert!(!report.passed(), "an incomplete artifact must not pass");
    assert!(report.summarize(20).contains("INCOMPLETE ARTIFACT"));
}

/// Compile-time check that the artifact directory layout is what the runbook
/// documents (a path an operator types under pressure).
#[test]
fn the_artifact_layout_matches_the_runbook() {
    let store = ArtifactStore::new(Path::new("/var/lib/mevwatch/backups"));
    assert_eq!(
        store.drills_dir("postgres"),
        Path::new("/var/lib/mevwatch/backups/drills/postgres")
    );
}
