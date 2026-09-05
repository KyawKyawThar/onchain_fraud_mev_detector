//! Postgres backup and restore, fingerprinted **inside `pg_dump`'s own MVCC
//! snapshot**.
//!
//! ## The one idea in this module
//!
//! A dump of a live OLTP database and a fingerprint of that database are two
//! reads at two different instants. Rows are written between them. So the
//! naive procedure — `pg_dump`, then `SELECT count(*)` — produces a
//! description of a database that never existed in the form the dump holds,
//! and a drill built on it either fails constantly (useless) or is run only
//! against a quiesced database (which is not the thing you need to restore).
//!
//! Postgres has the exact tool for this and it is not widely used:
//!
//! ```sql
//! BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
//! SELECT pg_export_snapshot();          -- hand this to pg_dump
//! ```
//!
//! `pg_dump --snapshot=<id>` then reads **the same MVCC snapshot** this
//! session holds. Every fingerprint query run in that transaction and every
//! row `pg_dump` copies see one instant — across every table, consistently
//! with every foreign key. The manifest therefore describes the dump, not the
//! database, and a restore that reproduces the manifest has reproduced the
//! dump exactly. (This is the same mechanism `pg_dump --jobs` uses internally
//! to keep its parallel workers consistent with each other.)
//!
//! The transaction is `READ ONLY` and `REPEATABLE READ`: it takes no locks
//! that block writers, so a snapshot of a busy production database is invisible
//! to it apart from holding back vacuum for the duration.
//!
//! ## The other thing that has to be pinned: text rendering
//!
//! The per-row hash is `sha256` of the row's text form, and a row's text form
//! depends on session settings — `DateStyle`, `TimeZone`, `IntervalStyle`,
//! `extra_float_digits`, `bytea_output`. A restore is verified on a *different
//! server* (the drill's scratch database, and in a real recovery a different
//! host entirely), whose defaults need not match. So every one of those is
//! pinned with `SET LOCAL` on both sides, in [`SESSION_PINS`], and the two
//! sides run the identical query text from [`fingerprint_sql`]. Without this
//! the drill would fail on a correct restore whenever the two servers'
//! `postgresql.conf` disagreed — the kind of failure that gets a drill
//! switched off.
//!
//! ## Why the digest is arithmetic and not `md5(string_agg(...))`
//!
//! The familiar one-liner materialises the whole table as one string. This
//! hashes per row and sums (`numeric`, then reduced mod 2^64 to match
//! [`crate::manifest::ContentAccumulator`]), so cost is bounded per row and
//! the result does not depend on read order — which `pg_restore` is free to
//! change.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use secrecy::{ExposeSecret, SecretString};
use sqlx::{Connection, Executor, PgConnection, Row};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

use crate::error::{from_sqlx, BackupError, Result};
use crate::manifest::{
    content_from_sum, BackupManifest, Cut, Derivation, TableFingerprint, TargetKind,
};
use crate::target::{
    is_sweepable, scratch_name, BackupTarget, Database, Scratch, Snapshot, StoreReader,
};

/// The dump file inside an artifact directory.
const DUMP_FILE: &str = "dump.pgc";

/// Session settings pinned on both sides of every fingerprint, so a row's text
/// form is a function of the row and nothing else. See the module docs.
const SESSION_PINS: &[&str] = &[
    "SET LOCAL DateStyle = 'ISO, MDY'",
    "SET LOCAL IntervalStyle = 'postgres'",
    "SET LOCAL TimeZone = 'UTC'",
    "SET LOCAL extra_float_digits = 3",
    "SET LOCAL bytea_output = 'hex'",
];

/// Tables whose contents a projection rebuild can reproduce from the event
/// store (`docs/runbooks/projection-rebuild.md`, and `simulation::rebuild`).
///
/// This list is **only** used to annotate the manifest — every table is backed
/// up either way. Its job is to tell an operator holding an incident which
/// rows have a second recovery path and which are gone if this artifact is
/// gone. Getting an entry wrong here is a documentation bug, never data loss;
/// getting it wrong in the *other* direction (marking something derived that
/// is not) is the one that would mislead, which is why the default for an
/// unlisted table is `SystemOfRecord`.
const DERIVED_TABLES: &[&str] = &[
    "public.incidents",
    "public.sim_jobs",
    "public.cross_chain_findings",
];

/// A Postgres server plus the database on it that holds production data.
#[derive(Debug, Clone)]
pub struct PostgresTarget {
    name: String,
    /// Connection URL for the live database, credentials included.
    url: SecretString,
    database: Database,
    /// Where `pg_dump`/`pg_restore` live. Defaults to `PATH` lookup.
    pg_dump: PathBuf,
    pg_restore: PathBuf,
}

impl PostgresTarget {
    /// Build from a `postgres://user:pass@host/db` URL.
    pub fn new(name: impl Into<String>, url: SecretString) -> Result<Self> {
        let database = Database::new(database_of(url.expose_secret())?)?;
        Ok(Self {
            name: name.into(),
            url,
            database,
            pg_dump: PathBuf::from("pg_dump"),
            pg_restore: PathBuf::from("pg_restore"),
        })
    }

    /// Override the client binaries (a pinned major version, a container path).
    pub fn with_binaries(mut self, pg_dump: PathBuf, pg_restore: PathBuf) -> Self {
        self.pg_dump = pg_dump;
        self.pg_restore = pg_restore;
        self
    }

    /// The live URL with its database swapped for `database`.
    fn url_for(&self, database: &str) -> Result<String> {
        let mut url = url::Url::parse(self.url.expose_secret())
            .map_err(|err| BackupError::permanent(err).context("parsing the Postgres URL"))?;
        url.set_path(database);
        Ok(url.to_string())
    }

    /// A URL for the maintenance database, used only to `CREATE`/`DROP` other
    /// databases (neither can run inside the database being created/dropped).
    fn maintenance_url(&self) -> Result<String> {
        self.url_for("postgres")
    }

    /// Connect, classifying the failure through the workspace's one
    /// classifier: an unreachable server is transient (the next cycle may well
    /// work), a rejected credential or a missing database is not.
    async fn connect(&self, database: &str) -> Result<PgConnection> {
        let url = self.url_for(database)?;
        PgConnection::connect(&url)
            .await
            .map_err(|err| from_sqlx(err, format!("connecting to Postgres database {database}")))
    }

    /// `DROP DATABASE`, shared by `drop_scratch` and the sweep.
    async fn drop_database(&self, database: &Database) -> Result<()> {
        let mut conn = PgConnection::connect(&self.maintenance_url()?)
            .await
            .map_err(|err| from_sqlx(err, "connecting to the maintenance database"))?;
        // FORCE terminates any session still connected — a drill that failed
        // mid-restore can leave one, and a cleanup that cannot run is a
        // cleanup nobody retries.
        let result = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE)"
        )))
        .execute(&mut conn)
        .await
        .map_err(|err| from_sqlx(err, format!("dropping database {database}")));
        let _ = conn.close().await;
        result.map(|_| ())
    }

    /// Run one of the PostgreSQL client binaries, killing it if shutdown is
    /// requested.
    ///
    /// A `pg_dump` of a production database runs for minutes to hours. Waiting
    /// on it with a plain `.output()` means a `SIGTERM` is ignored until it
    /// finishes, so the pod is `SIGKILL`ed at the end of its grace period with
    /// a child still running — which is also how a half-written dump file
    /// outlives the process that was writing it.
    ///
    /// stderr is drained on its own task rather than after the wait: the pipe
    /// buffer is finite, and a client that filled it while nobody was reading
    /// would block forever. A backup tool that hangs is worse than one that
    /// fails.
    async fn run_client(
        &self,
        binary: &Path,
        args: &[String],
        cancel: &CancellationToken,
    ) -> Result<()> {
        let mut child = tokio::process::Command::new(binary)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|err| {
                BackupError::permanent(err).context(format!("running {}", binary.display()))
            })?;

        let stderr = child.stderr.take();
        let drain = tokio::spawn(async move {
            let mut captured = String::new();
            if let Some(mut pipe) = stderr {
                let _ = pipe.read_to_string(&mut captured).await;
            }
            captured
        });

        let status = tokio::select! {
            status = child.wait() => status.map_err(|err| {
                BackupError::permanent(err).context(format!("waiting for {}", binary.display()))
            })?,
            () = cancel.cancelled() => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(BackupError::Cancelled("postgres client"));
            }
        };

        let captured = drain.await.unwrap_or_default();
        if !status.success() {
            // Permanent by default, deliberately: the common causes — a client
            // older than the server, a missing binary, an unwritable path — do
            // not improve on their own, and a spurious page is the cheaper of
            // the two mistakes for a control this one. See `crate::error`.
            return Err(BackupError::permanent_msg(format!(
                "{} failed ({status}): {}",
                binary.display(),
                captured.trim()
            )));
        }
        Ok(())
    }
}

/// The database component of a Postgres URL.
fn database_of(url: &str) -> Result<String> {
    let parsed = url::Url::parse(url)
        .map_err(|err| BackupError::permanent(err).context("parsing the Postgres URL"))?;
    let database = parsed.path().trim_start_matches('/').to_owned();
    if database.is_empty() {
        return Err(BackupError::permanent_msg(
            "the Postgres URL names no database",
        ));
    }
    Ok(database)
}

/// Every user table, schema-qualified, from a connection's point of view.
///
/// **Discovered, never listed.** A hand-maintained table list is a backup that
/// silently stops covering the next table anybody adds — the failure mode
/// where the control looks green for months and the data was never in the
/// artifact. Partitioned parents are included and their partitions excluded
/// (`NOT relispartition`), so a partitioned table is counted once, through the
/// parent, whether or not this schema ever grows one.
const TABLE_DISCOVERY_SQL: &str = "\
    SELECT n.nspname AS schema, c.relname AS table \
    FROM pg_class c \
    JOIN pg_namespace n ON n.oid = c.relnamespace \
    WHERE c.relkind IN ('r', 'p') \
      AND NOT c.relispartition \
      AND n.nspname NOT IN ('pg_catalog', 'information_schema') \
      AND n.nspname NOT LIKE 'pg\\_toast%' \
      AND n.nspname NOT LIKE 'pg\\_temp%' \
    ORDER BY 1, 2";

/// Databases on this server that a sweep may consider.
const SCRATCH_DISCOVERY_SQL: &str =
    "SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY 1";

/// Count and content digest for one table.
///
/// `sha256(record::text)` truncated to 60 bits keeps every term inside a
/// `bigint`; the sum is taken as `numeric` (arbitrary precision, so it cannot
/// overflow mid-aggregate) and only then reduced mod 2^64 to match the
/// client-side accumulator's wrapping arithmetic.
fn fingerprint_sql(schema: &str, table: &str) -> String {
    format!(
        "SELECT count(*)::bigint AS rows, \
         (COALESCE(sum(('x' || substr(encode(sha256(convert_to(t::text, 'UTF8')), 'hex'), 1, 15))::bit(60)::bigint::numeric), 0) \
          % 18446744073709551616::numeric)::text AS content \
         FROM \"{schema}\".\"{table}\" t",
    )
}

/// Pin the session, then fingerprint every discovered table on `conn`.
async fn fingerprint_tables(
    conn: &mut PgConnection,
    cut: Cut,
    cancel: &CancellationToken,
) -> Result<BTreeMap<String, TableFingerprint>> {
    for pin in SESSION_PINS {
        conn.execute(*pin)
            .await
            .map_err(|err| from_sqlx(err, format!("applying {pin}")))?;
    }

    let tables = sqlx::query(TABLE_DISCOVERY_SQL)
        .fetch_all(&mut *conn)
        .await
        .map_err(|err| from_sqlx(err, "discovering tables"))?;

    let mut out = BTreeMap::new();
    for row in tables {
        if cancel.is_cancelled() {
            return Err(BackupError::Cancelled("postgres fingerprint"));
        }
        let schema: String = row
            .try_get("schema")
            .map_err(|err| from_sqlx(err, "reading a discovered schema name"))?;
        let table: String = row
            .try_get("table")
            .map_err(|err| from_sqlx(err, "reading a discovered table name"))?;
        let qualified = format!("{schema}.{table}");

        // `AssertSqlSafe` is sqlx 0.9's explicit opt-in for SQL built at
        // runtime, and it is honest here: the table name is not user input —
        // it came back from `pg_class` on this same connection a moment ago —
        // and the statement takes no bind parameters, because an identifier
        // cannot be one.
        let measured = sqlx::query(sqlx::AssertSqlSafe(fingerprint_sql(&schema, &table)))
            .fetch_one(&mut *conn)
            .await
            .map_err(|err| from_sqlx(err, format!("fingerprinting {qualified}")))?;
        let rows: i64 = measured
            .try_get("rows")
            .map_err(|err| from_sqlx(err, format!("reading {qualified}'s row count")))?;
        // `numeric` comes back as text so the value crosses the wire exactly;
        // it is a 20-digit unsigned quantity that no Rust integer sqlx maps by
        // default would hold without a lossy cast.
        let content: String = measured
            .try_get("content")
            .map_err(|err| from_sqlx(err, format!("reading {qualified}'s content digest")))?;
        let content: u64 = content.parse().map_err(|_| {
            BackupError::permanent_msg(format!(
                "{qualified}: unreadable content digest {content:?}"
            ))
        })?;

        let derivation = if DERIVED_TABLES.contains(&qualified.as_str()) {
            Derivation::Derived
        } else {
            Derivation::SystemOfRecord
        };

        out.insert(
            qualified,
            TableFingerprint {
                rows: rows.max(0) as u64,
                content: content_from_sum(content),
                derivation,
                cut,
            },
        );
    }
    Ok(out)
}

#[async_trait]
impl StoreReader for PostgresTarget {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> TargetKind {
        TargetKind::Postgres
    }

    fn live(&self) -> Database {
        self.database.clone()
    }

    async fn fingerprint(&self, database: &Database) -> Result<BTreeMap<String, TableFingerprint>> {
        let mut conn = self.connect(database.as_str()).await?;
        // A transaction only so `SET LOCAL` has something to be local to; the
        // read itself needs no isolation on a database nothing is writing.
        conn.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .await
            .map_err(|err| from_sqlx(err, "opening the fingerprint transaction"))?;
        let tables = fingerprint_tables(
            &mut conn,
            Cut::TransactionSnapshot,
            &CancellationToken::new(),
        )
        .await;
        let _ = conn.execute("COMMIT").await;
        let _ = conn.close().await;
        tables
    }
}

#[async_trait]
impl BackupTarget for PostgresTarget {
    async fn snapshot(&self, dir: &Path, cancel: &CancellationToken) -> Result<Snapshot> {
        let mut conn = self.connect(self.database.as_str()).await?;

        // REPEATABLE READ + READ ONLY: the snapshot pg_dump will join, taken
        // without blocking a single writer.
        conn.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .await
            .map_err(|err| from_sqlx(err, "opening the snapshot transaction"))?;

        // Everything from here to COMMIT is inside one instant. Any early
        // return leaves the transaction to be closed by the connection drop,
        // which is correct: it wrote nothing.
        let result = async {
            let cut_at = Utc::now();
            let snapshot_id: String = sqlx::query_scalar("SELECT pg_export_snapshot()")
                .fetch_one(&mut conn)
                .await
                .map_err(|err| from_sqlx(err, "exporting the transaction snapshot"))?;

            let tables = fingerprint_tables(&mut conn, Cut::TransactionSnapshot, cancel).await?;

            // pg_dump joins the snapshot we are holding open. If this process
            // died here the transaction would abort and the dump would fail —
            // which is the right failure: a dump not joined to the fingerprint
            // is not the artifact this crate promises.
            let dump_path = dir.join(DUMP_FILE);
            self.run_client(
                &self.pg_dump.clone(),
                &[
                    "--format=custom".to_owned(),
                    "--no-owner".to_owned(),
                    "--no-privileges".to_owned(),
                    format!("--snapshot={snapshot_id}"),
                    format!("--file={}", dump_path.display()),
                    "--dbname".to_owned(),
                    self.url.expose_secret().to_owned(),
                ],
                cancel,
            )
            .await?;

            let tool = client_version(&self.pg_dump).await;
            Ok(Snapshot {
                cut_at,
                tables,
                files: vec![DUMP_FILE.to_owned()],
                schema: Vec::new(),
                tool,
                notes: Vec::new(),
            })
        }
        .await;

        // Read-only, so the outcome of this is immaterial to the database; it
        // only releases the snapshot (and the vacuum horizon) promptly.
        let _ = conn.execute("COMMIT").await;
        let _ = conn.close().await;
        result
    }

    async fn provision_scratch(&self) -> Result<Scratch> {
        let scratch = scratch_name(&self.database)?;
        let mut conn = PgConnection::connect(&self.maintenance_url()?)
            .await
            .map_err(|err| from_sqlx(err, "connecting to the maintenance database"))?;
        // CREATE DATABASE cannot be parameterised or run in a transaction; the
        // name came from `Database::new`, so it is a bare identifier by type.
        let created = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE DATABASE \"{}\"",
            scratch.database()
        )))
        .execute(&mut conn)
        .await
        .map_err(|err| {
            from_sqlx(
                err,
                format!("creating scratch database {}", scratch.database()),
            )
        });
        let _ = conn.close().await;
        created?;
        Ok(scratch)
    }

    async fn drop_scratch(&self, mut scratch: Scratch) -> Result<()> {
        self.drop_database(scratch.database()).await?;
        // Only after the database is actually gone: releasing first would make
        // a failed drop look tidy in the log.
        scratch.release();
        Ok(())
    }

    async fn sweep_scratch(&self, older_than: Duration) -> Result<Vec<String>> {
        let mut conn = self.connect(self.database.as_str()).await?;
        let rows = sqlx::query(SCRATCH_DISCOVERY_SQL)
            .fetch_all(&mut conn)
            .await
            .map_err(|err| from_sqlx(err, "listing databases for the scratch sweep"));
        let _ = conn.close().await;

        let now = Utc::now();
        let mut swept = Vec::new();
        for row in rows? {
            let name: String = row
                .try_get("datname")
                .map_err(|err| from_sqlx(err, "reading a database name"))?;
            if !is_sweepable(&name, now, older_than) {
                continue;
            }
            // Re-parsed rather than trusted: `is_sweepable` already refuses
            // anything it cannot positively identify, and this refuses
            // anything that is not an identifier.
            let database = Database::new(name.clone())?;
            self.drop_database(&database).await?;
            swept.push(name);
        }
        Ok(swept)
    }

    async fn restore(
        &self,
        dir: &Path,
        _manifest: &BackupManifest,
        into: &Database,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let dump_path = dir.join(DUMP_FILE);
        if !tokio::fs::try_exists(&dump_path).await.unwrap_or(false) {
            return Err(BackupError::permanent_msg(format!(
                "{DUMP_FILE} is missing from the artifact"
            )));
        }

        // `--single-transaction` with `--exit-on-error`: a restore either
        // lands completely or leaves nothing behind. A half-restored database
        // that the fingerprint then "verifies" against a partial manifest is
        // the failure this pairing exists to make impossible.
        self.run_client(
            &self.pg_restore.clone(),
            &[
                "--no-owner".to_owned(),
                "--no-privileges".to_owned(),
                "--exit-on-error".to_owned(),
                "--single-transaction".to_owned(),
                "--dbname".to_owned(),
                self.url_for(into.as_str())?,
                dump_path.display().to_string(),
            ],
            cancel,
        )
        .await
    }
}

/// `pg_dump --version`, or a marker when it cannot be run.
///
/// Never fails a backup: an unknown tool version is worth recording as
/// unknown, not worth refusing to take a backup over.
async fn client_version(binary: &Path) -> String {
    match tokio::process::Command::new(binary)
        .arg("--version")
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        }
        _ => format!("{} (version unknown)", binary.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_database_is_taken_from_the_url_path() {
        assert_eq!(
            database_of("postgres://u:p@host:5432/detector?sslmode=disable").expect("parse"),
            "detector"
        );
        assert!(database_of("postgres://u:p@host:5432/").is_err());
    }

    #[test]
    fn the_sweep_is_the_leak_guarantee_not_the_drop_impl() {
        // Async Drop does not exist and a SIGKILL runs no destructor, so
        // cleanup cannot depend on unwinding. These are the names the sweep
        // has to recognise, and the ones it must never touch.
        use chrono::TimeZone;
        let now = Utc
            .with_ymd_and_hms(2026, 9, 5, 12, 0, 0)
            .single()
            .expect("valid");
        let day = std::time::Duration::from_secs(86_400);
        assert!(crate::target::is_sweepable(
            "mev_drill_20260901120000_9",
            now,
            day
        ));
        assert!(!crate::target::is_sweepable("mev", now, day));
        // The discovery query must not offer template databases to the sweep:
        // dropping template1 is not recoverable by anything in this crate.
        assert!(SCRATCH_DISCOVERY_SQL.contains("NOT datistemplate"));
    }

    #[test]
    fn a_scratch_url_keeps_the_credentials_and_swaps_only_the_database() {
        let target = PostgresTarget::new(
            "postgres",
            SecretString::from("postgres://detector:secret@db:5432/detector?sslmode=disable"),
        )
        .expect("target");
        let url = target.url_for("detector_drill_1").expect("url");
        assert!(url.contains("/detector_drill_1"));
        assert!(url.contains("detector:secret@"));
        assert!(url.contains("sslmode=disable"));
    }

    #[test]
    fn the_fingerprint_query_is_order_independent_and_bounded_per_row() {
        let sql = fingerprint_sql("public", "rules");
        // No ORDER BY, no string_agg: the digest must not depend on read order
        // (pg_restore reorders rows) and must not materialise the table.
        assert!(!sql.to_lowercase().contains("order by"), "{sql}");
        assert!(!sql.to_lowercase().contains("string_agg"), "{sql}");
        assert!(sql.contains("sum("), "{sql}");
        assert!(sql.contains("\"public\".\"rules\""), "{sql}");
    }

    #[test]
    fn the_digest_is_reduced_by_the_same_modulus_the_client_accumulator_uses() {
        // 2^64 — the point where the SQL sum and ContentAccumulator's wrapping
        // add have to agree, or a correct restore reports as a divergence.
        assert!(fingerprint_sql("public", "rules").contains("18446744073709551616"));
        assert_eq!(u64::MAX as u128 + 1, 18_446_744_073_709_551_616_u128);
    }

    #[test]
    fn every_rendering_setting_that_affects_a_rows_text_form_is_pinned() {
        // Each of these changes `record::text` output, and the restore is
        // verified on a server whose defaults need not match production's.
        for setting in [
            "DateStyle",
            "IntervalStyle",
            "TimeZone",
            "extra_float_digits",
            "bytea_output",
        ] {
            assert!(
                SESSION_PINS.iter().any(|pin| pin.contains(setting)),
                "{setting} is not pinned"
            );
        }
    }

    #[test]
    fn table_discovery_excludes_system_schemas_and_counts_a_partitioned_table_once() {
        assert!(TABLE_DISCOVERY_SQL.contains("NOT c.relispartition"));
        assert!(TABLE_DISCOVERY_SQL.contains("'pg_catalog', 'information_schema'"));
        assert!(TABLE_DISCOVERY_SQL.contains("'r', 'p'"));
    }

    #[test]
    fn an_unlisted_table_defaults_to_system_of_record() {
        // The safe direction: a new table nobody classified is treated as
        // irreplaceable, so the runbook over-protects rather than under.
        assert!(!DERIVED_TABLES.contains(&"public.rules"));
        assert!(DERIVED_TABLES.contains(&"public.incidents"));
    }
}
