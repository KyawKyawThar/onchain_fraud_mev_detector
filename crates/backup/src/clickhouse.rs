//! ClickHouse backup and restore over the HTTP interface — the event store
//! (§4) and every derived analytics table beside it.
//!
//! ## Why no ClickHouse client
//!
//! This module speaks HTTP directly instead of using the `clickhouse` crate,
//! and the workspace's arch-conformance rules pin that choice. Two reasons:
//!
//! 1. **A backup must not migrate the thing it is copying.** Every ClickHouse
//!    consumer in the workspace pairs the client with `ch-migrate` and applies
//!    its own DDL at boot — that is the right discipline for a service that
//!    owns tables. It is exactly wrong for a tool whose job is to copy what is
//!    there *now*, including a schema this build has never heard of. A backup
//!    binary that mutated the schema of a database it was called to protect
//!    would be the worst kind of bug.
//! 2. **The typed client wants types.** `#[derive(Row)]` binds a compile-time
//!    struct per table; this crate must handle whatever tables exist, so it
//!    reads and writes an untyped row format and hashes the bytes.
//!
//! ## The consistent cut, per table
//!
//! `events` is the append-only system of record, so `appended_at < W` — with
//! `W` read from **the store's own clock**, not this process's — is a genuine
//! consistent cut: nothing below `W` can ever change. This is the same
//! watermark `crates/rebuild` pins a replay with, for the same reason, and it
//! means the artifact's contents are exactly reproducible.
//!
//! Every other ClickHouse table is a fold over that log. They are still backed
//! up (restoring is far cheaper than re-deriving), but their cut is
//! [`Cut::StreamedRead`]: fingerprinted from the bytes as they stream past, so
//! the artifact is internally consistent and its restore is verifiable, while
//! *across* tables it is not a single instant. That is an acceptable weakness
//! precisely because those tables have a second recovery path — the projection
//! rebuild — which is authoritative when the two disagree.
//!
//! ## Two traps this module exists to avoid
//!
//! **Materialized views must be created after the data lands.** A ClickHouse
//! MV is an insert trigger. Restore `usage_events` while `usage_rollup_daily_mv`
//! exists and the MV fires on every restored row, writing a second copy of the
//! rollup on top of the rollup you also restored. The result is a restore that
//! "succeeds" with silently doubled aggregates. So [`SchemaObjectKind`] orders
//! the DDL: tables, then data, then views.
//!
//! **A merging engine's raw rows are not stable.** `SummingMergeTree` and
//! `ReplacingMergeTree` collapse rows in background merges, so the raw row set
//! read at backup time may not be the raw row set read back after a restore —
//! a drill built on raw reads would fail at random. Both the dump and every
//! fingerprint therefore read merging engines with `FINAL`, which is the
//! *logical* content and is invariant under merges on both sides.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::error::{from_reqwest, from_status, BackupError, Result};
use crate::manifest::{
    BackupManifest, ContentAccumulator, Cut, Derivation, SchemaObject, SchemaObjectKind,
    SnapshotNote, TableFingerprint, TargetKind,
};
use crate::target::{
    is_sweepable, scratch_name, BackupTarget, Database, Scratch, Snapshot, StoreReader,
};

/// The one table that is the system of record (§4).
const SYSTEM_OF_RECORD_TABLE: &str = "events";
/// Its ingest-time column — the axis the watermark cut is taken on. Ingest
/// time, not event time: `occurred_at` is not monotonic with arrival, so a
/// bound on it is not a cut at all (the same finding `crates/rebuild` records).
const INGEST_COLUMN: &str = "appended_at";

/// Row format for dumps. Self-describing per row (so a column added between
/// backup and restore does not silently shift every value one place left),
/// splittable on newlines (so it can be hashed as it streams, without a
/// parser), and accepted verbatim by `INSERT`.
///
/// The cost is size: JSON text of a ZSTD-compressed payload column is far
/// bigger on disk than a binary dump. That is a deliberate trade — the format
/// is what makes the artifact independently verifiable and hand-inspectable
/// during an incident. Compression belongs on the offsite copy.
const ROW_FORMAT: &str = "JSONEachRow";

/// Settings pinned on **both** sides of every fingerprint and on the insert,
/// so a value's text form is a function of the value alone.
///
/// `date_time_output_format` is deliberately left at `simple`
/// (`2026-09-04 11:02:13.123`) rather than `iso`: the default *input* parser
/// does not accept the ISO form, so choosing the prettier output would produce
/// artifacts that fail to restore.
const OUTPUT_PINS: &str = "output_format_json_quote_64bit_integers = 1, \
     output_format_json_quote_denormals = 1, \
     date_time_output_format = 'simple'";
/// The insert side of the same pinning, carried as **HTTP query parameters**
/// rather than a `SETTINGS` clause.
///
/// This is not a style preference, it is the only correct place for them. In
/// `INSERT INTO t FORMAT JSONEachRow`, ClickHouse treats **everything after
/// the format name as the data** — so a trailing `SETTINGS …` is not parsed as
/// SQL at all, it is read as the first row, and the restore dies with
/// `Cannot parse input: expected '{'` naming a row number that does not exist
/// in the artifact. (`INSERT INTO t SETTINGS … FORMAT …` is the in-SQL form
/// that does work; out-of-band parameters are used here because they cannot be
/// swallowed by the data section no matter how the statement is later edited.)
const INPUT_PINS: &[(&str, &str)] = &[("date_time_input_format", "basic")];

/// Engines whose raw rows collapse in background merges — read with `FINAL`.
const MERGING_ENGINES: &[&str] = &[
    "ReplacingMergeTree",
    "SummingMergeTree",
    "AggregatingMergeTree",
    "CollapsingMergeTree",
    "VersionedCollapsingMergeTree",
    "GraphiteMergeTree",
];

/// One discovered ClickHouse object.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DiscoveredTable {
    name: String,
    engine: String,
    ddl: String,
}

impl DiscoveredTable {
    fn is_view(&self) -> bool {
        self.engine == "MaterializedView" || self.engine == "View" || self.engine == "LiveView"
    }

    fn is_data_table(&self) -> bool {
        self.engine.ends_with("MergeTree") || self.engine == "Log" || self.engine == "TinyLog"
    }

    fn needs_final(&self) -> bool {
        MERGING_ENGINES.contains(&self.engine.as_str())
    }

    /// The inner storage of a materialized view declared without `TO`. Skipped
    /// with a loud note rather than half-handled: its name embeds a UUID that
    /// cannot be recreated in another database, so an artifact containing it
    /// would not restore.
    fn is_view_inner_storage(&self) -> bool {
        self.name.starts_with(".inner")
    }
}

/// A ClickHouse server plus the database on it that holds production data.
#[derive(Debug, Clone)]
pub struct ClickHouseTarget {
    name: String,
    /// Base HTTP URL, no credentials, no database: `http://clickhouse:8123`.
    base_url: String,
    user: String,
    password: SecretString,
    database: Database,
    http: reqwest::Client,
}

impl ClickHouseTarget {
    pub fn new(
        name: impl Into<String>,
        base_url: impl Into<String>,
        user: impl Into<String>,
        password: SecretString,
        database: Database,
    ) -> Self {
        Self {
            name: name.into(),
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            user: user.into(),
            password,
            database,
            http: reqwest::Client::new(),
        }
    }

    fn request(&self) -> reqwest::RequestBuilder {
        self.http
            .post(&self.base_url)
            .header("X-ClickHouse-User", &self.user)
            .header("X-ClickHouse-Key", self.password.expose_secret())
    }

    /// Send a statement and return its body. For small results only.
    async fn execute(&self, sql: &str, context: &str) -> Result<String> {
        let response = self
            .request()
            .body(sql.to_owned())
            .send()
            .await
            .map_err(|err| from_reqwest(err, context))?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(from_status(status, &body, context));
        }
        Ok(body)
    }

    /// The store's own clock — never this process's. One clock means a
    /// watermark says the same thing to every reader, whatever the host skew.
    async fn watermark(&self) -> Result<DateTime<Utc>> {
        let raw = self
            .execute(
                "SELECT toUnixTimestamp64Milli(now64(3, 'UTC')) FORMAT TabSeparated",
                "reading the ingest watermark",
            )
            .await?;
        let millis: i64 = raw
            .trim()
            .parse()
            .map_err(|_| BackupError::permanent_msg(format!("unreadable watermark {raw:?}")))?;
        Utc.timestamp_millis_opt(millis).single().ok_or_else(|| {
            BackupError::permanent_msg(format!("watermark {millis} is not an instant"))
        })
    }

    async fn server_version(&self) -> String {
        match self
            .execute(
                "SELECT version() FORMAT TabSeparated",
                "reading the server version",
            )
            .await
        {
            Ok(raw) => format!("ClickHouse {}", raw.trim()),
            Err(_) => "ClickHouse (version unknown)".to_owned(),
        }
    }

    /// Every object in `database`, discovered — never a hard-coded list, for
    /// the same reason as the Postgres side: a table added by the next
    /// migration must be in the next artifact without anyone remembering.
    ///
    /// The database name travels as a server-side query *parameter*
    /// (`{db:String}`), so it is never spliced into SQL text.
    async fn discover_in(&self, database: &Database) -> Result<Vec<DiscoveredTable>> {
        let context = format!("discovering tables in {database}");
        let response = self
            .request()
            .query(&[("param_db", database.as_str())])
            .body(
                "SELECT name, engine, create_table_query FROM system.tables \
                 WHERE database = {db:String} AND NOT is_temporary ORDER BY name \
                 FORMAT JSONEachRow"
                    .to_owned(),
            )
            .send()
            .await
            .map_err(|err| from_reqwest(err, &context))?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(from_status(status, &text, &context));
        }
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let row: Value = serde_json::from_str(line).map_err(|err| {
                    BackupError::permanent(err).context("parsing a system.tables row")
                })?;
                Ok(DiscoveredTable {
                    name: string_field(&row, "name")?,
                    engine: string_field(&row, "engine")?,
                    ddl: string_field(&row, "create_table_query")?,
                })
            })
            .collect()
    }

    /// The `SELECT` a dump and a fingerprint both run, so the two can never
    /// diverge in what they consider the table's content.
    fn read_sql(
        &self,
        database: &Database,
        table: &DiscoveredTable,
        predicate: Option<&str>,
    ) -> String {
        format!(
            "SELECT * FROM {db}.{name}{final_}{where_} FORMAT {ROW_FORMAT} SETTINGS {OUTPUT_PINS}",
            db = quote_ident(database.as_str()),
            name = quote_ident(&table.name),
            final_ = if table.needs_final() { " FINAL" } else { "" },
            where_ = predicate.map(|p| format!(" WHERE {p}")).unwrap_or_default(),
        )
    }

    /// Stream one table's rows, hashing each as it goes and optionally writing
    /// them out.
    ///
    /// **One function for the dump and the read-back**, which is the point.
    /// These were two near-identical loops, and the copy used by the read-back
    /// had quietly lost the truncation check — so a connection cut mid-verify
    /// produced a short row count that was then reported as a *divergence*,
    /// i.e. "your backup is bad", when the truth was "the verification did not
    /// finish". Blaming the artifact for a transport fault is the worst thing
    /// a control can do, and the fix is structural: there is one loop, and the
    /// check lives in it.
    async fn stream_rows(
        &self,
        sql: String,
        table: &str,
        mut writer: Option<&mut (dyn AsyncWrite + Unpin + Send)>,
        cancel: &CancellationToken,
    ) -> Result<ContentAccumulator> {
        let context = format!("streaming {table}");
        let mut response = self
            .request()
            .body(sql)
            .send()
            .await
            .map_err(|err| from_reqwest(err, &context))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(from_status(status, &body, &context));
        }

        let mut accumulator = ContentAccumulator::new();
        // Rows are newline-delimited but chunk boundaries are not, so a
        // partial line is carried forward rather than hashed as a row.
        let mut pending: Vec<u8> = Vec::new();
        loop {
            let chunk = tokio::select! {
                chunk = response.chunk() => chunk.map_err(|err| from_reqwest(err, &context))?,
                () = cancel.cancelled() => return Err(BackupError::Cancelled("clickhouse stream")),
            };
            let Some(chunk) = chunk else { break };

            if let Some(writer) = writer.as_deref_mut() {
                writer
                    .write_all(&chunk)
                    .await
                    .map_err(|err| crate::error::from_io(err, format!("writing {table}")))?;
            }
            pending.extend_from_slice(&chunk);
            while let Some(newline) = pending.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = pending.drain(..=newline).collect();
                let row = &line[..line.len() - 1];
                if !row.is_empty() {
                    accumulator.absorb_row(row);
                }
            }
        }

        if !pending.is_empty() {
            // ClickHouse terminates every row with a newline; a trailing
            // fragment means the response was cut short. Transient: it is the
            // connection that failed, not the data.
            return Err(BackupError::transient_msg(format!(
                "the read of {table} ended mid-row after {} row(s) — the response was truncated",
                accumulator.rows()
            )));
        }
        if let Some(writer) = writer {
            writer
                .flush()
                .await
                .map_err(|err| crate::error::from_io(err, format!("flushing {table}")))?;
        }
        Ok(accumulator)
    }

    /// `DROP DATABASE`, shared by `drop_scratch` and the sweep.
    async fn drop_database(&self, database: &Database) -> Result<()> {
        self.execute(
            &format!("DROP DATABASE IF EXISTS {}", quote_ident(database.as_str())),
            &format!("dropping database {database}"),
        )
        .await
        .map(|_| ())
    }
}

/// A JSON string field, or a clear error naming what was missing.
fn string_field(row: &Value, field: &str) -> Result<String> {
    row.get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            BackupError::permanent_msg(format!("ClickHouse row has no string field {field:?}"))
        })
}

/// Backtick-quote an identifier. Callers still pass either a [`Database`]
/// (parsed) or a name discovered from the server itself.
fn quote_ident(name: &str) -> String {
    format!("`{}`", name.replace('`', "``"))
}

/// Rewrite DDL captured from `system.tables` so it creates the object in
/// `into` instead of the database it came from.
///
/// Two edits, both necessary:
///
/// * the database qualifier — including a materialized view's `TO <db>.<tbl>`
///   target, which would otherwise write into production from a scratch copy;
/// * the `UUID '…'` clause an Atomic database stamps into `CREATE TABLE`.
///   Replaying it verbatim asks the server to create a *second* object with an
///   existing UUID, which fails — and if it did not, would alias the two.
pub fn rewrite_ddl(ddl: &str, from: &str, into: &str) -> String {
    let mut out = ddl
        .replace(&format!("`{from}`."), &format!("`{into}`."))
        .replace(&format!("{from}."), &format!("{into}."));
    while let Some(start) = out.find(" UUID '") {
        let rest = &out[start + " UUID '".len()..];
        match rest.find('\'') {
            Some(end) => {
                let absolute = start + " UUID '".len() + end + 1;
                out.replace_range(start..absolute, "");
            }
            None => break,
        }
    }
    out
}

/// The file an artifact stores one table's rows in.
fn data_file(table: &str) -> String {
    format!("{table}.jsonl")
}

#[async_trait]
impl StoreReader for ClickHouseTarget {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> TargetKind {
        TargetKind::ClickHouse
    }

    fn live(&self) -> Database {
        self.database.clone()
    }

    async fn fingerprint(&self, database: &Database) -> Result<BTreeMap<String, TableFingerprint>> {
        let objects = self.discover_in(database).await?;
        let cancel = CancellationToken::new();
        let mut out = BTreeMap::new();
        for object in &objects {
            if object.is_view() || object.is_view_inner_storage() || !object.is_data_table() {
                continue;
            }
            let accumulator = self
                .stream_rows(
                    self.read_sql(database, object, None),
                    &object.name,
                    None,
                    &cancel,
                )
                .await?;
            let (derivation, cut) = classify(&object.name);
            out.insert(object.name.clone(), accumulator.finish(derivation, cut));
        }
        Ok(out)
    }
}

/// How a table is treated: the log is the system of record and gets a real
/// watermark cut; everything else is a fold over it.
fn classify(table: &str) -> (Derivation, Cut) {
    if table == SYSTEM_OF_RECORD_TABLE {
        (Derivation::SystemOfRecord, Cut::IngestWatermark)
    } else {
        (Derivation::Derived, Cut::StreamedRead)
    }
}

#[async_trait]
impl BackupTarget for ClickHouseTarget {
    async fn snapshot(&self, dir: &Path, cancel: &CancellationToken) -> Result<Snapshot> {
        let cut_at = self.watermark().await?;
        let objects = self.discover_in(&self.database).await?;

        let mut tables = BTreeMap::new();
        let mut files = Vec::new();
        let mut schema = Vec::new();
        let mut notes = Vec::new();

        for object in &objects {
            if cancel.is_cancelled() {
                return Err(BackupError::Cancelled("clickhouse snapshot"));
            }
            if object.is_view_inner_storage() {
                // NotCovered, not Skipped: this is data that will not be in the
                // artifact, which makes the artifact incomplete and fails the
                // drill rather than producing a line nobody reads.
                notes.push(SnapshotNote::NotCovered {
                    object: object.name.clone(),
                    reason: "a materialized view's inner storage — its name embeds a UUID that \
                             cannot be recreated in another database. Declare the view with an \
                             explicit `TO <table>` to make it backup-able."
                        .to_owned(),
                });
                continue;
            }
            if object.is_view() {
                schema.push(SchemaObject {
                    name: object.name.clone(),
                    kind: SchemaObjectKind::View,
                    ddl: object.ddl.clone(),
                });
                continue;
            }
            if !object.is_data_table() {
                // Skipped, not NotCovered: an engine like `Memory` or a
                // `Dictionary` holds nothing durable, so nothing is lost.
                notes.push(SnapshotNote::Skipped {
                    object: object.name.clone(),
                    reason: format!("engine {} holds no durable rows", object.engine),
                });
                continue;
            }

            schema.push(SchemaObject {
                name: object.name.clone(),
                kind: SchemaObjectKind::Table,
                ddl: object.ddl.clone(),
            });

            let (derivation, cut) = classify(&object.name);
            let predicate = (cut == Cut::IngestWatermark).then(|| {
                format!(
                    "{INGEST_COLUMN} < fromUnixTimestamp64Milli({}, 'UTC')",
                    cut_at.timestamp_millis()
                )
            });

            let relative = data_file(&object.name);
            let file = tokio::fs::File::create(dir.join(&relative))
                .await
                .map_err(|err| crate::error::from_io(err, format!("creating {relative}")))?;
            let mut writer = tokio::io::BufWriter::new(file);
            let accumulator = self
                .stream_rows(
                    self.read_sql(&self.database, object, predicate.as_deref()),
                    &object.name,
                    Some(&mut writer),
                    cancel,
                )
                .await?;
            tables.insert(object.name.clone(), accumulator.finish(derivation, cut));
            files.push(relative);
        }

        if tables.is_empty() {
            notes.push(SnapshotNote::NotCovered {
                object: self.database.to_string(),
                reason: "no storage tables were found — an artifact with no data is not a backup"
                    .to_owned(),
            });
        }

        Ok(Snapshot {
            cut_at,
            tables,
            files,
            schema,
            tool: self.server_version().await,
            notes,
        })
    }

    async fn provision_scratch(&self) -> Result<Scratch> {
        let scratch = scratch_name(&self.database)?;
        self.execute(
            &format!(
                "CREATE DATABASE {}",
                quote_ident(scratch.database().as_str())
            ),
            &format!("creating scratch database {}", scratch.database()),
        )
        .await?;
        Ok(scratch)
    }

    async fn drop_scratch(&self, mut scratch: Scratch) -> Result<()> {
        self.drop_database(scratch.database()).await?;
        scratch.release();
        Ok(())
    }

    async fn sweep_scratch(&self, older_than: Duration) -> Result<Vec<String>> {
        let listed = self
            .execute(
                "SELECT name FROM system.databases FORMAT TabSeparated",
                "listing databases for the scratch sweep",
            )
            .await?;
        let now = Utc::now();
        let mut swept = Vec::new();
        for name in listed.lines().map(str::trim).filter(|n| !n.is_empty()) {
            if !is_sweepable(name, now, older_than) {
                continue;
            }
            let database = Database::new(name.to_owned())?;
            self.drop_database(&database).await?;
            swept.push(name.to_owned());
        }
        Ok(swept)
    }

    async fn restore(
        &self,
        dir: &Path,
        manifest: &BackupManifest,
        into: &Database,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let source = manifest.source_database().to_owned();

        // 1. Tables first — nothing to insert into otherwise.
        for object in manifest
            .schema
            .iter()
            .filter(|o| o.kind == SchemaObjectKind::Table)
        {
            let ddl = rewrite_ddl(&object.ddl, &source, into.as_str());
            self.execute(&ddl, &format!("creating table {}", object.name))
                .await?;
        }

        // 2. Data. Views do not exist yet, so no insert trigger fires and no
        //    aggregate is written twice — see the module docs.
        for table in manifest.tables.keys() {
            if cancel.is_cancelled() {
                return Err(BackupError::Cancelled("clickhouse restore"));
            }
            let path = dir.join(data_file(table));
            if !tokio::fs::try_exists(&path).await.unwrap_or(false) {
                return Err(BackupError::permanent_msg(format!(
                    "{} is missing from the artifact",
                    data_file(table)
                )));
            }
            let file = tokio::fs::File::open(&path)
                .await
                .map_err(|err| crate::error::from_io(err, format!("opening {}", path.display())))?;
            let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(file));
            // Nothing may follow the format name — see INPUT_PINS.
            let query = format!(
                "INSERT INTO {db}.{name} FORMAT {ROW_FORMAT}",
                db = quote_ident(into.as_str()),
                name = quote_ident(table),
            );
            let context = format!("restoring {table}");
            let response = self
                .request()
                .query(&[("query", query.as_str())])
                .query(INPUT_PINS)
                .body(body)
                .send()
                .await
                .map_err(|err| from_reqwest(err, &context))?;
            let status = response.status();
            if !status.is_success() {
                let text = response.text().await.unwrap_or_default();
                return Err(from_status(status, &text, &context));
            }
        }

        // 3. Views last.
        for object in manifest
            .schema
            .iter()
            .filter(|o| o.kind == SchemaObjectKind::View)
        {
            let ddl = rewrite_ddl(&object.ddl, &source, into.as_str());
            self.execute(&ddl, &format!("creating view {}", object.name))
                .await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(name: &str, engine: &str) -> DiscoveredTable {
        DiscoveredTable {
            name: name.to_owned(),
            engine: engine.to_owned(),
            ddl: format!("CREATE TABLE detector.{name} (x UInt8) ENGINE = {engine}"),
        }
    }

    #[test]
    fn merging_engines_are_read_with_final_and_plain_ones_are_not() {
        // Without FINAL a background merge between backup and restore would
        // change the raw row set and fail a correct drill at random.
        assert!(table("incident_analytics", "SummingMergeTree").needs_final());
        assert!(table("address_embeddings", "ReplacingMergeTree").needs_final());
        assert!(!table("events", "MergeTree").needs_final());
    }

    #[test]
    fn views_are_schema_only_and_inner_storage_is_refused() {
        let view = table("usage_rollup_daily_mv", "MaterializedView");
        assert!(view.is_view());
        assert!(!view.is_data_table());

        let inner = table(".inner_id.8f2c", "MergeTree");
        assert!(inner.is_view_inner_storage());
    }

    #[test]
    fn ddl_rewriting_redirects_a_materialized_views_target_too() {
        // The dangerous case: a view restored into a scratch database whose
        // `TO` clause still points at production would write live rows from a
        // drill.
        let ddl = "CREATE MATERIALIZED VIEW detector.usage_rollup_daily_mv UUID '9f2c-…' \
                   TO detector.usage_rollup_daily AS SELECT day, sum(qty) FROM detector.usage_events";
        let rewritten = rewrite_ddl(ddl, "detector", "detector_drill_1");
        assert!(!rewritten.contains("detector."), "{rewritten}");
        assert_eq!(rewritten.matches("detector_drill_1.").count(), 3);
    }

    #[test]
    fn ddl_rewriting_strips_the_atomic_database_uuid() {
        // Replaying the UUID asks the server to create a second object with an
        // existing identity — it fails, and a restore that fails at the first
        // table is a restore nobody finishes.
        let ddl = "CREATE TABLE detector.events UUID '0e6b-1' (x UInt8) ENGINE = MergeTree";
        let rewritten = rewrite_ddl(ddl, "detector", "scratch");
        assert!(!rewritten.contains("UUID"), "{rewritten}");
        assert!(
            rewritten.starts_with("CREATE TABLE scratch.events ("),
            "{rewritten}"
        );
    }

    #[test]
    fn ddl_rewriting_handles_backticked_qualifiers() {
        let ddl = "CREATE TABLE `detector`.`events` (x UInt8) ENGINE = MergeTree";
        assert_eq!(
            rewrite_ddl(ddl, "detector", "scratch"),
            "CREATE TABLE `scratch`.`events` (x UInt8) ENGINE = MergeTree"
        );
    }

    #[test]
    fn a_table_and_its_data_are_classified_the_same_way_on_both_sides() {
        // `snapshot` and `fingerprint` must agree on what a table *is*, or a
        // correct restore reports as a divergence. One function decides.
        assert_eq!(
            classify("events"),
            (Derivation::SystemOfRecord, Cut::IngestWatermark)
        );
        assert_eq!(
            classify("incident_analytics"),
            (Derivation::Derived, Cut::StreamedRead)
        );
    }

    #[test]
    fn the_output_and_input_settings_agree_on_a_round_trippable_datetime_form() {
        // `iso` output is prettier and the default input parser rejects it —
        // choosing it would produce artifacts that cannot be restored.
        assert!(OUTPUT_PINS.contains("date_time_output_format = 'simple'"));
        assert!(INPUT_PINS.contains(&("date_time_input_format", "basic")));
    }

    #[test]
    fn insert_settings_never_ride_in_the_statement_after_the_format_name() {
        // The trap this pinning exists to avoid: ClickHouse reads everything
        // after `FORMAT JSONEachRow` as the DATA, so a `SETTINGS …` clause
        // appended there becomes row 1 and the whole restore fails to parse.
        // The settings are query parameters; the statement ends at the format.
        let statement = format!(
            "INSERT INTO {db}.{name} FORMAT {ROW_FORMAT}",
            db = quote_ident("detector"),
            name = quote_ident("events"),
        );
        assert!(statement.ends_with(ROW_FORMAT), "{statement}");
        assert!(!statement.contains("SETTINGS"), "{statement}");
    }

    #[test]
    fn identifiers_are_backtick_escaped() {
        assert_eq!(quote_ident("events"), "`events`");
        assert_eq!(quote_ident("we`ird"), "`we``ird`");
    }
}
