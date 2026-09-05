//! What a backup artifact *claims*, in a form a restore can be checked against.
//!
//! A dump file on a disk asserts nothing. The manifest is what turns it into a
//! testable claim: it names the cut the bytes were taken at, the exact set of
//! tables that were in the source at that instant, a row count and content
//! digest per table, and a SHA-256 per file. A restore is "tested" when the
//! copy that comes back out reproduces all of it — not when `pg_restore` exits
//! zero.
//!
//! ## The digest, and why it is a *sum* rather than an XOR
//!
//! Each table is fingerprinted as `(rows, content)` where `content` is the
//! order-independent combination of a per-row hash. Order independence is not
//! optional: `pg_restore` and a ClickHouse `INSERT` are both free to lay rows
//! down in a different physical order than the source held them, and a
//! read-back without `ORDER BY` is free to return them in yet another. So rows
//! are combined with **wrapping addition**, never XOR — XOR cancels duplicates
//! in pairs, which would make a table holding a row twice hash identically to
//! one holding it zero times. Addition does not, and the row count catches what
//! survives the modulus anyway.
//!
//! The per-row hash itself differs by store (Postgres computes it server-side
//! over the record's text form; ClickHouse's is computed client-side over the
//! `JSONEachRow` line as it streams past). That is fine and deliberate: a
//! fingerprint is only ever compared with another fingerprint of the *same*
//! target, taken by the same code. It is a change-detector, not a portable id.
//!
//! ## What the manifest deliberately does not contain
//!
//! Credentials, and any absolute path outside the artifact directory. A
//! manifest is meant to be copied offsite next to its bytes and read by
//! whoever is holding the incident.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Manifest format version. Bumped only for a change a previous reader could
/// not understand; [`BackupManifest::is_readable`] is the gate that turns an
/// unreadable artifact into a clear error instead of a confusing diff.
pub const MANIFEST_FORMAT: u16 = 1;

/// The file every artifact directory contains.
pub const MANIFEST_FILE: &str = "manifest.json";

/// Which kind of store an artifact came out of. The *name* of the target is a
/// separate, configurable string (there can be more than one Postgres), so
/// this is only the shape of the machinery involved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Postgres,
    ClickHouse,
}

impl std::fmt::Display for TargetKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Postgres => "postgres",
            Self::ClickHouse => "clickhouse",
        })
    }
}

/// Whether losing this table means losing *facts*, or only losing a cache of
/// facts the event store still holds.
///
/// This distinction is the whole reason the DR plan is not "restore
/// everything": §2 says projections are derived, and `crates/rebuild` turned
/// that from a claim into a passing test. So a derived table has two recovery
/// paths — restore it (fast) or re-derive it (authoritative) — while the
/// system of record has exactly one, and its backup is the only thing standing
/// between an incident and permanent data loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Derivation {
    /// Nothing else can reproduce these rows. The event-store log, and every
    /// Postgres table holding a customer's own writes (rules, approvals,
    /// monitored wallets, delivery ledgers).
    SystemOfRecord,
    /// A fold over the log. Restorable *and* rebuildable; if the two disagree,
    /// the rebuild wins by definition.
    Derived,
}

/// How the bytes were made consistent — recorded per table because the three
/// stores earn consistency in three different ways, and an operator reading a
/// manifest during an incident needs to know which guarantee they hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cut {
    /// One exported MVCC snapshot shared by the fingerprint queries and
    /// `pg_dump` (`pg_export_snapshot` / `pg_dump --snapshot`). Every table in
    /// the artifact is as of the same instant, including across foreign keys.
    TransactionSnapshot,
    /// `appended_at < W` on an append-only log, `W` read from the store's own
    /// clock. The same mechanic `crates/rebuild` pins a replay with, and a
    /// consistent cut for the same reason: nothing below `W` can change.
    IngestWatermark,
    /// A single streaming read, fingerprinted as it flew past. Not a snapshot
    /// across tables — but the fingerprint describes *the bytes that were
    /// written*, so "the artifact is internally consistent" still holds, and a
    /// restore of it is still verifiable. Used for ClickHouse's derived
    /// tables, where a torn read across tables is recoverable by rebuild.
    StreamedRead,
}

/// One table's contents, reduced to two numbers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableFingerprint {
    pub rows: u64,
    /// Order-independent combination of the per-row hashes, hex.
    pub content: String,
    pub derivation: Derivation,
    pub cut: Cut,
}

/// One file in the artifact directory, with the checksum that proves the bytes
/// on disk today are the bytes that were written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactFile {
    /// Relative to the artifact directory. Never absolute — an artifact must
    /// survive being copied somewhere else.
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

/// A schema object that must exist before (tables) or after (views) data lands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaObject {
    pub name: String,
    pub kind: SchemaObjectKind,
    pub ddl: String,
}

/// Something the snapshot could not do, typed by **what it costs you**.
///
/// This was a `Vec<String>` and that was wrong. "This materialized view's data
/// is not in the artifact" and "skipped a `Memory`-engine table that holds no
/// durable rows" are not the same fact: the first means the artifact does not
/// contain the whole system, and any drill that passes on it is giving false
/// assurance about a backup with a hole in it. A string in a log cannot be
/// alerted on, cannot fail a drill, and — as written — was a `tracing::warn!`
/// nobody would ever read.
///
/// So the distinction is a type: [`SnapshotNote::is_incompleteness`] drives
/// `BackupManifest::is_complete`, which drives both the drill's verdict and
/// the `backup_artifact_incomplete` gauge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "note", rename_all = "snake_case")]
pub enum SnapshotNote {
    /// **Data that is not in this artifact.** The artifact is incomplete, and
    /// restoring it restores less than the system holds.
    NotCovered { object: String, reason: String },
    /// An object deliberately not copied that holds no durable data of its own
    /// (a view's definition, a `Memory` table). Nothing is lost.
    Skipped { object: String, reason: String },
}

impl SnapshotNote {
    /// Whether this note means the artifact is missing data.
    pub fn is_incompleteness(&self) -> bool {
        matches!(self, Self::NotCovered { .. })
    }

    pub fn object(&self) -> &str {
        match self {
            Self::NotCovered { object, .. } | Self::Skipped { object, .. } => object,
        }
    }
}

impl std::fmt::Display for SnapshotNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotCovered { object, reason } => {
                write!(f, "{object}: NOT COVERED by this artifact — {reason}")
            }
            Self::Skipped { object, reason } => write!(f, "{object}: skipped — {reason}"),
        }
    }
}

/// The ordering constraint is the point of this enum — see
/// [`crate::clickhouse`] for the materialized-view double-write it prevents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaObjectKind {
    Table,
    /// A `MATERIALIZED VIEW` (or plain `VIEW`). Carries no data of its own —
    /// and must be created *after* the data is restored, never before.
    View,
}

/// Everything known about one artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupManifest {
    pub format: u16,
    /// `<target>-<RFC3339 basic, UTC>`, e.g. `postgres-20260904T110213Z`.
    /// Sorts chronologically as a string, which is what makes "the newest
    /// artifact" a directory listing rather than a database.
    pub artifact_id: String,
    pub target: String,
    pub kind: TargetKind,
    /// The database the bytes came out of.
    ///
    /// Recorded explicitly rather than recovered by string-parsing a
    /// `CREATE TABLE <db>.<table>` out of the stored DDL, which is what this
    /// replaced: a restore that rewrites DDL to point at a new database has to
    /// know the old name exactly, and inferring it from SQL text was a parser
    /// that would have been wrong the first time a database name appeared
    /// inside a literal. `#[serde(default)]` only so an artifact written
    /// moments before this field existed still parses; the fallback is
    /// [`BackupManifest::source_database`].
    #[serde(default)]
    pub source_database: String,
    /// The instant the contents are as-of. **This, not `finished_at`, is the
    /// RPO input** — a two-hour dump that started at 01:00 lost everything
    /// after 01:00, not everything after 03:00.
    pub cut_at: DateTime<Utc>,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    /// Fully qualified table name → fingerprint.
    pub tables: BTreeMap<String, TableFingerprint>,
    pub files: Vec<ArtifactFile>,
    /// DDL needed to recreate the objects. Empty for Postgres, whose
    /// `--format=custom` dump carries its own schema.
    #[serde(default)]
    pub schema: Vec<SchemaObject>,
    /// Version of the tool that produced the bytes (`pg_dump 18.0`,
    /// `ClickHouse 25.6`). A restore into an *older* server is the classic
    /// silent DR failure; recording this is what lets the runbook check.
    pub tool: String,
    pub writer_version: String,
    /// Anything skipped or not covered. Typed, so "the artifact is missing
    /// data" is a machine-readable fact rather than prose — see
    /// [`SnapshotNote`] and [`BackupManifest::is_complete`].
    #[serde(default)]
    pub notes: Vec<SnapshotNote>,
}

impl BackupManifest {
    /// Total artifact size.
    pub fn bytes(&self) -> u64 {
        self.files.iter().map(|f| f.bytes).sum()
    }

    pub fn rows(&self) -> u64 {
        self.tables.values().map(|t| t.rows).sum()
    }

    /// Whether this build can interpret the artifact at all.
    pub fn is_readable(&self) -> bool {
        self.format <= MANIFEST_FORMAT
    }

    /// The database these bytes came from, for DDL rewriting on restore.
    /// Falls back to the target name for an artifact written before the field
    /// existed — in this workspace those two have always been equal.
    pub fn source_database(&self) -> &str {
        if self.source_database.is_empty() {
            &self.target
        } else {
            &self.source_database
        }
    }

    /// Whether this artifact contains everything the snapshot found.
    ///
    /// A `false` here is materially different from a failed backup: the
    /// snapshot succeeded, the bytes are intact, and part of the system is
    /// simply not in them. It is the one condition under which a *passing*
    /// drill is still bad news, which is why [`crate::drill`] refuses to call
    /// such a run a pass.
    pub fn is_complete(&self) -> bool {
        !self.notes.iter().any(SnapshotNote::is_incompleteness)
    }

    /// The notes that say data is missing.
    pub fn incompleteness(&self) -> Vec<&SnapshotNote> {
        self.notes
            .iter()
            .filter(|note| note.is_incompleteness())
            .collect()
    }

    /// True when the artifact holds anything nothing else could reproduce.
    /// A `false` here is what lets the runbook say "rebuild instead".
    pub fn holds_system_of_record(&self) -> bool {
        self.tables
            .values()
            .any(|t| t.derivation == Derivation::SystemOfRecord)
    }

    /// Compare what the artifact claimed against what a restore produced.
    pub fn diff(&self, restored: &BTreeMap<String, TableFingerprint>) -> FingerprintDiff {
        let expected: BTreeSet<&String> = self.tables.keys().collect();
        let actual: BTreeSet<&String> = restored.keys().collect();

        let missing = expected
            .difference(&actual)
            .map(|t| (*t).clone())
            .collect::<Vec<_>>();
        let unexpected = actual
            .difference(&expected)
            .map(|t| (*t).clone())
            .collect::<Vec<_>>();

        let mut changed = Vec::new();
        for table in expected.intersection(&actual) {
            let want = &self.tables[*table];
            let got = &restored[*table];
            if want.rows != got.rows || want.content != got.content {
                changed.push(ChangedTable {
                    table: (*table).clone(),
                    expected_rows: want.rows,
                    actual_rows: got.rows,
                    expected_content: want.content.clone(),
                    actual_content: got.content.clone(),
                });
            }
        }

        FingerprintDiff {
            missing,
            unexpected,
            changed,
        }
    }
}

/// A table the artifact promised and the restore did not reproduce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedTable {
    pub table: String,
    pub expected_rows: u64,
    pub actual_rows: u64,
    pub expected_content: String,
    pub actual_content: String,
}

impl ChangedTable {
    /// `rows` alone can match while `content` does not — that is a table with
    /// the right *number* of wrong rows, which is the worse failure and worth
    /// saying out loud.
    pub fn describe(&self) -> String {
        if self.expected_rows == self.actual_rows {
            format!(
                "{}: {} row(s) restored, but the contents differ ({} != {}) \
                 — same count, different data",
                self.table, self.actual_rows, self.expected_content, self.actual_content
            )
        } else {
            format!(
                "{}: {} row(s) expected, {} restored",
                self.table, self.expected_rows, self.actual_rows
            )
        }
    }
}

/// The verdict of a restore, classified so a failure is a diagnosis.
///
/// The classes mirror `rebuild::Divergence`'s deliberately — an operator who
/// has read one runbook should not have to learn a second vocabulary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FingerprintDiff {
    /// In the artifact, absent from the restore. The restore did not finish,
    /// or the dump could not be read.
    pub missing: Vec<String>,
    /// In the restore, absent from the artifact. Almost always the scratch
    /// destination was not empty — which means the drill was measuring
    /// something other than this artifact.
    pub unexpected: Vec<String>,
    /// Restored, but not equal. The dangerous one: the restore "succeeded".
    pub changed: Vec<ChangedTable>,
}

impl FingerprintDiff {
    pub fn is_clean(&self) -> bool {
        self.missing.is_empty() && self.unexpected.is_empty() && self.changed.is_empty()
    }

    /// Rows at stake, for the metric. Uses the larger of the two sides so a
    /// wholly-empty restore of a big table reports the big number.
    pub fn rows_affected(&self) -> u64 {
        self.changed
            .iter()
            .map(|c| c.expected_rows.max(c.actual_rows))
            .sum()
    }

    /// A human summary, capped so a catastrophic diff cannot fill a terminal.
    pub fn summarize(&self, limit: usize) -> String {
        if self.is_clean() {
            return "no divergence: the restored copy matches the manifest exactly".to_owned();
        }
        let mut out = String::new();
        let mut push_list = |label: &str, items: &[String]| {
            if items.is_empty() {
                return;
            }
            out.push_str(&format!("{label} ({}):\n", items.len()));
            for item in items.iter().take(limit) {
                out.push_str(&format!("  - {item}\n"));
            }
            if items.len() > limit {
                out.push_str(&format!("  … and {} more\n", items.len() - limit));
            }
        };
        push_list("missing from the restore", &self.missing);
        push_list(
            "present in the restore but not in the artifact",
            &self.unexpected,
        );
        if !self.changed.is_empty() {
            out.push_str(&format!(
                "restored but not equal ({}):\n",
                self.changed.len()
            ));
            for change in self.changed.iter().take(limit) {
                out.push_str(&format!("  - {}\n", change.describe()));
            }
            if self.changed.len() > limit {
                out.push_str(&format!("  … and {} more\n", self.changed.len() - limit));
            }
        }
        out
    }
}

/// Accumulates per-row hashes into one order-independent digest.
///
/// See the module docs for why this adds rather than XORs.
#[derive(Debug, Default, Clone)]
pub struct ContentAccumulator {
    rows: u64,
    sum: u64,
}

impl ContentAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Absorb one row, given its already-computed 64-bit hash.
    pub fn absorb_hash(&mut self, hash: u64) {
        self.rows += 1;
        self.sum = self.sum.wrapping_add(hash);
    }

    /// Absorb one row given its canonical bytes (the ClickHouse path: the
    /// `JSONEachRow` line exactly as it was written to the artifact).
    pub fn absorb_row(&mut self, canonical: &[u8]) {
        self.absorb_hash(row_hash(canonical));
    }

    pub fn rows(&self) -> u64 {
        self.rows
    }

    pub fn content(&self) -> String {
        format!("{:016x}", self.sum)
    }

    pub fn finish(self, derivation: Derivation, cut: Cut) -> TableFingerprint {
        TableFingerprint {
            rows: self.rows,
            content: self.content(),
            derivation,
            cut,
        }
    }
}

/// SHA-256 of `bytes`, folded to the leading 64 bits.
///
/// Truncated deliberately: the digest is combined by addition, and a 64-bit
/// lane is what keeps the arithmetic (and the Postgres-side equivalent, which
/// has to fit in a `bigint`) identical on both sides of a comparison. This is
/// a corruption detector, not an anti-tamper seal — an adversary with write
/// access to the artifact directory can rewrite a manifest as easily as a dump.
pub fn row_hash(bytes: &[u8]) -> u64 {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut lead = [0_u8; 8];
    lead.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(lead)
}

/// Render the content digest the Postgres server computed. Kept beside
/// [`ContentAccumulator::content`] so the two formats cannot drift apart.
pub fn content_from_sum(sum: u64) -> String {
    format!("{sum:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint(rows: u64, content: &str) -> TableFingerprint {
        TableFingerprint {
            rows,
            content: content.to_owned(),
            derivation: Derivation::Derived,
            cut: Cut::StreamedRead,
        }
    }

    fn manifest(tables: &[(&str, TableFingerprint)]) -> BackupManifest {
        BackupManifest {
            format: MANIFEST_FORMAT,
            artifact_id: "postgres-20260904T110213Z".to_owned(),
            target: "postgres".to_owned(),
            kind: TargetKind::Postgres,
            source_database: "detector".to_owned(),
            cut_at: Utc::now(),
            started_at: Utc::now(),
            finished_at: Utc::now(),
            tables: tables
                .iter()
                .map(|(n, f)| ((*n).to_owned(), f.clone()))
                .collect(),
            files: Vec::new(),
            schema: Vec::new(),
            tool: "test".to_owned(),
            writer_version: "test".to_owned(),
            notes: Vec::new(),
        }
    }

    #[test]
    fn a_duplicated_row_changes_the_digest() {
        // The reason the accumulator adds instead of XORing: under XOR these
        // two tables would fingerprint identically, and a restore that dropped
        // a duplicate pair would pass.
        let mut once = ContentAccumulator::new();
        once.absorb_row(b"a");
        once.absorb_row(b"b");

        let mut twice = ContentAccumulator::new();
        twice.absorb_row(b"a");
        twice.absorb_row(b"b");
        twice.absorb_row(b"a");
        twice.absorb_row(b"a");

        assert_ne!(once.content(), twice.content());
    }

    #[test]
    fn the_digest_ignores_row_order() {
        // pg_restore and a ClickHouse INSERT both reorder rows; a fingerprint
        // that noticed would fail every drill.
        let mut forward = ContentAccumulator::new();
        let mut backward = ContentAccumulator::new();
        for row in [b"one".as_slice(), b"two", b"three"] {
            forward.absorb_row(row);
        }
        for row in [b"three".as_slice(), b"two", b"one"] {
            backward.absorb_row(row);
        }
        assert_eq!(forward.content(), backward.content());
        assert_eq!(forward.rows(), backward.rows());
    }

    #[test]
    fn diff_separates_missing_unexpected_and_changed() {
        let manifest = manifest(&[
            ("public.rules", fingerprint(10, "aaaa")),
            ("public.labels", fingerprint(5, "bbbb")),
            ("public.gone", fingerprint(1, "cccc")),
        ]);
        let restored = BTreeMap::from([
            ("public.rules".to_owned(), fingerprint(10, "aaaa")),
            ("public.labels".to_owned(), fingerprint(5, "dddd")),
            ("public.surprise".to_owned(), fingerprint(2, "eeee")),
        ]);

        let diff = manifest.diff(&restored);
        assert!(!diff.is_clean());
        assert_eq!(diff.missing, vec!["public.gone".to_owned()]);
        assert_eq!(diff.unexpected, vec!["public.surprise".to_owned()]);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].table, "public.labels");
        // Same count, different bytes — the summary must say so, because that
        // is the failure a row-count-only check would have passed.
        assert!(diff.changed[0].describe().contains("same count"));
    }

    #[test]
    fn an_exact_restore_is_clean() {
        let manifest = manifest(&[("public.rules", fingerprint(10, "aaaa"))]);
        let restored = BTreeMap::from([("public.rules".to_owned(), fingerprint(10, "aaaa"))]);
        assert!(manifest.diff(&restored).is_clean());
    }

    #[test]
    fn a_manifest_round_trips_through_json() {
        let manifest = manifest(&[("public.rules", fingerprint(10, "aaaa"))]);
        let encoded = serde_json::to_vec(&manifest).expect("encode");
        let decoded: BackupManifest = serde_json::from_slice(&encoded).expect("decode");
        assert_eq!(manifest, decoded);
        assert!(decoded.is_readable());
    }

    #[test]
    fn a_note_that_means_missing_data_makes_the_artifact_incomplete() {
        // The distinction a `Vec<String>` could not carry: one of these costs
        // you data, the other costs you nothing.
        let mut m = manifest(&[("public.rules", fingerprint(10, "aaaa"))]);
        assert!(m.is_complete());

        m.notes.push(SnapshotNote::Skipped {
            object: "usage_rollup_daily_mv".to_owned(),
            reason: "a view holds no durable rows of its own".to_owned(),
        });
        assert!(m.is_complete(), "skipping a view loses nothing");

        m.notes.push(SnapshotNote::NotCovered {
            object: ".inner_id.8f2c".to_owned(),
            reason: "its name embeds a UUID that cannot be recreated elsewhere".to_owned(),
        });
        assert!(!m.is_complete());
        assert_eq!(m.incompleteness().len(), 1);
        assert!(m.incompleteness()[0].to_string().contains("NOT COVERED"));
    }

    #[test]
    fn the_source_database_falls_back_rather_than_being_parsed_out_of_ddl() {
        let mut m = manifest(&[("public.rules", fingerprint(1, "aa"))]);
        assert_eq!(m.source_database(), "detector");
        m.source_database = String::new();
        assert_eq!(m.source_database(), "postgres");
    }

    #[test]
    fn a_future_manifest_format_is_refused_rather_than_misread() {
        let mut manifest = manifest(&[("public.rules", fingerprint(10, "aaaa"))]);
        manifest.format = MANIFEST_FORMAT + 1;
        assert!(!manifest.is_readable());
    }
}
