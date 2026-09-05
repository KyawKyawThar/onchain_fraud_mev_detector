//! The seams every backed-up store implements, and the types that make the
//! destructive operation hard to call by accident.
//!
//! ## Two traits, not one
//!
//! [`StoreReader`] can only *look*: name the store and fingerprint a database.
//! [`BackupTarget`] extends it with everything that writes — snapshot, restore,
//! provision and drop. The split is the same one `crates/rebuild` makes
//! (`Snapshotter` vs `Stageable`) and for the same reason: `backup fingerprint`
//! takes a `&dyn StoreReader`, so it **cannot** restore or drop anything, and
//! that is a property of the type rather than of the author's care. Conventions
//! §2's narrowest-trait corollary.
//!
//! ## Why a scratch database is its own type
//!
//! `drop_scratch` destroys a database. The previous shape took a
//! `Destination { database: String, scratch: bool }` and checked the flag at
//! runtime — boolean blindness guarding the single most dangerous call in the
//! crate, where a `true` in the wrong constructor is a dropped production
//! database.
//!
//! Now:
//!
//! * [`Database`] is *parsed*, not validated — constructing one checks it is a
//!   bare identifier, so every interpolation site downstream is safe by
//!   construction rather than by remembering to call a checker (§4);
//! * [`Scratch`] can only be produced by [`BackupTarget::provision_scratch`],
//!   so a live database cannot be passed to `drop_scratch` — there is no way to
//!   *spell* it;
//! * `drop_scratch` takes it **by value**, so it cannot be dropped twice;
//! * [`Scratch`] is `#[must_use]` and logs loudly on `Drop` if it was never
//!   released, which turns a leaked copy of production into a line in the log
//!   instead of a disk that fills up in three weeks.
//!
//! ## Cleanup happens on the next run, not on the way out
//!
//! The `Drop` warning above is a *diagnostic*, not the cleanup mechanism, and
//! it is important not to confuse the two. Rust has no async `Drop`, and a
//! `SIGKILL` runs no destructor at all — so any design where correctness
//! depends on unwinding is a design that leaks the first time a pod is evicted.
//! [`BackupTarget::sweep_scratch`] is the actual guarantee: at boot, and on
//! every drill, stale `…_drill_…` databases are removed. That is why the name
//! carries its own creation timestamp ([`scratch_name`]) — neither Postgres nor
//! ClickHouse records a per-database creation time an unprivileged role can
//! read, so the name *is* the clock, and [`scratch_age`] is what reads it.

use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, Utc};
use tokio_util::sync::CancellationToken;

use crate::error::{BackupError, Result};
use crate::manifest::{BackupManifest, SchemaObject, SnapshotNote, TableFingerprint};

/// The marker every scratch database's name carries, so a sweep can recognise
/// one without a registry that could itself be lost.
pub const SCRATCH_INFIX: &str = "_drill_";
/// `%Y%m%d%H%M%S` — the width of the timestamp embedded after [`SCRATCH_INFIX`].
const STAMP_LEN: usize = 14;
const STAMP_FORMAT: &str = "%Y%m%d%H%M%S";

/// A database name that has been checked to be a bare identifier.
///
/// Parsed once, at the edge; every SQL interpolation downstream takes one of
/// these and therefore needs no check of its own.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Database(String);

impl Database {
    /// Reject anything that is not a bare identifier.
    ///
    /// Every name this crate builds is generated rather than typed by a user —
    /// but "generated" is a property of today's call sites, and `--into` on the
    /// CLI is not.
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        if name.is_empty()
            || name.len() > 63
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(BackupError::permanent_msg(format!(
                "{name:?} is not a bare database identifier"
            )));
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Database {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A throwaway database, owned.
///
/// Only [`BackupTarget::provision_scratch`] produces one; [`BackupTarget::drop_scratch`]
/// consumes one. Anything else is a leak, and says so.
#[derive(Debug)]
#[must_use = "a provisioned scratch database must be dropped (or explicitly kept)"]
pub struct Scratch {
    database: Database,
    released: bool,
}

impl Scratch {
    /// Only the store implementations, immediately after `CREATE DATABASE`.
    pub(crate) fn new(database: Database) -> Self {
        Self {
            database,
            released: false,
        }
    }

    pub fn database(&self) -> &Database {
        &self.database
    }

    /// Mark it accounted for. Called by `drop_scratch` **after** the database
    /// is actually gone — before, and a failed drop would look tidy.
    pub(crate) fn release(&mut self) {
        self.released = true;
    }

    /// Deliberately leave the database in place (the `--keep` path). Returns
    /// the name so an operator can be told what to clean up.
    pub fn keep(mut self) -> Database {
        self.released = true;
        self.database.clone()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if !self.released {
            // Not the cleanup — the sweep is. This exists so a leak is visible
            // in the log of the run that caused it, rather than only as a
            // mystery database found weeks later.
            tracing::error!(
                database = %self.database,
                "leaked a scratch database — `backup drill` will sweep it on its next run"
            );
        }
    }
}

/// What one [`BackupTarget::snapshot`] produced, before it becomes a manifest.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// The instant the contents are as-of.
    pub cut_at: DateTime<Utc>,
    pub tables: std::collections::BTreeMap<String, TableFingerprint>,
    /// Files written into the artifact directory, relative paths.
    pub files: Vec<String>,
    /// DDL to recreate the objects (ClickHouse). Empty where the dump format
    /// carries its own schema (Postgres).
    pub schema: Vec<SchemaObject>,
    /// Server/tool version, recorded so a restore into an older server is a
    /// caught mismatch rather than a mystery.
    pub tool: String,
    /// Anything degraded or skipped — typed, because "this table's data is not
    /// in the artifact" and "skipped an object that holds no data" are not the
    /// same fact. See [`SnapshotNote`].
    pub notes: Vec<SnapshotNote>,
}

/// The read-only half. A holder of one of these cannot write anything.
#[async_trait]
pub trait StoreReader: Send + Sync {
    /// Stable name; the artifact directory and every metric label use it.
    fn name(&self) -> &str;

    fn kind(&self) -> crate::manifest::TargetKind;

    /// The production database this target backs up.
    fn live(&self) -> Database;

    /// Fingerprint whatever is in `database` right now, using the same
    /// encoding [`BackupTarget::snapshot`] used, so the two are comparable.
    async fn fingerprint(
        &self,
        database: &Database,
    ) -> Result<std::collections::BTreeMap<String, TableFingerprint>>;
}

#[async_trait]
pub trait BackupTarget: StoreReader {
    /// Take a consistent snapshot into `dir`, fingerprinting as it goes.
    ///
    /// Takes a [`CancellationToken`] like every other long-running loop in the
    /// workspace: a snapshot of a production database runs for minutes to
    /// hours, and a shutdown that cannot interrupt it is a pod that gets
    /// `SIGKILL`ed at the end of its grace period — mid-`pg_dump`, with a
    /// child process still running.
    async fn snapshot(&self, dir: &Path, cancel: &CancellationToken) -> Result<Snapshot>;

    /// Create an empty throwaway database.
    async fn provision_scratch(&self) -> Result<Scratch>;

    /// Drop it. Consumes the handle.
    async fn drop_scratch(&self, scratch: Scratch) -> Result<()>;

    /// Remove scratch databases older than `older_than` — the actual leak
    /// guarantee. Returns what it removed.
    async fn sweep_scratch(&self, older_than: Duration) -> Result<Vec<String>>;

    /// Load an artifact into `into`.
    async fn restore(
        &self,
        dir: &Path,
        manifest: &BackupManifest,
        into: &Database,
        cancel: &CancellationToken,
    ) -> Result<()>;
}

/// Name for a throwaway database.
///
/// The embedded timestamp is **load-bearing, not decorative**: it is how
/// [`sweep_scratch`](BackupTarget::sweep_scratch) knows a database's age
/// without a registry (which could be lost with the process that wrote it) and
/// without a privileged catalog read. Changing this format breaks the sweep,
/// which is why it has a test of its own.
pub fn scratch_name(prefix: &Database) -> Result<Scratch> {
    let name = format!(
        "{prefix}{SCRATCH_INFIX}{}_{}",
        Utc::now().format(STAMP_FORMAT),
        std::process::id()
    );
    Ok(Scratch::new(Database::new(name)?))
}

/// How long ago the scratch database called `name` was created, read out of
/// the name itself. `None` for anything that is not a scratch name — a sweep
/// must never delete a database it cannot positively identify.
pub fn scratch_age(name: &str, now: DateTime<Utc>) -> Option<Duration> {
    let stamp = name.split_once(SCRATCH_INFIX)?.1.get(..STAMP_LEN)?;
    let created = NaiveDateTime::parse_from_str(stamp, STAMP_FORMAT)
        .ok()?
        .and_utc();
    (now - created).to_std().ok()
}

/// Whether a sweep should remove `name`, given the age cutoff.
pub fn is_sweepable(name: &str, now: DateTime<Utc>, older_than: Duration) -> bool {
    scratch_age(name, now).is_some_and(|age| age > older_than)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 5, 12, 0, 0)
            .single()
            .expect("valid")
    }

    #[test]
    fn identifiers_reject_injection_shaped_names() {
        assert!(Database::new("detector_drill_20260904").is_ok());
        assert!(Database::new("").is_err());
        assert!(Database::new("a\"; DROP DATABASE detector; --").is_err());
        assert!(Database::new("x".repeat(64)).is_err());
    }

    #[test]
    fn a_scratch_name_carries_its_own_creation_clock() {
        // Neither Postgres nor ClickHouse exposes a per-database creation time
        // to an unprivileged role, so the sweep reads the name. This test is
        // what stops a "tidier" name format from silently disabling cleanup.
        let scratch = scratch_name(&Database::new("mev").expect("db")).expect("name");
        let name = scratch.keep();
        assert!(name.as_str().contains(SCRATCH_INFIX), "{name}");
        assert!(
            scratch_age(name.as_str(), Utc::now()).is_some(),
            "the sweep cannot read an age out of {name}"
        );
    }

    #[test]
    fn the_sweep_only_touches_databases_it_can_positively_identify() {
        let day = Duration::from_secs(86_400);
        // A stale drill leftover: removed.
        assert!(is_sweepable("mev_drill_20260901120000_42", now(), day));
        // A fresh one from a run still in flight: left alone.
        assert!(!is_sweepable("mev_drill_20260905115900_42", now(), day));
        // Production, and anything else that is not unambiguously a scratch
        // name — never, at any age.
        assert!(!is_sweepable("mev", now(), day));
        assert!(!is_sweepable("mev_drill_notatimestamp", now(), day));
        assert!(!is_sweepable("customer_drilling_data", now(), day));
        assert_eq!(scratch_age("mev", now()), None);
    }

    #[test]
    fn keeping_a_scratch_database_accounts_for_it() {
        // `keep` is the --keep path: the database survives on purpose, so it
        // must not also be reported as a leak.
        let scratch = Scratch::new(Database::new("mev_drill_1").expect("db"));
        let name = scratch.keep();
        assert_eq!(name.as_str(), "mev_drill_1");
    }

    #[test]
    fn releasing_marks_a_scratch_database_accounted_for() {
        let mut scratch = Scratch::new(Database::new("mev_drill_2").expect("db"));
        assert_eq!(scratch.database().as_str(), "mev_drill_2");
        scratch.release();
        assert!(scratch.released);
    }
}
