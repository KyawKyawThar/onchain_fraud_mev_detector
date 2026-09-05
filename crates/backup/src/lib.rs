//! **Backups with a tested restore** for the three stateful stores, and the
//! RPO/RTO those tests *measure* (readiness Epic B).
//!
//! > An untested backup is a belief, not a control.
//!
//! That sentence is the whole design brief, and it rules out the obvious
//! implementation. A cron job that runs `pg_dump` and a runbook page that says
//! "restore from the latest dump" is a belief with infrastructure attached:
//! nothing in it ever reads the dump back, so its first real execution is
//! during the incident, by whoever is on call, against a file nobody has
//! opened. The failure modes are not exotic — a dump of a database that was
//! being written to, a dump missing the table someone added in March, a
//! restore into a server whose client version cannot read the format, an
//! artifact whose bytes rotted six weeks ago — and they share one property:
//! **every one of them passes a check that the backup job exited zero.**
//!
//! So the control here is the *restore*:
//!
//! ```text
//!   snapshot ──────────────────────────────► artifact + manifest
//!   (fingerprint taken INSIDE the same cut)         │
//!                                                   ▼
//!   drill ──► throwaway database ──► restore ──► re-fingerprint ──► diff
//!                                                   │
//!                                                   ├─ pass: RTO measured, RPO armed
//!                                                   └─ fail: named, classified, alerted
//! ```
//!
//! ## The five decisions worth knowing
//!
//! **1. The fingerprint is taken inside the dump's own cut.** For Postgres
//! that is `pg_export_snapshot()` handed to `pg_dump --snapshot=…`, so the
//! manifest describes the bytes rather than the database at some nearby
//! instant. For the event store it is an `appended_at < W` watermark, the same
//! cut `crates/rebuild` replays against. For ClickHouse's derived tables the
//! fingerprint is computed from the streaming rows as they are written. In no
//! case are "dump" and "measure" two separate reads of a moving database —
//! that mistake makes a drill flaky, and a flaky drill gets turned off.
//!
//! **2. The drill is non-destructive, so it can run on a timer.** It restores
//! into a throwaway database created for the run. Nothing is stopped, no
//! window is needed. Backups go untested because testing them hurts; the fix
//! is to remove the hurt, not to schedule the pain quarterly. (Same move as
//! `crates/rebuild`'s staging namespace, for the same reason.)
//!
//! **3. Tables are discovered, never listed.** Both targets enumerate what is
//! actually there at snapshot time. A hand-maintained table list is a backup
//! that silently stops covering the next table anyone adds, and looks green
//! the whole time.
//!
//! **4. Backing up derived state is a convenience; the log is the guarantee.**
//! §2 says projections are derived and `crates/rebuild` made that a passing
//! test, so this crate marks each table [`Derivation::SystemOfRecord`] or
//! [`Derivation::Derived`] in the manifest. Derived tables are still backed up
//! — restoring is much faster than re-deriving — but if a restore and a
//! rebuild ever disagree, the rebuild wins. The tables that have no second
//! path (the event log; rules, approvals, labels, ledgers in Postgres) are the
//! ones the RPO is really about.
//!
//! **5. RPO and RTO are measurements, not declarations.** RPO is the age of
//! the newest artifact *that a recent drill has shown to be restorable* — a
//! stale drill breaches on its own, even while snapshots land on schedule.
//! RTO is the drill's own wall clock against today's data volume, plus a
//! separately-reported, human-declared orchestration overhead. See
//! [`objective`], which is where the definitions live.
//!
//! ## The shapes worth copying
//!
//! Four patterns here are not specific to backups, and are the ones to reuse:
//!
//! * **Typed failures that carry the decision** ([`error`]). Every failure
//!   answers "will retrying without a human plausibly work?", so a store blip
//!   and an unusable client version stop rendering identically. Ambiguity
//!   resolves to `Permanent`: a spurious page is cheaper than a silent gap.
//! * **Illegal states that do not compile** ([`target`]). A [`Scratch`]
//!   database is only constructible by `provision_scratch` and is consumed by
//!   `drop_scratch`, so "never drop production" is not a runtime `ensure!` on
//!   a boolean — it is unspellable, and dropping one twice is too.
//! * **Cleanup on the next run, not on the way out** ([`target::scratch_name`],
//!   `BackupTarget::sweep_scratch`). Async `Drop` does not exist and `SIGKILL`
//!   runs no destructor, so anything that leaks a resource must be swept by a
//!   later run — which is why the scratch database carries its creation time
//!   in its own name.
//! * **Schedules driven by observed state, not by a timer** (`main::serve`).
//!   "Is the newest artifact older than the cadence?" is idempotent: restarts
//!   cannot lose or duplicate a cycle, and no burst of missed ticks is ever
//!   replayed.
//!
//! ## What this is not
//!
//! Not high availability (that is Epic A: replication and failover), not
//! multi-region DR, and not a correctness check on the *contents* — a clean
//! drill on a backup of corrupted data is a clean drill. Restoring wrong data
//! faithfully is this crate's job; noticing it was wrong is the projection
//! rebuild's.
//!
//! ## Usage
//!
//! ```no_run
//! # async fn example() -> backup::Result<()> {
//! use backup::{artifact::ArtifactStore, config::Config, drill, snapshot};
//!
//! let config = Config::from_env()?;
//! let store = ArtifactStore::new(&config.root);
//! let cancel = tokio_util::sync::CancellationToken::new();
//! for target in config.targets()? {
//!     snapshot(target.as_ref(), &store, &cancel).await?;
//!     let report = drill::run_latest(target.as_ref(), &store, false, &cancel).await?;
//!     println!("{}", report.summarize(20));
//! }
//! # Ok(())
//! # }
//! ```

pub mod artifact;
pub mod clickhouse;
pub mod config;
pub mod drill;
pub mod error;
pub mod manifest;
pub mod objective;
pub mod observed;
pub mod postgres;
pub mod target;

use std::collections::BTreeMap;
use std::time::Instant;

use chrono::Utc;
use tokio_util::sync::CancellationToken;

pub use drill::DrillReport;
pub use error::{BackupError, Result};
pub use manifest::{
    BackupManifest, Cut, Derivation, FingerprintDiff, SnapshotNote, TableFingerprint,
};
pub use objective::{Measurement, RecoveryObjective, Report};
pub use target::{BackupTarget, Database, Scratch, StoreReader};

use crate::artifact::{describe_file, ArtifactStore, DrillRecord};

/// Take one snapshot of `target` into `store` and commit its manifest.
///
/// The manifest is written **last**, after every data file is on disk and
/// checksummed. That ordering is the crash contract: a directory without a
/// manifest is an interrupted snapshot, and the store skips it rather than
/// offering half a backup as the newest one.
pub async fn snapshot(
    target: &dyn BackupTarget,
    store: &ArtifactStore,
    cancel: &CancellationToken,
) -> Result<BackupManifest> {
    let started = Instant::now();
    let started_at = Utc::now();

    // The artifact id is named for when the snapshot *started*; `cut_at` in
    // the manifest is the instant the contents are as-of, and is what every
    // RPO figure reads. The two are within seconds of each other and are kept
    // separate rather than reconciled by renaming the directory mid-write —
    // the id is a name, the cut is the datum.
    let (_provisional_id, dir) = store.stage(target.name(), started_at).await?;

    let snapshot = match target.snapshot(&dir, cancel).await {
        Ok(snapshot) => snapshot,
        Err(err) => {
            let err = err.context(format!("snapshotting {}", target.name()));
            observed::record_snapshot_failure(target.name(), &err);
            // Leave nothing that could be mistaken for a backup.
            let _ = tokio::fs::remove_dir_all(&dir).await;
            return Err(err);
        }
    };

    let mut files = Vec::with_capacity(snapshot.files.len());
    for relative in &snapshot.files {
        files.push(describe_file(&dir, relative).await?);
    }

    let manifest = BackupManifest {
        format: manifest::MANIFEST_FORMAT,
        artifact_id: dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown")
            .to_owned(),
        target: target.name().to_owned(),
        kind: target.kind(),
        source_database: target.live().to_string(),
        cut_at: snapshot.cut_at,
        started_at,
        finished_at: Utc::now(),
        tables: snapshot.tables,
        files,
        schema: snapshot.schema,
        tool: snapshot.tool,
        writer_version: format!("backup {}", env!("CARGO_PKG_VERSION")),
        notes: snapshot.notes,
    };

    store.commit(&dir, &manifest).await?;
    observed::record_snapshot(target.name(), &manifest, started.elapsed());
    tracing::info!(
        target = target.name(),
        artifact = %manifest.artifact_id,
        tables = manifest.tables.len(),
        rows = manifest.rows(),
        bytes = manifest.bytes(),
        elapsed_s = started.elapsed().as_secs_f64(),
        "snapshot complete"
    );
    for note in &manifest.notes {
        if note.is_incompleteness() {
            tracing::error!(
                target = target.name(),
                note = %note,
                "this artifact does not cover part of the store"
            );
        } else {
            tracing::info!(target = target.name(), note = %note, "snapshot note");
        }
    }
    Ok(manifest)
}

/// What is in `database` right now.
///
/// Takes the **read-only** [`StoreReader`] rather than a whole
/// [`BackupTarget`], which is the point of the trait split: this function
/// cannot restore anything, drop anything, or write an artifact, and that is a
/// property of its signature rather than of its author. Point it at production
/// before and after a risky migration.
pub async fn fingerprint(
    reader: &dyn StoreReader,
    database: &Database,
) -> Result<BTreeMap<String, TableFingerprint>> {
    reader.fingerprint(database).await
}

/// Read the store and answer: where do we actually stand against the
/// objectives?
///
/// Pure over the artifact store — it runs nothing and touches no database, so
/// it is safe to call from a health endpoint, a CI gate, or a terminal during
/// an incident.
pub async fn measure(
    targets: &[String],
    store: &ArtifactStore,
    objective: RecoveryObjective,
) -> Result<Report> {
    let now = Utc::now();
    let mut measurements = Vec::with_capacity(targets.len());

    for target in targets {
        let newest = store.newest(target).await?;
        let drill = DrillRecord::newest_passing(store, target).await?;

        // A drill only vouches for artifacts up to the one it restored. It is
        // the *drill's* age that is measured, not the artifact's, precisely so
        // that a passing drill from a month ago cannot make today's untested
        // backup look verified.
        let verification_age = drill
            .as_ref()
            .and_then(|record| (now - record.finished_at).to_std().ok());

        measurements.push(Measurement {
            target: target.clone(),
            rpo: newest.as_ref().map(|artifact| artifact.age(now)),
            verification_age,
            measured_restore: drill
                .as_ref()
                .map(|record| std::time::Duration::from_secs_f64(record.restore_seconds)),
            artifact_bytes: newest.as_ref().map(|a| a.manifest.bytes()).unwrap_or(0),
            artifact_rows: newest.as_ref().map(|a| a.manifest.rows()).unwrap_or(0),
            holds_system_of_record: newest
                .as_ref()
                .map(|a| a.manifest.holds_system_of_record())
                // Unknown means "assume it matters": a target with no backup
                // at all must not be reported as merely a cache.
                .unwrap_or(true),
        });
    }

    Ok(Report {
        objective,
        measurements,
    })
}
