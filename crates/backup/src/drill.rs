//! The restore drill: the control that makes the backup a control.
//!
//! Everything else in this crate produces evidence. This is the part that
//! consumes it, and the only part whose passing means anything:
//!
//! ```text
//!   newest artifact ──► checksums ──► scratch database ──► restore ──► fingerprint
//!                                                                          │
//!                          manifest.tables ─────────── diff ───────────────┘
//!                                                        │
//!                                       pass: record RTO, arm the RPO clock
//!                                       fail: record the diagnosis, breach
//! ```
//!
//! ## Three properties, and why each one is load-bearing
//!
//! **It restores the real, newest artifact.** Not a fixture, not a small
//! sample. The measured RTO is therefore a measurement of *today's* data
//! volume, which is the only version of that number that is worth anything —
//! restore time grows with the data and an RTO measured once at launch is a
//! number that quietly stops being true.
//!
//! **It is non-destructive.** The restore lands in a throwaway database that
//! is created for the run and dropped after it. Nothing production holds is
//! read-modified, no service is stopped, no maintenance window is needed —
//! which is what lets the drill run *on a timer* instead of appearing on a
//! quarterly checklist. Backups go untested because testing them is
//! disruptive; removing the disruption is the actual fix.
//!
//! **A pass is a fingerprint match, not an exit code.** `pg_restore` exiting
//! zero says the file parsed. The diff against the manifest says the rows came
//! back, all of them, unchanged. See [`crate::manifest::FingerprintDiff`] for
//! what each failure class means.
//!
//! ## What the drill does not prove
//!
//! Worth stating plainly, because a control that is trusted past its evidence
//! is worse than none:
//!
//! * It restores to the **same server**. It does not prove you can obtain a
//!   new server, or that the offsite copy is complete — verify the offsite
//!   copy with `backup verify` run *there*.
//! * It measures the restore, not the cutover. The declared orchestration
//!   overhead in [`crate::objective`] is where that lives, labelled as an
//!   estimate.
//! * A clean drill on a backup of already-corrupted data is a clean drill.
//!   Correctness of the *contents* is the projection rebuild's job
//!   (`docs/runbooks/projection-rebuild.md`), which is a different control.

use std::time::{Duration, Instant};

use chrono::Utc;
use tokio_util::sync::CancellationToken;

use crate::artifact::{verify_artifact, ArtifactStore, DrillRecord, StoredArtifact};
use crate::error::{BackupError, Result};
use crate::manifest::{FingerprintDiff, SnapshotNote};
use crate::target::BackupTarget;

/// How stale a scratch database must be before a sweep removes it.
///
/// Comfortably longer than any drill, so a run in flight is never swept out
/// from under itself, and short enough that a leak is cleaned up the same day.
pub const SCRATCH_MAX_AGE: Duration = Duration::from_secs(6 * 60 * 60);

/// What one drill established.
#[derive(Debug, Clone)]
pub struct DrillReport {
    pub target: String,
    pub artifact_id: String,
    pub artifact_cut_at: chrono::DateTime<Utc>,
    pub artifact_bytes: u64,
    pub artifact_rows: u64,
    /// Wall clock of integrity + provision + restore + verify. The RTO input.
    pub elapsed: Duration,
    /// Split out because they answer different questions when the number is
    /// too big: a slow restore needs more IO, a slow verify needs a cheaper
    /// fingerprint.
    pub restore_elapsed: Duration,
    pub verify_elapsed: Duration,
    /// Integrity problems found before the restore was attempted. Non-empty
    /// means the drill did not run — the artifact is already unusable.
    pub integrity_problems: Vec<String>,
    /// Data the artifact never held. A restore cannot bring back what was
    /// never copied, so this fails the drill on its own — see [`DrillReport::passed`].
    pub incompleteness: Vec<SnapshotNote>,
    pub diff: FingerprintDiff,
    /// Scratch databases removed on the way in.
    pub swept: Vec<String>,
    /// Set when the scratch destination was deliberately left in place.
    pub scratch_kept: Option<String>,
}

impl DrillReport {
    /// Three independent conditions, all required.
    ///
    /// The third is the one worth stating: an artifact that was *known at
    /// snapshot time* not to cover part of the system can restore perfectly
    /// and still not be a backup of that system. Letting such a run report
    /// `PASSED` would be the control giving false assurance about a hole it
    /// already knew about, which is worse than not running it.
    pub fn passed(&self) -> bool {
        self.integrity_problems.is_empty() && self.incompleteness.is_empty() && self.diff.is_clean()
    }

    /// Every reason this drill failed, as lines fit for a ticket.
    pub fn failures(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .integrity_problems
            .iter()
            .map(|p| format!("artifact integrity: {p}"))
            .collect();
        out.extend(self.incompleteness.iter().map(SnapshotNote::to_string));
        out.extend(
            self.diff
                .missing
                .iter()
                .map(|t| format!("missing from the restore: {t}")),
        );
        out.extend(
            self.diff
                .unexpected
                .iter()
                .map(|t| format!("present in the restore but not the artifact: {t}")),
        );
        out.extend(self.diff.changed.iter().map(|c| c.describe()));
        out
    }

    pub fn summarize(&self, limit: usize) -> String {
        let verdict = if self.passed() { "PASSED" } else { "FAILED" };
        let mut out = format!(
            "drill {} on {} ({}): {} table(s), {} row(s), {} bytes restored and verified in {:.1}s \
             (restore {:.1}s, verify {:.1}s) — {}\n",
            verdict,
            self.target,
            self.artifact_id,
            self.diff.missing.len() + self.diff.changed.len(),
            self.artifact_rows,
            self.artifact_bytes,
            self.elapsed.as_secs_f64(),
            self.restore_elapsed.as_secs_f64(),
            self.verify_elapsed.as_secs_f64(),
            crate::objective::humanize(self.elapsed),
        );
        for note in &self.incompleteness {
            out.push_str(&format!("INCOMPLETE ARTIFACT: {note}\n"));
        }
        if !self.swept.is_empty() {
            out.push_str(&format!(
                "swept {} stale scratch database(s): {}\n",
                self.swept.len(),
                self.swept.join(", ")
            ));
        }
        out.push_str(&self.diff.summarize(limit));
        out
    }

    /// The persisted evidence `backup report` reads.
    pub fn record(&self) -> DrillRecord {
        DrillRecord {
            target: self.target.clone(),
            artifact_id: self.artifact_id.clone(),
            finished_at: Utc::now(),
            restore_seconds: self.elapsed.as_secs_f64(),
            artifact_cut_at: self.artifact_cut_at,
            artifact_bytes: self.artifact_bytes,
            artifact_rows: self.artifact_rows,
            passed: self.passed(),
            failures: self.failures(),
        }
    }
}

/// Restore `artifact` into a throwaway database and prove it came back whole.
///
/// `keep_scratch` leaves the restored copy in place for an operator to poke at
/// — the reason a failing drill is debuggable at all. It is off by default
/// because a drill that leaves a full second copy of production behind on
/// every run fills a disk, which is its own outage.
pub async fn run(
    target: &dyn BackupTarget,
    artifact: &StoredArtifact,
    keep_scratch: bool,
    cancel: &CancellationToken,
) -> Result<DrillReport> {
    let started = Instant::now();
    let manifest = &artifact.manifest;

    let mut report = DrillReport {
        target: target.name().to_owned(),
        artifact_id: manifest.artifact_id.clone(),
        artifact_cut_at: manifest.cut_at,
        artifact_bytes: manifest.bytes(),
        artifact_rows: manifest.rows(),
        elapsed: Duration::ZERO,
        restore_elapsed: Duration::ZERO,
        verify_elapsed: Duration::ZERO,
        integrity_problems: Vec::new(),
        incompleteness: manifest.incompleteness().into_iter().cloned().collect(),
        diff: FingerprintDiff::default(),
        swept: Vec::new(),
        scratch_kept: None,
    };

    // 0. Clean up after previous runs *first*. This — not any `Drop` impl — is
    //    the leak guarantee: async destructors do not exist and a SIGKILL runs
    //    no destructor at all, so cleanup has to happen on the next run rather
    //    than on the way out of the last one.
    match target.sweep_scratch(SCRATCH_MAX_AGE).await {
        Ok(swept) => {
            if !swept.is_empty() {
                tracing::warn!(
                    target = target.name(),
                    swept = ?swept,
                    "removed stale scratch databases left by an earlier run"
                );
            }
            report.swept = swept;
        }
        // A sweep that fails must not stop the drill: the drill is the control,
        // the sweep is housekeeping.
        Err(err) => tracing::error!(
            target = target.name(),
            error = %err,
            "could not sweep stale scratch databases"
        ),
    }

    // 1. Are the bytes the bytes? Cheap, and it distinguishes "the backup is
    //    damaged" from "the restore is broken" before the expensive part.
    report.integrity_problems = verify_artifact(artifact).await?;
    if !report.integrity_problems.is_empty() {
        report.elapsed = started.elapsed();
        return Ok(report);
    }

    // 2. Somewhere disposable to put it.
    let scratch = target.provision_scratch().await?;
    let database = scratch.database().clone();
    tracing::info!(
        target = target.name(),
        artifact = %manifest.artifact_id,
        scratch = %database,
        "restoring into a throwaway destination"
    );

    // From here the scratch database exists, so every exit has to account for
    // it. The restore/verify result is carried out and the teardown runs
    // unconditionally — a drill that fails must not also leak a database.
    let restore_started = Instant::now();
    let restored = target
        .restore(&artifact.dir, manifest, &database, cancel)
        .await;
    let restore_elapsed = restore_started.elapsed();

    let outcome = match restored {
        Ok(()) => {
            let verify_started = Instant::now();
            let fingerprints = target.fingerprint(&database).await;
            let verify_elapsed = verify_started.elapsed();
            fingerprints.map(|f| (f, verify_elapsed))
        }
        Err(err) => Err(err),
    };

    if keep_scratch {
        report.scratch_kept = Some(scratch.keep().to_string());
        tracing::warn!(
            scratch = %database,
            "leaving the restored copy in place — it will be swept once it ages out"
        );
    } else if let Err(err) = target.drop_scratch(scratch).await {
        // Never masks the drill's own result: a leaked scratch database is an
        // operational annoyance the sweep will fix, a mis-reported drill is a
        // false assurance nothing fixes.
        tracing::error!(
            scratch = %database,
            error = %err,
            "failed to drop the scratch destination — the next drill's sweep will remove it"
        );
    }

    let (fingerprints, verify_elapsed) = outcome?;
    report.restore_elapsed = restore_elapsed;
    report.verify_elapsed = verify_elapsed;
    report.diff = manifest.diff(&fingerprints);
    report.elapsed = started.elapsed();
    Ok(report)
}

/// [`run`] against the newest artifact for the target, then persist the
/// evidence. This is what the timer calls.
pub async fn run_latest(
    target: &dyn BackupTarget,
    store: &ArtifactStore,
    keep_scratch: bool,
    cancel: &CancellationToken,
) -> Result<DrillReport> {
    let artifact = store.newest(target.name()).await?.ok_or_else(|| {
        BackupError::permanent_msg(format!(
            "no artifact to drill for target {} — take one with `backup snapshot` first",
            target.name()
        ))
    })?;
    let report = run(target, &artifact, keep_scratch, cancel).await?;
    report.record().append(store).await?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;

    use async_trait::async_trait;

    use super::*;
    use crate::artifact::describe_file;
    use crate::manifest::{
        BackupManifest, Cut, Derivation, TableFingerprint, TargetKind, MANIFEST_FORMAT,
    };
    use crate::target::{Database, Scratch, Snapshot, StoreReader};

    /// A target whose restore is programmable, so the drill's own control flow
    /// can be tested without a database.
    #[derive(Clone)]
    struct FakeTarget {
        restored: BTreeMap<String, TableFingerprint>,
        restore_fails: bool,
        provisioned: Arc<AtomicUsize>,
        dropped: Arc<AtomicUsize>,
        swept: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl StoreReader for FakeTarget {
        fn name(&self) -> &str {
            "fake"
        }
        fn kind(&self) -> TargetKind {
            TargetKind::Postgres
        }
        fn live(&self) -> Database {
            Database::new("live").expect("db")
        }
        async fn fingerprint(
            &self,
            _database: &Database,
        ) -> Result<BTreeMap<String, TableFingerprint>> {
            Ok(self.restored.clone())
        }
    }

    #[async_trait]
    impl BackupTarget for FakeTarget {
        async fn snapshot(&self, _dir: &Path, _cancel: &CancellationToken) -> Result<Snapshot> {
            unimplemented!("the drill never snapshots")
        }
        async fn provision_scratch(&self) -> Result<Scratch> {
            self.provisioned.fetch_add(1, Ordering::SeqCst);
            Ok(Scratch::new(Database::new("scratch").expect("db")))
        }
        async fn drop_scratch(&self, mut scratch: Scratch) -> Result<()> {
            self.dropped.fetch_add(1, Ordering::SeqCst);
            scratch.release();
            Ok(())
        }
        async fn sweep_scratch(&self, _older_than: Duration) -> Result<Vec<String>> {
            self.swept.fetch_add(1, Ordering::SeqCst);
            Ok(vec!["fake_drill_20260101000000_1".to_owned()])
        }
        async fn restore(
            &self,
            _dir: &Path,
            _manifest: &BackupManifest,
            _into: &Database,
            _cancel: &CancellationToken,
        ) -> Result<()> {
            if self.restore_fails {
                return Err(BackupError::permanent_msg("pg_restore failed"));
            }
            Ok(())
        }
    }

    fn fingerprint(rows: u64, content: &str) -> TableFingerprint {
        TableFingerprint {
            rows,
            content: content.to_owned(),
            derivation: Derivation::SystemOfRecord,
            cut: Cut::TransactionSnapshot,
        }
    }

    async fn artifact_with(
        body: &[u8],
        notes: Vec<SnapshotNote>,
    ) -> (ArtifactStore, StoredArtifact) {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "backup-drill-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let store = ArtifactStore::new(&root);
        let cut_at = Utc::now();
        let (id, dir) = store.stage("fake", cut_at).await.expect("stage");
        tokio::fs::write(dir.join("dump.pgc"), body)
            .await
            .expect("write");
        let file = describe_file(&dir, "dump.pgc").await.expect("describe");
        let manifest = BackupManifest {
            format: MANIFEST_FORMAT,
            artifact_id: id,
            target: "fake".to_owned(),
            kind: TargetKind::Postgres,
            source_database: "live".to_owned(),
            cut_at,
            started_at: cut_at,
            finished_at: cut_at,
            tables: BTreeMap::from([("public.rules".to_owned(), fingerprint(3, "abcd"))]),
            files: vec![file],
            schema: Vec::new(),
            tool: "test".to_owned(),
            writer_version: "test".to_owned(),
            notes,
        };
        store.commit(&dir, &manifest).await.expect("commit");
        let artifact = store.newest("fake").await.expect("newest").expect("some");
        (store, artifact)
    }

    fn target(
        restored: BTreeMap<String, TableFingerprint>,
        restore_fails: bool,
    ) -> (
        FakeTarget,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
    ) {
        let provisioned = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let swept = Arc::new(AtomicUsize::new(0));
        (
            FakeTarget {
                restored,
                restore_fails,
                provisioned: provisioned.clone(),
                dropped: dropped.clone(),
                swept: swept.clone(),
            },
            provisioned,
            dropped,
            swept,
        )
    }

    fn matching() -> BTreeMap<String, TableFingerprint> {
        BTreeMap::from([("public.rules".to_owned(), fingerprint(3, "abcd"))])
    }

    #[tokio::test]
    async fn a_matching_restore_passes_and_measures_itself() {
        let (_store, artifact) = artifact_with(b"dump", Vec::new()).await;
        let (fake, provisioned, dropped, swept) = target(matching(), false);
        let report = run(&fake, &artifact, false, &CancellationToken::new())
            .await
            .expect("drill");
        assert!(report.passed(), "{}", report.summarize(5));
        assert_eq!(provisioned.load(Ordering::SeqCst), 1);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        // Housekeeping runs on the way IN, not on the way out.
        assert_eq!(swept.load(Ordering::SeqCst), 1);
        assert_eq!(report.swept.len(), 1);
        assert!(report.failures().is_empty());
    }

    #[tokio::test]
    async fn a_restore_that_loses_rows_fails_even_though_no_command_errored() {
        // The failure the drill exists for: pg_restore exits zero, the data is
        // not all there.
        let (_store, artifact) = artifact_with(b"dump", Vec::new()).await;
        let (fake, ..) = target(
            BTreeMap::from([("public.rules".to_owned(), fingerprint(2, "beef"))]),
            false,
        );
        let report = run(&fake, &artifact, false, &CancellationToken::new())
            .await
            .expect("drill");
        assert!(!report.passed());
        assert_eq!(report.diff.changed.len(), 1);
        assert!(report.failures()[0].contains("3 row(s) expected, 2 restored"));
    }

    #[tokio::test]
    async fn an_incomplete_artifact_cannot_pass_however_well_it_restores() {
        // The restore is perfect and the drill must still fail: the artifact
        // was known at snapshot time not to cover part of the system, so
        // reporting PASSED would be the control vouching for a hole it already
        // knew about.
        let (_store, artifact) = artifact_with(
            b"dump",
            vec![SnapshotNote::NotCovered {
                object: ".inner_id.8f2c".to_owned(),
                reason: "a materialized view's inner storage".to_owned(),
            }],
        )
        .await;
        let (fake, ..) = target(matching(), false);
        let report = run(&fake, &artifact, false, &CancellationToken::new())
            .await
            .expect("drill");
        assert!(report.diff.is_clean(), "the restore itself was exact");
        assert!(!report.passed());
        assert!(report.summarize(5).contains("INCOMPLETE ARTIFACT"));
    }

    #[tokio::test]
    async fn a_skipped_object_that_holds_no_data_does_not_fail_the_drill() {
        let (_store, artifact) = artifact_with(
            b"dump",
            vec![SnapshotNote::Skipped {
                object: "usage_rollup_daily_mv".to_owned(),
                reason: "a view holds no durable rows".to_owned(),
            }],
        )
        .await;
        let (fake, ..) = target(matching(), false);
        let report = run(&fake, &artifact, false, &CancellationToken::new())
            .await
            .expect("drill");
        assert!(report.passed(), "{}", report.summarize(5));
    }

    #[tokio::test]
    async fn a_corrupt_artifact_fails_before_a_scratch_database_is_created() {
        // No point provisioning, restoring and measuring a restore of bytes we
        // already know are damaged — and the report must say *that*, not blame
        // the restore.
        let (_store, artifact) = artifact_with(b"dump", Vec::new()).await;
        tokio::fs::write(artifact.dir.join("dump.pgc"), b"corrupted")
            .await
            .expect("corrupt");
        let (fake, provisioned, ..) = target(BTreeMap::new(), false);
        let report = run(&fake, &artifact, false, &CancellationToken::new())
            .await
            .expect("drill");
        assert!(!report.passed());
        assert_eq!(provisioned.load(Ordering::SeqCst), 0);
        assert!(report.failures()[0].contains("artifact integrity"));
    }

    #[tokio::test]
    async fn a_failed_restore_still_drops_the_scratch_database() {
        // A drill that leaks a full copy of production on every failure stops
        // being run long before anyone reads its output.
        let (_store, artifact) = artifact_with(b"dump", Vec::new()).await;
        let (fake, provisioned, dropped, _) = target(BTreeMap::new(), true);
        let err = run(&fake, &artifact, false, &CancellationToken::new())
            .await
            .expect_err("must fail");
        assert!(err.to_string().contains("pg_restore failed"));
        assert!(err.is_permanent());
        assert_eq!(provisioned.load(Ordering::SeqCst), 1);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn keeping_the_scratch_copy_is_reported_not_silent() {
        let (_store, artifact) = artifact_with(b"dump", Vec::new()).await;
        let (fake, _, dropped, _) = target(matching(), false);
        let report = run(&fake, &artifact, true, &CancellationToken::new())
            .await
            .expect("drill");
        assert_eq!(report.scratch_kept.as_deref(), Some("scratch"));
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_drill_writes_the_evidence_report_later_reads() {
        let (store, _artifact) = artifact_with(b"dump", Vec::new()).await;
        let (fake, ..) = target(matching(), false);
        let report = run_latest(&fake, &store, false, &CancellationToken::new())
            .await
            .expect("drill");
        assert!(report.passed());
        let record = DrillRecord::newest_passing(&store, "fake")
            .await
            .expect("read")
            .expect("some");
        assert_eq!(record.artifact_id, report.artifact_id);
        assert!(record.passed);
    }
}
