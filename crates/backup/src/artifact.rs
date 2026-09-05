//! The artifact store: a directory of self-describing backups, and the
//! integrity check that is *not* a restore.
//!
//! Layout, deliberately boring:
//!
//! ```text
//! $BACKUP_DIR/
//!   artifacts/
//!     postgres/
//!       postgres-20260904T110213Z/
//!         manifest.json           ← the claim (crate::manifest)
//!         dump.pgc                ← the bytes
//!     clickhouse/
//!       clickhouse-20260904T110213Z/
//!         manifest.json
//!         events.jsonl
//!         incident_analytics.jsonl
//!   drills/
//!     postgres/20260904T113000Z.json   ← the evidence (crate::drill)
//! ```
//!
//! Plain files, no index, no database. Two reasons, both about the moment this
//! is used: an artifact must be readable when the thing that wrote it is the
//! thing that is down, and "the newest artifact" has to be answerable by
//! `ls`. Artifact ids sort chronologically as strings, so a directory listing
//! *is* the index. Offsite replication is therefore `aws s3 sync` / `rsync` of
//! this root, and the per-file SHA-256 in each manifest is what makes the copy
//! at the far end checkable — [`verify_artifact`] runs against a synced copy
//! exactly as it runs against the original.
//!
//! ## Integrity is not a restore
//!
//! [`verify_artifact`] proves the bytes on disk are the bytes that were
//! written. It cannot prove they are restorable — a dump truncated *before*
//! its checksum was taken passes, and so does a perfectly-preserved dump of a
//! schema no current binary can read. That is why it is cheap enough to run on
//! every artifact every cycle, and why it is not the control. The control is
//! [`crate::drill`].

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

use crate::error::{from_io, BackupError, Result};
use crate::manifest::{ArtifactFile, BackupManifest, MANIFEST_FILE};

/// Directory name for backups under the root.
const ARTIFACTS_DIR: &str = "artifacts";
/// Directory name for drill evidence under the root.
const DRILLS_DIR: &str = "drills";
/// Read chunk for checksumming — big enough to keep syscalls off the profile,
/// small enough that a multi-gigabyte dump never lands in memory.
const CHUNK: usize = 1 << 20;

/// A rooted artifact store. Cheap to clone; holds no handles.
#[derive(Debug, Clone)]
pub struct ArtifactStore {
    root: PathBuf,
}

/// One artifact, located.
#[derive(Debug, Clone)]
pub struct StoredArtifact {
    pub dir: PathBuf,
    pub manifest: BackupManifest,
}

impl StoredArtifact {
    /// How stale this artifact is *as data* — measured from the cut, not from
    /// when the dump finished. See [`crate::objective`].
    pub fn age(&self, now: DateTime<Utc>) -> std::time::Duration {
        (now - self.manifest.cut_at).to_std().unwrap_or_default()
    }
}

impl ArtifactStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn target_dir(&self, target: &str) -> PathBuf {
        self.root.join(ARTIFACTS_DIR).join(target)
    }

    pub fn drills_dir(&self, target: &str) -> PathBuf {
        self.root.join(DRILLS_DIR).join(target)
    }

    /// Reserve and create the directory a new artifact will be written into.
    /// The id embeds the cut instant so the name is meaningful in a listing
    /// and sorts into place without being parsed.
    pub async fn stage(&self, target: &str, cut_at: DateTime<Utc>) -> Result<(String, PathBuf)> {
        let id = format!("{target}-{}", cut_at.format("%Y%m%dT%H%M%SZ"));
        let dir = self.target_dir(target).join(&id);
        if tokio::fs::try_exists(&dir).await.unwrap_or(false) {
            // Transient: the next cycle lands in a different second. A backup
            // that pages because two runs collided would be crying wolf.
            return Err(BackupError::transient_msg(format!(
                "artifact {id} already exists — a second snapshot inside the same second \
                 would overwrite the first"
            )));
        }
        tokio::fs::create_dir_all(&dir).await.map_err(|err| {
            from_io(
                err,
                format!("creating artifact directory {}", dir.display()),
            )
        })?;
        Ok((id, dir))
    }

    /// Write the manifest last, once every data file is on disk. The ordering
    /// is the store's crash contract: an artifact directory without a
    /// `manifest.json` is an interrupted snapshot, and [`list`](Self::list)
    /// skips it rather than offering half a backup as the newest one.
    pub async fn commit(&self, dir: &Path, manifest: &BackupManifest) -> Result<()> {
        let encoded = serde_json::to_vec_pretty(manifest)
            .map_err(|err| BackupError::permanent(err).context("encoding the artifact manifest"))?;
        let path = dir.join(MANIFEST_FILE);
        tokio::fs::write(&path, encoded)
            .await
            .map_err(|err| from_io(err, format!("writing {}", path.display())))?;
        Ok(())
    }

    /// Every complete artifact for `target`, oldest first.
    pub async fn list(&self, target: &str) -> Result<Vec<StoredArtifact>> {
        let dir = self.target_dir(target);
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(entries) => entries,
            // No directory yet is not an error: it is "no backups have ever
            // been taken", which the report turns into an unbounded breach.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(from_io(err, format!("reading {}", dir.display()))),
        };

        let mut out = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|err| from_io(err, "listing artifacts"))?
        {
            let path = entry.path();
            if !entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            match read_manifest(&path).await {
                Ok(manifest) => out.push(StoredArtifact {
                    dir: path,
                    manifest,
                }),
                // A directory with no manifest is the *expected* state of a
                // snapshot that is still running (the manifest is written
                // last, which is the crash contract) or one that died. Both
                // are skipped identically, but only the second is unusual —
                // and neither is a warning, because the scheduled agent reads
                // this store every 30 seconds and would otherwise emit a WARN
                // per heartbeat for the entire duration of every snapshot.
                // Log noise that recurs for hours is how a real warning gets
                // trained out of an operator.
                Err(_) if !manifest_present(&path).await => {
                    tracing::debug!(
                        dir = %path.display(),
                        "skipping an artifact with no manifest — in flight, or an interrupted snapshot"
                    );
                }
                Err(err) => {
                    tracing::warn!(dir = %path.display(), error = %err, "skipping unreadable artifact");
                }
            }
        }
        out.sort_by(|a, b| a.manifest.artifact_id.cmp(&b.manifest.artifact_id));
        Ok(out)
    }

    /// The newest complete artifact for `target`, if any.
    pub async fn newest(&self, target: &str) -> Result<Option<StoredArtifact>> {
        Ok(self.list(target).await?.pop())
    }

    /// Look one up by id.
    pub async fn find(&self, target: &str, artifact_id: &str) -> Result<StoredArtifact> {
        self.list(target)
            .await?
            .into_iter()
            .find(|a| a.manifest.artifact_id == artifact_id)
            .ok_or_else(|| {
                BackupError::permanent_msg(format!("no artifact {artifact_id} for target {target}"))
            })
    }

    /// Delete artifacts older than `keep` — but **never** the newest one, and
    /// never one whose deletion would leave the target with no backup at all.
    /// A retention policy that can empty the store is a retention policy that
    /// will, on the day the snapshot job has been failing quietly for a week.
    pub async fn prune(&self, target: &str, keep: std::time::Duration) -> Result<Vec<String>> {
        let now = Utc::now();
        let artifacts = self.list(target).await?;
        let mut removed = Vec::new();
        // `list` is oldest-first, so dropping the last element leaves every
        // candidate except the newest.
        let candidates = artifacts.len().saturating_sub(1);
        for artifact in artifacts.into_iter().take(candidates) {
            if artifact.age(now) <= keep {
                continue;
            }
            tokio::fs::remove_dir_all(&artifact.dir)
                .await
                .map_err(|err| from_io(err, format!("removing {}", artifact.dir.display())))?;
            removed.push(artifact.manifest.artifact_id);
        }
        Ok(removed)
    }
}

/// Whether the directory has a manifest at all — the difference between "this
/// snapshot has not finished" and "this artifact is damaged".
async fn manifest_present(dir: &Path) -> bool {
    tokio::fs::try_exists(dir.join(MANIFEST_FILE))
        .await
        .unwrap_or(false)
}

/// Read and validate an artifact directory's manifest.
pub async fn read_manifest(dir: &Path) -> Result<BackupManifest> {
    let path = dir.join(MANIFEST_FILE);
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|err| from_io(err, format!("reading {}", path.display())))?;
    let manifest: BackupManifest = serde_json::from_slice(&bytes).map_err(|err| {
        BackupError::permanent(err).context(format!("parsing {}", path.display()))
    })?;
    if !manifest.is_readable() {
        return Err(BackupError::permanent_msg(format!(
            "{} is manifest format {}, and this build understands at most {} — \
             restore it with the version of `backup` that wrote it",
            path.display(),
            manifest.format,
            crate::manifest::MANIFEST_FORMAT
        )));
    }
    Ok(manifest)
}

/// Recompute every file's checksum and compare it with the manifest.
///
/// Returns the list of problems; empty means the bytes are intact. Never
/// returns "ok" for a file it could not read.
pub async fn verify_artifact(artifact: &StoredArtifact) -> Result<Vec<String>> {
    let mut problems = Vec::new();
    for file in &artifact.manifest.files {
        let path = artifact.dir.join(&file.path);
        let metadata = match tokio::fs::metadata(&path).await {
            Ok(metadata) => metadata,
            Err(err) => {
                problems.push(format!("{}: {err}", file.path));
                continue;
            }
        };
        if metadata.len() != file.bytes {
            problems.push(format!(
                "{}: {} bytes on disk, manifest says {}",
                file.path,
                metadata.len(),
                file.bytes
            ));
            continue;
        }
        let actual = sha256_file(&path).await?;
        if actual != file.sha256 {
            problems.push(format!(
                "{}: checksum {} does not match the manifest's {}",
                file.path, actual, file.sha256
            ));
        }
    }
    if artifact.manifest.files.is_empty() {
        problems.push("the manifest lists no files — this artifact holds no data".to_owned());
    }
    Ok(problems)
}

/// Streaming SHA-256 of a file, hex-encoded.
pub async fn sha256_file(path: &Path) -> Result<String> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|err| from_io(err, format!("opening {}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0_u8; CHUNK];
    loop {
        let read = file
            .read(&mut buf)
            .await
            .map_err(|err| from_io(err, format!("reading {}", path.display())))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hex(&hasher.finalize()))
}

/// Describe a file for the manifest.
pub async fn describe_file(dir: &Path, relative: &str) -> Result<ArtifactFile> {
    let path = dir.join(relative);
    let metadata = tokio::fs::metadata(&path)
        .await
        .map_err(|err| from_io(err, format!("stat {}", path.display())))?;
    Ok(ArtifactFile {
        path: relative.to_owned(),
        bytes: metadata.len(),
        sha256: sha256_file(&path).await?,
    })
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        // The write cannot fail on a String.
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Drill evidence, persisted so `report` can read it without re-running one.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DrillRecord {
    pub target: String,
    pub artifact_id: String,
    pub finished_at: DateTime<Utc>,
    /// Seconds of measured restore-and-verify (the RTO input).
    pub restore_seconds: f64,
    /// `cut_at` of the artifact restored, so the record proves *which* backup
    /// was verified — a passing drill against a three-week-old artifact says
    /// nothing about last night's.
    pub artifact_cut_at: DateTime<Utc>,
    pub artifact_bytes: u64,
    pub artifact_rows: u64,
    pub passed: bool,
    #[serde(default)]
    pub failures: Vec<String>,
}

impl DrillRecord {
    pub async fn append(&self, store: &ArtifactStore) -> Result<PathBuf> {
        let dir = store.drills_dir(&self.target);
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|err| from_io(err, format!("creating {}", dir.display())))?;
        let path = dir.join(format!(
            "{}.json",
            self.finished_at.format("%Y%m%dT%H%M%SZ")
        ));
        let encoded = serde_json::to_vec_pretty(self)
            .map_err(|err| BackupError::permanent(err).context("encoding the drill record"))?;
        tokio::fs::write(&path, encoded)
            .await
            .map_err(|err| from_io(err, format!("writing {}", path.display())))?;
        Ok(path)
    }

    /// The newest drill record of **any** outcome.
    ///
    /// Distinct from [`newest_passing`](Self::newest_passing) on purpose, and
    /// the two answer different questions. Verification age must only count
    /// *passing* drills — a failing one proves nothing. But the scheduler asks
    /// "has a drill been attempted recently?", and using the passing record
    /// there would make a persistently failing drill re-run on every heartbeat
    /// forever, hammering the store precisely when it is already unhealthy.
    pub async fn newest_attempt(store: &ArtifactStore, target: &str) -> Result<Option<Self>> {
        Self::newest_matching(store, target, |_| true).await
    }

    /// The newest **passing** drill for a target. A failing drill is kept on
    /// disk (it is the incident record) but never counts as verification.
    pub async fn newest_passing(store: &ArtifactStore, target: &str) -> Result<Option<Self>> {
        Self::newest_matching(store, target, |record| record.passed).await
    }

    async fn newest_matching(
        store: &ArtifactStore,
        target: &str,
        accept: impl Fn(&Self) -> bool,
    ) -> Result<Option<Self>> {
        let dir = store.drills_dir(target);
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(from_io(err, format!("reading {}", dir.display()))),
        };
        let mut newest: Option<Self> = None;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|err| from_io(err, "listing drills"))?
        {
            let bytes = match tokio::fs::read(entry.path()).await {
                Ok(bytes) => bytes,
                Err(err) => {
                    tracing::warn!(path = %entry.path().display(), error = %err, "skipping drill record");
                    continue;
                }
            };
            let record: Self = match serde_json::from_slice(&bytes) {
                Ok(record) => record,
                Err(err) => {
                    tracing::warn!(path = %entry.path().display(), error = %err, "skipping drill record");
                    continue;
                }
            };
            if !accept(&record) {
                continue;
            }
            if newest
                .as_ref()
                .is_none_or(|current| record.finished_at > current.finished_at)
            {
                newest = Some(record);
            }
        }
        Ok(newest)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use chrono::TimeZone;

    use super::*;
    use crate::manifest::{Cut, Derivation, TableFingerprint, TargetKind, MANIFEST_FORMAT};

    fn manifest(id: &str, cut_at: DateTime<Utc>, files: Vec<ArtifactFile>) -> BackupManifest {
        BackupManifest {
            format: MANIFEST_FORMAT,
            artifact_id: id.to_owned(),
            target: "postgres".to_owned(),
            kind: TargetKind::Postgres,
            source_database: "detector".to_owned(),
            cut_at,
            started_at: cut_at,
            finished_at: cut_at,
            tables: BTreeMap::from([(
                "public.rules".to_owned(),
                TableFingerprint {
                    rows: 1,
                    content: "00".to_owned(),
                    derivation: Derivation::SystemOfRecord,
                    cut: Cut::TransactionSnapshot,
                },
            )]),
            files,
            schema: Vec::new(),
            tool: "test".to_owned(),
            writer_version: "test".to_owned(),
            notes: Vec::new(),
        }
    }

    async fn write_artifact(store: &ArtifactStore, cut_at: DateTime<Utc>, body: &[u8]) -> String {
        let (id, dir) = store.stage("postgres", cut_at).await.expect("stage");
        tokio::fs::write(dir.join("dump.pgc"), body)
            .await
            .expect("write dump");
        let file = describe_file(&dir, "dump.pgc").await.expect("describe");
        store
            .commit(&dir, &manifest(&id, cut_at, vec![file]))
            .await
            .expect("commit");
        id
    }

    fn at(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 4, hour, 0, 0)
            .single()
            .expect("valid")
    }

    #[tokio::test]
    async fn artifacts_list_oldest_first_and_newest_is_the_latest_cut() {
        let tmp = tempdir();
        let store = ArtifactStore::new(&tmp);
        write_artifact(&store, at(1), b"one").await;
        let newest_id = write_artifact(&store, at(3), b"three").await;
        write_artifact(&store, at(2), b"two").await;

        let listed = store.list("postgres").await.expect("list");
        assert_eq!(listed.len(), 3);
        assert!(listed[0].manifest.cut_at < listed[2].manifest.cut_at);
        assert_eq!(
            store
                .newest("postgres")
                .await
                .expect("newest")
                .expect("some")
                .manifest
                .artifact_id,
            newest_id
        );
    }

    #[tokio::test]
    async fn an_interrupted_snapshot_is_not_offered_as_the_newest_backup() {
        // A directory with data but no manifest is a snapshot that died
        // mid-run. Treating it as the newest artifact is how a restore ends
        // up reaching for half a backup.
        let tmp = tempdir();
        let store = ArtifactStore::new(&tmp);
        let good = write_artifact(&store, at(1), b"one").await;
        let (_, dir) = store.stage("postgres", at(5)).await.expect("stage");
        tokio::fs::write(dir.join("dump.pgc"), b"partial")
            .await
            .expect("write");

        let newest = store
            .newest("postgres")
            .await
            .expect("newest")
            .expect("some");
        assert_eq!(newest.manifest.artifact_id, good);
    }

    #[tokio::test]
    async fn an_in_flight_snapshot_is_distinguished_from_a_damaged_one() {
        // Both are skipped, but only one is unusual. The scheduled agent reads
        // this store every 30 seconds, so warning about a directory that is
        // simply still being written would emit a WARN per heartbeat for the
        // whole duration of every snapshot — and a warning that fires for
        // hours is one an operator learns to ignore.
        let tmp = tempdir();
        let store = ArtifactStore::new(&tmp);
        let (_, in_flight) = store.stage("postgres", at(5)).await.expect("stage");
        tokio::fs::write(in_flight.join("dump.pgc"), b"partial")
            .await
            .expect("write");
        assert!(!manifest_present(&in_flight).await);

        let (_, damaged) = store.stage("postgres", at(6)).await.expect("stage");
        tokio::fs::write(damaged.join(MANIFEST_FILE), b"{ not json")
            .await
            .expect("write");
        assert!(manifest_present(&damaged).await);

        // Neither is offered as an artifact either way.
        assert!(store.list("postgres").await.expect("list").is_empty());
    }

    #[tokio::test]
    async fn verification_catches_a_truncated_dump() {
        let tmp = tempdir();
        let store = ArtifactStore::new(&tmp);
        write_artifact(&store, at(1), b"the original bytes").await;
        let artifact = store
            .newest("postgres")
            .await
            .expect("newest")
            .expect("some");
        assert!(verify_artifact(&artifact).await.expect("verify").is_empty());

        tokio::fs::write(artifact.dir.join("dump.pgc"), b"short")
            .await
            .expect("truncate");
        let problems = verify_artifact(&artifact).await.expect("verify");
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("bytes on disk"), "{problems:?}");
    }

    #[tokio::test]
    async fn verification_catches_a_same_length_corruption() {
        let tmp = tempdir();
        let store = ArtifactStore::new(&tmp);
        write_artifact(&store, at(1), b"aaaa").await;
        let artifact = store
            .newest("postgres")
            .await
            .expect("newest")
            .expect("some");
        tokio::fs::write(artifact.dir.join("dump.pgc"), b"bbbb")
            .await
            .expect("corrupt");
        let problems = verify_artifact(&artifact).await.expect("verify");
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("checksum"), "{problems:?}");
    }

    #[tokio::test]
    async fn prune_never_empties_the_store() {
        // Every artifact here is far older than the retention window. Pruning
        // them all would be a correct reading of the policy and a catastrophic
        // one: the snapshot job may simply have been broken for a month.
        let tmp = tempdir();
        let store = ArtifactStore::new(&tmp);
        write_artifact(&store, at(1), b"one").await;
        write_artifact(&store, at(2), b"two").await;
        let newest = write_artifact(&store, at(3), b"three").await;

        let removed = store
            .prune("postgres", Duration::from_secs(1))
            .await
            .expect("prune");
        assert_eq!(removed.len(), 2);
        let left = store.list("postgres").await.expect("list");
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].manifest.artifact_id, newest);
    }

    #[tokio::test]
    async fn only_a_passing_drill_counts_as_verification() {
        let tmp = tempdir();
        let store = ArtifactStore::new(&tmp);
        let failed = DrillRecord {
            target: "postgres".to_owned(),
            artifact_id: "postgres-20260904T120000Z".to_owned(),
            finished_at: at(12),
            restore_seconds: 4.0,
            artifact_cut_at: at(12),
            artifact_bytes: 10,
            artifact_rows: 1,
            passed: false,
            failures: vec!["public.rules: 1 row(s) expected, 0 restored".to_owned()],
        };
        let passed = DrillRecord {
            finished_at: at(9),
            passed: true,
            failures: Vec::new(),
            ..failed.clone()
        };
        failed.append(&store).await.expect("append failed");
        passed.append(&store).await.expect("append passed");

        let newest = DrillRecord::newest_passing(&store, "postgres")
            .await
            .expect("read")
            .expect("some");
        // The *later* record failed; verification must fall back to the older
        // passing one rather than reporting the newest run's timestamp.
        assert_eq!(newest.finished_at, at(9));
    }

    /// A scratch directory unique to one test, so the suite is safe under a
    /// parallel runner (and under a runner that reuses threads).
    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir().join(format!(
            "backup-artifact-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&base).expect("create temp dir");
        base
    }
}
