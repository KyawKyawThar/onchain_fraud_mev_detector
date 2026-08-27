//! A self-deleting temp file for the artifact-loading tests.
//!
//! Deliberately hand-rolled rather than pulling `tempfile` into the workspace
//! (conventions §10 — every dependency is a decision): the tests need exactly
//! "a unique path with these bytes in it, gone afterwards", which is a dozen
//! lines. Internal to this crate's own tests; not part of the public
//! `test_util` double.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Unique-per-file within a process; the pid separates concurrent test
/// binaries (nextest runs each test in its own process, but `cargo test`
/// doesn't).
static NEXT: AtomicU64 = AtomicU64::new(0);

pub struct TempArtifact {
    path: PathBuf,
}

impl TempArtifact {
    /// Write `bytes` to a fresh path under the system temp dir.
    pub fn with_bytes(label: &str, bytes: &[u8]) -> Self {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("inference-{label}-{}-{n}.onnx", std::process::id()));
        std::fs::write(&path, bytes).expect("writing a temp file");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempArtifact {
    fn drop(&mut self) {
        // Best-effort: a leaked temp file must never fail a test.
        let _ = std::fs::remove_file(&self.path);
    }
}
