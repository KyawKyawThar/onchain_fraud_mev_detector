//! Reading and writing windows: encodings, the storage [`Budget`], and the
//! corpus directory (see the crate docs, "Storage").

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use flate2::{Compression, GzBuilder};

use crate::{CorpusError, Window};

const MIB: u64 = 1024 * 1024;

/// What a file header looks like when git-lfs checked out a pointer.
const LFS_POINTER_PREFIX: &[u8] = b"version https://git-lfs.github.com/spec/v1";

/// Size limits for windows on disk and in memory. A value, so tests and a
/// future object-store backend can use different limits without editing the
/// committed ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// Largest single window file, as stored. Well under GitHub's 50 MiB
    /// warning (and 100 MiB refusal), so a push never fails late.
    pub max_file_bytes: u64,
    /// Largest window once decoded. Guards against a corrupt or hostile
    /// archive expanding without bound.
    pub max_decoded_bytes: u64,
    /// Largest total corpus, as stored. Past it, windows belong in an object
    /// store with their digests in git, not in the repository itself.
    pub max_corpus_bytes: u64,
}

impl Budget {
    /// The limits the committed corpus is held to.
    pub const COMMITTED: Budget = Budget {
        max_file_bytes: 24 * MIB,
        max_decoded_bytes: 512 * MIB,
        max_corpus_bytes: 256 * MIB,
    };
}

/// How a window file is encoded, from its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// `*.json` — readable diffs; right for small windows.
    Json,
    /// `*.json.gz` — the default for real captures (roughly 10x smaller).
    JsonGzip,
}

impl Encoding {
    /// The encoding a path names, or `None` for a file that is not a window.
    pub fn of(path: &Path) -> Option<Self> {
        let name = path.file_name()?.to_str()?;
        if name.ends_with(".json.gz") {
            Some(Encoding::JsonGzip)
        } else if name.ends_with(".json") {
            Some(Encoding::Json)
        } else {
            None
        }
    }
}

fn read_err(path: &Path) -> impl FnOnce(std::io::Error) -> CorpusError + '_ {
    move |source| CorpusError::Read {
        path: path.to_path_buf(),
        source,
    }
}

fn unsupported(path: &Path) -> CorpusError {
    CorpusError::Read {
        path: path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "a window file must end in .json or .json.gz",
        ),
    }
}

/// Read and validate one window under [`Budget::COMMITTED`].
pub fn load(path: &Path) -> Result<Window, CorpusError> {
    load_with(path, &Budget::COMMITTED)
}

fn load_with(path: &Path, budget: &Budget) -> Result<Window, CorpusError> {
    let encoding = Encoding::of(path).ok_or_else(|| unsupported(path))?;
    let stored = std::fs::metadata(path).map_err(read_err(path))?.len();
    if stored > budget.max_file_bytes {
        return Err(CorpusError::TooLarge {
            path: path.to_path_buf(),
            what: "the file",
            bytes: stored,
            limit: budget.max_file_bytes,
            remedy: "split the window into shorter ones",
        });
    }
    let raw = std::fs::read(path).map_err(read_err(path))?;
    if raw.starts_with(LFS_POINTER_PREFIX) {
        return Err(CorpusError::LfsPointer {
            path: path.to_path_buf(),
        });
    }

    let text = match encoding {
        Encoding::Json => raw,
        Encoding::JsonGzip => {
            // Read one byte past the limit: a decoder that yields it has proven
            // the file is over, without inflating the rest.
            let mut decoded = Vec::new();
            GzDecoder::new(raw.as_slice())
                .take(budget.max_decoded_bytes + 1)
                .read_to_end(&mut decoded)
                .map_err(read_err(path))?;
            if decoded.len() as u64 > budget.max_decoded_bytes {
                return Err(CorpusError::TooLarge {
                    path: path.to_path_buf(),
                    what: "the decoded window",
                    bytes: decoded.len() as u64,
                    limit: budget.max_decoded_bytes,
                    remedy: "split the window, or treat the file as corrupt",
                });
            }
            decoded
        }
    };

    let window: Window = serde_json::from_slice(&text).map_err(|source| CorpusError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    window.validate().map_err(|problem| CorpusError::Invalid {
        path: path.to_path_buf(),
        problem,
    })?;
    Ok(window)
}

/// Validate, encode by extension, and write `window` under
/// [`Budget::COMMITTED`]. Nothing is written if the window is invalid or the
/// encoded file would be over budget: a file this crate cannot load back must
/// never exist.
pub fn save(window: &Window, path: &Path) -> Result<(), CorpusError> {
    save_with(window, path, &Budget::COMMITTED)
}

fn save_with(window: &Window, path: &Path, budget: &Budget) -> Result<(), CorpusError> {
    let encoding = Encoding::of(path).ok_or_else(|| unsupported(path))?;
    window.validate().map_err(|problem| CorpusError::Invalid {
        path: path.to_path_buf(),
        problem,
    })?;
    let mut text = serde_json::to_vec_pretty(window).map_err(CorpusError::Serialize)?;
    text.push(b'\n');
    if text.len() as u64 > budget.max_decoded_bytes {
        return Err(CorpusError::TooLarge {
            path: path.to_path_buf(),
            what: "the decoded window",
            bytes: text.len() as u64,
            limit: budget.max_decoded_bytes,
            remedy: "capture a shorter window",
        });
    }

    let write_err = |source| CorpusError::Write {
        path: path.to_path_buf(),
        source,
    };
    let bytes = match encoding {
        Encoding::Json => text,
        Encoding::JsonGzip => {
            // `GzBuilder` with no name and mtime 0: one window, one byte
            // sequence, whenever and wherever it is captured.
            let mut encoder = GzBuilder::new()
                .mtime(0)
                .write(Vec::new(), Compression::best());
            encoder.write_all(&text).map_err(write_err)?;
            encoder.finish().map_err(write_err)?
        }
    };
    if bytes.len() as u64 > budget.max_file_bytes {
        return Err(CorpusError::TooLarge {
            path: path.to_path_buf(),
            what: "the encoded file",
            bytes: bytes.len() as u64,
            limit: budget.max_file_bytes,
            remedy: "capture a shorter window, or write .json.gz",
        });
    }
    std::fs::write(path, bytes).map_err(write_err)
}

/// Every window in `dir` (`*.json` and `*.json.gz`), in file-name order,
/// validated, checked for overlap, and held to [`Budget::COMMITTED`].
///
/// A missing directory is an error, not an empty corpus: the committed corpus
/// directory always exists, so its absence means the caller is looking in the
/// wrong place — and "found nothing" would read as "measured nothing" without
/// anyone noticing.
pub fn load_dir(dir: &Path) -> Result<Vec<(PathBuf, Window)>, CorpusError> {
    load_dir_with(dir, &Budget::COMMITTED)
}

fn load_dir_with(dir: &Path, budget: &Budget) -> Result<Vec<(PathBuf, Window)>, CorpusError> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(read_err(dir))? {
        let path = entry.map_err(read_err(dir))?.path();
        if Encoding::of(&path).is_some() {
            paths.push(path);
        }
    }
    paths.sort();

    // The total is checked before anything is decoded.
    let mut total = 0u64;
    for path in &paths {
        total += std::fs::metadata(path).map_err(read_err(path))?.len();
    }
    if total > budget.max_corpus_bytes {
        return Err(CorpusError::TooLarge {
            path: dir.to_path_buf(),
            what: "the corpus",
            bytes: total,
            limit: budget.max_corpus_bytes,
            remedy: "move windows to an object store and keep their digests in git",
        });
    }

    let mut windows = Vec::with_capacity(paths.len());
    // Keyed by the raw chain id: `Chain` is not `Ord`.
    let mut covered: BTreeMap<(u64, u64), PathBuf> = BTreeMap::new();
    for path in paths {
        let window = load_with(&path, budget)?;
        let chain = window.provenance.chain;
        for block in &window.blocks {
            if let Some(first) = covered.insert((chain.0, block.number), path.clone()) {
                return Err(CorpusError::Overlap {
                    first,
                    second: path,
                    chain,
                    block: block.number,
                });
            }
        }
        windows.push((path, window));
    }
    Ok(windows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{scratch, window};

    #[test]
    fn encoding_is_read_from_the_name() {
        assert_eq!(Encoding::of(Path::new("a.json")), Some(Encoding::Json));
        assert_eq!(
            Encoding::of(Path::new("dir/a.json.gz")),
            Some(Encoding::JsonGzip)
        );
        assert_eq!(Encoding::of(Path::new("README.md")), None);
        assert_eq!(Encoding::of(Path::new("a.gz")), None);
    }

    #[test]
    fn gzip_round_trips_and_is_smaller() {
        let dir = scratch("gzip");
        let original = window(&[10, 11, 12, 13, 14, 15]);
        save(&original, &dir.join("w.json")).unwrap();
        save(&original, &dir.join("w.json.gz")).unwrap();
        assert_eq!(load(&dir.join("w.json.gz")).unwrap(), original);
        let size = |name: &str| std::fs::metadata(dir.join(name)).unwrap().len();
        assert!(
            size("w.json.gz") * 3 < size("w.json"),
            "gzip should pay for itself"
        );
    }

    #[test]
    fn gzip_output_is_deterministic() {
        let dir = scratch("gzip-det");
        save(&window(&[10]), &dir.join("a.json.gz")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        save(&window(&[10]), &dir.join("b.json.gz")).unwrap();
        assert_eq!(
            std::fs::read(dir.join("a.json.gz")).unwrap(),
            std::fs::read(dir.join("b.json.gz")).unwrap(),
            "no timestamp may leak into the header"
        );
    }

    #[test]
    fn an_lfs_pointer_is_named_as_one() {
        let dir = scratch("lfs");
        let path = dir.join("w.json.gz");
        std::fs::write(
            &path,
            "version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 123\n",
        )
        .unwrap();
        assert!(matches!(load(&path), Err(CorpusError::LfsPointer { .. })));
    }

    fn tiny(file: u64, decoded: u64, corpus: u64) -> Budget {
        Budget {
            max_file_bytes: file,
            max_decoded_bytes: decoded,
            max_corpus_bytes: corpus,
        }
    }

    #[test]
    fn save_refuses_a_file_over_budget_and_writes_nothing() {
        let dir = scratch("budget-save");
        let path = dir.join("w.json");
        let err = save_with(&window(&[10]), &path, &tiny(100, u64::MAX, u64::MAX)).unwrap_err();
        assert!(
            matches!(
                err,
                CorpusError::TooLarge {
                    what: "the encoded file",
                    ..
                }
            ),
            "{err}"
        );
        assert!(!path.exists());
    }

    #[test]
    fn load_refuses_a_file_over_budget() {
        let dir = scratch("budget-load");
        let path = dir.join("w.json");
        save(&window(&[10]), &path).unwrap();
        let err = load_with(&path, &tiny(100, u64::MAX, u64::MAX)).unwrap_err();
        assert!(
            matches!(
                err,
                CorpusError::TooLarge {
                    what: "the file",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn a_decompression_bomb_stops_at_the_decoded_limit() {
        // Megabytes of one byte compress to almost nothing.
        let dir = scratch("bomb");
        let path = dir.join("w.json.gz");
        let mut encoder = GzBuilder::new().write(Vec::new(), Compression::best());
        encoder.write_all(&vec![b' '; 8 * MIB as usize]).unwrap();
        std::fs::write(&path, encoder.finish().unwrap()).unwrap();

        let err = load_with(&path, &tiny(u64::MAX, MIB, u64::MAX)).unwrap_err();
        assert!(
            matches!(err, CorpusError::TooLarge { what: "the decoded window", bytes, .. } if bytes == MIB + 1),
            "{err}"
        );
    }

    #[test]
    fn the_corpus_total_is_checked_before_decoding() {
        let dir = scratch("budget-corpus");
        save(&window(&[10]), &dir.join("a.json")).unwrap();
        save(&window(&[20]), &dir.join("b.json")).unwrap();
        let one = std::fs::metadata(dir.join("a.json")).unwrap().len();
        let err = load_dir_with(&dir, &tiny(u64::MAX, u64::MAX, one + 1)).unwrap_err();
        assert!(
            matches!(
                err,
                CorpusError::TooLarge {
                    what: "the corpus",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn load_dir_reads_both_encodings() {
        let dir = scratch("mixed");
        save(&window(&[10]), &dir.join("a.json")).unwrap();
        save(&window(&[20]), &dir.join("b.json.gz")).unwrap();
        assert_eq!(load_dir(&dir).unwrap().len(), 2);
    }

    #[test]
    fn an_unknown_extension_is_refused_on_save() {
        let dir = scratch("ext");
        assert!(save(&window(&[10]), &dir.join("w.txt")).is_err());
    }
}
