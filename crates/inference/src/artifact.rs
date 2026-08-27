//! The model artifact and its digest — "weights are config" (§20.2).
//!
//! A trained model reaches this system as one opaque file: an ONNX graph plus
//! its weights. [`ArtifactDigest`] is the SHA-256 of exactly those bytes, and
//! it is what makes a weight change *visible* to the rest of the platform —
//! folded into the registry `config_hash`, it turns a retrain into a new
//! `(id, version, config_hash)` triple, so historical evidence stays
//! attributable to the weights that produced it and rollback is the registry's
//! existing `deprecated_at` mechanism rather than a bespoke "which .onnx was
//! deployed in March?" investigation.
//!
//! The digest is deliberately shaped like [`detection::ConfigHash`]: the raw 32
//! bytes held, hex at the edges, never constructible from arbitrary text. An
//! artifact hash that could be a typo'd string is not an audit identifier.
//!
//! [`detection::ConfigHash`]: https://docs.rs/detection

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The SHA-256 of a model artifact's bytes.
///
/// Held as the raw digest, rendered as lowercase hex at every edge
/// ([`to_hex`](Self::to_hex), `Display`, serde) — so a descriptor logged, a
/// model card persisted, and a config file pinning an expected artifact all
/// speak the same 64-character string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ArtifactDigest([u8; 32]);

impl ArtifactDigest {
    /// Digest a model artifact's bytes.
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Parse the lowercase-hex rendering (how an operator pins an expected
    /// artifact in config). Rejects anything that isn't 32 hex-encoded bytes,
    /// so a truncated paste fails at boot rather than silently never matching.
    pub fn from_hex(hex: &str) -> Result<Self, DigestParseError> {
        let bytes = alloy_primitives::hex::decode(hex)
            .map_err(|_| DigestParseError::NotHex(hex.to_owned()))?;
        let digest: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| DigestParseError::WrongLength(bytes.len()))?;
        Ok(Self(digest))
    }

    /// The raw 32-byte digest — what the registry folds into its
    /// `config_hash` (see the crate docs).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The lowercase-hex rendering.
    pub fn to_hex(&self) -> String {
        alloy_primitives::hex::encode(self.0)
    }
}

/// A pinned artifact digest in config could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DigestParseError {
    #[error("artifact digest is not hex: {0:?}")]
    NotHex(String),
    #[error("artifact digest must be 32 bytes (64 hex chars), got {0}")]
    WrongLength(usize),
}

impl std::fmt::Display for ArtifactDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for ArtifactDigest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ArtifactDigest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let hex = String::deserialize(deserializer)?;
        Self::from_hex(&hex).map_err(D::Error::custom)
    }
}

/// A model artifact read into memory once, at boot, with its digest.
///
/// Loading is deliberately eager and total: the bytes are read, hashed, and
/// (optionally) checked against the digest the deployment pinned *before* any
/// backend touches them. A truncated download, a half-written file, or the
/// wrong model dropped into the mount is then a typed boot error naming the
/// path — not a detector that quietly scores everything 0.5 in production.
#[derive(Debug, Clone)]
pub struct ModelArtifact {
    path: PathBuf,
    digest: ArtifactDigest,
    bytes: Vec<u8>,
}

impl ModelArtifact {
    /// Read and digest the artifact at `path`.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ArtifactError> {
        let path = path.as_ref().to_path_buf();
        let bytes = std::fs::read(&path).map_err(|source| ArtifactError::Read {
            path: path.clone(),
            source,
        })?;
        if bytes.is_empty() {
            return Err(ArtifactError::Empty { path });
        }
        Ok(Self::from_bytes(path, bytes))
    }

    /// Build from bytes already in hand (a test fixture, an artifact fetched
    /// by something other than the filesystem). `path` is provenance for error
    /// messages only — nothing reads it back.
    pub fn from_bytes(path: impl Into<PathBuf>, bytes: Vec<u8>) -> Self {
        let digest = ArtifactDigest::of(&bytes);
        Self {
            path: path.into(),
            digest,
            bytes,
        }
    }

    /// Fail unless this artifact is *exactly* the one the deployment pinned.
    ///
    /// Optional by design: a first deploy legitimately has nothing to pin
    /// against. Once pinned, though, this is the check that stops a weight
    /// swap from riding into production without a new registry triple — the
    /// one thing §20.2's "weights are config" rule forbids.
    pub fn verify(&self, expected: &ArtifactDigest) -> Result<(), ArtifactError> {
        if self.digest == *expected {
            Ok(())
        } else {
            Err(ArtifactError::DigestMismatch {
                path: self.path.clone(),
                expected: expected.to_hex(),
                actual: self.digest.to_hex(),
            })
        }
    }

    /// Where this artifact came from — provenance for logs and errors.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The SHA-256 of [`bytes`](Self::bytes).
    pub fn digest(&self) -> ArtifactDigest {
        self.digest
    }

    /// The raw artifact bytes — what a backend hands to its runtime.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Size in bytes, for the boot log line.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// A model artifact could not be loaded or is not the pinned one. Every
/// variant is a **deployment** fault that no retry fixes — which is why they
/// are raised at boot (link-or-fail) and never on the fast path.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("reading model artifact at {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// A zero-byte file is the shape a half-finished copy or an empty volume
    /// mount takes; call it out rather than letting the runtime report a
    /// confusing parse failure.
    #[error("model artifact at {path} is empty")]
    Empty { path: PathBuf },

    #[error(
        "model artifact at {path} is not the pinned build: expected {expected}, found {actual}"
    )]
    DigestMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempArtifact;

    #[test]
    fn the_digest_is_the_sha256_of_the_bytes() {
        // Vector from the SHA-256 spec's canonical "abc" example — so this
        // test pins the *algorithm*, not just self-consistency.
        assert_eq!(
            ArtifactDigest::of(b"abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn different_weights_are_a_different_digest() {
        assert_ne!(
            ArtifactDigest::of(b"weights-v1"),
            ArtifactDigest::of(b"weights-v2")
        );
    }

    #[test]
    fn hex_round_trips_and_rejects_junk() {
        let digest = ArtifactDigest::of(b"model");
        assert_eq!(ArtifactDigest::from_hex(&digest.to_hex()).unwrap(), digest);
        assert!(matches!(
            ArtifactDigest::from_hex("zz"),
            Err(DigestParseError::NotHex(_))
        ));
        assert!(matches!(
            ArtifactDigest::from_hex("abcd"),
            Err(DigestParseError::WrongLength(2))
        ));
    }

    #[test]
    fn serde_is_the_hex_string() {
        let digest = ArtifactDigest::of(b"model");
        let json = serde_json::to_string(&digest).unwrap();
        assert_eq!(json, format!("\"{}\"", digest.to_hex()));
        assert_eq!(
            serde_json::from_str::<ArtifactDigest>(&json).unwrap(),
            digest
        );
    }

    #[test]
    fn loading_reads_and_digests_the_file() {
        let file = TempArtifact::with_bytes("load", b"onnx-bytes");
        let artifact = ModelArtifact::load(file.path()).expect("written above");
        assert_eq!(artifact.bytes(), b"onnx-bytes");
        assert_eq!(artifact.digest(), ArtifactDigest::of(b"onnx-bytes"));
        assert_eq!(artifact.len(), 10);
    }

    #[test]
    fn a_missing_artifact_names_the_path() {
        let err = ModelArtifact::load("/nonexistent/model.onnx").unwrap_err();
        assert!(matches!(err, ArtifactError::Read { .. }), "{err:?}");
        assert!(err.to_string().contains("/nonexistent/model.onnx"));
    }

    #[test]
    fn an_empty_artifact_is_its_own_error() {
        let file = TempArtifact::with_bytes("empty", b"");
        let err = ModelArtifact::load(file.path()).unwrap_err();
        assert!(matches!(err, ArtifactError::Empty { .. }), "{err:?}");
    }

    #[test]
    fn verify_accepts_the_pinned_build_and_rejects_a_swap() {
        let artifact = ModelArtifact::from_bytes("m.onnx", b"weights-v1".to_vec());
        assert!(artifact.verify(&ArtifactDigest::of(b"weights-v1")).is_ok());

        let err = artifact
            .verify(&ArtifactDigest::of(b"weights-v2"))
            .unwrap_err();
        assert!(
            matches!(err, ArtifactError::DigestMismatch { .. }),
            "{err:?}"
        );
        // The message carries both digests: an operator diffing a deploy needs
        // to see what it *is*, not only that it isn't what was expected.
        let message = err.to_string();
        assert!(message.contains(&ArtifactDigest::of(b"weights-v1").to_hex()));
        assert!(message.contains(&ArtifactDigest::of(b"weights-v2").to_hex()));
    }
}
