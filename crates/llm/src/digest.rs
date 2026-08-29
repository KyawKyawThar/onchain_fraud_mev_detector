//! [`ContentDigest`] — SHA-256 over an artifact, rendered as hex.
//!
//! The workspace already makes this move three times: `detection::ConfigHash`
//! (a detector's config), `ml_features::FeatureSchema::content_hash` (a
//! feature schema) and `inference::ModelDescriptor::content_hash` (weights +
//! feature contract). Each exists so a produced artifact stays attributable to
//! the *exact* inputs that produced it, forever, without a "which version was
//! live in March?" investigation.
//!
//! §20.4 needs the same thing twice over, which is why this is one type used
//! for both:
//!
//! * a **prompt digest**, because a prompt is a versioned artifact and a
//!   version string cannot catch an edit made underneath it (the same reason
//!   Sprint 19's embeddings are double-stamped with a schema hash);
//! * a **request digest**, because a rendered request is a cache key — and a
//!   cache key that collides across tenants is a data leak, not a stale read.
//!
//! A real cryptographic digest and not a `DefaultHasher`, for the second
//! reason above: collision-resistance is load-bearing here.

use sha2::{Digest, Sha256};

/// SHA-256 of some content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentDigest([u8; 32]);

impl ContentDigest {
    /// Hash `bytes`.
    pub fn of(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(hasher.finalize().into())
    }

    /// The raw digest.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Full 64-character lowercase hex — what goes on the wire, into an event,
    /// and into a cache key.
    pub fn to_hex(self) -> String {
        alloy_primitives::hex::encode(self.0)
    }

    /// The first 12 hex characters, for logs and spans. Never for identity: a
    /// short digest is a fine label and a terrible key.
    pub fn short(self) -> String {
        self.to_hex().chars().take(12).collect()
    }
}

/// Renders as the short form — the log/label case is the common one, and a
/// full 64-char digest in a log line is noise. Use
/// [`to_hex`](ContentDigest::to_hex) wherever identity is meant.
impl std::fmt::Display for ContentDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.short())
    }
}

/// Accumulates fields into one digest, length-prefixing each so that
/// concatenation is unambiguous.
///
/// Without the prefix, `("ab", "c")` and `("a", "bc")` hash identically — for
/// a cache key spanning tenant, prompt and message text, that is a
/// cross-tenant collision waiting for the right pair of inputs.
#[derive(Debug, Default)]
pub struct DigestBuilder {
    hasher: Sha256,
}

impl DigestBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Absorb one field.
    pub fn field(mut self, bytes: &[u8]) -> Self {
        self.hasher.update((bytes.len() as u64).to_be_bytes());
        self.hasher.update(bytes);
        self
    }

    /// Absorb one text field.
    pub fn text(self, text: &str) -> Self {
        self.field(text.as_bytes())
    }

    /// Absorb an optional text field. `None` and `Some("")` are deliberately
    /// distinct: an absent system prompt is not an empty one.
    pub fn optional_text(self, text: Option<&str>) -> Self {
        match text {
            Some(text) => self.text("some").text(text),
            None => self.text("none"),
        }
    }

    pub fn finish(self) -> ContentDigest {
        ContentDigest(self.hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_bytes_hash_the_same_and_different_bytes_do_not() {
        assert_eq!(
            ContentDigest::of(b"prompt-v1"),
            ContentDigest::of(b"prompt-v1")
        );
        assert_ne!(
            ContentDigest::of(b"prompt-v1"),
            ContentDigest::of(b"prompt-v2")
        );
        assert_eq!(ContentDigest::of(b"x").to_hex().len(), 64);
        assert_eq!(ContentDigest::of(b"x").short().len(), 12);
    }

    /// The reason fields are length-prefixed: without it, a cache key built
    /// from (customer, prompt) would collide across a shifted boundary — two
    /// different tenants' requests hashing alike.
    #[test]
    fn field_boundaries_are_unambiguous() {
        let a = DigestBuilder::new().text("ab").text("c").finish();
        let b = DigestBuilder::new().text("a").text("bc").finish();
        assert_ne!(a, b, "concatenation must not be reinterpretable");
    }

    #[test]
    fn an_absent_field_differs_from_an_empty_one() {
        let absent = DigestBuilder::new().optional_text(None).finish();
        let empty = DigestBuilder::new().optional_text(Some("")).finish();
        assert_ne!(absent, empty);
    }
}
