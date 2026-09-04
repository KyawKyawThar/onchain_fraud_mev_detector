//! Canonical fingerprints of a read model's persisted contents — the "assert
//! byte-identical" half of a projection rebuild (readiness Epic B).
//!
//! ## Why a digest and not `SELECT * EXCEPT … EXCEPT …` on both sides
//!
//! The comparison has to survive a table with millions of rows, run against a
//! *live* database, and — when it fails — say **which row** diverged. Streaming
//! both sides into memory does none of those. So a read model is fingerprinted
//! as a map of `row key → SHA-256 of that row's canonical encoding`
//! ([`ModelDigest`]): one pass, bounded per-row cost, and a mismatch is a set
//! difference that names the offending keys ([`ModelDigest::diff`]).
//!
//! ## What "byte-identical" is allowed to mean
//!
//! Not every column is derived. `incidents.updated_at`, `sim_jobs.updated_at`
//! and `incident_analytics.appended_at` are **ingest-time bookkeeping** — they
//! record when *this process* wrote the row, and a rebuild that reproduced them
//! would be reproducing a clock, not a projection. They are excluded from the
//! encoding, by name, and each read model's docs must list what it excluded.
//! Everything else — every value a query can return to a customer — is in.
//!
//! Excluding a column is therefore a **weakening of the proof**, and the rule
//! is: a column is excluded only if it is a function of wall-clock time at
//! write, never of the events. If you find yourself wanting to exclude a column
//! because "it comes out different", that is the finding, not the fix.
//!
//! ## Encoding rules (why floats are hashed as bits)
//!
//! Fields are **length-prefixed** before hashing, so `("ab", "c")` and
//! `("a", "bc")` cannot collide — the same reason
//! [`llm::digest::DigestBuilder`](../../llm/src/digest.rs) prefixes.
//! `f64` is absorbed as its raw `to_bits()` big-endian bytes rather than a
//! formatted string: the workspace has already been bitten once by exact
//! equality over round-tripped floats, and a digest that depends on
//! `{}`-formatting would report a divergence for two values that are the same
//! number. `NaN` is normalised to one bit pattern so it hashes stably (it is
//! still never *equal* to itself in Rust, which is exactly why it must not be
//! compared as a float here).

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

/// SHA-256 of a canonical encoding, rendered as hex.
///
/// A separate type from `detection::ConfigHash` / `llm::digest::ContentDigest`
/// (and the two `content_hash`es in `ml-features`/`inference`) only because
/// none of those sits in a crate this one can depend on without inverting the
/// dependency graph. If a shared hashing primitive is ever promoted out of
/// `llm`, this is one of its call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RowDigest([u8; 32]);

impl RowDigest {
    /// Full 64-character lowercase hex — the form that goes into a report, a
    /// log line, or a runbook paste.
    pub fn to_hex(self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    /// The first 12 hex characters, for logs. Never for identity.
    pub fn short(self) -> String {
        self.to_hex().chars().take(12).collect()
    }
}

impl std::fmt::Display for RowDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.short())
    }
}

/// Accumulates a row's derived fields into one digest, length-prefixing each so
/// concatenation is unambiguous.
///
/// The call order **is** the encoding: two read-model implementations that
/// absorb the same columns in different orders produce different digests, which
/// is fine (a digest is only ever compared against another digest of the *same*
/// model) but means a change to a `row_digest` function invalidates every
/// baseline taken before it. That is intentional — the encoding is part of the
/// projection's definition, and a silent re-ordering that still compared equal
/// would be the bug.
#[derive(Debug, Default)]
pub struct RowEncoder {
    hasher: Sha256,
}

impl RowEncoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Absorb one raw field, length-prefixed.
    pub fn field(mut self, bytes: &[u8]) -> Self {
        self.hasher.update((bytes.len() as u64).to_be_bytes());
        self.hasher.update(bytes);
        self
    }

    /// Absorb a text field.
    pub fn text(self, text: &str) -> Self {
        self.field(text.as_bytes())
    }

    /// Absorb an optional text field. `None` and `Some("")` stay distinct — an
    /// absent retraction reason is not an empty one.
    pub fn optional_text(self, text: Option<&str>) -> Self {
        match text {
            Some(text) => self.text("some").text(text),
            None => self.text("none"),
        }
    }

    /// Absorb an integer.
    pub fn int(self, value: i64) -> Self {
        self.field(&value.to_be_bytes())
    }

    /// Absorb an optional integer.
    pub fn optional_int(self, value: Option<i64>) -> Self {
        match value {
            Some(value) => self.text("some").int(value),
            None => self.text("none"),
        }
    }

    /// Absorb a float **as its bit pattern**, not as text — see the module docs.
    /// `NaN` is normalised to a single canonical payload so it hashes stably.
    pub fn float(self, value: f64) -> Self {
        let bits = if value.is_nan() {
            f64::NAN.to_bits()
        } else {
            // `-0.0` and `0.0` are the same number; without this they hash apart
            // and a rebuild that produced `0.0` where the live row held `-0.0`
            // would be reported as a divergence it is not.
            (value + 0.0).to_bits()
        };
        self.field(&bits.to_be_bytes())
    }

    /// Absorb an optional float.
    pub fn optional_float(self, value: Option<f64>) -> Self {
        match value {
            Some(value) => self.text("some").float(value),
            None => self.text("none"),
        }
    }

    /// Absorb an ordered sequence of text values (e.g. an incident's `txs`).
    /// The count is absorbed first so `["a"]` and `["a", ""]` differ.
    pub fn text_seq<'a>(self, values: impl IntoIterator<Item = &'a str>) -> Self {
        let values: Vec<&str> = values.into_iter().collect();
        let mut encoder = self.int(values.len() as i64);
        for value in values {
            encoder = encoder.text(value);
        }
        encoder
    }

    /// Absorb a timestamp at the storage column's own resolution
    /// (**milliseconds** — `TIMESTAMPTZ` round-trips finer than
    /// `DateTime64(3)`, and a digest must not depend on which store a value came
    /// back from).
    pub fn timestamp(self, at: chrono::DateTime<chrono::Utc>) -> Self {
        self.int(at.timestamp_millis())
    }

    /// Absorb an optional timestamp.
    pub fn optional_timestamp(self, at: Option<chrono::DateTime<chrono::Utc>>) -> Self {
        match at {
            Some(at) => self.text("some").timestamp(at),
            None => self.text("none"),
        }
    }

    pub fn finish(self) -> RowDigest {
        RowDigest(self.hasher.finalize().into())
    }
}

/// A whole read model's fingerprint: every row, keyed by its stable business
/// key, in sorted order.
///
/// Keys are namespaced by the operator's own convention when one model spans
/// several tables (`"incidents/<alert_id>"`, `"sim_jobs/<alert_id>"`), so a
/// [`diff`](Self::diff) points at a table as well as a row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModelDigest {
    rows: BTreeMap<String, RowDigest>,
}

impl ModelDigest {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one row. A duplicate key is a caller bug (two rows claiming the
    /// same business key), so it is reported rather than silently overwritten.
    pub fn insert(&mut self, key: impl Into<String>, digest: RowDigest) -> Result<(), String> {
        let key = key.into();
        if self.rows.insert(key.clone(), digest).is_some() {
            return Err(key);
        }
        Ok(())
    }

    /// How many rows the model holds.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The single hash that stands for "this read model, exactly" — over the
    /// sorted `(key, row digest)` pairs, so it is independent of the order rows
    /// came back from storage. Two models are byte-identical iff their roots
    /// match.
    pub fn root(&self) -> RowDigest {
        let mut encoder = RowEncoder::new().int(self.rows.len() as i64);
        for (key, digest) in &self.rows {
            encoder = encoder.text(key).field(&digest.0);
        }
        encoder.finish()
    }

    /// Set-difference against another digest, from the perspective of `self`
    /// being the *before* (live) state and `other` the *after* (rebuilt) state.
    pub fn diff(&self, other: &ModelDigest) -> Divergence {
        let mut divergence = Divergence::default();
        for (key, digest) in &self.rows {
            match other.rows.get(key) {
                None => divergence.lost.push(key.clone()),
                Some(rebuilt) if rebuilt != digest => divergence.changed.push(key.clone()),
                Some(_) => {}
            }
        }
        for key in other.rows.keys() {
            if !self.rows.contains_key(key) {
                divergence.gained.push(key.clone());
            }
        }
        divergence
    }
}

/// What a rebuild changed. Empty on every count means the read model was
/// exactly reproduced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Divergence {
    /// Present live, absent after the rebuild — the event store does not
    /// contain what produced this row. The most serious of the three: either an
    /// event was never appended (an audit-completeness hole, Bucket 1) or the
    /// row was written by something other than the projection.
    pub lost: Vec<String>,
    /// Absent live, present after the rebuild — the live projection dropped a
    /// write it should have made (e.g. a store fault between two writes of the
    /// same event), or the row was deleted out of band.
    pub gained: Vec<String>,
    /// Present on both sides with different content — the fold and the stored
    /// row disagree. Usually a projection-logic change deployed without a
    /// rebuild.
    pub changed: Vec<String>,
}

impl Divergence {
    /// Whether the two digests agreed on every row.
    pub fn is_identical(&self) -> bool {
        self.lost.is_empty() && self.gained.is_empty() && self.changed.is_empty()
    }

    /// Total number of diverging keys.
    pub fn len(&self) -> usize {
        self.lost.len() + self.gained.len() + self.changed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.is_identical()
    }

    /// A bounded, human-readable summary — at most `max` keys per category, so
    /// a wholly-diverged model does not print a million lines into a terminal
    /// during an incident.
    pub fn summarize(&self, max: usize) -> String {
        fn list(label: &str, keys: &[String], max: usize) -> String {
            if keys.is_empty() {
                return String::new();
            }
            let shown: Vec<&str> = keys.iter().take(max).map(String::as_str).collect();
            let more = keys.len().saturating_sub(shown.len());
            let suffix = if more > 0 {
                format!(" (+{more} more)")
            } else {
                String::new()
            };
            format!("\n  {label} ({}): {}{suffix}", keys.len(), shown.join(", "))
        }

        if self.is_identical() {
            return "identical".to_string();
        }
        format!(
            "{} diverging row(s){}{}{}",
            self.len(),
            list("lost (live only)", &self.lost, max),
            list("gained (rebuild only)", &self.gained, max),
            list("changed", &self.changed, max),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(profit: f64) -> RowDigest {
        RowEncoder::new().text("row").float(profit).finish()
    }

    #[test]
    fn the_same_fields_hash_the_same_and_different_fields_do_not() {
        assert_eq!(digest(1.5), digest(1.5));
        assert_ne!(digest(1.5), digest(1.6));
        assert_eq!(digest(1.5).to_hex().len(), 64);
    }

    /// The reason fields are length-prefixed: without it a shifted boundary
    /// between two adjacent text columns hashes identically, so a row whose
    /// `kind`/`severity` split moved would compare equal.
    #[test]
    fn field_boundaries_are_unambiguous() {
        let a = RowEncoder::new().text("sandwich").text("high").finish();
        let b = RowEncoder::new().text("sandwichh").text("igh").finish();
        assert_ne!(a, b);
    }

    #[test]
    fn an_absent_field_differs_from_an_empty_or_zero_one() {
        assert_ne!(
            RowEncoder::new().optional_text(None).finish(),
            RowEncoder::new().optional_text(Some("")).finish()
        );
        assert_ne!(
            RowEncoder::new().optional_float(None).finish(),
            RowEncoder::new().optional_float(Some(0.0)).finish()
        );
    }

    /// `-0.0 == 0.0` is true in arithmetic and in Postgres; a digest that
    /// disagreed would report a rebuild as diverged over a sign bit.
    #[test]
    fn negative_zero_hashes_as_zero_and_nan_hashes_stably() {
        assert_eq!(digest(0.0), digest(-0.0));
        assert_eq!(digest(f64::NAN), digest(f64::NAN));
        assert_ne!(digest(f64::NAN), digest(0.0));
    }

    #[test]
    fn a_sequence_absorbs_its_length_so_a_boundary_shift_is_visible() {
        let a = RowEncoder::new().text_seq(["0xaa", "0xbb"]).finish();
        let b = RowEncoder::new().text_seq(["0xaa0xbb"]).finish();
        assert_ne!(a, b);
    }

    #[test]
    fn the_root_is_order_independent_but_content_sensitive() {
        let mut first = ModelDigest::new();
        first.insert("incidents/b", digest(2.0)).unwrap();
        first.insert("incidents/a", digest(1.0)).unwrap();

        let mut second = ModelDigest::new();
        second.insert("incidents/a", digest(1.0)).unwrap();
        second.insert("incidents/b", digest(2.0)).unwrap();

        assert_eq!(first.root(), second.root(), "row order must not matter");
        assert!(first.diff(&second).is_identical());

        let mut third = ModelDigest::new();
        third.insert("incidents/a", digest(1.0)).unwrap();
        third.insert("incidents/b", digest(9.0)).unwrap();
        assert_ne!(first.root(), third.root());
    }

    #[test]
    fn a_diff_classifies_each_kind_of_divergence() {
        let mut live = ModelDigest::new();
        live.insert("incidents/a", digest(1.0)).unwrap();
        live.insert("incidents/b", digest(2.0)).unwrap();

        let mut rebuilt = ModelDigest::new();
        rebuilt.insert("incidents/a", digest(1.0)).unwrap();
        rebuilt.insert("incidents/c", digest(3.0)).unwrap();

        let divergence = live.diff(&rebuilt);
        assert_eq!(divergence.lost, vec!["incidents/b".to_string()]);
        assert_eq!(divergence.gained, vec!["incidents/c".to_string()]);
        assert!(divergence.changed.is_empty());
        assert!(!divergence.is_identical());

        let mut changed = ModelDigest::new();
        changed.insert("incidents/a", digest(1.0)).unwrap();
        changed.insert("incidents/b", digest(99.0)).unwrap();
        assert_eq!(
            live.diff(&changed).changed,
            vec!["incidents/b".to_string()],
            "same key, different content"
        );
    }

    #[test]
    fn a_duplicate_row_key_is_reported_not_swallowed() {
        let mut model = ModelDigest::new();
        model.insert("incidents/a", digest(1.0)).unwrap();
        assert_eq!(
            model.insert("incidents/a", digest(2.0)),
            Err("incidents/a".to_string())
        );
    }

    #[test]
    fn a_summary_is_bounded_regardless_of_how_far_apart_the_sides_are() {
        let divergence = Divergence {
            lost: (0..1000).map(|i| format!("incidents/{i}")).collect(),
            ..Default::default()
        };
        let summary = divergence.summarize(3);
        assert!(summary.contains("+997 more"), "{summary}");
        assert!(summary.lines().count() <= 2, "{summary}");
    }
}
