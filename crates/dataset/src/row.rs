//! [`DatasetRow`] — one labeled training example, plus the provenance that
//! makes it auditable and the digest that makes a dataset verifiable.
//!
//! A row is three things stacked:
//!
//! 1. **The example** — `features` (in schema order) and `label`. This is all a
//!    training job strictly needs.
//! 2. **The provenance** — which block, which detector build, which trigger
//!    event, which alert, under which `feature_version` and schema digest, at
//!    what context fidelity and binding strength. Enough to walk from any row
//!    back to the exact events that produced it (§4's audit trail), and enough
//!    for the §20.5 skew check to compare a serving-time vector against the
//!    schema this row was trained under.
//! 3. **The outcome metadata** — `outcome`, `profit`, `victim_loss`. Kept
//!    *beside* the label, deliberately never inside `features`: they are
//!    measured by simulation after the fact, so a model given them as input
//!    would be reading its own answer.
//!
//! # The label-leak rule
//!
//! Everything in `features` comes from `ml-features`, which extracts from a
//! `DetectionCtx` — a structure that carries no labels, no attribution and no
//! simulation results by construction (§6). Nothing in this module adds to that
//! vector. That is the whole guarantee, and it is why the feature column and
//! the provenance columns are separate fields rather than one flat map.

use alloy_primitives::B256;
use chrono::{DateTime, Utc};
use ml_features::FeatureVector;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ctx::Fidelity;
use crate::join::Binding;
use crate::label::{Label, Outcome};

/// One `(features, label)` row with its provenance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatasetRow {
    // ── identity ──────────────────────────────────────────────────────
    /// The spec that produced this row ([`crate::DatasetSpec::dataset_id`]) —
    /// what lets two datasets share a table without being confused.
    pub dataset_id: String,
    /// The `DetectorTriggered` envelope id this row was derived from. Together
    /// with `tx_hash` it is the row's natural key: re-exporting the same spec
    /// produces the same keys, which is what makes the ClickHouse table
    /// idempotent under a re-run.
    pub trigger_event_id: uuid::Uuid,

    // ── provenance ────────────────────────────────────────────────────
    pub chain: u64,
    pub block_number: u64,
    pub block_hash: B256,
    /// The trigger's `occurred_at` — the column a time-ordered train/test split
    /// cuts on. Using the *finding's* time rather than the export's is what
    /// keeps a split reproducible across re-runs.
    pub occurred_at: DateTime<Utc>,
    pub detector_id: String,
    pub detector_version: String,
    pub detector_config_hash: String,
    /// The transaction this row describes, for `Granularity::Tx`. `None` for a
    /// block-granularity row.
    pub tx_hash: Option<B256>,
    pub alert_id: Option<uuid::Uuid>,
    /// How the finding was tied to its alert ([`Binding`]) — recorded so a
    /// consumer can re-filter without re-exporting.
    pub binding: Binding,
    /// How faithful the context behind `features` was ([`Fidelity`]).
    pub fidelity: Fidelity,

    // ── the example ───────────────────────────────────────────────────
    pub feature_version: u32,
    pub granularity: String,
    /// `FeatureSchema::content_hash` — the digest a serving-side vector is
    /// compared against to detect training/serving skew (§20.5). Stored per row
    /// so the check needs nothing but the row.
    pub schema_hash: String,
    /// Feature values in schema order.
    pub features: Vec<f64>,

    // ── the label ─────────────────────────────────────────────────────
    pub label: Label,
    /// The outcome the label was derived from, as text — so a consumer can tell
    /// a refutation from a retraction without re-running the join.
    pub outcome: String,
    pub raw_confidence: f64,
    /// Simulation's measured figures when it confirmed. `0.0` when there were
    /// none: a negative example has no profit *by definition*, so a sentinel
    /// would be noise, not information.
    pub profit: f64,
    pub victim_loss: f64,
}

impl DatasetRow {
    /// Fold this row into a hasher, in a fixed field order, with floats hashed
    /// by their **bit pattern**.
    ///
    /// Bit-level hashing is the point: `ml-features` guarantees the same
    /// context yields the same bits on every platform (its `log10` is pinned to
    /// pure-Rust `libm` for exactly this reason), so a digest over the bits is
    /// a real equality check between two exports. A digest over formatted
    /// decimals would silently pass where the last ulp differs — the failure
    /// mode the pinning exists to prevent.
    pub fn hash_into(&self, hasher: &mut Sha256) {
        let mut field = |bytes: &[u8]| {
            // Length-prefix every field so no concatenation of two fields can
            // collide with a different split of the same bytes.
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        };
        field(self.dataset_id.as_bytes());
        field(self.trigger_event_id.as_bytes());
        field(&self.chain.to_le_bytes());
        field(&self.block_number.to_le_bytes());
        field(self.block_hash.as_slice());
        field(&self.occurred_at.timestamp_millis().to_le_bytes());
        field(self.detector_id.as_bytes());
        field(self.detector_version.as_bytes());
        field(self.detector_config_hash.as_bytes());
        field(self.tx_hash.as_ref().map_or(&[][..], |h| h.as_slice()));
        field(self.alert_id.as_ref().map_or(&[][..], |a| a.as_bytes()));
        field(self.binding.as_str().as_bytes());
        field(self.fidelity.as_str().as_bytes());
        field(&self.feature_version.to_le_bytes());
        field(self.granularity.as_bytes());
        field(self.schema_hash.as_bytes());
        field(&(self.features.len() as u64).to_le_bytes());
        for value in &self.features {
            field(&value.to_bits().to_le_bytes());
        }
        field(&[self.label.as_u8()]);
        field(self.outcome.as_bytes());
        field(&self.raw_confidence.to_bits().to_le_bytes());
        field(&self.profit.to_bits().to_le_bytes());
        field(&self.victim_loss.to_bits().to_le_bytes());
    }

    /// This row's own digest, hex-encoded — handy in a failure message when two
    /// exports disagree, so the diff names a row instead of just a total.
    pub fn content_hash(&self) -> String {
        let mut hasher = Sha256::new();
        self.hash_into(&mut hasher);
        alloy_primitives::hex::encode(hasher.finalize())
    }
}

/// The running digest of a dataset: SHA-256 over every row's fields, in row
/// order, hex-encoded at the end.
///
/// **Streaming, deliberately.** The digest is what makes an export checkable,
/// so it must not be the thing that forces the whole dataset into memory. Rows
/// are folded in as they are produced and then dropped, which is what lets
/// [`crate::export`] shard a large window and still finish with the digest the
/// unsharded run would have produced — shards feed the same hasher in window
/// order, so the value depends on the rows, never on how the work was sliced.
///
/// Order-sensitive on purpose. Row order *is* part of the dataset — it comes
/// from the store's total order, so a reproducible export reproduces it, and a
/// change in ordering is a change worth failing on rather than shrugging at.
///
/// The row count is folded in at [`finish`](Self::finish) rather than up front
/// (it isn't known until the end) and still pins the length, so no shorter
/// dataset can share a prefix and collide.
#[derive(Debug, Default)]
pub struct RowDigest {
    hasher: Sha256,
    rows: u64,
}

impl RowDigest {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one row in. Call in row order.
    pub fn update(&mut self, row: &DatasetRow) {
        row.hash_into(&mut self.hasher);
        self.rows += 1;
    }

    /// Fold a batch in, in order.
    pub fn update_all(&mut self, rows: &[DatasetRow]) {
        for row in rows {
            self.update(row);
        }
    }

    /// How many rows have been folded in.
    pub fn rows(&self) -> u64 {
        self.rows
    }

    /// The hex-encoded digest.
    pub fn finish(mut self) -> String {
        self.hasher.update(self.rows.to_le_bytes());
        alloy_primitives::hex::encode(self.hasher.finalize())
    }
}

/// The digest of a complete, in-memory dataset — [`RowDigest`] in one call, for
/// tests and callers that already hold every row.
pub fn content_hash(rows: &[DatasetRow]) -> String {
    let mut digest = RowDigest::new();
    digest.update_all(rows);
    digest.finish()
}

/// Assemble a row from an already-extracted vector plus its provenance. Takes
/// the pieces the export has to hand so the field-by-field construction lives
/// in one place instead of inline in the pipeline.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_row(
    dataset_id: &str,
    finding: &crate::join::Finding,
    tx_hash: Option<B256>,
    vector: &FeatureVector,
    schema_hash: &str,
    fidelity: Fidelity,
    label: Label,
    outcome: Outcome,
) -> DatasetRow {
    let (profit, victim_loss) = outcome.figures().unwrap_or((0.0, 0.0));
    DatasetRow {
        dataset_id: dataset_id.to_owned(),
        trigger_event_id: finding.trigger_event_id,
        chain: finding.chain.id(),
        block_number: finding.block.number,
        block_hash: finding.block.hash,
        occurred_at: finding.occurred_at,
        detector_id: finding.detector.id.clone(),
        detector_version: finding.detector.version.clone(),
        detector_config_hash: finding.detector.config_hash.clone(),
        tx_hash,
        alert_id: finding.alert_id.map(|a| a.0),
        binding: finding.binding,
        fidelity,
        feature_version: vector.feature_version().0,
        granularity: crate::spec::granularity_str(vector.granularity()).to_owned(),
        schema_hash: schema_hash.to_owned(),
        features: vector.values().to_vec(),
        label,
        outcome: outcome.as_str().to_owned(),
        raw_confidence: finding.raw_confidence.get(),
        profit,
        victim_loss,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> DatasetRow {
        DatasetRow {
            dataset_id: "abcd".into(),
            trigger_event_id: uuid::Uuid::from_u128(1),
            chain: 1,
            block_number: 42,
            block_hash: B256::repeat_byte(0xaa),
            occurred_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            detector_id: "sandwich".into(),
            detector_version: "1.2.0".into(),
            detector_config_hash: "deadbeef".into(),
            tx_hash: Some(B256::repeat_byte(1)),
            alert_id: Some(uuid::Uuid::from_u128(2)),
            binding: Binding::Exact,
            fidelity: Fidelity::Enriched,
            feature_version: 1,
            granularity: "tx".into(),
            schema_hash: "0123".into(),
            features: vec![0.25, 1.5, 0.0],
            label: Label::Positive,
            outcome: "confirmed".into(),
            raw_confidence: 0.8,
            profit: 100.0,
            victim_loss: 40.0,
        }
    }

    /// [`row`] with a distinguishing seed, for tests that need several
    /// non-identical rows.
    fn row_n(seed: u128) -> DatasetRow {
        DatasetRow {
            trigger_event_id: uuid::Uuid::from_u128(seed),
            block_number: seed as u64,
            ..row()
        }
    }

    #[test]
    fn the_digest_is_stable_and_order_sensitive() {
        let rows = vec![row(), {
            let mut r = row();
            r.trigger_event_id = uuid::Uuid::from_u128(9);
            r
        }];
        assert_eq!(content_hash(&rows), content_hash(&rows));

        let reversed: Vec<_> = rows.iter().rev().cloned().collect();
        assert_ne!(
            content_hash(&rows),
            content_hash(&reversed),
            "row order is part of the dataset — reordering must be visible"
        );
    }

    /// One "change exactly this field" edit, for the coverage test below.
    type Mutation = fn(&mut DatasetRow);

    #[test]
    fn every_field_participates_in_the_digest() {
        let base = row().content_hash();
        let mutations: &[Mutation] = &[
            |r| r.dataset_id = "other".into(),
            |r| r.trigger_event_id = uuid::Uuid::from_u128(7),
            |r| r.chain = 8453,
            |r| r.block_number = 43,
            |r| r.block_hash = B256::repeat_byte(0xbb),
            |r| r.occurred_at = Utc::now(),
            |r| r.detector_id = "arb".into(),
            |r| r.detector_version = "2.0.0".into(),
            |r| r.detector_config_hash = "feed".into(),
            |r| r.tx_hash = None,
            |r| r.alert_id = None,
            |r| r.binding = Binding::Ambiguous,
            |r| r.fidelity = Fidelity::HeaderOnly,
            |r| r.feature_version = 2,
            |r| r.granularity = "block".into(),
            |r| r.schema_hash = "4567".into(),
            |r| r.features = vec![0.25, 1.5],
            |r| r.features[0] = 0.26,
            |r| r.label = Label::Negative,
            |r| r.outcome = "refuted".into(),
            |r| r.raw_confidence = 0.81,
            |r| r.profit = 101.0,
            |r| r.victim_loss = 41.0,
        ];
        for mutate in mutations {
            let mut other = row();
            mutate(&mut other);
            assert_ne!(base, other.content_hash(), "unhashed field in {other:?}");
        }
    }

    #[test]
    fn floats_are_hashed_by_bits_so_a_one_ulp_difference_is_caught() {
        let mut a = row();
        let mut b = row();
        a.features[1] = 1.5;
        b.features[1] = f64::from_bits(1.5_f64.to_bits() + 1);
        assert_ne!(
            a.content_hash(),
            b.content_hash(),
            "the last ulp is exactly what the libm pinning protects; the digest must see it"
        );
    }

    #[test]
    fn negative_zero_and_zero_are_distinguished() {
        // A consequence of bit-hashing worth pinning: -0.0 == 0.0 numerically
        // but is a different bit pattern, so it is a different dataset. Any
        // extractor change that starts emitting -0.0 should be noticed.
        let mut a = row();
        let mut b = row();
        a.features[2] = 0.0;
        b.features[2] = -0.0;
        assert_ne!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn field_boundaries_cannot_be_shifted_between_adjacent_strings() {
        // Length-prefixing is what stops ("ab","c") hashing like ("a","bc").
        let mut a = row();
        let mut b = row();
        a.detector_id = "ab".into();
        a.detector_version = "c".into();
        b.detector_id = "a".into();
        b.detector_version = "bc".into();
        assert_ne!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn a_streamed_digest_equals_the_all_at_once_one_however_it_is_batched() {
        // The property sharding relies on: how the rows were sliced on the way
        // in must not change the dataset's identity.
        let rows: Vec<DatasetRow> = (1..=7).map(row_n).collect();
        let expected = content_hash(&rows);

        for chunk in [1usize, 2, 3, 7, 100] {
            let mut digest = RowDigest::new();
            for batch in rows.chunks(chunk) {
                digest.update_all(batch);
            }
            assert_eq!(digest.rows(), 7);
            assert_eq!(
                digest.finish(),
                expected,
                "batching in chunks of {chunk} must not move the digest"
            );
        }
    }

    #[test]
    fn the_row_count_is_pinned_so_a_prefix_cannot_collide() {
        let rows: Vec<DatasetRow> = (1..=4).map(row_n).collect();
        assert_ne!(
            content_hash(&rows[..3]),
            content_hash(&rows),
            "a shorter dataset that is a prefix of a longer one is still a different dataset"
        );
        assert_eq!(content_hash(&[]), content_hash(&[]));
    }

    #[test]
    fn a_row_round_trips_through_json() {
        let json = serde_json::to_string(&row()).expect("serialize");
        let back: DatasetRow = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, row());
    }
}
