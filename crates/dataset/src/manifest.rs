//! [`DatasetManifest`] — the artefact that makes "reproducible by
//! construction" a claim you can *check*.
//!
//! Determinism is asserted three times over in this pipeline (the store's
//! immutable total order, `ml-features`' cross-platform bit-determinism, a
//! join that reads no clock and no random id), but an assertion nobody
//! evaluates is a comment. The manifest turns it into a comparison: every
//! export emits one, and its [`content_hash`](DatasetManifest::content_hash)
//! covers the **rows** — so two exports of the same spec produce the same
//! hash, and a change in the extractor, the label rule, or the stored events
//! moves it.
//!
//! What the hash deliberately does *not* cover: `generated_at`, the tool
//! version, and where the rows were written. Those describe the *run*, not the
//! dataset — folding them in would make every re-run "different" and the check
//! worthless.
//!
//! The manifest is also the model card's other half. A trained model cites a
//! `dataset_id` + `content_hash` + `feature_schema_hash`, and those three
//! resolve the exact rows, the exact schema, and the exact window it learned
//! from (§20.1, §20.5).

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::join::JoinStats;
use crate::row::RowDigest;
use crate::spec::DatasetSpec;

/// Everything one export run produced and everything it dropped.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatasetManifest {
    /// [`DatasetSpec::dataset_id`] — the identity of the dataset, independent
    /// of this particular run.
    pub dataset_id: String,
    /// The spec verbatim, so a re-run is a copy-paste.
    pub spec: DatasetSpec,
    /// The label rule that mapped outcomes to labels.
    pub label_rule: String,
    /// `FeatureSchema::content_hash` for the granularity exported — what a
    /// serving-time skew check (§20.5) compares against.
    pub feature_schema_hash: String,
    /// Feature names in vector order. The one place a consumer needs to look to
    /// interpret a bare `Array(Float64)`.
    pub feature_names: Vec<String>,
    /// Digest over the rows, in row order. **The reproducibility check.**
    pub content_hash: String,

    pub rows: RowCounts,
    /// What the replay's join saw — the numerator behind every exclusion.
    pub join: JoinStats,

    // ── run metadata, deliberately outside `content_hash` ──────────────
    /// When this run happened. Two runs of one spec differ here and nowhere
    /// else.
    pub generated_at: DateTime<Utc>,
    /// The exporting build, for the audit trail.
    pub tool_version: String,
}

/// Row-level accounting: what came out, and why everything else did not.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowCounts {
    /// Rows written.
    pub written: u64,
    /// Findings the label rule gave a label — the denominator for the
    /// drop-rate gate. Excludes findings with no ground truth, which are
    /// `unlabeled` rather than dropped.
    pub labeled: u64,
    /// Findings the label rule declined to label (see [`crate::label`]).
    pub unlabeled: u64,
    /// Findings dropped because their context fidelity was below
    /// `--min-fidelity`.
    pub below_min_fidelity: u64,
    /// Findings whose block the context source knew nothing about.
    pub no_context: u64,
    /// Labeled findings that produced no row because the context held none of
    /// their transactions (tx granularity only) — a partial reconstruction that
    /// happened to miss exactly the implicated txs.
    pub no_extractable_tx: u64,
    /// Findings seen only to resolve in-window outcomes — they fell in a
    /// shard's lookahead tail and belong to a later shard (or to no shard at
    /// all, past `to`). Never rows; counted so the totals reconcile.
    pub lookahead_only: u64,
    /// Rows by label, keyed by `"positive"`/`"negative"`. A `BTreeMap` so the
    /// serialised manifest is byte-stable.
    pub by_label: BTreeMap<String, u64>,
    /// Findings by outcome, including the excluded ones — the histogram that
    /// explains a small dataset.
    pub by_outcome: BTreeMap<String, u64>,
    /// Findings by context fidelity.
    pub by_fidelity: BTreeMap<String, u64>,
}

impl RowCounts {
    /// Increment a histogram bucket by name.
    pub(crate) fn bump(map: &mut BTreeMap<String, u64>, key: &str) {
        *map.entry(key.to_owned()).or_default() += 1;
    }

    /// Labeled findings that had ground truth but no usable context — the
    /// numerator of the selection-bias measure. All three paths correlate with
    /// busy blocks, which is why their *rate* matters and not just their count
    /// (see `ExportError::ExcessiveDrop`).
    pub fn dropped_for_context(&self) -> u64 {
        self.no_context + self.below_min_fidelity + self.no_extractable_tx
    }

    /// The share of labeled findings lost to a missing or too-weak context, in
    /// `[0, 1]`. Zero when nothing was labeled — an empty window is not a
    /// biased one.
    pub fn drop_fraction(&self) -> f64 {
        if self.labeled == 0 {
            return 0.0;
        }
        self.dropped_for_context() as f64 / self.labeled as f64
    }
}

impl DatasetManifest {
    /// Build a manifest for `rows`, computing the content hash over them.
    /// Build a manifest, consuming the running [`RowDigest`] the export folded
    /// its rows into. Taking the digest rather than the rows is what lets a
    /// sharded export finish without ever holding the whole dataset.
    pub fn new(
        spec: &DatasetSpec,
        feature_schema_hash: String,
        feature_names: Vec<String>,
        digest: RowDigest,
        counts: RowCounts,
        join: JoinStats,
    ) -> Self {
        Self {
            dataset_id: spec.dataset_id(),
            spec: spec.clone(),
            label_rule: spec.label_rule().to_owned(),
            feature_schema_hash,
            feature_names,
            content_hash: digest.finish(),
            rows: counts,
            join,
            generated_at: Utc::now(),
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    /// Whether two manifests describe the same dataset — same spec identity and
    /// same rows — ignoring when each was produced.
    ///
    /// This is the assertion the determinism test makes, and the check an
    /// operator runs after re-exporting a window they already have.
    pub fn describes_same_dataset(&self, other: &Self) -> bool {
        self.dataset_id == other.dataset_id
            && self.content_hash == other.content_hash
            && self.feature_schema_hash == other.feature_schema_hash
    }

    /// A short human summary for the CLI. Deliberately leads with the two
    /// numbers an operator checks first — how many rows, and the digest to
    /// compare against a previous run.
    pub fn summary(&self) -> String {
        let positives = self.rows.by_label.get("positive").copied().unwrap_or(0);
        let negatives = self.rows.by_label.get("negative").copied().unwrap_or(0);
        let mut out = format!(
            "dataset {id}\n  rows        {written} ({positives} positive / {negatives} negative)\n  \
             content     {hash}\n  schema      {schema} ({version}, {granularity}, {features} features)\n  \
             label rule  {rule}\n",
            id = self.dataset_id,
            written = self.rows.written,
            hash = self.content_hash,
            schema = self.feature_schema_hash,
            version = self.spec.feature_version,
            granularity = crate::spec::granularity_str(self.spec.granularity),
            features = self.feature_names.len(),
            rule = self.label_rule,
        );
        out.push_str(&format!(
            "  dropped     {unlabeled} unlabeled, {fidelity} below fidelity, \
             {no_ctx} without context, {no_tx} without an extractable tx\n",
            unlabeled = self.rows.unlabeled,
            fidelity = self.rows.below_min_fidelity,
            no_ctx = self.rows.no_context,
            no_tx = self.rows.no_extractable_tx,
        ));
        out.push_str("  outcomes    ");
        out.push_str(&histogram(&self.rows.by_outcome));
        out.push_str("\n  fidelity    ");
        out.push_str(&histogram(&self.rows.by_fidelity));
        out.push('\n');
        if self.join.ambiguous_bindings > 0 || self.join.binding_conflicts > 0 {
            out.push_str(&format!(
                "  bindings    {ambiguous} ambiguous ({corrected} repaired by incident), \
                 {conflicts} conflicting\n",
                ambiguous = self.join.ambiguous_bindings,
                corrected = self.join.corrected_bindings,
                conflicts = self.join.binding_conflicts,
            ));
        }
        out
    }
}

fn histogram(map: &BTreeMap<String, u64>) -> String {
    if map.is_empty() {
        return "—".to_owned();
    }
    map.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ctx::Fidelity;
    use crate::join::Binding;
    use crate::label::Label;
    use crate::row::{DatasetRow, RowDigest};
    use alloy_primitives::B256;
    use ml_features::Granularity;

    fn spec() -> DatasetSpec {
        DatasetSpec {
            chain: events::primitives::Chain::ETHEREUM,
            from: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            to: DateTime::from_timestamp(1_700_003_600, 0).unwrap(),
            feature_version: ml_features::FEATURE_VERSION,
            granularity: Granularity::Tx,
            min_fidelity: Fidelity::HeaderOnly,
            include_ambiguous: false,
            lookahead_secs: crate::spec::DEFAULT_LOOKAHEAD_SECS,
        }
    }

    fn row(seed: u128) -> DatasetRow {
        DatasetRow {
            dataset_id: spec().dataset_id(),
            trigger_event_id: uuid::Uuid::from_u128(seed),
            chain: 1,
            block_number: seed as u64,
            block_hash: B256::repeat_byte(seed as u8),
            occurred_at: DateTime::from_timestamp(1_700_000_100, 0).unwrap(),
            detector_id: "sandwich".into(),
            detector_version: "1.2.0".into(),
            detector_config_hash: "deadbeef".into(),
            tx_hash: None,
            alert_id: None,
            binding: Binding::Exact,
            fidelity: Fidelity::Enriched,
            feature_version: 1,
            granularity: "tx".into(),
            schema_hash: "0123".into(),
            features: vec![0.5],
            label: Label::Positive,
            outcome: "confirmed".into(),
            raw_confidence: 0.8,
            profit: 1.0,
            victim_loss: 0.0,
        }
    }

    fn manifest(rows: &[DatasetRow]) -> DatasetManifest {
        DatasetManifest::new(
            &spec(),
            "0123".to_owned(),
            vec!["f0".to_owned()],
            {
                let mut d = RowDigest::new();
                d.update_all(rows);
                d
            },
            RowCounts {
                written: rows.len() as u64,
                ..Default::default()
            },
            JoinStats::default(),
        )
    }

    #[test]
    fn two_runs_over_the_same_rows_describe_the_same_dataset() {
        let rows = vec![row(1), row(2)];
        let a = manifest(&rows);
        // A later run: same rows, different wall clock.
        let b = manifest(&rows);
        assert!(
            a.describes_same_dataset(&b),
            "generated_at must not be part of the dataset's identity"
        );
        assert_eq!(a.content_hash, b.content_hash);
    }

    #[test]
    fn a_changed_row_moves_the_content_hash() {
        let a = manifest(&[row(1), row(2)]);
        let mut changed = row(2);
        changed.features = vec![0.6];
        let b = manifest(&[row(1), changed]);
        assert_ne!(a.content_hash, b.content_hash);
        assert!(!a.describes_same_dataset(&b));
    }

    #[test]
    fn a_changed_schema_is_a_different_dataset_even_with_identical_rows() {
        let rows = vec![row(1)];
        let a = manifest(&rows);
        let mut b = manifest(&rows);
        b.feature_schema_hash = "ffff".into();
        assert!(!a.describes_same_dataset(&b));
    }

    #[test]
    fn the_manifest_round_trips_through_json() {
        let m = manifest(&[row(1)]);
        let back: DatasetManifest =
            serde_json::from_str(&serde_json::to_string(&m).expect("serialize"))
                .expect("deserialize");
        assert_eq!(back, m);
    }

    #[test]
    fn the_summary_leads_with_row_count_and_digest() {
        let mut counts = RowCounts {
            written: 2,
            ..Default::default()
        };
        RowCounts::bump(&mut counts.by_label, "positive");
        RowCounts::bump(&mut counts.by_outcome, "confirmed");
        RowCounts::bump(&mut counts.by_fidelity, "enriched");
        let m = DatasetManifest::new(
            &spec(),
            "0123".to_owned(),
            vec!["f0".to_owned()],
            {
                let mut d = RowDigest::new();
                d.update_all(&[row(1), row(2)]);
                d
            },
            counts,
            JoinStats::default(),
        );
        let summary = m.summary();
        assert!(summary.contains(&m.content_hash), "{summary}");
        assert!(summary.contains("rows        2"), "{summary}");
        assert!(summary.contains("confirmed=1"), "{summary}");
    }
}
