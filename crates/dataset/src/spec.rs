//! [`DatasetSpec`] — the four things that define a dataset (§20.1).
//!
//! > *"A dataset is defined by `(time window, feature_version, label rule)` and
//! > materialized by replaying that window (§16) — reproducible byte-for-byte,
//! > because replay is."*
//!
//! This type is that sentence as a value. Everything an export does is a total
//! function of it plus the event store's (immutable) contents, so re-running
//! the same spec re-produces the same rows — the claim [`crate::manifest`]
//! turns into a checkable digest.
//!
//! The one thing deliberately *not* in the spec is the output destination: a
//! ClickHouse table and a Parquet file materialised from the same spec hold the
//! same rows, so where they were written must not change the dataset's
//! identity.

use chrono::{DateTime, Utc};
use events::primitives::Chain;
use ml_features::{FeatureVersion, Granularity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ctx::Fidelity;
use crate::label::LABEL_RULE_ID;

/// A window that cannot produce a dataset, caught before any I/O.
#[derive(Debug, thiserror::Error)]
pub enum SpecError {
    /// The window is empty or inverted. Half-open `[from, to)` means `from ==
    /// to` selects nothing — almost always a scripting bug, so it is refused
    /// rather than silently exporting zero rows.
    #[error("window must be non-empty and ordered: from ({from}) < to ({to})")]
    EmptyWindow {
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    },

    /// The requested `feature_version` has no extractor in this build. Refused
    /// at spec time (link-or-fail, the `DetectionPlan::link` discipline)
    /// instead of failing per-block halfway through an export.
    #[error(
        "feature version {version} is not registered in this build — a dataset must name a \
         version whose extractor still ships, so it stays reproducible (§20.1)"
    )]
    UnknownFeatureVersion { version: FeatureVersion },

    /// A zero lookahead truncates the labels of every finding near `to` (see
    /// [`DatasetSpec::lookahead_secs`]). Refused rather than silently produced,
    /// because the damage is invisible in the output: the rows that *should*
    /// have been positives simply are not there.
    #[error(
        "lookahead must be non-zero — with none, findings near the end of the window lose \
         their simulation outcome and are silently dropped, so the window's labels depend \
         on where it happens to end (§20.1)"
    )]
    NoLookahead,
}

/// Everything that defines *which* dataset an export produces.
///
/// Serialisable so it embeds verbatim in the manifest: a model card can cite
/// the exact spec its training data came from, and re-running it is a
/// copy-paste rather than an archaeology exercise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetSpec {
    /// The chain whose stream is replayed. Single-chain by design: features are
    /// block-relative and gas/price regimes differ per chain (§23), so mixing
    /// chains into one dataset silently mixes two distributions.
    pub chain: Chain,
    /// Inclusive lower bound on `occurred_at`.
    pub from: DateTime<Utc>,
    /// Exclusive upper bound — half-open so adjacent windows tile without
    /// overlap (the same convention as the replay API's own filters).
    pub to: DateTime<Utc>,
    /// Which frozen feature schema to extract under. Historical versions stay
    /// resolvable through `ml_features::extractor_for`, which is what lets an
    /// old dataset be regenerated after the current version has moved on.
    pub feature_version: FeatureVersion,
    /// Whether a row describes a whole block or one transaction in it.
    pub granularity: Granularity,
    /// Lowest context fidelity a row may be built from (see [`Fidelity`]).
    /// Rows below it are dropped and counted, never silently downgraded.
    pub min_fidelity: Fidelity,
    /// Whether to keep findings whose alert binding was ambiguous (see
    /// [`crate::join`]). Off by default: a mislabeled row is worse for a model
    /// than a missing one.
    pub include_ambiguous: bool,
    /// How far **past** `to` to keep reading events, purely to resolve the
    /// outcomes of findings inside the window.
    ///
    /// # Why this exists
    ///
    /// Without it, `[from, to)` tiles the *events* but not the *labels*. A
    /// `DetectorTriggered` near `to` has its `SimulationCompleted` land after
    /// `to`, so it reads as [`Outcome::Unresolved`] and is dropped — while the
    /// same trigger inside a longer window reads as `Confirmed`. That makes a
    /// finding's label a function of where the window happens to end, biases
    /// the loss toward the tail of every window, and means two adjacent
    /// windows do **not** compose into the one that spans them.
    ///
    /// With a lookahead, a finding's outcome is decided by events within
    /// `lookahead` of the finding itself, so the label is a property of the
    /// finding rather than of the window — which is what makes windows
    /// genuinely tile, and what lets [`crate::export`] shard a large window
    /// into sub-windows that reproduce the unsharded result exactly.
    ///
    /// # Choosing a value
    ///
    /// It is the maximum plausible trigger→outcome lifetime: the simulation
    /// queue's SLA plus the chain's finality depth (§7, §15). Past that a
    /// finding is `Unresolved` *by definition* rather than by accident.
    /// [`DEFAULT_LOOKAHEAD_SECS`] is a deliberately generous hour.
    ///
    /// Part of [`dataset_id`](Self::dataset_id) because it changes labels.
    /// Zero reproduces the old truncating behaviour and is refused by
    /// [`validate`](Self::validate).
    ///
    /// [`Outcome::Unresolved`]: crate::label::Outcome::Unresolved
    pub lookahead_secs: u64,
}

/// One hour: comfortably past simulation's queue SLA and Ethereum's ~13-minute
/// finality, without dragging a meaningful amount of extra stream through the
/// join.
pub const DEFAULT_LOOKAHEAD_SECS: u64 = 3_600;

impl DatasetSpec {
    /// Validate the window and pin the feature version to a shipped extractor.
    /// Every other entry point takes an already-validated spec, so nothing
    /// downstream re-checks.
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.from >= self.to {
            return Err(SpecError::EmptyWindow {
                from: self.from,
                to: self.to,
            });
        }
        if ml_features::extractor_for(self.feature_version).is_none() {
            return Err(SpecError::UnknownFeatureVersion {
                version: self.feature_version,
            });
        }
        if self.lookahead_secs == 0 {
            return Err(SpecError::NoLookahead);
        }
        Ok(())
    }

    /// The exclusive end of the range the replay actually *reads*: `to` plus
    /// the lookahead. Events between `to` and here resolve outcomes; they never
    /// contribute rows of their own.
    pub fn replay_end(&self) -> DateTime<Utc> {
        self.to + chrono::Duration::seconds(self.lookahead_secs as i64)
    }

    /// Whether a finding observed at `occurred_at` is one this dataset emits
    /// rows for — i.e. it fell inside `[from, to)` rather than in the lookahead
    /// tail that exists only to resolve outcomes.
    pub fn emits(&self, occurred_at: DateTime<Utc>) -> bool {
        occurred_at >= self.from && occurred_at < self.to
    }

    /// The label rule this build applies. Not a spec *field* because there is
    /// exactly one rule today and inventing a selector for a set of one would
    /// be speculative; it is stamped into [`dataset_id`](Self::dataset_id) and
    /// the manifest all the same, so a future second rule cannot be mistaken
    /// for this one after the fact.
    pub fn label_rule(&self) -> &'static str {
        LABEL_RULE_ID
    }

    /// A stable content id for this dataset: SHA-256 over the canonical spec
    /// text, hex-encoded (first 16 bytes — 128 bits, ample for an identifier
    /// nobody is attacking).
    ///
    /// Two specs that would materialise the same rows share an id; changing
    /// *any* field — including the filters that decide which rows are dropped —
    /// mints a new one. That is what makes a `dataset_id` column on a row
    /// meaningful: rows from two different specs can share a table without
    /// being mistaken for one dataset.
    pub fn dataset_id(&self) -> String {
        let mut hasher = Sha256::new();
        for part in [
            self.chain.id().to_string(),
            self.from.timestamp_millis().to_string(),
            self.to.timestamp_millis().to_string(),
            self.feature_version.to_string(),
            granularity_str(self.granularity).to_owned(),
            self.min_fidelity.as_str().to_owned(),
            self.include_ambiguous.to_string(),
            // In the id because it changes labels, not merely how many events
            // are read (see `lookahead_secs`).
            self.lookahead_secs.to_string(),
            self.label_rule().to_owned(),
        ] {
            hasher.update(part.as_bytes());
            hasher.update(b"\n");
        }
        alloy_primitives::hex::encode(&hasher.finalize()[..16])
    }
}

/// The wire name of a granularity. `Granularity`'s own `as_str` is
/// crate-private to `ml-features`, and its serde form is the same snake_case
/// text, so this reproduces it rather than widening that crate's API.
pub fn granularity_str(granularity: Granularity) -> &'static str {
    match granularity {
        Granularity::Block => "block",
        Granularity::Tx => "tx",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("valid timestamp")
    }

    fn spec() -> DatasetSpec {
        DatasetSpec {
            chain: Chain::ETHEREUM,
            from: at(1_700_000_000),
            to: at(1_700_003_600),
            feature_version: ml_features::FEATURE_VERSION,
            granularity: Granularity::Tx,
            min_fidelity: Fidelity::HeaderOnly,
            include_ambiguous: false,
            lookahead_secs: DEFAULT_LOOKAHEAD_SECS,
        }
    }

    #[test]
    fn a_well_formed_spec_validates() {
        spec().validate().expect("valid");
    }

    #[test]
    fn a_zero_lookahead_is_refused_because_its_damage_is_invisible() {
        let mut s = spec();
        s.lookahead_secs = 0;
        assert!(matches!(s.validate(), Err(SpecError::NoLookahead)));
    }

    #[test]
    fn the_replay_reads_past_to_but_only_emits_inside_the_window() {
        let s = spec();
        assert_eq!(
            s.replay_end(),
            s.to + chrono::Duration::seconds(DEFAULT_LOOKAHEAD_SECS as i64)
        );

        assert!(s.emits(s.from), "the lower bound is inclusive");
        assert!(s.emits(s.to - chrono::Duration::seconds(1)));
        assert!(
            !s.emits(s.to),
            "the upper bound is exclusive, so windows tile"
        );
        assert!(
            !s.emits(s.to + chrono::Duration::seconds(1)),
            "a finding in the lookahead tail resolves outcomes but is not itself a row"
        );
        assert!(!s.emits(s.from - chrono::Duration::seconds(1)));
    }

    #[test]
    fn adjacent_windows_share_a_boundary_without_double_emitting_it() {
        // The property the lookahead exists to protect: split [from, to) at any
        // point and every instant is emitted by exactly one of the halves.
        let whole = spec();
        let mid = whole.from + chrono::Duration::seconds(1_800);
        let first = DatasetSpec {
            to: mid,
            ..whole.clone()
        };
        let second = DatasetSpec {
            from: mid,
            ..whole.clone()
        };

        for offset in [0, 1, 1_799, 1_800, 1_801, 3_599] {
            let at = whole.from + chrono::Duration::seconds(offset);
            assert_eq!(
                usize::from(first.emits(at)) + usize::from(second.emits(at)),
                usize::from(whole.emits(at)),
                "instant +{offset}s must be emitted by exactly as many halves as the whole"
            );
        }
    }

    #[test]
    fn an_empty_or_inverted_window_is_refused_before_any_io() {
        let mut s = spec();
        s.to = s.from;
        assert!(matches!(s.validate(), Err(SpecError::EmptyWindow { .. })));

        s.to = at(1_699_000_000);
        assert!(matches!(s.validate(), Err(SpecError::EmptyWindow { .. })));
    }

    #[test]
    fn an_unshipped_feature_version_fails_at_spec_time_not_mid_export() {
        let mut s = spec();
        s.feature_version = FeatureVersion(9_999);
        assert!(matches!(
            s.validate(),
            Err(SpecError::UnknownFeatureVersion { .. })
        ));
    }

    /// One "change exactly this field" edit, for the coverage test below.
    type Mutation = fn(&mut DatasetSpec);

    #[test]
    fn dataset_id_is_stable_and_covers_every_field() {
        let base = spec();
        assert_eq!(base.dataset_id(), base.dataset_id(), "stable across calls");

        // Each field that changes which rows are produced must move the id.
        let mutations: &[Mutation] = &[
            |s| s.chain = Chain(8453),
            |s| s.from = at(1_700_000_001),
            |s| s.to = at(1_700_003_601),
            |s| s.granularity = Granularity::Block,
            |s| s.min_fidelity = Fidelity::Enriched,
            |s| s.include_ambiguous = true,
            |s| s.lookahead_secs = DEFAULT_LOOKAHEAD_SECS * 2,
        ];
        for mutate in mutations {
            let mut other = spec();
            mutate(&mut other);
            assert_ne!(
                base.dataset_id(),
                other.dataset_id(),
                "a spec change must mint a new dataset id: {other:?}"
            );
        }
    }

    #[test]
    fn spec_round_trips_through_json_for_the_manifest() {
        let json = serde_json::to_string(&spec()).expect("serialize");
        let back: DatasetSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, spec());
    }
}
