//! The label rule (§20.1) — how a replayed outcome becomes a training label.
//!
//! > *"`DetectorTriggered` joined to its `SimulationCompleted` outcome.
//! > `confirmed: true` with measured profit is a positive; a retraction or
//! > failed confirmation is a hard negative."*
//!
//! The rule is a **total function of an [`Outcome`]**, and the outcome is
//! decided by [`crate::join`] from the event stream alone. Splitting it this
//! way is deliberate: the join owns "what happened to this finding" (a
//! question about events), and this module owns "what does that make it" (a
//! question about training). A second label rule later is a new
//! [`LABEL_RULE_ID`] over the same outcomes, not a second replay.
//!
//! ## Why several outcomes yield *no* label
//!
//! Four of the seven outcomes are excluded rather than labeled, each for a
//! different reason, and all four are counted in the manifest so a small
//! dataset is explainable rather than mysterious:
//!
//! - [`Outcome::Unalerted`] — a `Shadow`/`Deprecated` detector emits its
//!   `DetectorTriggered` but no alert (`detection::emit::evidence_events`), so
//!   nothing ever simulates it. There is no ground truth to be had, not a
//!   negative one.
//! - [`Outcome::Unresolved`] — the trigger's simulation had not completed by
//!   the window's end. This is *window truncation*, not a refutation; labeling
//!   it negative would teach a model that late confirmations are false.
//! - [`Outcome::Reverted`] — the block was orphaned by a reorg (§15). The
//!   features describe a block that is not on the canonical chain, so the row
//!   is dropped whatever the simulation said.
//! - [`Outcome::Unlinkable`] — the finding could not be tied to an alert with
//!   enough confidence to trust the label (see `join::Binding`). A mislabeled
//!   row is worse than a missing one.

use serde::{Deserialize, Serialize};

/// The identifier of the label rule implemented here, stamped into every
/// dataset id and manifest. Bump the suffix (never edit the semantics in
/// place) when the mapping below changes — an old dataset must stay
/// interpretable under the rule that produced it, exactly as a
/// `FeatureVersion` keeps its schema interpretable.
pub const LABEL_RULE_ID: &str = "sim-outcome-v1";

/// What the replay found happened to one `DetectorTriggered`.
///
/// Ordered from "we know it was right" to "we cannot say", which is also the
/// order [`LabelRule::apply`] reads best in.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum Outcome {
    /// Simulation confirmed the finding, with revm-measured figures (§7).
    Confirmed { profit: f64, victim_loss: f64 },
    /// Simulation ran and did *not* confirm — the flywheel's hard negative.
    Refuted,
    /// Simulation confirmed, but the incident was later withdrawn (§7/§15) —
    /// also a hard negative, and a more informative one: something about the
    /// finding survived simulation and still turned out wrong.
    Retracted,
    /// The finding's block was orphaned by a reorg (§15).
    Reverted,
    /// No alert was raised, so nothing simulated it (a `Shadow` detector).
    Unalerted,
    /// An alert was raised but no `SimulationCompleted` for it appears in the
    /// window — almost always the window ending mid-flight.
    Unresolved,
    /// The finding could not be tied to its alert unambiguously.
    Unlinkable,
}

impl Outcome {
    /// Stable snake_case name for the row's `outcome` column and the manifest
    /// histogram. Hand-written rather than derived so the column values are
    /// obviously stable text a dashboard can group by.
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Confirmed { .. } => "confirmed",
            Outcome::Refuted => "refuted",
            Outcome::Retracted => "retracted",
            Outcome::Reverted => "reverted",
            Outcome::Unalerted => "unalerted",
            Outcome::Unresolved => "unresolved",
            Outcome::Unlinkable => "unlinkable",
        }
    }

    /// The simulated `(profit, victim_loss)` if there were any. Carried onto
    /// the row as *metadata*, never as a feature: they are measured after the
    /// fact and would leak the label straight into the model's input.
    pub fn figures(self) -> Option<(f64, f64)> {
        match self {
            Outcome::Confirmed {
                profit,
                victim_loss,
            } => Some((profit, victim_loss)),
            _ => None,
        }
    }
}

/// A training label. Binary by design — the flywheel's ground truth is
/// "simulation agreed" / "simulation disagreed", and inventing a third class
/// out of exclusions would smuggle window artefacts into the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Label {
    Positive,
    Negative,
}

impl Label {
    /// The numeric encoding written to ClickHouse/Parquet: the conventional
    /// `1`/`0` a classifier trains against directly.
    pub fn as_u8(self) -> u8 {
        match self {
            Label::Positive => 1,
            Label::Negative => 0,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Label::Positive => "positive",
            Label::Negative => "negative",
        }
    }
}

/// The [`LABEL_RULE_ID`] rule. A unit struct rather than free functions so a
/// future second rule is a second type behind the same call, and every call
/// site already names which rule it applied.
#[derive(Debug, Clone, Copy, Default)]
pub struct LabelRule;

impl LabelRule {
    /// Map an outcome to its label, or `None` for the four outcomes that carry
    /// no honest ground truth (see the module docs).
    ///
    /// A confirmation with non-positive measured profit is **still a
    /// positive**: `confirmed` is simulation's verdict on whether the pattern
    /// is real, and a real sandwich that netted its searcher nothing is a real
    /// sandwich. Re-deciding that here from the figures would quietly override
    /// the slow path's judgement with a threshold nobody agreed on; a training
    /// job that wants a profit floor has `profit` on the row and can apply one
    /// explicitly.
    pub fn apply(self, outcome: Outcome) -> Option<Label> {
        match outcome {
            Outcome::Confirmed { .. } => Some(Label::Positive),
            Outcome::Refuted | Outcome::Retracted => Some(Label::Negative),
            Outcome::Reverted | Outcome::Unalerted | Outcome::Unresolved | Outcome::Unlinkable => {
                None
            }
        }
    }

    pub fn id(self) -> &'static str {
        LABEL_RULE_ID
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmation_is_positive_regardless_of_measured_profit() {
        for profit in [1_000.0, 0.0, -5.0] {
            assert_eq!(
                LabelRule.apply(Outcome::Confirmed {
                    profit,
                    victim_loss: 0.0
                }),
                Some(Label::Positive),
                "confirmed is simulation's verdict, not a profit threshold (profit {profit})"
            );
        }
    }

    #[test]
    fn refutation_and_retraction_are_both_hard_negatives() {
        assert_eq!(LabelRule.apply(Outcome::Refuted), Some(Label::Negative));
        assert_eq!(LabelRule.apply(Outcome::Retracted), Some(Label::Negative));
    }

    #[test]
    fn the_four_no_ground_truth_outcomes_are_excluded_not_defaulted_to_negative() {
        for outcome in [
            Outcome::Reverted,
            Outcome::Unalerted,
            Outcome::Unresolved,
            Outcome::Unlinkable,
        ] {
            assert_eq!(
                LabelRule.apply(outcome),
                None,
                "{} must be excluded — it is an absence of ground truth, not a negative one",
                outcome.as_str()
            );
        }
    }

    #[test]
    fn outcome_names_are_distinct_so_the_manifest_histogram_is_unambiguous() {
        let names = [
            Outcome::Confirmed {
                profit: 0.0,
                victim_loss: 0.0,
            },
            Outcome::Refuted,
            Outcome::Retracted,
            Outcome::Reverted,
            Outcome::Unalerted,
            Outcome::Unresolved,
            Outcome::Unlinkable,
        ]
        .map(Outcome::as_str);
        let unique: std::collections::BTreeSet<_> = names.iter().collect();
        assert_eq!(unique.len(), names.len(), "{names:?}");
    }

    #[test]
    fn only_a_confirmation_carries_figures() {
        assert_eq!(
            Outcome::Confirmed {
                profit: 12.5,
                victim_loss: 3.0
            }
            .figures(),
            Some((12.5, 3.0))
        );
        assert_eq!(Outcome::Refuted.figures(), None);
        assert_eq!(Outcome::Retracted.figures(), None);
    }
}
