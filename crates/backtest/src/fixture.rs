//! [`Fixture`] — one backtest scenario: a sequence of historical blocks plus
//! the ground-truth incidents the detector roster is expected to catch on them
//! (§18, Sprint 10 t2).

use detector_api::{DetectionCtx, DetectorId};
use events::primitives::AlertKind;

/// One known incident a fixture's blocks are labeled with — the ground truth a
/// replay is scored against.
///
/// `detector` names the specific detector expected to catch it (not just the
/// [`AlertKind`], which several future detectors could in principle share), so a
/// miss is attributable to exactly one detector's recall and an unexplained
/// alert from a *different* detector on the same block still counts as that
/// detector's false positive. Typed as the same [`DetectorId`] every detector
/// crate, the registry and the feature-flag seam already use, rather than a
/// bare string, so a fixture names a detector the same way the rest of the
/// system does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedIncident {
    /// The block the incident's alert should be raised on.
    pub block: u64,
    pub detector: DetectorId,
    pub kind: AlertKind,
    /// Human-readable context, surfaced in the report on a miss.
    pub description: &'static str,
}

impl ExpectedIncident {
    pub fn new(
        block: u64,
        detector: DetectorId,
        kind: AlertKind,
        description: &'static str,
    ) -> Self {
        Self {
            block,
            detector,
            kind,
            description,
        }
    }
}

/// A named backtest scenario: consecutive blocks, in order, replayed through the
/// roster, plus the incidents ground-truthed on them.
///
/// Most scenarios are one block; wash-trading (the one `Scope::CrossBlock`
/// detector) needs the several leading blocks that build its trailing window
/// before the block its round trip completes on, so `blocks` is a sequence, fed
/// through the roster one at a time exactly as the live scheduler would.
pub struct Fixture {
    pub name: &'static str,
    pub blocks: Vec<DetectionCtx>,
    pub expected: Vec<ExpectedIncident>,
}

impl Fixture {
    pub fn new(
        name: &'static str,
        blocks: Vec<DetectionCtx>,
        expected: Vec<ExpectedIncident>,
    ) -> Self {
        Self {
            name,
            blocks,
            expected,
        }
    }

    /// A one-block fixture — the common case; every detector but wash-trading
    /// decides from a single block alone.
    pub fn single(
        name: &'static str,
        block: DetectionCtx,
        expected: Vec<ExpectedIncident>,
    ) -> Self {
        Self::new(name, vec![block], expected)
    }
}
