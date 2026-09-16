//! [`Fixture`] — one backtest scenario: a sequence of historical blocks plus
//! the ground truth the detector roster is scored against (§18, Sprint 10 t2).
//!
//! # Closed world and open world
//!
//! What an alert nobody listed *means* depends on where the labels came from,
//! and the two answers differ on purpose:
//!
//! - **Authored** fixtures (known incidents and adversarial near misses) are
//!   *closed-world*. Their authors wrote every block, so they know every
//!   incident on it: an alert that matches no listed incident is a false
//!   positive.
//! - A **mainnet replay** window is *open-world*. Its labels are simulation's
//!   verdicts on findings the live roster raised (§20.1), so they cover only
//!   what was flagged at the time. An alert the replay raises that simulation
//!   never saw is **unadjudicated** — not a false positive, and not a true
//!   one. Only an alert matching a refuted verdict is a false positive there.
//!
//! Scoring an open-world window as closed-world would turn every improvement
//! in a detector (a true finding the old build missed) into a counted false
//! positive. The reverse would let a hand-built fixture's stray alert go
//! uncounted.
//!
//! # One field, so the two cannot disagree
//!
//! Which world a fixture lives in, and which labels it may carry, are a single
//! [`GroundTruth`] value rather than parallel fields. An authored fixture has
//! nowhere to put a refutation, and a replay cannot be scored closed-world.
//! The invariant holds by construction instead of by convention.

use std::borrow::Cow;

use alloy_primitives::B256;
use detector_api::{DetectionCtx, DetectorId};
use events::primitives::AlertKind;

/// Where a fixture's labels came from — the reporting label derived from its
/// [`GroundTruth`]. `Copy`, so a result can carry it without cloning labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Provenance {
    /// A known-incident scenario written by hand, mirroring a detector's own
    /// regression test.
    HandBuilt,
    /// A near miss written by hand: structurally close to a detector's
    /// signature and outside it by that detector's own definition.
    Adversarial,
    /// Consecutive mainnet blocks captured by `dataset window`, labelled by
    /// simulation (see the `corpus` crate). The only provenance an FP-rate
    /// claim may rest on ([`crate::claim`]).
    MainnetReplay,
}

impl Provenance {
    /// Whether every incident on the fixture's blocks is listed (see the
    /// module docs).
    pub fn is_closed_world(self) -> bool {
        !matches!(self, Provenance::MainnetReplay)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Provenance::HandBuilt => "hand-built",
            Provenance::Adversarial => "adversarial",
            Provenance::MainnetReplay => "mainnet-replay",
        }
    }
}

/// A fixture's labels, and the world they are interpreted in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroundTruth {
    /// Closed-world: every incident on the blocks is listed.
    Authored {
        /// [`Provenance::HandBuilt`] or [`Provenance::Adversarial`].
        provenance: Provenance,
        incidents: Vec<ExpectedIncident>,
    },
    /// Open-world: simulation's verdicts on what the live roster flagged.
    Replay {
        /// The window file the fixture was loaded from, for the report.
        source: String,
        /// Verdicts that the finding was real.
        confirmed: Vec<ExpectedIncident>,
        /// Verdicts that it was not (refuted or retracted).
        refuted: Vec<ExpectedIncident>,
        /// Verdicts for detectors this build does not link. Not scored — a
        /// detector that is absent here has not missed anything — but counted,
        /// so a shrinking verdict set is visible.
        orphaned: u64,
    },
}

impl GroundTruth {
    pub fn provenance(&self) -> Provenance {
        match self {
            GroundTruth::Authored { provenance, .. } => *provenance,
            GroundTruth::Replay { .. } => Provenance::MainnetReplay,
        }
    }

    /// Incidents that are real: each caught is a true positive, each missed a
    /// false negative.
    pub fn expected(&self) -> &[ExpectedIncident] {
        match self {
            GroundTruth::Authored { incidents, .. } => incidents,
            GroundTruth::Replay { confirmed, .. } => confirmed,
        }
    }

    /// Findings known to be wrong. Always empty when authored: there, *every*
    /// unlisted alert already is one.
    pub fn refuted(&self) -> &[ExpectedIncident] {
        match self {
            GroundTruth::Authored { .. } => &[],
            GroundTruth::Replay { refuted, .. } => refuted,
        }
    }
}

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
    /// The exact transactions the finding must implicate, or `None` to accept
    /// any finding of this detector and kind on the block.
    ///
    /// Hand-built fixtures leave it `None` — one incident per block, nothing
    /// to confuse it with. Mainnet labels always set it: a busy block can hold
    /// several findings of one detector, and simulation's verdict is about one
    /// particular bundle, so matching on less would hand a refutation to the
    /// wrong alert.
    pub txs: Option<Vec<B256>>,
    /// Human-readable context, surfaced in the report on a miss.
    pub description: Cow<'static, str>,
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
            txs: None,
            description: Cow::Borrowed(description),
        }
    }

    /// Restrict the match to exactly these implicated transactions (order
    /// ignored — see [`crate::scoring`]).
    #[must_use]
    pub fn with_txs(mut self, txs: Vec<B256>) -> Self {
        self.txs = Some(txs);
        self
    }
}

/// A named backtest scenario: consecutive blocks, in order, replayed through the
/// roster, plus the ground truth they are scored against.
///
/// Most scenarios are one block; wash-trading (the one `Scope::CrossBlock`
/// detector) needs the several leading blocks that build its trailing window
/// before the block its round trip completes on, so `blocks` is a sequence, fed
/// through the roster one at a time exactly as the live scheduler would.
///
/// `truth` is private and set only by the constructors below, which is what
/// makes the [`GroundTruth`] invariant hold.
pub struct Fixture {
    pub name: Cow<'static, str>,
    pub blocks: Vec<DetectionCtx>,
    truth: GroundTruth,
}

impl Fixture {
    /// A hand-built known-incident scenario.
    pub fn new(
        name: &'static str,
        blocks: Vec<DetectionCtx>,
        expected: Vec<ExpectedIncident>,
    ) -> Self {
        Self {
            name: Cow::Borrowed(name),
            blocks,
            truth: GroundTruth::Authored {
                provenance: Provenance::HandBuilt,
                incidents: expected,
            },
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

    /// A near-miss scenario: no incident on it, and every alert a false
    /// positive.
    pub fn adversarial(name: &'static str, blocks: Vec<DetectionCtx>) -> Self {
        Self {
            name: Cow::Borrowed(name),
            blocks,
            truth: GroundTruth::Authored {
                provenance: Provenance::Adversarial,
                incidents: Vec::new(),
            },
        }
    }

    /// A mainnet replay window, labelled by simulation.
    pub fn replay(
        name: String,
        source: String,
        blocks: Vec<DetectionCtx>,
        confirmed: Vec<ExpectedIncident>,
        refuted: Vec<ExpectedIncident>,
        orphaned: u64,
    ) -> Self {
        Self {
            name: Cow::Owned(name),
            blocks,
            truth: GroundTruth::Replay {
                source,
                confirmed,
                refuted,
                orphaned,
            },
        }
    }

    pub fn truth(&self) -> &GroundTruth {
        &self.truth
    }

    pub fn provenance(&self) -> Provenance {
        self.truth.provenance()
    }

    /// See [`GroundTruth::expected`].
    pub fn expected(&self) -> &[ExpectedIncident] {
        self.truth.expected()
    }
}
