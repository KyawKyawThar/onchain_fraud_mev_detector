//! The [`CrossBlockDetector`] seam (§6, §15) — a detector that accumulates state
//! across a sliding window of blocks, rather than deciding from one block alone.
//!
//! A [`DetectorPlugin`](crate::DetectorPlugin) is a *pure* function of one
//! [`DetectionCtx`] — the fast path fans those out over a rayon pool because they
//! share nothing (sandwich, arb). A `CrossBlockDetector` (e.g. wash-trading over a
//! trailing window) instead *folds each canonical block into a running state* and
//! detects from the accumulated window. That state is the thing a reorg must roll
//! back (§15), so the detection service keeps it reorg-versioned (one snapshot per
//! block) and rewinds it to the common ancestor on `BlockReverted`.
//!
//! ## Why a separate trait, not a method on `DetectorPlugin`
//!
//! Keeping the two seams apart is what lets each stay honest about its concurrency
//! contract. `DetectorPlugin::detect(&self, ctx)` takes no state and can therefore
//! be run in parallel and in any order; a cross-block detector inherently needs
//! `&mut Self::State` threaded through, so it runs **serially** on the scheduler's
//! single state-owning task. A detector implements whichever fits; the service
//! drives them on the matching path.
//!
//! ## The contract
//!
//! `Self::State` is the snapshot the detector wants preserved per block. It is
//! `Clone` because the service forks the previous block's snapshot to build this
//! block's (a full snapshot per block makes reorg rollback a cheap discard — see
//! `detection::state::CrossBlockState`), and `Send + 'static` because the scheduler
//! owns it across `.await` points. For each canonical block the service:
//!   1. clones the tip snapshot (or [`init_state`](CrossBlockDetector::init_state)
//!      if this is the first block),
//!   2. calls [`observe`](CrossBlockDetector::observe) to fold the block in,
//!   3. records the result as the new tip snapshot, then
//!   4. calls [`detect`](CrossBlockDetector::detect) to read findings off the
//!      accumulated window.
//!
//! Like [`DetectorPlugin`](crate::DetectorPlugin), it is attribution-blind: it sees
//! only on-chain facts + enrichment and returns [`Evidence`] describing behaviour,
//! never an actor (§6).

use crate::ctx::DetectionCtx;
use crate::plugin::{DetectorId, Evidence, ModelKind, SemVer};

/// A detector that accumulates state across a trailing window of blocks (§6, §15).
///
/// See the [module docs](self) for the per-block lifecycle the detection service
/// drives this through, and why it is a separate seam from the pure, parallel-safe
/// [`DetectorPlugin`](crate::DetectorPlugin).
pub trait CrossBlockDetector: Send + Sync {
    /// The detector's accumulated state — the snapshot preserved per block.
    ///
    /// `Clone` so the service forks the previous snapshot to build the next;
    /// `Send + 'static` so the scheduler can own it across `.await`.
    type State: Clone + Send + 'static;

    /// Stable id, e.g. `DetectorId::new("wash-trading")`.
    fn id(&self) -> DetectorId;

    /// This build's version. `(id, version)` is unique within the roster.
    fn version(&self) -> SemVer;

    /// Rule / ML / Hybrid — metadata for the model registry and reporting.
    fn kind(&self) -> ModelKind;

    /// How many trailing blocks of history the detector needs — the
    /// `Scope::CrossBlock { window_blocks }` the service sizes its snapshot store to.
    fn window_blocks(&self) -> u32;

    /// The empty state for a detector that has observed no blocks yet — the seed
    /// the service forks the first block's snapshot from.
    fn init_state(&self) -> Self::State;

    /// Fold one canonical block into the running `state` (called once per block, in
    /// ascending order). Pure in everything but `state`: no I/O, no clock, no labels
    /// — so it stays replayable in backtests (§18).
    fn observe(&self, ctx: &DetectionCtx, state: &mut Self::State);

    /// Read findings off the accumulated `state` after this block was folded in. An
    /// empty vec means "nothing this block" — the common case, so keep it cheap.
    fn detect(&self, ctx: &DetectionCtx, state: &Self::State) -> Vec<Evidence>;
}
