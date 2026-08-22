//! Candidate legs (§24) — the unit the correlator buffers and, eventually
//! (Sprint 17 task 2), joins: one observed on-chain fact that *might* be one
//! side of a cross-chain bridge-MEV or arbitrage pattern.

use alloy_primitives::{Address, B256};
use chrono::{DateTime, Utc};
use events::primitives::{BlockRef, Chain};
use events::EventEnvelope;

/// Which observed behaviour this leg is a candidate instance of (§24's "What
/// this correlates").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegKind {
    /// A large transfer into a known bridge contract on the source chain.
    BridgeDeposit,
    /// A large swap that could be the arrival/fill leg of a bridge round-trip
    /// or a same-asset cross-chain arbitrage close.
    LargeSwap,
}

/// A bridge or cross-chain trading-pair identity — the routing key a
/// [`crate::router::LegRouter`] uses to find the one
/// [`crate::actor::CorrelationActor`] responsible for it (§17: "a single
/// correlation actor per bridge/pair"). Opaque on purpose: what identifies a
/// bridge/pair (a contract address pair, a symbolic name from config) is an
/// operator/config concern, not a wire concept this crate needs to interpret.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BridgeOrPair(pub String);

impl std::fmt::Display for BridgeOrPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One candidate leg observed on one chain, buffered until it either joins
/// with a leg from another chain (Sprint 17 task 2) or ages out of its
/// bridge/pair's window (§24).
#[derive(Debug, Clone, PartialEq)]
pub struct CandidateLeg {
    pub chain: Chain,
    pub block: BlockRef,
    pub tx: B256,
    pub kind: LegKind,
    /// Which correlation actor owns this leg's window.
    pub bridge_or_pair: BridgeOrPair,
    /// The behaviour-derived join key candidate (§6, §24) — a shared
    /// funder/profit-receiver/bridge-recipient observed on-chain, an
    /// attribution-blind fact rather than an intelligence label. Carried here
    /// so the buffer/actor plumbing has a concrete field to group on; task 2
    /// ("windowed join on a behaviour-derived key") decides exactly how it is
    /// derived and does the actual matching.
    pub correlation_key: Address,
    /// Wall-clock time this leg was observed, not the block's own timestamp
    /// — §24's join is windowed on observation time (with a configurable
    /// clock-skew tolerance), not block numbers, since chains finalize at
    /// different rates.
    pub observed_at: DateTime<Utc>,
}

/// The leg-recognition seam: given one decoded event on a chain consumer's
/// subscribed topics, decide whether it is a candidate bridge deposit or
/// large swap. A trait — not a bare free function — so
/// [`crate::chain_consumer::ChainConsumer`] is generic over it the same way
/// `predictive::position_consumer::PositionConsumer<S: LendingLogSource>` is
/// generic over its log source: task 2 plugs in the real extractor at the
/// `main.rs` wiring site without touching `ChainConsumer`'s own logic, and a
/// test can substitute a fake that returns `Some(..)` to exercise the
/// consumer's routing without waiting on the real implementation.
pub trait LegExtractor: Send + Sync {
    fn extract(&self, envelope: &EventEnvelope) -> Option<CandidateLeg>;
}

/// Today's extractor: always `None`. **Sprint 17 task 1's scope is the
/// consumer/actor/buffer skeleton, not leg recognition.** Neither a
/// `BridgeDeposit` domain event nor per-tx enrichment exists on the live
/// chain-event stream yet (the proposed wire shapes in
/// `docs/onchain_mev_detector_v2_microservices_rev2.md` §2 are aspirational),
/// and the real extraction is tied to task 2's join-key design ("windowed
/// join on a behaviour-derived key") — both land together rather than
/// guessing a leg shape here that task 2 would have to unwind. `main.rs`
/// wires this in until a real [`LegExtractor`] replaces it.
pub struct StubExtractor;

impl LegExtractor for StubExtractor {
    fn extract(&self, _envelope: &EventEnvelope) -> Option<CandidateLeg> {
        None
    }
}
