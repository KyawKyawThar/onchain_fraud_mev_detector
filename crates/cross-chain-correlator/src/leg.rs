//! Candidate legs (§24) — the unit the correlator buffers and (Sprint 17
//! task 2) joins: one observed on-chain fact that *might* be one side of a
//! cross-chain bridge-MEV or arbitrage pattern.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};

use alloy_primitives::{Address, B256};
use chrono::{DateTime, Utc};
use events::primitives::{BlockRef, Chain, Confidence, UsdAmount};
use events::{DomainEvent, EventEnvelope};
use serde::{Deserialize, Serialize};

/// Which observed behaviour this leg is a candidate instance of (§24's "What
/// this correlates").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BridgeOrPair(pub String);

impl std::fmt::Display for BridgeOrPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl BridgeOrPair {
    /// Whether replica `replica_index` (of `replica_count` total) owns this
    /// bridge/pair when the roster is horizontally sharded across replicas
    /// (production hardening, §17). Every replica computes this
    /// independently from the same deterministic hash — no coordination, no
    /// shared state, the same "each member derives its own share of the work
    /// from a stable function of the key" property a Kafka consumer-group
    /// partition assignment gives for free.
    ///
    /// Sharding happens *here* (which bridge/pair a replica keeps an actor
    /// for) rather than by splitting each chain's Kafka partitions, because
    /// a bridge/pair's two legs can land on any chain's stream in any
    /// partition — only a shard-by-bridge/pair scheme guarantees both legs
    /// of one correlation always reach the same replica's actor. Every
    /// replica therefore still consumes the *entire* stream of every
    /// configured chain (see [`crate::config::Config::consumer_group_for`])
    /// and only decides, per leg, whether it's the one replica responsible
    /// for holding onto it.
    ///
    /// `DefaultHasher` is not guaranteed stable across Rust/std versions,
    /// only deterministic *within* one — sufficient here since every
    /// replica in a deployment runs the identical binary build.
    pub fn owned_by(&self, replica_index: u32, replica_count: u32) -> bool {
        if replica_count <= 1 {
            return true;
        }
        let mut hasher = DefaultHasher::new();
        self.0.hash(&mut hasher);
        (hasher.finish() % u64::from(replica_count)) as u32 == replica_index
    }
}

/// One candidate leg observed on one chain, buffered until it either joins
/// with a leg from another chain (Sprint 17 task 2) or ages out of its
/// bridge/pair's window (§24).
///
/// `Serialize`/`Deserialize` back the leg-buffer changelog
/// ([`crate::changelog`], production hardening): every leg entering or
/// leaving a buffer is durably logged in exactly this shape so a restart can
/// replay and reconstruct in-flight state rather than silently losing it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// The triggering detector's own on-chain confidence
    /// (`DetectorTriggered.raw_confidence`, §6) — carried through so a
    /// correlated finding's `confidence` (the windowed join, task 2) is the
    /// weakest of its matched legs' confidences, not a guessed constant.
    pub confidence: Confidence,
    /// The triggering detector's priced impact for this leg, if it could
    /// price one (`detector_api::Evidence::impact_usd`, §6) — `None` when it
    /// couldn't. A matched finding's `profit`/`victim_loss` is a coarse,
    /// fast-path sum over whatever legs *did* price, exactly as
    /// conservative as `PreliminaryAlertCreated.impact_usd`'s own "unpriced,
    /// not zero" discipline.
    pub impact_usd: Option<UsdAmount>,
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

/// A no-op extractor: always `None`. Kept as the trivial fixture for tests
/// that only need to prove *routing* (see `chain_consumer`'s tests) — no
/// longer what `main.rs` wires in (see [`EvidenceLegExtractor`]).
pub struct StubExtractor;

impl LegExtractor for StubExtractor {
    fn extract(&self, _envelope: &EventEnvelope) -> Option<CandidateLeg> {
        None
    }
}

/// The `DetectorTriggered.evidence` field naming this leg's join-key address
/// (§6, §24) — a shared funder / profit-receiver / bridge-recipient, an
/// on-chain *fact*. A generic, detector-agnostic contract rather than a
/// per-detector parse: any detector crate opts a finding into cross-chain
/// correlation by adding this one field to its evidence JSON (alongside
/// [`BRIDGE_OR_PAIR_FIELD`]), with no change needed here.
pub const CORRELATION_ADDRESS_FIELD: &str = "correlation_address";

/// The `DetectorTriggered.evidence` field naming which configured
/// bridge/pair (matched against the operator's roster, §17) this leg belongs
/// to.
pub const BRIDGE_OR_PAIR_FIELD: &str = "bridge_or_pair";

/// The `DetectorTriggered.evidence` field carrying this leg's priced impact,
/// if the detector could price one — the same vocabulary
/// `detector_api::Evidence::impact_usd`/`PreliminaryAlertCreated.impact_usd`
/// already use elsewhere on the fast path, reused rather than invented.
pub const IMPACT_USD_FIELD: &str = "impact_usd";

/// The real [`LegExtractor`] (Sprint 17 task 2): recognizes a
/// `DetectorTriggered` as a candidate leg when (a) its detector id is on the
/// operator-configured bridge-deposit or large-swap roster (§17 — which
/// detector spots which behaviour is a deployment fact, the same
/// "operator/config concern" [`BridgeOrPair`]'s own docs describe, not
/// something this crate hard-codes) and (b) its `evidence` carries
/// [`CORRELATION_ADDRESS_FIELD`] and [`BRIDGE_OR_PAIR_FIELD`]. Neither
/// requirement holds for any detector shipped so far (§6's live detectors are
/// still header-only/no-op per Sprint 4's note), so this stays a legitimate
/// no-op today — the moment a detector's evidence carries those fields, legs
/// start flowing with no correlator-side change, the same "seam wired ahead
/// of its data" pattern `predictive`'s position tracker used before a
/// tx-carrying source existed.
pub struct EvidenceLegExtractor {
    bridge_deposit_detector_ids: HashSet<String>,
    large_swap_detector_ids: HashSet<String>,
}

impl EvidenceLegExtractor {
    pub fn new(
        bridge_deposit_detector_ids: HashSet<String>,
        large_swap_detector_ids: HashSet<String>,
    ) -> Self {
        Self {
            bridge_deposit_detector_ids,
            large_swap_detector_ids,
        }
    }

    fn leg_kind(&self, detector_id: &str) -> Option<LegKind> {
        if self.bridge_deposit_detector_ids.contains(detector_id) {
            Some(LegKind::BridgeDeposit)
        } else if self.large_swap_detector_ids.contains(detector_id) {
            Some(LegKind::LargeSwap)
        } else {
            None
        }
    }
}

impl LegExtractor for EvidenceLegExtractor {
    fn extract(&self, envelope: &EventEnvelope) -> Option<CandidateLeg> {
        let DomainEvent::DetectorTriggered(triggered) = &envelope.payload else {
            return None;
        };
        let kind = self.leg_kind(&triggered.detector.id)?;
        let correlation_key: Address = triggered
            .evidence
            .get(CORRELATION_ADDRESS_FIELD)?
            .as_str()?
            .parse()
            .ok()?;
        let bridge_or_pair = triggered
            .evidence
            .get(BRIDGE_OR_PAIR_FIELD)?
            .as_str()
            .map(|s| BridgeOrPair(s.to_owned()))?;
        let tx = *triggered.txs.first()?;
        let impact_usd = triggered
            .evidence
            .get(IMPACT_USD_FIELD)
            .and_then(|v| v.as_f64())
            .and_then(|v| UsdAmount::try_new(v).ok());

        Some(CandidateLeg {
            chain: envelope.chain,
            block: triggered.block,
            tx,
            kind,
            bridge_or_pair,
            correlation_key,
            observed_at: envelope.occurred_at,
            confidence: triggered.raw_confidence,
            impact_usd,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_replica_owns_everything() {
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        assert!(bridge.owned_by(0, 1));
    }

    #[test]
    fn exactly_one_replica_in_the_roster_owns_a_given_bridge_or_pair() {
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        let replica_count = 5;
        let owners: Vec<u32> = (0..replica_count)
            .filter(|&i| bridge.owned_by(i, replica_count))
            .collect();
        assert_eq!(
            owners.len(),
            1,
            "exactly one replica must own a bridge/pair, got {owners:?}"
        );
    }

    #[test]
    fn ownership_is_deterministic_across_calls() {
        let bridge = BridgeOrPair("weth-eth-arb".to_owned());
        let first = bridge.owned_by(2, 4);
        for _ in 0..10 {
            assert_eq!(bridge.owned_by(2, 4), first);
        }
    }

    #[test]
    fn a_full_roster_partitions_across_every_replica_with_no_gaps() {
        // Every bridge/pair in a roster must land on exactly one replica, and
        // (for a large enough roster) every replica should end up owning at
        // least one — otherwise sharding would silently strand a replica
        // doing nothing.
        let replica_count = 4;
        let roster: Vec<BridgeOrPair> =
            (0..40).map(|i| BridgeOrPair(format!("pair-{i}"))).collect();
        let mut owned_counts = vec![0usize; replica_count as usize];
        for bridge in &roster {
            let owners: Vec<u32> = (0..replica_count)
                .filter(|&i| bridge.owned_by(i, replica_count))
                .collect();
            assert_eq!(owners.len(), 1);
            owned_counts[owners[0] as usize] += 1;
        }
        assert_eq!(owned_counts.iter().sum::<usize>(), roster.len());
        assert!(
            owned_counts.iter().all(|&c| c > 0),
            "every replica should own at least one bridge/pair from a 40-entry \
             roster sharded 4 ways, got {owned_counts:?}"
        );
    }
}
