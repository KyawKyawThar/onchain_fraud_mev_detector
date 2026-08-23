//! The windowed join (§24, Sprint 17 task 2): given a newly-arrived
//! candidate leg and the legs already buffered for its bridge/pair, decide
//! whether it completes a correlated cross-chain finding — a shared
//! [`CandidateLeg::correlation_key`] observed on a *different* chain within
//! the buffer's window (chains, not blocks — the buffer already enforces the
//! window/capacity bound, §24).
//!
//! **Match strategies (production hardening).** What counts as a match is a
//! small, closed set of rules tried in priority order — a
//! Chain-of-Responsibility over [`MatchStrategy`] rather than an `if`/`else`
//! chain baked into [`join_leg`]'s body, so a future finding shape (task 4's
//! intelligence-linked kinds, say) is one more `impl MatchStrategy` plus one
//! line in [`STRATEGIES`], not a rewrite of the matching logic itself:
//!
//! 1. **Bridge MEV** ([`BridgeStrategy`]) — a complementary
//!    `(BridgeDeposit, LargeSwap)` pair: the deposit on the source chain and
//!    its front-run/back-run fill on the destination chain (§24's "What this
//!    correlates"). The more specific, higher-confidence finding, so it is
//!    tried first and wins over a same-kind arb match.
//! 2. **Cross-chain arbitrage** ([`CrossChainArbStrategy`]) — two or more
//!    `LargeSwap` legs sharing the key across distinct chains, closing a
//!    round trip no single-chain detector would see.
//!
//! Pure and total over its inputs (no I/O), like [`crate::buffer`] — the
//! only mutation is consuming matched legs out of the buffer via
//! [`crate::buffer::CandidateLegBuffer::remove`], so an unmatched leg is
//! left for the caller to [`crate::buffer::CandidateLegBuffer::insert`]
//! exactly as before (§24's window/capacity eviction still applies to it).

use alloy_primitives::B256;
use events::cross_chain::{BridgeMevDetected, CrossChainLegRef, CrossChainMevDetected};
use events::primitives::{AlertKind, Confidence, CrossChainFindingId, UsdAmount};
use events::scoring::severity_band;

use crate::buffer::CandidateLegBuffer;
use crate::leg::{CandidateLeg, LegKind};

/// What folding one newly-arrived leg into its bridge/pair's buffer found.
/// The matched variants carry both the built finding and the tx(s) that were
/// actually removed from the buffer to complete it (excluding the new leg
/// itself, which was never buffered) — the caller
/// ([`crate::actor::CorrelationActor::on_leg`]) uses that list to emit the
/// matching `Removed` entries on the leg-buffer changelog
/// (`crate::changelog`, production hardening).
#[derive(Debug, Clone, PartialEq)]
pub enum JoinOutcome {
    /// No match — the caller buffers `leg` exactly as task 1 already did.
    Unmatched(CandidateLeg),
    /// A deposit/fill pair completed (§24): the finding, and the tx of the
    /// one buffered leg it consumed.
    Bridge(BridgeMevDetected, B256),
    /// Two or more same-kind legs across distinct chains completed a
    /// multi-leg cycle (§24): the finding, and the txs of every buffered leg
    /// it consumed.
    CrossChain(CrossChainMevDetected, Vec<B256>),
}

/// One matching rule: given the buffer and a newly-arrived leg, decide
/// whether they complete a finding — but only *decide* (read-only over the
/// buffer); [`join_leg`] applies the winning decision by actually removing
/// the matched legs, so a strategy never has to reason about the buffer's
/// mutation half.
trait MatchStrategy: Sync {
    fn decide(&self, buffer: &CandidateLegBuffer, new_leg: &CandidateLeg) -> Option<MatchDecision>;
}

enum MatchDecision {
    Bridge(B256),
    CrossChain(Vec<B256>),
}

struct BridgeStrategy;

impl MatchStrategy for BridgeStrategy {
    fn decide(&self, buffer: &CandidateLegBuffer, new_leg: &CandidateLeg) -> Option<MatchDecision> {
        buffer
            .candidates_for(new_leg.correlation_key)
            .find(|other| {
                other.chain != new_leg.chain && is_complementary(other.kind, new_leg.kind)
            })
            .map(|other| MatchDecision::Bridge(other.tx))
    }
}

struct CrossChainArbStrategy;

impl MatchStrategy for CrossChainArbStrategy {
    fn decide(&self, buffer: &CandidateLegBuffer, new_leg: &CandidateLeg) -> Option<MatchDecision> {
        if new_leg.kind != LegKind::LargeSwap {
            return None;
        }
        let txs: Vec<B256> = buffer
            .candidates_for(new_leg.correlation_key)
            .filter(|other| other.chain != new_leg.chain && other.kind == LegKind::LargeSwap)
            .map(|other| other.tx)
            .collect();
        (!txs.is_empty()).then_some(MatchDecision::CrossChain(txs))
    }
}

/// Priority order: tried top-to-bottom, first `Some` wins (§24's "Bridge MEV
/// is the more specific finding" — see module docs).
static STRATEGIES: &[&dyn MatchStrategy] = &[&BridgeStrategy, &CrossChainArbStrategy];

fn leg_ref(leg: &CandidateLeg) -> CrossChainLegRef {
    CrossChainLegRef {
        chain: leg.chain,
        block: leg.block,
        tx: leg.tx,
    }
}

/// A leg's priced impact as a plain, non-negative amount — `0.0` when the
/// detector couldn't price it. `BridgeMevDetected`/`CrossChainMevDetected`'s
/// `profit`/`victim_loss` are coarse fast-path sums over this, the same
/// "unpriced reads conservative, not alarming" discipline
/// `events::scoring::severity_band` already applies to `None`.
fn impact(leg: &CandidateLeg) -> f64 {
    leg.impact_usd.map(UsdAmount::get).unwrap_or(0.0)
}

/// `true` when `a`/`b` are one `BridgeDeposit` and one `LargeSwap`, in either
/// order — the deposit-leg/fill-leg pair §24 calls Bridge MEV.
fn is_complementary(a: LegKind, b: LegKind) -> bool {
    matches!(
        (a, b),
        (LegKind::BridgeDeposit, LegKind::LargeSwap) | (LegKind::LargeSwap, LegKind::BridgeDeposit)
    )
}

/// Fold `new_leg` into `buffer`: try each [`STRATEGIES`] entry in priority
/// order, consuming whichever legs complete the first one that matches.
/// Returns [`JoinOutcome::Unmatched`] (still holding `new_leg`, nothing
/// removed) when none applies.
pub fn join_leg(buffer: &mut CandidateLegBuffer, new_leg: CandidateLeg) -> JoinOutcome {
    for strategy in STRATEGIES {
        if let Some(decision) = strategy.decide(buffer, &new_leg) {
            return apply(buffer, new_leg, decision);
        }
    }
    JoinOutcome::Unmatched(new_leg)
}

fn apply(
    buffer: &mut CandidateLegBuffer,
    new_leg: CandidateLeg,
    decision: MatchDecision,
) -> JoinOutcome {
    match decision {
        MatchDecision::Bridge(other_tx) => {
            let other = buffer
                .remove(other_tx)
                .expect("just decided by scanning the same buffer");
            JoinOutcome::Bridge(build_bridge_mev(new_leg, other), other_tx)
        }
        MatchDecision::CrossChain(other_txs) => {
            let mut legs: Vec<CandidateLeg> = other_txs
                .iter()
                .map(|&tx| {
                    buffer
                        .remove(tx)
                        .expect("just decided by scanning the same buffer")
                })
                .collect();
            legs.push(new_leg);
            JoinOutcome::CrossChain(build_cross_chain_mev(legs), other_txs)
        }
    }
}

/// Build the finding from a matched `(deposit, fill)` pair, in either arrival
/// order — `deposit_leg`/`fill_leg` are assigned by [`LegKind`], not by which
/// leg arrived first.
fn build_bridge_mev(a: CandidateLeg, b: CandidateLeg) -> BridgeMevDetected {
    let (deposit, fill) = if a.kind == LegKind::BridgeDeposit {
        (a, b)
    } else {
        (b, a)
    };
    let confidence = min_confidence([deposit.confidence, fill.confidence]);
    let profit = impact(&fill);
    let victim_loss = impact(&deposit);
    let severity = severity_band(Some(UsdAmount::new(profit.max(victim_loss))), confidence);
    BridgeMevDetected {
        finding_id: CrossChainFindingId::new(),
        bridge: deposit.bridge_or_pair.to_string(),
        deposit_leg: leg_ref(&deposit),
        fill_leg: leg_ref(&fill),
        entity_hint: deposit.correlation_key,
        profit,
        victim_loss,
        confidence,
        severity,
        // Always true — see `BridgeMevDetected::provisional`'s docs (§15,
        // Sprint 17 task 3): this finding is retracted, not confirmed.
        provisional: true,
    }
}

/// Build the finding from every leg in a completed multi-leg cycle, ordered
/// chronologically by `observed_at` (§24: the join is windowed on
/// observation time, so that is the meaningful cross-chain order — not
/// arrival/insertion order).
fn build_cross_chain_mev(mut legs: Vec<CandidateLeg>) -> CrossChainMevDetected {
    legs.sort_by_key(|leg| leg.observed_at);
    let confidence = min_confidence(legs.iter().map(|leg| leg.confidence));
    let profit: f64 = legs.iter().map(impact).sum();
    let latency_ms = legs
        .last()
        .zip(legs.first())
        .map(|(last, first)| {
            (last.observed_at - first.observed_at)
                .num_milliseconds()
                .max(0) as u64
        })
        .unwrap_or(0);
    let severity = severity_band(Some(UsdAmount::new(profit)), confidence);
    CrossChainMevDetected {
        finding_id: CrossChainFindingId::new(),
        kind: AlertKind::Arbitrage,
        bridge: legs[0].bridge_or_pair.to_string(),
        entity_hint: legs[0].correlation_key,
        legs: legs.iter().map(leg_ref).collect(),
        profit,
        latency_ms,
        confidence,
        severity,
        provisional: true,
    }
}

fn min_confidence(confidences: impl IntoIterator<Item = Confidence>) -> Confidence {
    confidences.into_iter().fold(Confidence::CERTAIN, |acc, c| {
        if c.get() < acc.get() {
            c
        } else {
            acc
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leg::BridgeOrPair;
    use alloy_primitives::{Address, B256};
    use chrono::{TimeDelta, Utc};
    use events::primitives::{BlockRef, Chain};

    fn bridge() -> BridgeOrPair {
        BridgeOrPair("usdc-eth-base".to_owned())
    }

    fn leg(
        chain: Chain,
        kind: LegKind,
        key: u8,
        tag: u8,
        observed_at: chrono::DateTime<Utc>,
    ) -> CandidateLeg {
        CandidateLeg {
            chain,
            block: BlockRef::new(1, B256::repeat_byte(tag)),
            tx: B256::repeat_byte(tag),
            kind,
            bridge_or_pair: bridge(),
            correlation_key: Address::repeat_byte(key),
            observed_at,
            confidence: Confidence::new(0.9),
            impact_usd: Some(UsdAmount::new(1_000.0)),
        }
    }

    #[test]
    fn a_lone_leg_is_unmatched_and_left_untouched() {
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        let now = Utc::now();
        let outcome = join_leg(
            &mut buf,
            leg(Chain::ETHEREUM, LegKind::BridgeDeposit, 1, 1, now),
        );
        assert!(matches!(outcome, JoinOutcome::Unmatched(_)));
        assert!(buf.is_empty(), "join_leg must not insert on its own");
    }

    #[test]
    fn a_deposit_and_fill_on_different_chains_complete_a_bridge_match() {
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        let now = Utc::now();
        let deposit = leg(Chain::ETHEREUM, LegKind::BridgeDeposit, 7, 1, now);
        buf.insert(deposit.clone(), now);

        let fill = leg(
            Chain::BASE,
            LegKind::LargeSwap,
            7,
            2,
            now + TimeDelta::seconds(30),
        );
        let outcome = join_leg(&mut buf, fill.clone());

        match outcome {
            JoinOutcome::Bridge(event, consumed_tx) => {
                assert_eq!(event.deposit_leg.chain, Chain::ETHEREUM);
                assert_eq!(event.deposit_leg.tx, deposit.tx);
                assert_eq!(event.fill_leg.chain, Chain::BASE);
                assert_eq!(event.fill_leg.tx, fill.tx);
                assert_eq!(event.entity_hint, Address::repeat_byte(7));
                assert_eq!(event.bridge, "usdc-eth-base");
                assert_eq!(consumed_tx, deposit.tx, "the buffered leg, not the new one");
            }
            other => panic!("expected a bridge match, got {other:?}"),
        }
        assert!(buf.is_empty(), "the matched deposit leg must be consumed");
    }

    #[test]
    fn role_assignment_does_not_depend_on_arrival_order() {
        // The fill (LargeSwap) arrives first and buffers; the deposit
        // arrives second and matches it — deposit_leg/fill_leg must still be
        // assigned by kind, not by which leg was already buffered.
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        let now = Utc::now();
        let fill = leg(Chain::BASE, LegKind::LargeSwap, 7, 1, now);
        buf.insert(fill.clone(), now);

        let deposit = leg(Chain::ETHEREUM, LegKind::BridgeDeposit, 7, 2, now);
        let outcome = join_leg(&mut buf, deposit.clone());

        match outcome {
            JoinOutcome::Bridge(event, _) => {
                assert_eq!(event.deposit_leg.tx, deposit.tx);
                assert_eq!(event.fill_leg.tx, fill.tx);
            }
            other => panic!("expected a bridge match, got {other:?}"),
        }
    }

    #[test]
    fn same_chain_deposit_and_fill_do_not_match() {
        // §24: a cross-chain finding needs the legs on *different* chains —
        // a same-chain pair is not this correlator's job.
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        let now = Utc::now();
        buf.insert(leg(Chain::ETHEREUM, LegKind::BridgeDeposit, 7, 1, now), now);

        let outcome = join_leg(
            &mut buf,
            leg(Chain::ETHEREUM, LegKind::LargeSwap, 7, 2, now),
        );
        assert!(matches!(outcome, JoinOutcome::Unmatched(_)));
        assert_eq!(buf.len(), 1, "the buffered leg must be untouched");
    }

    #[test]
    fn a_different_correlation_key_does_not_match() {
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        let now = Utc::now();
        buf.insert(leg(Chain::ETHEREUM, LegKind::BridgeDeposit, 7, 1, now), now);

        let outcome = join_leg(&mut buf, leg(Chain::BASE, LegKind::LargeSwap, 8, 2, now));
        assert!(matches!(outcome, JoinOutcome::Unmatched(_)));
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn two_large_swaps_on_different_chains_complete_a_cross_chain_arb() {
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        let t0 = Utc::now();
        let leg_a = leg(Chain::ETHEREUM, LegKind::LargeSwap, 9, 1, t0);
        buf.insert(leg_a.clone(), t0);

        let t1 = t0 + TimeDelta::milliseconds(2_500);
        let leg_b = leg(Chain::BASE, LegKind::LargeSwap, 9, 2, t1);
        let outcome = join_leg(&mut buf, leg_b.clone());

        match outcome {
            JoinOutcome::CrossChain(event, consumed_txs) => {
                assert_eq!(event.kind, AlertKind::Arbitrage);
                assert_eq!(event.legs.len(), 2);
                assert_eq!(event.legs[0].tx, leg_a.tx, "chronological order");
                assert_eq!(event.legs[1].tx, leg_b.tx);
                assert_eq!(event.latency_ms, 2_500);
                assert_eq!(event.entity_hint, Address::repeat_byte(9));
                assert_eq!(
                    consumed_txs,
                    vec![leg_a.tx],
                    "only the buffered leg, not the new one"
                );
            }
            other => panic!("expected a cross-chain match, got {other:?}"),
        }
        assert!(buf.is_empty());
    }

    #[test]
    fn three_matching_legs_all_join_into_one_cross_chain_cycle() {
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        let t0 = Utc::now();
        buf.insert(leg(Chain::ETHEREUM, LegKind::LargeSwap, 5, 1, t0), t0);
        buf.insert(
            leg(
                Chain::BASE,
                LegKind::LargeSwap,
                5,
                2,
                t0 + TimeDelta::seconds(1),
            ),
            t0,
        );

        let outcome = join_leg(
            &mut buf,
            leg(
                Chain(999),
                LegKind::LargeSwap,
                5,
                3,
                t0 + TimeDelta::seconds(2),
            ),
        );
        match outcome {
            JoinOutcome::CrossChain(event, consumed_txs) => {
                assert_eq!(event.legs.len(), 3);
                assert_eq!(consumed_txs.len(), 2);
            }
            other => panic!("expected a 3-leg cross-chain match, got {other:?}"),
        }
        assert!(buf.is_empty());
    }

    #[test]
    fn a_bridge_match_takes_priority_over_a_same_kind_arb_match() {
        // The new leg could complete either an arb match (against a buffered
        // LargeSwap) or a bridge match (against a buffered BridgeDeposit).
        // Bridge MEV must win — it is the more specific finding.
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        let now = Utc::now();
        buf.insert(leg(Chain::ETHEREUM, LegKind::LargeSwap, 3, 1, now), now);
        buf.insert(leg(Chain(999), LegKind::BridgeDeposit, 3, 2, now), now);

        let outcome = join_leg(&mut buf, leg(Chain::BASE, LegKind::LargeSwap, 3, 3, now));
        assert!(matches!(outcome, JoinOutcome::Bridge(_, _)));
        // Only the deposit leg is consumed; the unrelated LargeSwap stays
        // buffered for a future match.
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.iter().next().unwrap().kind, LegKind::LargeSwap);
    }

    #[test]
    fn confidence_is_the_weakest_matched_leg() {
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        let now = Utc::now();
        let mut weak = leg(Chain::ETHEREUM, LegKind::BridgeDeposit, 1, 1, now);
        weak.confidence = Confidence::new(0.4);
        buf.insert(weak, now);

        let mut strong = leg(Chain::BASE, LegKind::LargeSwap, 1, 2, now);
        strong.confidence = Confidence::new(0.95);
        let outcome = join_leg(&mut buf, strong);

        match outcome {
            JoinOutcome::Bridge(event, _) => assert_eq!(event.confidence.get(), 0.4),
            other => panic!("expected a bridge match, got {other:?}"),
        }
    }

    #[test]
    fn unpriced_legs_read_as_zero_profit_not_a_guess() {
        let mut buf = CandidateLegBuffer::new(TimeDelta::minutes(10), 100);
        let now = Utc::now();
        let mut deposit = leg(Chain::ETHEREUM, LegKind::BridgeDeposit, 1, 1, now);
        deposit.impact_usd = None;
        buf.insert(deposit, now);

        let mut fill = leg(Chain::BASE, LegKind::LargeSwap, 1, 2, now);
        fill.impact_usd = None;
        let outcome = join_leg(&mut buf, fill);

        match outcome {
            JoinOutcome::Bridge(event, _) => {
                assert_eq!(event.profit, 0.0);
                assert_eq!(event.victim_loss, 0.0);
                assert_eq!(event.severity, events::primitives::Severity::Low);
            }
            other => panic!("expected a bridge match, got {other:?}"),
        }
    }
}
