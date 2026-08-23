//! Correlation actors (§17) — "a single correlation actor per bridge/pair":
//! every configured bridge/pair gets exactly one long-lived task owning
//! exactly one [`CandidateLegBuffer`], fed by every per-chain
//! [`crate::chain_consumer::ChainConsumer`] over a bounded channel
//! (backpressure, §17). [`CorrelationActor::on_leg`] is the windowed-join
//! seam (Sprint 17 task 2): it folds an arriving leg through
//! [`crate::join::join_leg`] first, publishing a
//! `BridgeMevDetected`/`CrossChainMevDetected` on a match and only falling
//! back to task 1's plain buffer/evict path when nothing matched.
//!
//! This is also the buffer's effectful shell (see `buffer` module docs): the
//! buffer itself is silent, and `on_leg` is where an eviction — or a
//! completed join — becomes a log line/metric/published event/changelog
//! entry.
//!
//! **Durability (production hardening).** Every buffer mutation `on_leg`
//! decides is first turned into one or more [`ChangelogEntry`]s
//! ([`LegOutcome::changelog`]); [`CorrelationActor::run`] durably appends
//! them (via [`ChangelogWriter::append`], retried like a domain-event
//! publish) *before* publishing any resulting finding — so a finding is
//! never reported upstream on the strength of a mutation this process can't
//! actually replay after a crash. See `crate::changelog` module docs for the
//! full design and its accepted limits.
//!
//! **Finality/reorg tracking (§15, Sprint 17 task 3).** `run` also registers
//! every published finding's legs with the shared
//! [`crate::finality::SharedFindingFinalityTracker`] — *before* publishing,
//! the same "durable/trackable before public" causality the changelog
//! append already follows — so [`crate::finality::FinalityConsumer`] can
//! retract it later if any leg's block reverts. See `crate::finality`
//! module docs for the full design.

use std::sync::Arc;
use std::time::Duration;

use chrono::{TimeDelta, Utc};
use event_bus::{publish_resilient, EventSink};
use events::{DomainEvent, EventEnvelope};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::buffer::CandidateLegBuffer;
use crate::changelog::{ChangelogEntry, ChangelogSink};
use crate::finality::SharedFindingFinalityTracker;
use crate::finding_changelog::{FindingKind, LegKey};
use crate::join::{self, JoinOutcome};
use crate::leg::{BridgeOrPair, CandidateLeg};

/// One bridge/pair's correlation actor: its identity and its window.
pub struct CorrelationActor {
    bridge_or_pair: BridgeOrPair,
    buffer: CandidateLegBuffer,
}

/// What folding one leg into the buffer produced: the changelog entries that
/// must be durably appended (in order) to make the mutation replayable, and
/// the finding (if any) to publish once they are.
pub struct LegOutcome {
    pub changelog: Vec<ChangelogEntry>,
    pub finding: Option<DomainEvent>,
}

impl CorrelationActor {
    pub fn new(bridge_or_pair: BridgeOrPair, window: TimeDelta, capacity: usize) -> Self {
        Self::new_with_seed(bridge_or_pair, window, capacity, Vec::new())
    }

    /// Like [`Self::new`], but pre-populates the buffer from a leg-buffer
    /// changelog replay (`crate::changelog::replay`, production hardening)
    /// instead of starting empty — the warm-start path `main.rs` uses at
    /// boot. Immediately re-applies window eviction against the current
    /// time, since the seeded legs' `observed_at` values are historical and
    /// some may have aged out during however long this process was down.
    pub fn new_with_seed(
        bridge_or_pair: BridgeOrPair,
        window: TimeDelta,
        capacity: usize,
        seed: Vec<CandidateLeg>,
    ) -> Self {
        let mut buffer = CandidateLegBuffer::new(window, capacity);
        let seeded = seed.len();
        buffer.seed(seed);
        let aged_out = buffer.evict_expired(Utc::now()).len();
        if seeded > 0 {
            tracing::info!(
                bridge_or_pair = %bridge_or_pair,
                seeded,
                aged_out,
                restored = seeded - aged_out,
                "correlation actor warm-started from the leg-changelog replay"
            );
        }
        Self {
            bridge_or_pair,
            buffer,
        }
    }

    pub fn bridge_or_pair(&self) -> &BridgeOrPair {
        &self.bridge_or_pair
    }

    pub fn buffer(&self) -> &CandidateLegBuffer {
        &self.buffer
    }

    fn removed_entry(&self, tx: alloy_primitives::B256) -> ChangelogEntry {
        ChangelogEntry::Removed {
            bridge_or_pair: self.bridge_or_pair.clone(),
            tx,
        }
    }

    /// Fold one candidate leg into this bridge/pair's window (Sprint 17 task
    /// 2): try the windowed join first ([`join::join_leg`]); on a completed
    /// match, log/record it and return the finding to publish, plus the
    /// changelog entries covering whatever legs it consumed. Otherwise
    /// buffer the (unmatched) leg exactly as task 1 did, logging/recording
    /// whatever the buffer had to evict to make room (the buffer itself
    /// reports but never logs — see `buffer` module docs) and covering
    /// every mutation (buffered + evicted) with a changelog entry.
    pub fn on_leg(&mut self, leg: CandidateLeg) -> LegOutcome {
        match join::join_leg(&mut self.buffer, leg) {
            JoinOutcome::Unmatched(leg) => {
                let now = Utc::now();
                crate::metrics::record_leg_buffered(&self.bridge_or_pair);

                let mut changelog = vec![ChangelogEntry::Buffered(leg.clone())];
                let outcome = self.buffer.insert(leg, now);

                crate::metrics::record_legs_evicted(
                    &self.bridge_or_pair,
                    "window",
                    outcome.window_evicted.len() as u64,
                );
                for evicted in &outcome.window_evicted {
                    changelog.push(self.removed_entry(evicted.tx));
                }
                if let Some(dropped) = &outcome.capacity_evicted {
                    tracing::warn!(
                        bridge_or_pair = %self.bridge_or_pair,
                        capacity = self.buffer.capacity(),
                        dropped_tx = %dropped.tx,
                        "candidate-leg buffer at capacity; evicting the oldest unmatched leg \
                         (check for a stalled/slow chain consumer)"
                    );
                    crate::metrics::record_legs_evicted(&self.bridge_or_pair, "capacity", 1);
                    changelog.push(self.removed_entry(dropped.tx));
                }

                crate::metrics::record_buffer_size(&self.bridge_or_pair, self.buffer.len());
                LegOutcome {
                    changelog,
                    finding: None,
                }
            }
            JoinOutcome::Bridge(event, consumed_tx) => {
                tracing::info!(
                    bridge_or_pair = %self.bridge_or_pair,
                    deposit_chain = event.deposit_leg.chain.id(),
                    fill_chain = event.fill_leg.chain.id(),
                    entity_hint = %event.entity_hint,
                    severity = ?event.severity,
                    "bridge MEV correlated across chains"
                );
                crate::metrics::record_finding(&self.bridge_or_pair, "bridge_mev");
                crate::metrics::record_buffer_size(&self.bridge_or_pair, self.buffer.len());
                LegOutcome {
                    changelog: vec![self.removed_entry(consumed_tx)],
                    finding: Some(DomainEvent::BridgeMevDetected(event)),
                }
            }
            JoinOutcome::CrossChain(event, consumed_txs) => {
                tracing::info!(
                    bridge_or_pair = %self.bridge_or_pair,
                    legs = event.legs.len(),
                    entity_hint = %event.entity_hint,
                    latency_ms = event.latency_ms,
                    severity = ?event.severity,
                    "cross-chain arbitrage correlated"
                );
                crate::metrics::record_finding(&self.bridge_or_pair, "cross_chain_mev");
                crate::metrics::record_buffer_size(&self.bridge_or_pair, self.buffer.len());
                let changelog = consumed_txs
                    .into_iter()
                    .map(|tx| self.removed_entry(tx))
                    .collect();
                LegOutcome {
                    changelog,
                    finding: Some(DomainEvent::CrossChainMevDetected(event)),
                }
            }
        }
    }

    /// Drive this actor off `rx` until the channel closes (every feeding
    /// consumer stopped) or `shutdown` fires. Every leg's changelog entries
    /// are durably appended before any resulting finding is published (see
    /// module docs).
    pub async fn run(
        mut self,
        mut rx: mpsc::Receiver<CandidateLeg>,
        sink: Arc<dyn EventSink>,
        changelog: Arc<dyn ChangelogSink>,
        finality: Arc<SharedFindingFinalityTracker>,
        publish_backoff: Duration,
        shutdown: CancellationToken,
    ) {
        tracing::info!(bridge_or_pair = %self.bridge_or_pair, "correlation actor starting");
        loop {
            let leg = tokio::select! {
                biased;
                () = shutdown.cancelled() => {
                    tracing::info!(bridge_or_pair = %self.bridge_or_pair, "correlation actor shutting down");
                    return;
                }
                leg = rx.recv() => match leg {
                    Some(leg) => leg,
                    None => {
                        tracing::info!(bridge_or_pair = %self.bridge_or_pair, "leg router closed; correlation actor exiting");
                        return;
                    }
                },
            };
            let outcome = self.on_leg(leg);
            for entry in &outcome.changelog {
                changelog.append(entry, publish_backoff, &shutdown).await;
            }
            if let Some(event) = outcome.finding {
                let chain = envelope_chain(&event);
                // Start tracking the finding's legs for reorg retraction
                // *before* publishing it (`crate::finality` module docs):
                // once the finding is on the wire, a revert of any leg must
                // already be able to retract it, not race a window where
                // it's public but not yet watched.
                let (finding_id, legs, kind) = finding_record_args(&event);
                finality
                    .record_finding(
                        finding_id,
                        self.bridge_or_pair.clone(),
                        kind,
                        legs,
                        Utc::now(),
                    )
                    .await;
                crate::metrics::record_pending_findings(finality.len());
                let envelope = EventEnvelope::new(chain, event);
                publish_resilient(sink.as_ref(), envelope, publish_backoff, &shutdown).await;
            }
        }
    }
}

/// Which chain to stamp on a correlated finding's envelope (§20 still needs
/// *a* chain even though the finding spans several): the fill leg for a
/// bridge match (where the extraction is realized), or the chronologically
/// last leg for a cross-chain cycle (the leg whose arrival closed it) —
/// matches [`crate::join`]'s "closing leg" framing.
fn envelope_chain(event: &DomainEvent) -> events::primitives::Chain {
    match event {
        DomainEvent::BridgeMevDetected(e) => e.fill_leg.chain,
        DomainEvent::CrossChainMevDetected(e) => {
            e.legs
                .last()
                .expect("join::join_leg never builds an empty leg list")
                .chain
        }
        _ => unreachable!("CorrelationActor::on_leg only ever returns a cross-chain finding"),
    }
}

/// Everything [`crate::finality::SharedFindingFinalityTracker::record_finding`]
/// needs from a just-built finding: its retraction key, the `(chain, block
/// hash)` of every leg to watch, and the metric/log label for its kind.
fn finding_record_args(
    event: &DomainEvent,
) -> (
    events::primitives::CrossChainFindingId,
    Vec<LegKey>,
    FindingKind,
) {
    match event {
        DomainEvent::BridgeMevDetected(e) => (
            e.finding_id,
            vec![
                (e.deposit_leg.chain, e.deposit_leg.block.hash),
                (e.fill_leg.chain, e.fill_leg.block.hash),
            ],
            FindingKind::BridgeMev,
        ),
        DomainEvent::CrossChainMevDetected(e) => (
            e.finding_id,
            e.legs
                .iter()
                .map(|leg| (leg.chain, leg.block.hash))
                .collect(),
            FindingKind::CrossChainMev,
        ),
        _ => unreachable!("CorrelationActor::on_leg only ever returns a cross-chain finding"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changelog::RecordingChangelogWriter;
    use crate::leg::LegKind;
    use alloy_primitives::{Address, B256};
    use event_bus::test_util::RecordingSink;
    use events::primitives::{BlockRef, Chain, Confidence};

    fn a_leg(bridge_or_pair: BridgeOrPair, tag: u8) -> CandidateLeg {
        CandidateLeg {
            chain: Chain::ETHEREUM,
            block: BlockRef::new(1, B256::repeat_byte(tag)),
            tx: B256::repeat_byte(tag),
            kind: LegKind::LargeSwap,
            bridge_or_pair,
            // Distinct per-tag key: these fixtures are only exercising the
            // unmatched buffer/evict path, so no two legs should accidentally
            // complete a join::join_leg match.
            correlation_key: Address::repeat_byte(tag),
            observed_at: Utc::now(),
            confidence: Confidence::new(0.9),
            impact_usd: None,
        }
    }

    fn test_finality() -> Arc<SharedFindingFinalityTracker> {
        use crate::finding_changelog::{FindingChangelogSink, RecordingFindingChangelogWriter};
        let changelog: Arc<dyn FindingChangelogSink> =
            Arc::new(RecordingFindingChangelogWriter::default());
        SharedFindingFinalityTracker::new(
            TimeDelta::hours(1),
            100,
            changelog,
            CancellationToken::new(),
        )
    }

    fn a_deposit_leg(bridge_or_pair: BridgeOrPair, key: u8, tag: u8) -> CandidateLeg {
        CandidateLeg {
            kind: LegKind::BridgeDeposit,
            correlation_key: Address::repeat_byte(key),
            chain: Chain::BASE,
            ..a_leg(bridge_or_pair, tag)
        }
    }

    #[test]
    fn on_leg_buffers_it() {
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        let mut actor = CorrelationActor::new(bridge.clone(), TimeDelta::minutes(10), 100);
        let outcome = actor.on_leg(a_leg(bridge, 1));
        assert!(
            outcome.finding.is_none(),
            "a lone leg must not publish anything"
        );
        assert_eq!(
            outcome.changelog.len(),
            1,
            "one Buffered entry, no evictions"
        );
        assert!(matches!(outcome.changelog[0], ChangelogEntry::Buffered(_)));
        assert_eq!(actor.buffer().len(), 1);
    }

    #[test]
    fn on_leg_survives_a_capacity_eviction_without_panicking() {
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        let mut actor = CorrelationActor::new(bridge.clone(), TimeDelta::minutes(10), 1);
        actor.on_leg(a_leg(bridge.clone(), 1));
        let outcome = actor.on_leg(a_leg(bridge, 2)); // must evict leg 1 via the capacity backstop
        assert_eq!(actor.buffer().len(), 1);
        assert_eq!(
            outcome.changelog.len(),
            2,
            "a Buffered entry for leg 2 plus a Removed entry for the evicted leg 1"
        );
    }

    #[test]
    fn on_leg_completes_a_bridge_match_and_returns_the_finding() {
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        let mut actor = CorrelationActor::new(bridge.clone(), TimeDelta::minutes(10), 100);
        actor.on_leg(a_deposit_leg(bridge.clone(), 7, 1)); // Chain::BASE, buffers
        let outcome = actor.on_leg({
            let mut fill = a_leg(bridge, 2); // Chain::ETHEREUM, LargeSwap
            fill.correlation_key = Address::repeat_byte(7);
            fill
        });
        match outcome.finding {
            Some(DomainEvent::BridgeMevDetected(_)) => {}
            other => panic!("expected a published BridgeMevDetected, got {other:?}"),
        }
        assert_eq!(
            outcome.changelog.len(),
            1,
            "one Removed entry for the deposit leg the match consumed"
        );
        assert!(
            actor.buffer().is_empty(),
            "both matched legs must be consumed, not left buffered"
        );
    }

    #[test]
    fn new_with_seed_restores_legs_and_prunes_ones_already_aged_out() {
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        let fresh = a_leg(bridge.clone(), 1);
        let mut stale = a_leg(bridge.clone(), 2);
        stale.observed_at = Utc::now() - TimeDelta::hours(1);

        let actor = CorrelationActor::new_with_seed(
            bridge,
            TimeDelta::minutes(10),
            100,
            vec![fresh, stale],
        );
        assert_eq!(
            actor.buffer().len(),
            1,
            "the stale seeded leg must be pruned by the immediate post-seed eviction"
        );
        assert_eq!(
            actor.buffer().iter().next().unwrap().tx,
            B256::repeat_byte(1)
        );
    }

    #[tokio::test]
    async fn run_buffers_legs_until_the_channel_closes() {
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        let actor = CorrelationActor::new(bridge.clone(), TimeDelta::minutes(10), 100);
        let (tx, rx) = mpsc::channel(8);
        tx.send(a_leg(bridge.clone(), 1)).await.unwrap();
        tx.send(a_leg(bridge, 2)).await.unwrap();
        drop(tx);

        let sink: Arc<dyn EventSink> = Arc::new(RecordingSink::default());
        let changelog: Arc<dyn ChangelogSink> = Arc::new(RecordingChangelogWriter::default());
        // `run` consumes `self`; hand it a dedicated handle to check afterwards
        // isn't possible directly, so this test only proves it doesn't hang or
        // panic when the channel closes — buffering itself is covered above.
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            actor.run(
                rx,
                sink,
                changelog,
                test_finality(),
                Duration::from_millis(1),
                CancellationToken::new(),
            ),
        )
        .await
        .expect("run must return once the channel closes, not hang");
    }

    #[tokio::test]
    async fn run_publishes_a_finding_and_logs_its_changelog_entry() {
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        let actor = CorrelationActor::new(bridge.clone(), TimeDelta::minutes(10), 100);
        let (tx, rx) = mpsc::channel(8);
        tx.send(a_deposit_leg(bridge.clone(), 7, 1)).await.unwrap();
        tx.send({
            let mut fill = a_leg(bridge, 2);
            fill.correlation_key = Address::repeat_byte(7);
            fill
        })
        .await
        .unwrap();
        drop(tx);

        let sink = Arc::new(RecordingSink::default());
        let sink_dyn: Arc<dyn EventSink> = sink.clone();
        let changelog = Arc::new(RecordingChangelogWriter::default());
        let changelog_dyn: Arc<dyn ChangelogSink> = changelog.clone();
        let finality = test_finality();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            actor.run(
                rx,
                sink_dyn,
                changelog_dyn,
                finality.clone(),
                Duration::from_millis(1),
                CancellationToken::new(),
            ),
        )
        .await
        .expect("run must return once the channel closes, not hang");

        let published = sink.events();
        assert_eq!(published.len(), 1);
        assert!(matches!(published[0], DomainEvent::BridgeMevDetected(_)));

        // The first leg only buffers (one Buffered entry); the second
        // completes the match, logging one Removed entry for the leg it
        // consumed. Total: 2 changelog entries, both written before the
        // finding was published (run appends before it publishes).
        let entries = changelog.entries();
        assert_eq!(entries.len(), 2);
        assert!(matches!(entries[0], ChangelogEntry::Buffered(_)));
        assert!(matches!(entries[1], ChangelogEntry::Removed { .. }));

        // The published finding's legs are now tracked for reorg retraction
        // (§15, Sprint 17 task 3) — see `crate::finality`.
        assert_eq!(finality.len(), 1);
    }

    #[tokio::test]
    async fn run_returns_promptly_on_shutdown() {
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        let actor = CorrelationActor::new(bridge, TimeDelta::minutes(10), 100);
        let (_tx, rx) = mpsc::channel(8); // kept open — only shutdown should end `run`
        let sink: Arc<dyn EventSink> = Arc::new(RecordingSink::default());
        let changelog: Arc<dyn ChangelogSink> = Arc::new(RecordingChangelogWriter::default());
        let shutdown = CancellationToken::new();
        shutdown.cancel();

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            actor.run(
                rx,
                sink,
                changelog,
                test_finality(),
                Duration::from_millis(1),
                shutdown,
            ),
        )
        .await
        .expect("run must return on an already-cancelled shutdown token");
    }
}
