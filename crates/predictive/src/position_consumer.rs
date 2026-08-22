//! The position tracker's Kafka consumer (§16.1): folds `BlockCanonicalized`
//! into the tracked position book — fetching that block's lending logs via a
//! [`LendingLogSource`] and decoding them — and rewinds it on `BlockReverted`,
//! driven by the shared at-least-once [`event_bus::run_consumer`] loop (§20),
//! the same seam `intelligence::reorg`'s `ReorgConsumer` runs through.
//!
//! Single-chain, single-writer (§16 — one predictive instance per chain, no
//! roster of trackers): a foreign-chain record is a committable no-op, matching
//! every other per-chain consumer on the backbone (`detection::scheduler`,
//! `intelligence::production_consumer`).
//!
//! Publishes nothing itself: this task's whole job is the tracked *state* the
//! Sprint 16 task 2 cascade engine reads off [`PositionTracker::current`] —
//! unlike `intelligence::reorg::ReorgConsumer`, there is no downstream fact to
//! announce here. The tracker is `Arc<Mutex<_>>`-shared with that cascade
//! loop (`main.rs`) precisely so it can be read from outside this consumer.
//!
//! Sprint 16 task 4 (§16.4/§19) adds one observation, though still no
//! publish: every decoded [`LendingEvent::Liquidation`] is a real, on-chain
//! liquidation, so this is also where the §19
//! lead-time-to-actual-liquidation accuracy signal is measured —
//! [`crate::lead_time::LeadTimeTracker`], shared with the cascade engine the
//! same way the position tracker itself is.

use async_trait::async_trait;
use chrono::Utc;
use event_bus::lag::{build_reporting_consumer, LagReporting};
use event_bus::{run_consumer, EventHandler, Handled, Transience};
use events::chain::{BlockCanonicalized, BlockReverted};
use events::primitives::Chain;
use events::{DomainEvent, EventEnvelope};
use rdkafka::consumer::StreamConsumer;
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

use crate::lead_time::LeadTimeTracker;
use crate::lending_decode::{decode_log, LendingEvent};
use crate::metrics;
use crate::position::PositionTracker;
use crate::position_source::{LendingLogSource, SourceError};

/// An RPC transport failure is worth retrying (a network blip, a node
/// hiccup) — there is no "this call can never succeed" case for `eth_getLogs`
/// the way an encode bug is permanent for a publish.
impl Transience for SourceError {
    fn is_transient(&self) -> bool {
        true
    }
}

/// The two events this consumer subscribes to — the canonical-chain trigger and
/// the reorg revert, mirroring `detection::scheduler`'s explicit two-topic list
/// (an explicit list, not a `mev.events.*` regex, so a renamed/missing topic
/// fails loudly rather than silently matching nothing).
const CONSUMED_EVENT_TYPES: &[&str] = &["BlockCanonicalized", "BlockReverted"];

pub fn consumed_topics() -> Vec<String> {
    events::topics_for(CONSUMED_EVENT_TYPES)
}

/// Build the consumer. Manual offset commit (`enable.auto.commit=false`, set by
/// [`build_reporting_consumer`]) ties the commit to a fully folded block;
/// `earliest` means a fresh group replays retained canonical history from the
/// start, the same discipline every other consumer on this backbone follows.
pub fn build_consumer(
    brokers: &str,
    group_id: &str,
) -> anyhow::Result<StreamConsumer<LagReporting>> {
    build_reporting_consumer(brokers, group_id, "position-tracker")
}

/// The position-tracking consumer: the log source it fetches a block's lending
/// logs through, and the tracker it folds them into. The tracker is shared
/// (`Arc<Mutex<_>>`) rather than owned outright — the Sprint 16 task 2 cascade
/// engine reads the same instance's [`PositionTracker::current`] snapshot
/// concurrently (see module docs).
pub struct PositionConsumer<S> {
    chain: Chain,
    source: S,
    tracker: Arc<Mutex<PositionTracker>>,
    /// Sprint 16 task 4 (§16.4/§19): shared with the cascade engine
    /// (`main.rs`) so a real `LendingEvent::Liquidation` decoded here can be
    /// paired with the `LiquidationRiskPredicted` forecast (if any) that
    /// warned about the same `(protocol, account)`.
    lead_time: Arc<Mutex<LeadTimeTracker>>,
}

impl<S: LendingLogSource> PositionConsumer<S> {
    pub fn new(
        chain: Chain,
        source: S,
        tracker: Arc<Mutex<PositionTracker>>,
        lead_time: Arc<Mutex<LeadTimeTracker>>,
    ) -> Self {
        Self {
            chain,
            source,
            tracker,
            lead_time,
        }
    }

    /// Fetch `canonicalized`'s lending logs, decode the ones this tracker
    /// recognizes, and fold them into the position book as this block's new
    /// snapshot. Also measures the §19 lead-time-to-actual-liquidation
    /// signal for every decoded [`LendingEvent::Liquidation`] (see the
    /// module docs) — `Utc::now()` (this consumer's processing time) stands
    /// in for the liquidation's observed time, since `BlockCanonicalized`
    /// carries no block timestamp; an accepted approximation, same spirit as
    /// this crate's other first-cut §16.1 debts.
    async fn on_canonicalized(
        &self,
        canonicalized: &BlockCanonicalized,
    ) -> Result<(), SourceError> {
        let logs = self.source.logs_for_block(canonicalized.block.hash).await?;
        let events: Vec<_> = logs.iter().filter_map(decode_log).collect();
        if !events.is_empty() {
            tracing::info!(
                block = canonicalized.block.number,
                lending_events = events.len(),
                "folding lending events into the tracked position book"
            );
        }
        self.record_liquidation_lead_times(&events);
        self.tracker
            .lock()
            .unwrap()
            .apply_block(canonicalized.block, &events);
        Ok(())
    }

    /// For every real liquidation decoded this block, consume the
    /// forecast (if any) the cascade engine recorded for the same
    /// `(protocol, account)` and record the §19 lead-time signal.
    fn record_liquidation_lead_times(&self, events: &[LendingEvent]) {
        let observed_at = Utc::now();
        for event in events {
            if !matches!(event, LendingEvent::Liquidation { .. }) {
                continue;
            }
            let key = event.position_key();
            let lead_time = self
                .lead_time
                .lock()
                .unwrap()
                .take_lead_time(&key, observed_at);
            metrics::record_liquidation_lead_time(lead_time);
        }
    }

    /// Roll back the tracked position book iff `reverted.block` is exactly the
    /// tip (§15) — a stale/duplicate/out-of-window revert is a no-op, per
    /// [`PositionTracker::revert_tip`].
    fn on_reverted(&self, reverted: &BlockReverted) {
        let rewound = self.tracker.lock().unwrap().revert_tip(reverted.block);
        if rewound {
            tracing::info!(
                block = reverted.block.number,
                "rewound tracked positions through a reorg"
            );
        }
    }

    async fn dispatch(&self, envelope: EventEnvelope) -> Handled {
        if envelope.chain != self.chain {
            // Shared topics (§20, one predictive instance per chain): not ours,
            // but its offset must still advance.
            return Handled::Commit;
        }
        match envelope.payload {
            DomainEvent::BlockCanonicalized(canonicalized) => {
                match self.on_canonicalized(&canonicalized).await {
                    Ok(()) => Handled::Commit,
                    Err(err) => event_bus::handled(err, "position-tracker"),
                }
            }
            DomainEvent::BlockReverted(reverted) => {
                self.on_reverted(&reverted);
                Handled::Commit
            }
            other => {
                tracing::warn!(
                    event = other.event_type(),
                    "unexpected event on the position-tracker topics; skipping"
                );
                Handled::Commit
            }
        }
    }

    /// Drive the consumer off Kafka until shutdown or a fatal subscribe error,
    /// via the shared [`run_consumer`] loop. Consumes `self` (mirrors
    /// `intelligence::reorg::ReorgConsumer::run`) — the loop owns the handler
    /// for the life of the subscription.
    pub async fn run(
        self,
        consumer: StreamConsumer<LagReporting>,
        retry_backoff: std::time::Duration,
        dlq: Option<&event_bus::dlq::DeadLetterQueue>,
        shutdown: &CancellationToken,
    ) -> anyhow::Result<()> {
        let topics = consumed_topics();
        let topic_refs: Vec<&str> = topics.iter().map(String::as_str).collect();
        run_consumer(
            consumer,
            &topic_refs,
            "position-tracker",
            retry_backoff,
            dlq,
            self,
            shutdown,
        )
        .await
    }
}

#[async_trait]
impl<S: LendingLogSource> EventHandler for PositionConsumer<S> {
    async fn handle(&self, envelope: EventEnvelope) -> Handled {
        self.dispatch(envelope).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lending_decode::RawLog;
    use crate::position::{LiquidationThresholds, Protocol};
    use alloy_primitives::{Address, Bytes, B256, U256};
    use events::primitives::BlockRef;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    fn addr(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }

    fn block(number: u64) -> BlockRef {
        BlockRef::new(number, B256::repeat_byte(number as u8))
    }

    fn envelope(chain: Chain, payload: DomainEvent) -> EventEnvelope {
        EventEnvelope::new(chain, payload)
    }

    /// A deterministic, in-memory [`LendingLogSource`] double: returns whatever
    /// logs were seeded for a block hash (empty if none), or a canned transient
    /// error when `fail_next` is armed — enough to drive every branch of
    /// [`PositionConsumer::dispatch`] without a live node.
    struct FakeSource {
        by_hash: HashMap<B256, Vec<RawLog>>,
        fail_next: StdMutex<bool>,
    }

    impl FakeSource {
        fn new(by_hash: HashMap<B256, Vec<RawLog>>) -> Self {
            Self {
                by_hash,
                fail_next: StdMutex::new(false),
            }
        }

        fn empty() -> Self {
            Self::new(HashMap::new())
        }

        fn arm_failure(&self) {
            *self.fail_next.lock().unwrap() = true;
        }
    }

    #[async_trait]
    impl LendingLogSource for FakeSource {
        async fn logs_for_block(&self, block_hash: B256) -> Result<Vec<RawLog>, SourceError> {
            if std::mem::take(&mut *self.fail_next.lock().unwrap()) {
                return Err(SourceError::Transport(
                    alloy_transport::TransportErrorKind::custom_str("boom"),
                ));
            }
            Ok(self.by_hash.get(&block_hash).cloned().unwrap_or_default())
        }
    }

    /// A Compound `Mint` log fixture, self-contained (no dependency on
    /// `lending_decode`'s own test fixtures).
    fn mint_log(market: Address, minter: Address, amount: u64) -> RawLog {
        use alloy_primitives::keccak256;

        fn addr_word(a: Address) -> [u8; 32] {
            let mut w = [0u8; 32];
            w[12..32].copy_from_slice(a.as_slice());
            w
        }
        let mut data = Vec::new();
        data.extend_from_slice(&addr_word(minter));
        data.extend_from_slice(&U256::from(amount).to_be_bytes::<32>());
        data.extend_from_slice(&U256::from(amount).to_be_bytes::<32>());
        RawLog {
            address: market,
            topics: vec![keccak256(b"Mint(address,uint256,uint256)")],
            data: Bytes::from(data),
        }
    }

    fn consumer(source: FakeSource) -> PositionConsumer<FakeSource> {
        PositionConsumer::new(
            Chain::ETHEREUM,
            source,
            Arc::new(Mutex::new(PositionTracker::new(
                64,
                LiquidationThresholds::default(),
            ))),
            Arc::new(Mutex::new(LeadTimeTracker::new())),
        )
    }

    #[tokio::test]
    async fn a_canonicalized_block_folds_its_decoded_logs_into_the_position_book() {
        let market = addr(0xC1);
        let minter = addr(0x11);
        let b = block(1);
        let mut by_hash = HashMap::new();
        by_hash.insert(b.hash, vec![mint_log(market, minter, 1_000)]);
        let c = consumer(FakeSource::new(by_hash));

        let handled = c
            .dispatch(envelope(
                Chain::ETHEREUM,
                DomainEvent::BlockCanonicalized(BlockCanonicalized { block: b }),
            ))
            .await;
        assert_eq!(handled, Handled::Commit);

        let tracker = c.tracker.lock().unwrap();
        let position = tracker
            .current()
            .unwrap()
            .get(&crate::position::PositionKey {
                protocol: Protocol::Compound,
                account: minter,
            })
            .expect("position opened from the decoded Mint");
        assert_eq!(
            position.collateral.get(&market),
            Some(&U256::from(1_000u64))
        );
        assert_eq!(tracker.tip(), Some(b));
    }

    #[tokio::test]
    async fn a_redelivered_canonicalized_block_does_not_double_count_its_collateral() {
        // §7: `event_bus::run_consumer` commits offsets asynchronously and can
        // redeliver an already-handled record without a process restart —
        // `CrossBlockState::apply`'s idempotency guard must stop this from
        // folding the same Mint's collateral into the tracked position twice.
        let market = addr(0xC1);
        let minter = addr(0x11);
        let b = block(1);
        let mut by_hash = HashMap::new();
        by_hash.insert(b.hash, vec![mint_log(market, minter, 1_000)]);
        let c = consumer(FakeSource::new(by_hash));

        for _ in 0..2 {
            let handled = c
                .dispatch(envelope(
                    Chain::ETHEREUM,
                    DomainEvent::BlockCanonicalized(BlockCanonicalized { block: b }),
                ))
                .await;
            assert_eq!(handled, Handled::Commit);
        }

        let tracker = c.tracker.lock().unwrap();
        let position = tracker
            .current()
            .unwrap()
            .get(&crate::position::PositionKey {
                protocol: Protocol::Compound,
                account: minter,
            })
            .expect("position opened from the decoded Mint");
        assert_eq!(
            position.collateral.get(&market),
            Some(&U256::from(1_000u64)),
            "the redelivered block must not double the tracked collateral"
        );
    }

    #[tokio::test]
    async fn a_block_with_no_recognized_logs_still_advances_the_tip() {
        let c = consumer(FakeSource::empty());
        let handled = c
            .dispatch(envelope(
                Chain::ETHEREUM,
                DomainEvent::BlockCanonicalized(BlockCanonicalized { block: block(1) }),
            ))
            .await;
        assert_eq!(handled, Handled::Commit);
        assert_eq!(c.tracker.lock().unwrap().tip(), Some(block(1)));
    }

    #[tokio::test]
    async fn a_source_failure_retries_without_advancing_the_tip() {
        let source = FakeSource::empty();
        source.arm_failure();
        let c = consumer(source);

        let handled = c
            .dispatch(envelope(
                Chain::ETHEREUM,
                DomainEvent::BlockCanonicalized(BlockCanonicalized { block: block(1) }),
            ))
            .await;
        assert_eq!(handled, Handled::Retry);
        assert_eq!(
            c.tracker.lock().unwrap().tip(),
            None,
            "nothing applied when the log fetch failed"
        );
    }

    #[tokio::test]
    async fn a_foreign_chain_record_commits_without_touching_the_tracker() {
        let c = consumer(FakeSource::empty());
        let handled = c
            .dispatch(envelope(
                Chain::BASE,
                DomainEvent::BlockCanonicalized(BlockCanonicalized { block: block(1) }),
            ))
            .await;
        assert_eq!(handled, Handled::Commit);
        assert_eq!(c.tracker.lock().unwrap().tip(), None);
    }

    #[tokio::test]
    async fn block_reverted_rewinds_the_tracked_positions() {
        let c = consumer(FakeSource::empty());
        c.dispatch(envelope(
            Chain::ETHEREUM,
            DomainEvent::BlockCanonicalized(BlockCanonicalized { block: block(1) }),
        ))
        .await;
        c.dispatch(envelope(
            Chain::ETHEREUM,
            DomainEvent::BlockCanonicalized(BlockCanonicalized { block: block(2) }),
        ))
        .await;

        let handled = c
            .dispatch(envelope(
                Chain::ETHEREUM,
                DomainEvent::BlockReverted(BlockReverted {
                    block: block(2),
                    replaced_by: B256::repeat_byte(0xff),
                }),
            ))
            .await;
        assert_eq!(handled, Handled::Commit);
        assert_eq!(c.tracker.lock().unwrap().tip(), Some(block(1)));
    }

    #[tokio::test]
    async fn an_unexpected_event_type_is_skipped_and_committed() {
        let c = consumer(FakeSource::empty());
        let handled = c
            .dispatch(envelope(
                Chain::ETHEREUM,
                DomainEvent::BlockAssembled(events::chain::BlockAssembled {
                    block: block(1),
                    tx_count: 0,
                    trace_available: false,
                }),
            ))
            .await;
        assert_eq!(handled, Handled::Commit);
    }

    // ── §16.4/§19: lead-time-to-actual-liquidation ─────────────────────────

    fn liquidation(account: Address) -> LendingEvent {
        LendingEvent::Liquidation {
            protocol: Protocol::Aave,
            account,
            debt_asset: addr(0x22),
            debt_repaid: U256::from(600u64),
            collateral_asset: addr(0x11),
            collateral_seized: U256::from(660u64),
        }
    }

    /// A real liquidation decoded for a `(protocol, account)` that a prior
    /// `LiquidationRiskPredicted` forecast covers consumes that forecast —
    /// a later liquidation of the same account, with no fresh prediction
    /// recorded, finds nothing left to pair with.
    #[tokio::test]
    async fn a_predicted_liquidation_consumes_its_forecast() {
        let account = addr(0x33);
        let key = crate::position::PositionKey {
            protocol: Protocol::Aave,
            account,
        };
        let c = consumer(FakeSource::empty());
        c.lead_time
            .lock()
            .unwrap()
            .record_prediction(key, Utc::now());

        c.record_liquidation_lead_times(&[liquidation(account)]);

        assert!(
            c.lead_time
                .lock()
                .unwrap()
                .take_lead_time(&key, Utc::now())
                .is_none(),
            "the forecast was consumed by the liquidation, nothing left to take"
        );
    }

    /// A liquidation with no prior forecast is a no-op on the tracker (it
    /// was never inserted in the first place) — this just proves the
    /// unpredicted path doesn't panic reaching into an empty tracker.
    #[tokio::test]
    async fn an_unforecast_liquidation_is_a_no_op_on_the_tracker() {
        let account = addr(0x44);
        let c = consumer(FakeSource::empty());
        c.record_liquidation_lead_times(&[liquidation(account)]);
    }

    /// A non-liquidation event (a `Supply`) is ignored by the lead-time pass
    /// — its forecast, if any, stays intact for the real liquidation later.
    #[tokio::test]
    async fn a_non_liquidation_event_leaves_the_forecast_untouched() {
        let account = addr(0x55);
        let key = crate::position::PositionKey {
            protocol: Protocol::Aave,
            account,
        };
        let c = consumer(FakeSource::empty());
        c.lead_time
            .lock()
            .unwrap()
            .record_prediction(key, Utc::now());

        c.record_liquidation_lead_times(&[LendingEvent::Supply {
            protocol: Protocol::Aave,
            account,
            asset: addr(0x11),
            amount: U256::from(1_000u64),
        }]);

        assert!(
            c.lead_time
                .lock()
                .unwrap()
                .take_lead_time(&key, Utc::now())
                .is_some(),
            "a Supply event must not consume an unrelated liquidation forecast"
        );
    }
}
