//! Correlation actors (§17) — "a single correlation actor per bridge/pair":
//! every configured bridge/pair gets exactly one long-lived task owning
//! exactly one [`CandidateLegBuffer`], fed by every per-chain
//! [`crate::chain_consumer::ChainConsumer`] over a bounded channel
//! (backpressure, §17). Task 1's actor only buffers (and evicts) —
//! [`CorrelationActor::on_leg`] is the seam Sprint 17 task 2's windowed join
//! ("match against the buffer, emit `BridgeMevDetected`/
//! `CrossChainMevDetected`") slots into.
//!
//! This is also the buffer's effectful shell (see `buffer` module docs): the
//! buffer itself is silent, and `on_leg` is where an eviction becomes a log
//! line/metric.

use chrono::{TimeDelta, Utc};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::buffer::CandidateLegBuffer;
use crate::leg::{BridgeOrPair, CandidateLeg};

/// One bridge/pair's correlation actor: its identity and its window.
pub struct CorrelationActor {
    bridge_or_pair: BridgeOrPair,
    buffer: CandidateLegBuffer,
}

impl CorrelationActor {
    pub fn new(bridge_or_pair: BridgeOrPair, window: TimeDelta, capacity: usize) -> Self {
        Self {
            bridge_or_pair,
            buffer: CandidateLegBuffer::new(window, capacity),
        }
    }

    pub fn bridge_or_pair(&self) -> &BridgeOrPair {
        &self.bridge_or_pair
    }

    pub fn buffer(&self) -> &CandidateLegBuffer {
        &self.buffer
    }

    /// Fold one candidate leg into this bridge/pair's window, then log/record
    /// whatever the buffer had to evict to make room (the buffer itself
    /// reports but never logs — see `buffer` module docs). Sprint 17 task 2
    /// is where matching a newly-arrived leg against
    /// [`CandidateLegBuffer::iter`] and emitting a correlated finding
    /// happens; today this only buffers — the §17/§24 skeleton this sprint
    /// task scopes.
    pub fn on_leg(&mut self, leg: CandidateLeg) {
        let now = Utc::now();
        crate::metrics::record_leg_buffered(&self.bridge_or_pair);

        let outcome = self.buffer.insert(leg, now);

        crate::metrics::record_legs_evicted(
            &self.bridge_or_pair,
            "window",
            outcome.window_evicted as u64,
        );
        if let Some(dropped) = outcome.capacity_evicted {
            tracing::warn!(
                bridge_or_pair = %self.bridge_or_pair,
                capacity = self.buffer.capacity(),
                dropped_tx = %dropped.tx,
                "candidate-leg buffer at capacity; evicting the oldest unmatched leg \
                 (check for a stalled/slow chain consumer)"
            );
            crate::metrics::record_legs_evicted(&self.bridge_or_pair, "capacity", 1);
        }

        crate::metrics::record_buffer_size(&self.bridge_or_pair, self.buffer.len());
    }

    /// Drive this actor off `rx` until the channel closes (every feeding
    /// consumer stopped) or `shutdown` fires.
    pub async fn run(mut self, mut rx: mpsc::Receiver<CandidateLeg>, shutdown: CancellationToken) {
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
            self.on_leg(leg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leg::LegKind;
    use alloy_primitives::{Address, B256};
    use events::primitives::{BlockRef, Chain};

    fn a_leg(bridge_or_pair: BridgeOrPair, tag: u8) -> CandidateLeg {
        CandidateLeg {
            chain: Chain::ETHEREUM,
            block: BlockRef::new(1, B256::repeat_byte(tag)),
            tx: B256::repeat_byte(tag),
            kind: LegKind::LargeSwap,
            bridge_or_pair,
            correlation_key: Address::repeat_byte(tag),
            observed_at: Utc::now(),
        }
    }

    #[test]
    fn on_leg_buffers_it() {
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        let mut actor = CorrelationActor::new(bridge.clone(), TimeDelta::minutes(10), 100);
        actor.on_leg(a_leg(bridge, 1));
        assert_eq!(actor.buffer().len(), 1);
    }

    #[test]
    fn on_leg_survives_a_capacity_eviction_without_panicking() {
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        let mut actor = CorrelationActor::new(bridge.clone(), TimeDelta::minutes(10), 1);
        actor.on_leg(a_leg(bridge.clone(), 1));
        actor.on_leg(a_leg(bridge, 2)); // must evict leg 1 via the capacity backstop
        assert_eq!(actor.buffer().len(), 1);
    }

    #[tokio::test]
    async fn run_buffers_legs_until_the_channel_closes() {
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        let actor = CorrelationActor::new(bridge.clone(), TimeDelta::minutes(10), 100);
        let (tx, rx) = mpsc::channel(8);
        tx.send(a_leg(bridge.clone(), 1)).await.unwrap();
        tx.send(a_leg(bridge, 2)).await.unwrap();
        drop(tx);

        // `run` consumes `self`; hand it a dedicated handle to check afterwards
        // isn't possible directly, so this test only proves it doesn't hang or
        // panic when the channel closes — buffering itself is covered above.
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            actor.run(rx, CancellationToken::new()),
        )
        .await
        .expect("run must return once the channel closes, not hang");
    }

    #[tokio::test]
    async fn run_returns_promptly_on_shutdown() {
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        let actor = CorrelationActor::new(bridge, TimeDelta::minutes(10), 100);
        let (_tx, rx) = mpsc::channel(8); // kept open — only shutdown should end `run`
        let shutdown = CancellationToken::new();
        shutdown.cancel();

        tokio::time::timeout(std::time::Duration::from_secs(1), actor.run(rx, shutdown))
            .await
            .expect("run must return on an already-cancelled shutdown token");
    }
}
