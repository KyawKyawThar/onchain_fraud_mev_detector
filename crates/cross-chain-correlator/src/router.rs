//! The leg router — the fan-in side of §17's "one async consumer per chain's
//! event stream feeding a single correlation actor per bridge/pair": every
//! chain consumer shares one [`LegRouter`], built once at boot from the
//! configured bridge/pair roster, and uses it to hand each recognized leg to
//! its owning actor.
//!
//! **Non-blocking routing (production hardening).** [`LegRouter::route`]
//! uses `try_send`, never a blocking `send`. A blocking send on one
//! bridge/pair's full channel would stall the *calling*
//! [`crate::chain_consumer::ChainConsumer`] — and since one chain's stream
//! can carry legs for every bridge/pair, a single stalled/slow actor would
//! head-of-line-block every other (healthy) bridge/pair sharing that
//! consumer, and transitively the whole chain's ingestion. A full channel
//! now drops the new leg instead (with a metric an operator can alert on) —
//! the sick bridge/pair loses a leg it was already failing to keep up with,
//! but every unrelated bridge/pair on the same chain stays unaffected.

use std::collections::HashMap;

use tokio::sync::mpsc;

use crate::leg::{BridgeOrPair, CandidateLeg};

/// Maps a bridge/pair to the [`mpsc::Sender`] half of its
/// [`crate::actor::CorrelationActor`]'s channel. Built once at boot (one
/// sender per configured bridge/pair) and shared (`Arc`) across every
/// per-chain consumer task.
pub struct LegRouter {
    senders: HashMap<BridgeOrPair, mpsc::Sender<CandidateLeg>>,
}

impl LegRouter {
    pub fn new(senders: HashMap<BridgeOrPair, mpsc::Sender<CandidateLeg>>) -> Self {
        Self { senders }
    }

    /// Forward `leg` to its bridge/pair's correlation actor — never blocking
    /// the caller (see module docs). A leg for a bridge/pair with no
    /// configured actor, one whose actor's channel is full (§17
    /// backpressure has a limit: past it, the leg is dropped rather than
    /// stalling every other bridge/pair on the same chain consumer), or one
    /// whose actor task has already exited is dropped with a warning +
    /// metric instead.
    pub async fn route(&self, leg: CandidateLeg) {
        let Some(tx) = self.senders.get(&leg.bridge_or_pair) else {
            tracing::warn!(
                bridge_or_pair = %leg.bridge_or_pair,
                "no correlation actor configured for this bridge/pair; dropping leg"
            );
            crate::metrics::record_leg_dropped(&leg.bridge_or_pair, "unconfigured");
            return;
        };
        match tx.try_send(leg) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(leg)) => {
                tracing::warn!(
                    bridge_or_pair = %leg.bridge_or_pair,
                    "correlation actor's channel is full; dropping this leg rather than \
                     blocking every other bridge/pair on the same chain consumer \
                     (check for a stalled/slow actor)"
                );
                crate::metrics::record_leg_dropped(&leg.bridge_or_pair, "actor_backpressure");
            }
            Err(mpsc::error::TrySendError::Closed(leg)) => {
                tracing::warn!(
                    bridge_or_pair = %leg.bridge_or_pair,
                    "correlation actor channel closed; dropping leg"
                );
                crate::metrics::record_leg_dropped(&leg.bridge_or_pair, "actor_closed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leg::LegKind;
    use alloy_primitives::{Address, B256};
    use chrono::Utc;
    use events::primitives::{BlockRef, Chain, Confidence};

    fn a_leg(bridge_or_pair: BridgeOrPair) -> CandidateLeg {
        CandidateLeg {
            chain: Chain::ETHEREUM,
            block: BlockRef::new(1, B256::repeat_byte(1)),
            tx: B256::repeat_byte(1),
            kind: LegKind::BridgeDeposit,
            bridge_or_pair,
            correlation_key: Address::repeat_byte(1),
            observed_at: Utc::now(),
            confidence: Confidence::new(0.9),
            impact_usd: None,
        }
    }

    #[tokio::test]
    async fn routes_to_the_matching_bridge_or_pairs_sender() {
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        let (tx, mut rx) = mpsc::channel(1);
        let router = LegRouter::new(HashMap::from([(bridge.clone(), tx)]));

        router.route(a_leg(bridge.clone())).await;

        let received = rx.recv().await.expect("the leg must be routed through");
        assert_eq!(received.bridge_or_pair, bridge);
    }

    #[tokio::test]
    async fn an_unconfigured_bridge_or_pair_is_dropped_not_panicked() {
        let router = LegRouter::new(HashMap::new());
        router
            .route(a_leg(BridgeOrPair("unknown-bridge".to_owned())))
            .await;
        // No assertion beyond "did not panic/hang" — the drop is a log line.
    }

    #[tokio::test]
    async fn a_closed_actor_channel_is_handled_without_panicking() {
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let router = LegRouter::new(HashMap::from([(bridge.clone(), tx)]));

        router.route(a_leg(bridge)).await;
    }

    #[tokio::test]
    async fn a_full_channel_drops_the_leg_instead_of_blocking() {
        // The head-of-line-blocking fix: routing into a full channel must
        // return immediately (not await capacity) so a stalled actor can
        // never stall the chain consumer feeding every other bridge/pair.
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        let (tx, mut rx) = mpsc::channel(1);
        let router = LegRouter::new(HashMap::from([(bridge.clone(), tx)]));

        router.route(a_leg(bridge.clone())).await; // fills the capacity-1 channel
        tokio::time::timeout(
            std::time::Duration::from_millis(200),
            router.route(a_leg(bridge)),
        )
        .await
        .expect("route must never block on a full channel");

        // Only the first leg made it through; the second was dropped.
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err());
    }
}
