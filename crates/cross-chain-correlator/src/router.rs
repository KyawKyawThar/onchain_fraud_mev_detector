//! The leg router — the fan-in side of §17's "one async consumer per chain's
//! event stream feeding a single correlation actor per bridge/pair": every
//! chain consumer shares one [`LegRouter`], built once at boot from the
//! configured bridge/pair roster, and uses it to hand each recognized leg to
//! its owning actor.

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

    /// Forward `leg` to its bridge/pair's correlation actor, blocking on the
    /// bounded channel if that actor is behind (§17 backpressure — a slow
    /// actor can't be outrun into unbounded memory by its feeding
    /// consumers). A leg for a bridge/pair with no configured actor is
    /// dropped with a warning: the operator never declared it, so there is
    /// no window to hold it in.
    pub async fn route(&self, leg: CandidateLeg) {
        let Some(tx) = self.senders.get(&leg.bridge_or_pair) else {
            tracing::warn!(
                bridge_or_pair = %leg.bridge_or_pair,
                "no correlation actor configured for this bridge/pair; dropping leg"
            );
            return;
        };
        if tx.send(leg).await.is_err() {
            tracing::warn!("correlation actor channel closed; dropping leg");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leg::LegKind;
    use alloy_primitives::{Address, B256};
    use chrono::Utc;
    use events::primitives::{BlockRef, Chain};

    fn a_leg(bridge_or_pair: BridgeOrPair) -> CandidateLeg {
        CandidateLeg {
            chain: Chain::ETHEREUM,
            block: BlockRef::new(1, B256::repeat_byte(1)),
            tx: B256::repeat_byte(1),
            kind: LegKind::BridgeDeposit,
            bridge_or_pair,
            correlation_key: Address::repeat_byte(1),
            observed_at: Utc::now(),
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
}
