//! Turn any [`ChainSource`] into an ordered stream of new [`ChainHead`]s by
//! polling `eth_blockNumber` and back-filling each height since the last one
//! seen.
//!
//! This is the source layer's output and the block tree's input (task 2):
//! consecutive heads carry the `parent_hash` linkage the reorg-aware assembler
//! walks. The RPC failover-pool adapter has no push subscription (that's the
//! node-IPC `newHeads` adapter #2, Phase 8), so we poll; the pool underneath
//! makes each poll resilient to a single endpoint failing.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::{ChainHead, ChainSource};

/// Cap on heads back-filled in a single tick, so a large gap (a long stall, or
/// the very first poll against a high tip) is drained over several ticks instead
/// of issuing thousands of requests at once.
const MAX_CATCHUP_PER_TICK: u64 = 256;

/// Poll `source` every `interval` and send each new head, in ascending height
/// order, to `tx`. Returns when `shutdown` is cancelled or `tx` is closed
/// (the consumer went away). Transient fetch errors are logged and retried on
/// the next tick — the pool has already failed over internally, so an error
/// here means *every* endpoint was down.
pub async fn run_head_poller(
    source: Arc<dyn ChainSource>,
    interval: Duration,
    tx: mpsc::Sender<ChainHead>,
    shutdown: CancellationToken,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Height of the last head we emitted; `None` until the first successful poll,
    // which seeds from the current tip (we don't back-fill all of history).
    let mut last_emitted: Option<u64> = None;

    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                tracing::info!("head poller shutting down");
                return;
            }
            _ = ticker.tick() => {}
        }

        let tip = match source.latest_block_number().await {
            Ok(tip) => tip,
            Err(err) => {
                tracing::warn!(error = %err, "head poll failed (all endpoints down); retrying next tick");
                continue;
            }
        };

        // First successful poll seeds the cursor at the tip without emitting the
        // whole backlog; thereafter emit every new height.
        let from = match last_emitted {
            None => tip,
            Some(last) if tip > last => last + 1,
            Some(_) => continue, // no new blocks (or a lower tip mid-reorg)
        };
        let to = (from + MAX_CATCHUP_PER_TICK.saturating_sub(1)).min(tip);

        for number in from..=to {
            let head = match source.head_by_number(number).await {
                Ok(head) => head,
                Err(err) => {
                    // Stop this tick at the gap; resume from here next tick.
                    tracing::warn!(number, error = %err, "fetching head failed; retrying next tick");
                    break;
                }
            };
            last_emitted = Some(number);
            if tx.send(head).await.is_err() {
                tracing::info!("head consumer dropped; stopping poller");
                return;
            }
        }
    }
}
