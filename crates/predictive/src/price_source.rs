//! The oracle price **source** adapter (§16.2, Sprint 16 task 2): a single RPC
//! endpoint polled for Chainlink-style `latestRoundData()` answers, mirroring
//! [`crate::source`]'s single-endpoint poller shape (§16 — no failover pool,
//! same deliberately-scoped-down first cut every other adapter in this crate
//! takes).
//!
//! Unlike the mempool source (`eth_newPendingTransactionFilter` +
//! `eth_getFilterChanges`), there is no server-side filter for "what changed
//! since my last poll" over a `view` call — [`RpcPriceSource::poll`] instead
//! remembers each feed's last-seen `updatedAt` itself and only reports a
//! [`PriceTick`] for a feed whose `updatedAt` actually advanced. That's what
//! makes the cascade engine's recompute driven by "each oracle/mark-price
//! update" rather than "each poll tick" (most ticks see no change at all).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy_primitives::{keccak256, Address, Bytes, U256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use alloy_transport::TransportError;
use async_trait::async_trait;
use detector_api::UsdPrice;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::abi_words::u256_at;
use crate::config::AssetFeed;

/// A genuine oracle/mark-price update: `asset`'s reference price advanced to
/// `price` as of the feed's `updated_at` (the Chainlink round's `updatedAt`,
/// raw unix-seconds `U256` — kept as the on-chain word rather than narrowed to
/// a `u64`, since it's only ever compared, never put on the wire).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PriceTick {
    pub asset: Address,
    pub price: UsdPrice,
    pub updated_at: U256,
}

/// What can go wrong talking to the oracle price source.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("oracle price-feed RPC call failed: {0}")]
    Transport(#[from] TransportError),
}

/// The seam the poller (below) is written against, so it's testable without a
/// live node — mirrors [`crate::source::MempoolSource`]. One method (not
/// `MempoolSource`'s open-filter/drain-changes split): a `view` call has no
/// server-side filter concept, so change-detection lives inside the
/// implementation instead (see [`RpcPriceSource`]).
#[async_trait]
pub trait PriceSource: Send + Sync {
    /// Every feed that has genuinely advanced since the last call.
    async fn poll(&self) -> Result<Vec<PriceTick>, SourceError>;
}

/// The production [`PriceSource`]: a single HTTP RPC endpoint, calling
/// `latestRoundData()` on each configured [`AssetFeed`].
pub struct RpcPriceSource {
    provider: RootProvider,
    feeds: Vec<AssetFeed>,
    /// Last-seen `updatedAt` per feed address — the change-detection state
    /// `poll` needs despite being `&self` (called repeatedly from one poller
    /// loop, §16).
    last_updated_at: Mutex<HashMap<Address, U256>>,
}

impl RpcPriceSource {
    /// Build a source over `url`, watching `feeds`. Constructing the provider
    /// does no I/O — the first `poll` call is what actually touches the
    /// network.
    pub fn new(url: Url, feeds: Vec<AssetFeed>) -> Self {
        Self {
            provider: RootProvider::new_http(url),
            feeds,
            last_updated_at: Mutex::new(HashMap::new()),
        }
    }
}

/// The 4-byte selector for Chainlink's `AggregatorV3Interface.latestRoundData()`
/// — no arguments, so the call's `input` is exactly this selector.
fn latest_round_data_selector() -> [u8; 4] {
    let hash = keccak256(b"latestRoundData()");
    [hash[0], hash[1], hash[2], hash[3]]
}

/// Decode a `latestRoundData()` return into `(answer, updatedAt)` — the two of
/// its five ABI-encoded words (`roundId`, `answer`, `startedAt`, `updatedAt`,
/// `answeredInRound`) this source needs. `None` if the response is shorter
/// than the standard 5-word tuple (a malformed/unexpected responder).
fn decode_round_data(bytes: &[u8]) -> Option<(U256, U256)> {
    let answer = u256_at(bytes, 1)?;
    let updated_at = u256_at(bytes, 3)?;
    Some((answer, updated_at))
}

#[async_trait]
impl PriceSource for RpcPriceSource {
    async fn poll(&self) -> Result<Vec<PriceTick>, SourceError> {
        let mut ticks = Vec::new();
        let calldata = Bytes::from(latest_round_data_selector().to_vec());

        for feed in &self.feeds {
            let call = TransactionRequest::default()
                .to(feed.feed)
                .input(TransactionInput::new(calldata.clone()));
            let response = self.provider.call(call).await?;

            let Some((answer, updated_at)) = decode_round_data(&response) else {
                tracing::warn!(
                    feed = %feed.feed,
                    "malformed latestRoundData() response; skipping this feed this tick"
                );
                continue;
            };

            let advanced = {
                let mut last = self.last_updated_at.lock().unwrap();
                let is_new = last
                    .get(&feed.feed)
                    .is_none_or(|previous| updated_at > *previous);
                if is_new {
                    last.insert(feed.feed, updated_at);
                }
                is_new
            };
            if !advanced {
                continue;
            }

            let scaled = f64::from(answer) / 10f64.powi(i32::from(feed.feed_decimals));
            let price = match UsdPrice::try_new(scaled) {
                Ok(price) => price,
                Err(err) => {
                    tracing::warn!(
                        feed = %feed.feed,
                        error = %err,
                        "oracle feed answer isn't a valid price; skipping this update"
                    );
                    continue;
                }
            };

            ticks.push(PriceTick {
                asset: feed.asset,
                price,
                updated_at,
            });
        }

        Ok(ticks)
    }
}

/// Poll `source` every `interval` and forward each genuine price update to
/// `tx`. Returns when `shutdown` is cancelled or `tx` is closed (the cascade
/// engine went away). Mirrors [`crate::source::run_mempool_poller`]'s
/// log-and-retry-next-tick discipline for transient errors, but with no
/// filter-id lifecycle to manage — `RpcPriceSource::poll` is self-contained.
pub async fn run_price_poller(
    source: Arc<dyn PriceSource>,
    interval: Duration,
    tx: mpsc::Sender<PriceTick>,
    shutdown: CancellationToken,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                tracing::info!("oracle price poller shutting down");
                return;
            }
            _ = ticker.tick() => {}
        }

        let ticks = match source.poll().await {
            Ok(ticks) => ticks,
            Err(err) => {
                tracing::warn!(error = %err, "polling oracle price feeds failed; retrying next tick");
                continue;
            }
        };

        for tick in ticks {
            if tx.send(tick).await.is_err() {
                tracing::info!("cascade engine dropped; stopping oracle price poller");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word32(value: &[u8]) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[32 - value.len()..].copy_from_slice(value);
        w
    }

    /// A synthetic ABI-encoded `latestRoundData()` return: the standard
    /// 5-word tuple with the given `answer`/`updated_at`.
    fn round_data_bytes(answer: u64, updated_at: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&word32(&[1])); // roundId
        bytes.extend_from_slice(&word32(&answer.to_be_bytes())); // answer
        bytes.extend_from_slice(&word32(&[0])); // startedAt
        bytes.extend_from_slice(&word32(&updated_at.to_be_bytes())); // updatedAt
        bytes.extend_from_slice(&word32(&[1])); // answeredInRound
        bytes
    }

    #[test]
    fn decode_round_data_reads_answer_and_updated_at() {
        let bytes = round_data_bytes(200_000_000_000, 1_700_000_000);
        let (answer, updated_at) = decode_round_data(&bytes).expect("decodes");
        assert_eq!(answer, U256::from(200_000_000_000u64));
        assert_eq!(updated_at, U256::from(1_700_000_000u64));
    }

    #[test]
    fn decode_round_data_rejects_a_short_response() {
        let bytes = round_data_bytes(1, 1);
        assert!(decode_round_data(&bytes[..64]).is_none());
    }

    #[tokio::test]
    async fn an_empty_feed_list_polls_to_no_ticks_without_a_network_call() {
        let source = RpcPriceSource::new(
            Url::parse("http://127.0.0.1:1").unwrap(), // nothing listens here
            Vec::new(),
        );
        let ticks = source.poll().await.unwrap();
        assert!(ticks.is_empty());
    }
}
