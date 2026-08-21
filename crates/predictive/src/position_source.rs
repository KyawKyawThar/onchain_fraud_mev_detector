//! The lending log **source** adapter (§16.1): fetches Aave/Compound position
//! event logs for one canonical block via `eth_getLogs`, mirroring
//! [`crate::source`]'s single-RPC-endpoint adapter shape (§16 — no failover
//! pool, same deliberately-scoped-down first cut).
//!
//! Unlike the mempool source's own polling loop, this isn't driven by a ticker:
//! there's no "poll for new logs" shape to a `BlockCanonicalized`-triggered
//! fetch, so [`position_consumer`](crate::position_consumer) calls
//! [`LendingLogSource::logs_for_block`] once per canonical block rather than
//! this module running its own loop.

use std::sync::Arc;

use alloy_primitives::{Address, B256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types_eth::Filter;
use alloy_transport::TransportError;
use async_trait::async_trait;
use url::Url;

use crate::lending_decode::RawLog;

/// What can go wrong fetching a block's lending logs.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("lending log RPC call failed: {0}")]
    Transport(#[from] TransportError),
}

/// The seam [`position_consumer`](crate::position_consumer) fetches a block's
/// lending logs through, so it's testable without a live node — mirrors
/// [`crate::source::MempoolSource`].
#[async_trait]
pub trait LendingLogSource: Send + Sync {
    /// Every log emitted by the tracked lending contracts in the block
    /// identified by `block_hash`.
    async fn logs_for_block(&self, block_hash: B256) -> Result<Vec<RawLog>, SourceError>;
}

/// The production [`LendingLogSource`]: a single HTTP RPC endpoint, filtered to
/// the configured set of lending contract addresses (Aave `Pool` proxy(ies),
/// Compound `CToken` markets) so the log volume `eth_getLogs` returns per block
/// stays bounded to what this tracker actually decodes, rather than every log
/// the block emitted.
pub struct RpcLendingLogSource {
    provider: RootProvider,
    addresses: Arc<[Address]>,
}

impl RpcLendingLogSource {
    /// Build a source over `url`, watching `addresses`. Constructing the
    /// provider does no I/O — the first `logs_for_block` call is what actually
    /// touches the network.
    pub fn new(url: Url, addresses: Vec<Address>) -> Self {
        Self {
            provider: RootProvider::new_http(url),
            addresses: addresses.into(),
        }
    }
}

#[async_trait]
impl LendingLogSource for RpcLendingLogSource {
    async fn logs_for_block(&self, block_hash: B256) -> Result<Vec<RawLog>, SourceError> {
        if self.addresses.is_empty() {
            // No lending contracts configured — nothing to fetch. An
            // address-less `eth_getLogs` filter would instead return every log
            // in the block, unbounded, so this short-circuits rather than
            // sending that query.
            return Ok(Vec::new());
        }
        let filter = Filter::new()
            .at_block_hash(block_hash)
            .address(self.addresses.to_vec());
        let logs = self.provider.get_logs(&filter).await?;
        Ok(logs
            .into_iter()
            .map(|log| RawLog {
                address: log.address(),
                topics: log.data().topics().to_vec(),
                data: log.data().data.clone(),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A source with no configured addresses must not query the node at all
    /// (an unfiltered `eth_getLogs` would be unbounded) — this exercises the
    /// short-circuit without a live provider.
    #[tokio::test]
    async fn an_empty_address_list_short_circuits_without_a_network_call() {
        let source = RpcLendingLogSource::new(
            Url::parse("http://127.0.0.1:1").unwrap(), // nothing listens here
            Vec::new(),
        );
        let logs = source.logs_for_block(B256::ZERO).await.unwrap();
        assert!(logs.is_empty());
    }
}
