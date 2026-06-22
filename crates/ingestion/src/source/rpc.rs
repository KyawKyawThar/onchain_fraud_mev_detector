//! Adapter #3 (§5): the **RPC failover pool**, health-checked and
//! circuit-broken.
//!
//! The pool owns an ordered list of [`RpcEndpoint`]s. Every read goes through
//! [`RpcFailoverPool::dispatch`], which tries each *routable* endpoint in order,
//! returns the first success, and records each outcome against that endpoint's
//! circuit breaker — so a sick endpoint trips out of rotation and the pool fails
//! over to the next without the caller noticing. A per-call timeout means a
//! *hung* endpoint counts as a failure too, not an indefinite stall.
//!
//! Liveness has two feeders into the same breakers: ordinary traffic (above)
//! and an active [`health_check_once`](RpcFailoverPool::health_check_once) probe
//! for endpoints that aren't currently receiving traffic (because they're open,
//! or simply never first in line) and to catch a wrong-chain misconfiguration.

use std::future::Future;
use std::time::{Duration, Instant};

use alloy_primitives::B256;
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types_eth::{Block, BlockNumberOrTag};
use alloy_transport::TransportError;
use async_trait::async_trait;
use events::primitives::Chain;
use url::Url;

use super::circuit::BreakerConfig;
use super::endpoint::RpcEndpoint;
use super::{ChainHead, ChainSource, SourceError};

/// A pool of RPC endpoints with health-checked, circuit-broken failover.
#[derive(Debug)]
pub struct RpcFailoverPool {
    endpoints: Vec<RpcEndpoint>,
    /// The chain every endpoint must serve; a mismatch quarantines it. Kept as
    /// the typed [`Chain`] (not a bare `u64`) so it can't be confused with the
    /// other `u64`s flying around (block numbers, ids).
    expected_chain: Chain,
    /// Per-call ceiling: a slower response is treated as a failure so the pool
    /// fails over instead of stalling.
    request_timeout: Duration,
}

impl RpcFailoverPool {
    /// Build a pool over `endpoints` (preference order). Pure — no network I/O
    /// happens until the first call or a health probe.
    pub fn new(
        endpoints: &[Url],
        expected_chain: Chain,
        request_timeout: Duration,
        breaker: BreakerConfig,
    ) -> Self {
        Self {
            endpoints: endpoints
                .iter()
                .map(|u| RpcEndpoint::new(u.clone(), breaker))
                .collect(),
            expected_chain,
            request_timeout,
        }
    }

    /// How many endpoints could be routed to right now — for tests and health
    /// logging. (Calls `is_routable`, which may flip open→half-open.)
    pub fn routable_count(&self, now: Instant) -> usize {
        self.endpoints.iter().filter(|e| e.is_routable(now)).count()
    }

    /// Try each routable endpoint in order; return the first success. Each
    /// attempt goes through [`RpcEndpoint::guarded`], which applies the per-call
    /// timeout and records the outcome against the breaker — so this method only
    /// owns *selection* and *failover*, not the resilience policy itself.
    async fn dispatch<T, F, Fut>(&self, op: &'static str, call: F) -> Result<T, SourceError>
    where
        F: Fn(RootProvider) -> Fut,
        Fut: Future<Output = Result<T, TransportError>>,
    {
        let mut routable = 0;
        let mut last_error = String::new();

        for ep in &self.endpoints {
            if !ep.is_routable(Instant::now()) {
                continue;
            }
            routable += 1;

            match ep.guarded(self.request_timeout, &call).await {
                Ok(value) => return Ok(value),
                Err(err) => {
                    tracing::warn!(op, endpoint = %ep.url(), error = %err, "RPC call failed; failing over");
                    last_error = err.to_string();
                }
            }
        }

        if routable == 0 {
            last_error = "all endpoints circuit-broken or quarantined".to_owned();
        }
        Err(SourceError::AllEndpointsDown {
            op,
            total: self.endpoints.len(),
            routable,
            last_error,
        })
    }

    /// Fetch a head by block selector, mapping an absent block (RPC `null`) to
    /// [`SourceError::BlockNotFound`].
    async fn head_by_tag(
        &self,
        op: &'static str,
        tag: BlockNumberOrTag,
        label: impl std::fmt::Display,
    ) -> Result<ChainHead, SourceError> {
        let block = self
            .dispatch(op, move |p| async move { p.get_block_by_number(tag).await })
            .await?;
        map_head(block, label)
    }

    /// Probe every endpoint's `eth_chainId` once and update its health:
    /// right chain → clears any quarantine; wrong chain → quarantine; error or
    /// timeout → a failure against the breaker. The breaker recording (and the
    /// timeout) happen inside [`RpcEndpoint::guarded`] — the same path ordinary
    /// traffic takes — so the two can never drift apart. Drive this on an interval.
    pub async fn health_check_once(&self) {
        for ep in &self.endpoints {
            match ep
                .guarded(
                    self.request_timeout,
                    |p| async move { p.get_chain_id().await },
                )
                .await
            {
                Ok(id) if Chain(id) == self.expected_chain => {
                    if ep.is_quarantined() {
                        tracing::info!(endpoint = %ep.url(), chain_id = id, "endpoint back on the expected chain; clearing quarantine");
                        ep.clear_quarantine();
                    }
                }
                Ok(id) => {
                    tracing::error!(
                        endpoint = %ep.url(),
                        expected = self.expected_chain.id(),
                        found = id,
                        "RPC endpoint is on the wrong chain; quarantining"
                    );
                    ep.quarantine();
                }
                Err(err) => {
                    tracing::warn!(endpoint = %ep.url(), error = %err, "health probe failed");
                }
            }
        }
    }

    /// Whether *every* endpoint is quarantined (all on the wrong chain) — a
    /// non-recoverable config error the caller should fail fast on.
    pub fn all_quarantined(&self) -> bool {
        !self.endpoints.is_empty() && self.endpoints.iter().all(RpcEndpoint::is_quarantined)
    }
}

/// Map an optional RPC block to a [`ChainHead`], turning an absent block (RPC
/// `null`) into [`SourceError::BlockNotFound`] with a caller-supplied label.
fn map_head(block: Option<Block>, label: impl std::fmt::Display) -> Result<ChainHead, SourceError> {
    match block {
        Some(block) => Ok(ChainHead {
            number: block.header.number,
            hash: block.header.hash,
            parent_hash: block.header.parent_hash,
            timestamp: block.header.timestamp,
        }),
        None => Err(SourceError::BlockNotFound(label.to_string())),
    }
}

#[async_trait]
impl ChainSource for RpcFailoverPool {
    async fn latest_block_number(&self) -> Result<u64, SourceError> {
        self.dispatch(
            "eth_blockNumber",
            |p| async move { p.get_block_number().await },
        )
        .await
    }

    async fn head_by_number(&self, number: u64) -> Result<ChainHead, SourceError> {
        self.head_by_tag(
            "eth_getBlockByNumber",
            BlockNumberOrTag::Number(number),
            number,
        )
        .await
    }

    async fn head_by_hash(&self, hash: B256) -> Result<ChainHead, SourceError> {
        let block = self
            .dispatch("eth_getBlockByHash", move |p| async move {
                p.get_block_by_hash(hash).await
            })
            .await?;
        map_head(block, hash)
    }

    async fn finalized_head(&self) -> Result<ChainHead, SourceError> {
        self.head_by_tag(
            "eth_getBlockByNumber(finalized)",
            BlockNumberOrTag::Finalized,
            "finalized",
        )
        .await
    }
}
