//! The archive-read seam: the four reads enrichment needs, and how their
//! failures are classified.
//!
//! Object-safe, so a caller holds `Arc<dyn ArchiveRpc>` and a test swaps in
//! [`crate::test_util::FakeChain`]. The production implementation is
//! [`crate::alloy::AlloyArchiveRpc`].

use alloy_primitives::{Address, Bytes, B256};
use async_trait::async_trait;

use crate::decode::{RawBlock, RawReceipt};

/// Which state a contract call reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StateAt {
    /// The state after the block with this hash. By hash rather than number,
    /// so a reorg cannot silently answer from a different block.
    Block(B256),
    /// The node's current head. Used only for boot-time checks of immutable
    /// facts (a feed's description).
    Latest,
}

/// A contract call that reached the EVM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallOutcome {
    /// The call returned. Empty bytes mean the address had no code.
    Returned(Bytes),
    /// The call reverted: the contract exists and refused. For a probe
    /// (`decimals()` on a non-token) this is an answer, not a failure.
    Reverted,
}

/// A read that did not produce an answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RpcError {
    /// Worth retrying later: a timeout, a dropped connection, a rate limit, a
    /// 5xx. The transport has already retried within its own budget.
    #[error("archive node unavailable ({op}): {detail}")]
    Transient { op: &'static str, detail: String },
    /// The node answered, but has no state for the block. Enrichment needs an
    /// archive node; a pruned full node fails here for anything old.
    #[error(
        "the node has no state for {op} — an archive node is required (a full node prunes \
         historical state): {detail}"
    )]
    NotArchive { op: &'static str, detail: String },
    /// Anything else: bad credentials, a malformed response, a method the
    /// node does not support. Retrying will not help.
    #[error("archive node refused {op}: {detail}")]
    Permanent { op: &'static str, detail: String },
}

impl RpcError {
    pub fn is_transient(&self) -> bool {
        matches!(self, RpcError::Transient { .. })
    }
}

#[async_trait]
pub trait ArchiveRpc: Send + Sync {
    /// The chain the node serves (`eth_chainId`).
    async fn chain_id(&self) -> Result<u64, RpcError>;

    /// A block with its full transactions, or `None` if the node does not
    /// know the hash (it was never canonical there, or was reorged away).
    async fn block(&self, hash: B256) -> Result<Option<RawBlock>, RpcError>;

    /// Every receipt in the block (`eth_getBlockReceipts`), in block order.
    async fn receipts(&self, hash: B256) -> Result<Option<Vec<RawReceipt>>, RpcError>;

    /// `eth_call` with no value and no sender.
    async fn call(&self, to: Address, data: Bytes, at: StateAt) -> Result<CallOutcome, RpcError>;
}

#[async_trait]
impl<T: ArchiveRpc + ?Sized> ArchiveRpc for std::sync::Arc<T> {
    async fn chain_id(&self) -> Result<u64, RpcError> {
        (**self).chain_id().await
    }
    async fn block(&self, hash: B256) -> Result<Option<RawBlock>, RpcError> {
        (**self).block(hash).await
    }
    async fn receipts(&self, hash: B256) -> Result<Option<Vec<RawReceipt>>, RpcError> {
        (**self).receipts(hash).await
    }
    async fn call(&self, to: Address, data: Bytes, at: StateAt) -> Result<CallOutcome, RpcError> {
        (**self).call(to, data, at).await
    }
}
