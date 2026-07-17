//! Chain data **source adapters** (§5).
//!
//! §5 lists three adapters in order of preference:
//!   1. **reth ExEx (in-node) — post-execution pipeline** — delivered as
//!      [`exex::ExExSource`] + [`exex::run_bridge`] (Sprint 11). Push-based: it
//!      translates each reth notification into the same [`ChainHead`] stream the
//!      poller produces and feeds the *same* pipeline, so the
//!      `BlockAssembled`/reorg contract is preserved (the reth crate wiring lives
//!      in the excluded `ingestion-exex-node` crate — see that module's docs).
//!   2. own-node IPC/WebSocket — deferred to Phase 8.
//!   3. **RPC failover pool — health-checked, circuit-broken** — delivered as
//!      [`rpc::RpcFailoverPool`] (Sprint 2).
//!
//! They share one seam, the [`ChainSource`] trait, so the rest of the ingestion
//! service (the reorg-aware block tree, tasks 2–4) is written against the trait
//! and the adapter is chosen by configuration — adding adapter #2 later is a new
//! `impl`, not a rewrite. Adapter #1 reuses the pipeline wholesale rather than
//! re-implementing the reorg walk (see [`exex`]).

pub mod circuit;
pub mod endpoint;
pub mod exex;
pub mod head_stream;
pub mod rpc;

use alloy_primitives::B256;
use async_trait::async_trait;
use events::primitives::BlockRef;

/// A block header observed from a source, reduced to the fields the reorg-aware
/// block tree (§5) needs: `number`+`hash` order and identify the block,
/// `parent_hash` links it to its parent (the edge a reorg walk follows to the
/// common ancestor), and `timestamp` carries onto [`events::chain::RawBlockReceived`].
///
/// Deliberately *not* the full block — the source layer streams cheap heads;
/// execution traces are fetched on demand during assembly. `tx_count` is the one
/// body fact carried along, because the header fetch (`eth_getBlockByNumber`)
/// already returns the transaction-hash array, so counting it is free and saves
/// a second round-trip just to fill [`events::chain::BlockAssembled::tx_count`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainHead {
    pub number: u64,
    pub hash: B256,
    pub parent_hash: B256,
    /// Block timestamp as reported by the chain (unix seconds).
    pub timestamp: u64,
    /// Number of transactions in the block, from the header fetch's tx-hash
    /// array. Feeds [`events::chain::BlockAssembled::tx_count`].
    pub tx_count: u32,
}

impl ChainHead {
    /// The `(number, hash)` pair the event schema uses everywhere downstream.
    pub fn block_ref(&self) -> BlockRef {
        BlockRef::new(self.number, self.hash)
    }
}

/// What can go wrong fetching from a source. [`SourceError::AllEndpointsDown`]
/// is the failover pool's "everyone is sick" signal — distinct from a transport
/// error against a single endpoint, which the pool absorbs by failing over.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    /// Every endpoint was either circuit-broken/quarantined (so `routable` of
    /// `total` were even attempted) or failed the call. Carries the last
    /// underlying error so the cause isn't lost behind the pool abstraction.
    #[error(
        "all RPC endpoints failed for `{op}` ({routable} routable of {total}); last error: {last_error}"
    )]
    AllEndpointsDown {
        op: &'static str,
        total: usize,
        routable: usize,
        last_error: String,
    },

    /// The block was not present on the queried endpoint (RPC returned null) —
    /// e.g. a height ahead of the node's tip, or a hash it doesn't know.
    #[error("block {0} not found")]
    BlockNotFound(String),

    /// The source cannot answer *yet* — not a missing block, but a fact the
    /// source hasn't observed at all (the in-node [`exex::ExExSource`] before its
    /// first notification, or before the node has reported a `finalized` tag).
    /// Distinct from [`BlockNotFound`](Self::BlockNotFound) so a caller can tell
    /// "no such block" from "come back later"; both are non-fatal to the pipeline
    /// (a finality tick treats either as "retry next tick").
    #[error("source unavailable: {0}")]
    Unavailable(&'static str),
}

/// The seam every source adapter implements (§5). Object-safe (via
/// `async_trait`) so the service can hold a `Box<dyn ChainSource>` chosen by
/// config and swap adapters without generics rippling through it.
///
/// Reads are header-only; assembling full blocks (txs/traces) is task 2.
#[async_trait]
pub trait ChainSource: Send + Sync {
    /// The latest block height the source has seen (`eth_blockNumber`). The head
    /// poller diffs this against the last emitted height to find new blocks.
    async fn latest_block_number(&self) -> Result<u64, SourceError>;

    /// The head at `number` (`eth_getBlockByNumber`, hashes only).
    async fn head_by_number(&self, number: u64) -> Result<ChainHead, SourceError>;

    /// The head with `hash` (`eth_getBlockByHash`, hashes only). The reorg walk
    /// (task 4) follows `parent_hash` back to the common ancestor with this.
    async fn head_by_hash(&self, hash: B256) -> Result<ChainHead, SourceError>;

    /// The latest *finalized* head (`finalized` tag, post-merge). Drives
    /// `BlockFinalized` and bounds the in-memory block tree (§5, §15).
    async fn finalized_head(&self) -> Result<ChainHead, SourceError>;

    /// Whether this source can supply execution traces for an assembled block,
    /// carried onto [`events::chain::BlockAssembled::trace_available`] so
    /// trace-dependent detectors gate on it rather than assuming. The RPC
    /// failover pool (adapter #3) is header-only and returns `false`; the in-node
    /// reth ExEx adapter ([`exex::ExExSource`], #1) *can* observe post-execution
    /// state, but only advertises `true` once a trace-delivery seam actually backs
    /// it ([`exex::ExExSource::advertising_traces`]) — a capability follows its
    /// mechanism, so its header-only default is honestly `false`.
    fn traces_available(&self) -> bool {
        false
    }
}
