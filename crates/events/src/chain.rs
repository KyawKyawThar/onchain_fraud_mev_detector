//! Chain events — emitted by the ingestion service (§5). These are the root of
//! every audit trail: a block arrives, gets assembled, becomes canonical (or
//! reverted on a reorg), and is eventually finalized.

use crate::primitives::BlockRef;
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

/// A block header was observed from a source adapter, before assembly (§5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RawBlockReceived {
    pub block: BlockRef,
    /// Block timestamp (unix seconds), as reported by the chain.
    pub timestamp: u64,
}

/// A block was fully assembled (txs + traces available for detection) (§5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BlockAssembled {
    pub block: BlockRef,
    pub tx_count: u32,
    /// Whether execution traces are available — detectors that need traces gate
    /// on this rather than assuming.
    pub trace_available: bool,
}

/// A block entered the canonical chain (§5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BlockCanonicalized {
    pub block: BlockRef,
}

/// A block was orphaned by a reorg; consumers of cross-block state roll back to
/// the common ancestor (§5, §15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BlockReverted {
    pub block: BlockRef,
    /// The block that now occupies this height on the canonical chain.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub replaced_by: B256,
}

/// A block passed the finalization depth and can no longer be reorged (§15).
/// Provisional state keyed to it can be promoted to final.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BlockFinalized {
    pub block: BlockRef,
}
