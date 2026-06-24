//! [`DetectionCtx`] — everything a detector sees about one block (§6).
//!
//! **Skeleton for task 1.** The plugin seam needs a context type to be shaped
//! against, so this file defines the boundary: a [`BlockBundle`] of on-chain
//! facts plus the *place* enrichment attaches. Task 3 ("`DetectionCtx`
//! enrichment — token/pool/price, **no labels** on the hot path") fills the
//! enrichment in; the public surface here is what detectors already compile
//! against, so adding enrichment is additive, not a breaking change.
//!
//! The one invariant fixed now and enforced forever: **no labels live on this
//! context.** Attribution is the intelligence service's job, off the hot path
//! (§6, §8). A detector physically cannot read a label because the context never
//! carries one.

use alloy_primitives::B256;
use events::primitives::{BlockRef, Chain};

/// The assembled block a detector runs over: the canonical facts from the
/// ingestion service's `BlockAssembled` (§5).
///
/// Task 1 carries the minimum the seam needs — which block, on which chain, and
/// the transactions in it (by hash). Task 3 enriches each transaction with
/// decoded calls / token transfers / pool state; that lands as added fields or a
/// richer `txs` element type, so detectors written against `block`/`chain`
/// keep compiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockBundle {
    pub chain: Chain,
    pub block: BlockRef,
    /// Transaction hashes in block order. Becomes the decoded/enriched tx set in
    /// task 3.
    pub txs: Vec<B256>,
}

impl BlockBundle {
    pub fn new(chain: Chain, block: BlockRef, txs: Vec<B256>) -> Self {
        Self { chain, block, txs }
    }
}

/// What a detector is handed (§6): the [`BlockBundle`] plus enrichment
/// (token/pool/price), and **never** labels.
///
/// Constructed once per block by the detection service and passed by shared
/// reference to every detector, so building it is amortised across the whole
/// roster. Enrichment fields arrive in task 3 — see the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionCtx {
    bundle: BlockBundle,
    // Task 3: `enrichment: Enrichment` (token metadata, pool reserves, prices).
    // Intentionally absent here so the seam and its tests compile and lock the
    // attribution-blind boundary before enrichment exists.
}

impl DetectionCtx {
    pub fn new(bundle: BlockBundle) -> Self {
        Self { bundle }
    }

    /// The block under inspection.
    pub fn block(&self) -> BlockRef {
        self.bundle.block
    }

    /// The chain this block is on.
    pub fn chain(&self) -> Chain {
        self.bundle.chain
    }

    /// The block's transactions (hashes for now; enriched in task 3).
    pub fn txs(&self) -> &[B256] {
        &self.bundle.txs
    }

    /// The full bundle, for detectors that want everything at once.
    pub fn bundle(&self) -> &BlockBundle {
        &self.bundle
    }
}
