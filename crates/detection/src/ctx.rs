//! [`DetectionCtx`] — everything a detector sees about one block (§6).
//!
//! The context is two halves: a [`BlockBundle`] of raw on-chain facts (which
//! block, which txs by hash) and an [`Enrichment`] (token/pool/price + decoded
//! per-tx swaps/transfers) layered on top. Task 1 shaped the boundary as a
//! skeleton; task 3 filled the enrichment in — additively, so detectors written
//! against `block`/`chain`/`txs` kept compiling while gaining
//! [`enrichment`](DetectionCtx::enrichment).
//!
//! The one invariant fixed now and enforced forever: **no labels live on this
//! context.** Attribution is the intelligence service's job, off the hot path
//! (§6, §8). A detector physically cannot read a label because neither the bundle
//! nor the enrichment carries one (see [`crate::enrichment`]).

use alloy_primitives::B256;
use events::primitives::{BlockRef, Chain};

use crate::enrichment::Enrichment;

/// The assembled block a detector runs over: the canonical facts from the
/// ingestion service's `BlockAssembled` (§5).
///
/// Carries the canonical facts the seam needs — which block, on which chain, and
/// the transactions in it (by hash, in block order). The decoded view of each
/// transaction (swaps, transfers, pool state) lives alongside on the
/// [`DetectionCtx`]'s [`Enrichment`], keyed by hash, so the bundle stays *what
/// the chain said* and enrichment stays *what we decoded*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockBundle {
    pub chain: Chain,
    pub block: BlockRef,
    /// Transaction hashes in block order. The decoded actions for each live on
    /// the [`DetectionCtx`]'s [`Enrichment`], looked up by hash.
    pub txs: Vec<B256>,
}

impl BlockBundle {
    pub fn new(chain: Chain, block: BlockRef, txs: Vec<B256>) -> Self {
        Self { chain, block, txs }
    }
}

/// What a detector is handed (§6): the [`BlockBundle`] of raw facts plus the
/// [`Enrichment`] (token/pool/price + decoded per-tx actions), and **never**
/// labels.
///
/// Constructed once per block by the detection service and passed by shared
/// reference to every detector, so building it is amortised across the whole
/// roster (§17). `Eq` is intentionally *not* derived: enrichment carries
/// floating-point prices, which have no total equality.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectionCtx {
    bundle: BlockBundle,
    enrichment: Enrichment,
}

impl DetectionCtx {
    /// A context over `bundle` with no enrichment — the honest "raw facts only"
    /// state (e.g. a header-only source). Add enrichment with
    /// [`with_enrichment`](Self::with_enrichment).
    pub fn new(bundle: BlockBundle) -> Self {
        Self {
            bundle,
            enrichment: Enrichment::default(),
        }
    }

    /// A context over `bundle` carrying the decoded `enrichment` for its block.
    ///
    /// The enrichment must describe only transactions that are in the bundle —
    /// the detection service decodes both from the same `BlockAssembled`, so a
    /// tx in the enrichment but not the block is a wiring bug, never untrusted
    /// input. Checked with `debug_assert!`: it runs in every test/CI build (where
    /// such a bug would be introduced) and compiles out of the release hot path.
    pub fn with_enrichment(bundle: BlockBundle, enrichment: Enrichment) -> Self {
        debug_assert!(
            {
                let in_block: std::collections::HashSet<B256> =
                    bundle.txs.iter().copied().collect();
                enrichment.txs().all(|tx| in_block.contains(&tx.hash))
            },
            "enrichment carries decoded actions for a tx not in the block bundle \
             — detection-service decode/assembly wiring bug"
        );
        Self { bundle, enrichment }
    }

    /// The block under inspection.
    pub fn block(&self) -> BlockRef {
        self.bundle.block
    }

    /// The chain this block is on.
    pub fn chain(&self) -> Chain {
        self.bundle.chain
    }

    /// The block's transaction hashes, in block order. Look up a tx's decoded
    /// actions via [`enrichment`](Self::enrichment)`.tx(hash)`.
    pub fn txs(&self) -> &[B256] {
        &self.bundle.txs
    }

    /// The full bundle of raw facts, for detectors that want everything at once.
    pub fn bundle(&self) -> &BlockBundle {
        &self.bundle
    }

    /// The decoded enrichment (token metadata, pool reserves, prices, per-tx
    /// swaps/transfers) — **no labels** (§6, see [`crate::enrichment`]).
    pub fn enrichment(&self) -> &Enrichment {
        &self.enrichment
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrichment::TxActions;
    use alloy_primitives::Address;

    fn bundle(txs: Vec<B256>) -> BlockBundle {
        BlockBundle::new(
            Chain::ETHEREUM,
            BlockRef::new(1, B256::repeat_byte(0xaa)),
            txs,
        )
    }

    #[test]
    fn with_enrichment_accepts_actions_for_txs_in_the_block() {
        let tx_hash = B256::repeat_byte(1);
        let mut b = Enrichment::builder();
        b.add_tx(TxActions::new(tx_hash, Address::repeat_byte(2), None));
        let ctx = DetectionCtx::with_enrichment(bundle(vec![tx_hash]), b.build());
        assert!(ctx.enrichment().tx(tx_hash).is_some());
    }

    // The integrity guard is a `debug_assert!`, so this only exists in debug
    // builds (where the bug would be caught); a `--release` test run skips it
    // rather than failing on the absent panic.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "not in the block bundle")]
    fn with_enrichment_rejects_actions_for_a_tx_not_in_the_block() {
        let mut b = Enrichment::builder();
        b.add_tx(TxActions::new(
            B256::repeat_byte(0xff),
            Address::repeat_byte(2),
            None,
        ));
        // Block contains a *different* tx than the enrichment describes.
        let _ = DetectionCtx::with_enrichment(bundle(vec![B256::repeat_byte(1)]), b.build());
    }
}
