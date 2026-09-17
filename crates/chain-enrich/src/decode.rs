//! Pure decoding: a block and its receipts, plus the facts read about the
//! contracts they touched, into a [`DetectionCtx`].
//!
//! Nothing here performs I/O. The input types ([`RawBlock`], [`RawReceipt`])
//! are this crate's own, not alloy's RPC types, so the decoder is tested with
//! plain values and the transport adapter ([`crate::alloy`]) is the only code
//! that knows the node's wire shapes.
//!
//! # What is decoded, and what is refused
//!
//! - **ERC-20 transfers**: a `Transfer` log with exactly three topics and a
//!   32-byte body. ERC-721 emits the same signature with the id as a fourth
//!   topic, so the topic count is what tells them apart.
//! - **Uniswap-V2-style swaps**: a `Swap` log whose emitter is a pool
//!   [`crate::venue`] verified. Anyone can emit a byte-identical `Swap` from any
//!   contract, and a detector that trusted one could be fed a sandwich that
//!   never happened. Swaps from unverified emitters are dropped and counted.
//!   A swap with more than one leg on a side (a flash swap repaying in the same
//!   token) has no single direction and is dropped and counted too.
//! - **Receipts**: every transaction must have exactly one, or the block is
//!   refused. A reverted transaction keeps its gas facts and has no actions.

use std::collections::{BTreeMap, BTreeSet};

use alloy_primitives::{b256, Address, Bytes, B256, U256};
use detector_api::{
    BlockBundle, DetectionCtx, Enrichment, PoolState, Swap, TokenMeta, TokenTransfer, TxActions,
    TxGas, UsdPrice,
};
use events::primitives::{BlockRef, Chain};

use crate::abi;

/// `keccak256("Transfer(address,address,uint256)")`.
pub const TRANSFER_TOPIC: B256 =
    b256!("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");

/// `keccak256("Swap(address,uint256,uint256,uint256,uint256,address)")`, the
/// Uniswap V2 pair event (sender and `to` indexed; four amounts in the body).
pub const V2_SWAP_TOPIC: B256 =
    b256!("d78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822");

/// A block as the archive node reported it, full transactions included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawBlock {
    pub number: u64,
    pub hash: B256,
    pub parent_hash: B256,
    pub timestamp: u64,
    /// In block order.
    pub txs: Vec<RawTx>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawTx {
    pub hash: B256,
    pub from: Address,
    /// `None` for contract creation.
    pub to: Option<Address>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawReceipt {
    pub tx_hash: B256,
    pub success: bool,
    pub gas_used: u64,
    pub effective_gas_price: u128,
    pub logs: Vec<RawLog>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLog {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
}

/// A V2 `Swap` log before its pool is known to be real.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V2SwapLog {
    pub pool: Address,
    pub amount0_in: U256,
    pub amount1_in: U256,
    pub amount0_out: U256,
    pub amount1_out: U256,
}

impl V2SwapLog {
    fn parse(log: &RawLog) -> Option<Self> {
        if log.topics.first() != Some(&V2_SWAP_TOPIC)
            || log.topics.len() != 3
            || log.data.len() != 4 * 32
        {
            return None;
        }
        Some(Self {
            pool: log.address,
            amount0_in: abi::u256_word(&log.data, 0)?,
            amount1_in: abi::u256_word(&log.data, 1)?,
            amount0_out: abi::u256_word(&log.data, 2)?,
            amount1_out: abi::u256_word(&log.data, 3)?,
        })
    }

    /// The swap's single direction against `(token0, token1)`, or `None` when
    /// it has none (a leg on both sides, or nothing moved).
    pub fn resolve(&self, token0: Address, token1: Address) -> Option<Swap> {
        let zero = U256::ZERO;
        let (token_in, token_out, amount_in, amount_out) = match (
            self.amount0_in > zero,
            self.amount1_in > zero,
            self.amount0_out > zero,
            self.amount1_out > zero,
        ) {
            (true, false, false, true) => (token0, token1, self.amount0_in, self.amount1_out),
            (false, true, true, false) => (token1, token0, self.amount1_in, self.amount0_out),
            _ => return None,
        };
        Some(Swap {
            pool: self.pool,
            token_in,
            token_out,
            amount_in,
            amount_out,
        })
    }
}

fn parse_transfer(log: &RawLog) -> Option<TokenTransfer> {
    if log.topics.first() != Some(&TRANSFER_TOPIC) || log.topics.len() != 3 || log.data.len() != 32
    {
        return None;
    }
    Some(TokenTransfer {
        token: log.address,
        from: abi::address_word(log.topics[1].as_slice(), 0)?,
        to: abi::address_word(log.topics[2].as_slice(), 0)?,
        amount: abi::u256_word(&log.data, 0)?,
    })
}

/// What a block's logs ask the enricher to look up.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Needs {
    /// Every ERC-20 contract a transfer was emitted by.
    pub tokens: BTreeSet<Address>,
    /// Every contract a V2 `Swap` was emitted by, verified or not.
    pub pools: BTreeSet<Address>,
}

/// The contracts a block's receipts refer to.
pub fn needs(receipts: &[RawReceipt]) -> Needs {
    let mut needs = Needs::default();
    for log in receipts.iter().filter(|r| r.success).flat_map(|r| &r.logs) {
        if parse_transfer(log).is_some() {
            needs.tokens.insert(log.address);
        } else if V2SwapLog::parse(log).is_some() {
            needs.pools.insert(log.address);
        }
    }
    needs
}

/// What was read about the contracts a block touched.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct BlockFacts {
    /// Tokens whose metadata could be read. A token absent here is not an
    /// ERC-20 as far as the chain would say.
    pub tokens: BTreeMap<Address, TokenMeta>,
    /// Pools verified against a known venue, as `(token0, token1)`.
    pub pool_tokens: BTreeMap<Address, (Address, Address)>,
    /// Reserves before the block, for verified pools that existed then.
    pub pool_states: BTreeMap<Address, PoolState>,
    pub prices: BTreeMap<Address, UsdPrice>,
}

/// Counts of everything [`assemble`] decoded or refused, for the report.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AssembleStats {
    pub txs: u64,
    pub reverted_txs: u64,
    pub transfers: u64,
    pub swaps: u64,
    /// `Swap` logs from contracts no venue vouches for.
    pub unverified_swap_logs: u64,
    /// `Swap` logs with no single direction.
    pub ambiguous_swap_logs: u64,
}

/// Why a block cannot be assembled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("block {block}: {receipts} receipts for {txs} transactions")]
    ReceiptCount {
        block: u64,
        txs: usize,
        receipts: usize,
    },
    #[error("block {block}: no receipt for transaction {tx}")]
    MissingReceipt { block: u64, tx: B256 },
    #[error("block {block}: transaction {tx} appears twice")]
    DuplicateTx { block: u64, tx: B256 },
}

/// Build the context a detector runs on.
pub fn assemble(
    chain: Chain,
    block: &RawBlock,
    receipts: &[RawReceipt],
    facts: &BlockFacts,
) -> Result<(DetectionCtx, AssembleStats), DecodeError> {
    let number = block.number;
    if receipts.len() != block.txs.len() {
        return Err(DecodeError::ReceiptCount {
            block: number,
            txs: block.txs.len(),
            receipts: receipts.len(),
        });
    }
    let by_hash: BTreeMap<B256, &RawReceipt> = receipts.iter().map(|r| (r.tx_hash, r)).collect();

    let mut stats = AssembleStats::default();
    let mut enrichment = Enrichment::builder();
    let mut seen = BTreeSet::new();
    for tx in &block.txs {
        if !seen.insert(tx.hash) {
            return Err(DecodeError::DuplicateTx {
                block: number,
                tx: tx.hash,
            });
        }
        let receipt = by_hash.get(&tx.hash).ok_or(DecodeError::MissingReceipt {
            block: number,
            tx: tx.hash,
        })?;
        stats.txs += 1;

        let mut transfers = Vec::new();
        let mut swaps = Vec::new();
        if receipt.success {
            for log in &receipt.logs {
                if let Some(transfer) = parse_transfer(log) {
                    transfers.push(transfer);
                } else if let Some(raw) = V2SwapLog::parse(log) {
                    let Some(&(token0, token1)) = facts.pool_tokens.get(&raw.pool) else {
                        stats.unverified_swap_logs += 1;
                        continue;
                    };
                    match raw.resolve(token0, token1) {
                        Some(swap) => swaps.push(swap),
                        None => stats.ambiguous_swap_logs += 1,
                    }
                }
            }
        } else {
            stats.reverted_txs += 1;
        }
        stats.transfers += transfers.len() as u64;
        stats.swaps += swaps.len() as u64;

        enrichment.add_tx(
            TxActions::new(tx.hash, tx.from, tx.to)
                .with_transfers(transfers)
                .with_swaps(swaps)
                .with_gas(TxGas {
                    gas_used: receipt.gas_used,
                    effective_gas_price: receipt.effective_gas_price,
                }),
        );
    }

    for meta in facts.tokens.values() {
        enrichment.add_token(meta.clone());
    }
    for state in facts.pool_states.values() {
        enrichment.add_pool(state.clone());
    }
    for (token, price) in &facts.prices {
        enrichment.set_price(*token, *price);
    }

    let bundle = BlockBundle::new(
        chain,
        BlockRef::new(number, block.hash),
        block.txs.iter().map(|tx| tx.hash).collect(),
    );
    Ok((
        DetectionCtx::with_enrichment(bundle, enrichment.build()),
        stats,
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloy_primitives::keccak256;

    pub(crate) fn addr(b: u8) -> Address {
        Address::repeat_byte(b)
    }

    pub(crate) fn topic_addr(a: Address) -> B256 {
        a.into_word()
    }

    pub(crate) fn transfer_log(token: Address, from: Address, to: Address, amount: u64) -> RawLog {
        RawLog {
            address: token,
            topics: vec![TRANSFER_TOPIC, topic_addr(from), topic_addr(to)],
            data: Bytes::copy_from_slice(&U256::from(amount).to_be_bytes::<32>()),
        }
    }

    pub(crate) fn swap_log(pool: Address, amounts: [u64; 4]) -> RawLog {
        let mut data = Vec::new();
        for a in amounts {
            data.extend_from_slice(&U256::from(a).to_be_bytes::<32>());
        }
        RawLog {
            address: pool,
            topics: vec![V2_SWAP_TOPIC, topic_addr(addr(1)), topic_addr(addr(2))],
            data: data.into(),
        }
    }

    fn receipt(tx: u8, logs: Vec<RawLog>) -> RawReceipt {
        RawReceipt {
            tx_hash: B256::repeat_byte(tx),
            success: true,
            gas_used: 21_000,
            effective_gas_price: 30_000_000_000,
            logs,
        }
    }

    fn block(txs: &[u8]) -> RawBlock {
        RawBlock {
            number: 100,
            hash: B256::repeat_byte(0xB1),
            parent_hash: B256::repeat_byte(0xB0),
            timestamp: 1_700_000_000,
            txs: txs
                .iter()
                .map(|t| RawTx {
                    hash: B256::repeat_byte(*t),
                    from: addr(*t),
                    to: Some(addr(0xEE)),
                })
                .collect(),
        }
    }

    #[test]
    fn topics_are_the_event_signature_hashes() {
        assert_eq!(
            TRANSFER_TOPIC,
            keccak256("Transfer(address,address,uint256)")
        );
        assert_eq!(
            V2_SWAP_TOPIC,
            keccak256("Swap(address,uint256,uint256,uint256,uint256,address)")
        );
    }

    #[test]
    fn an_erc721_transfer_is_not_an_erc20_transfer() {
        let mut nft = transfer_log(addr(0xAA), addr(1), addr(2), 7);
        nft.topics.push(B256::with_last_byte(7));
        nft.data = Bytes::new();
        assert_eq!(parse_transfer(&nft), None);
        assert!(parse_transfer(&transfer_log(addr(0xAA), addr(1), addr(2), 7)).is_some());
    }

    #[test]
    fn swap_direction_needs_exactly_one_leg_each_side() {
        let (t0, t1) = (addr(0x10), addr(0x20));
        let log = |a| V2SwapLog::parse(&swap_log(addr(0xCC), a)).unwrap();
        let s = log([5, 0, 0, 9]).resolve(t0, t1).unwrap();
        assert_eq!((s.token_in, s.token_out), (t0, t1));
        assert_eq!((s.amount_in, s.amount_out), (U256::from(5), U256::from(9)));
        let s = log([0, 5, 9, 0]).resolve(t0, t1).unwrap();
        assert_eq!((s.token_in, s.token_out), (t1, t0));
        assert_eq!(log([5, 1, 0, 9]).resolve(t0, t1), None, "flash-swap repay");
        assert_eq!(log([0, 0, 0, 0]).resolve(t0, t1), None);
    }

    #[test]
    fn assembly_keeps_verified_swaps_and_counts_the_rest() {
        let pool = addr(0xCC);
        let fake = addr(0xCD);
        let receipts = vec![
            receipt(
                1,
                vec![
                    transfer_log(addr(0x10), addr(1), pool, 5),
                    swap_log(pool, [5, 0, 0, 9]),
                    swap_log(fake, [5, 0, 0, 9]),
                    swap_log(pool, [5, 1, 0, 9]),
                ],
            ),
            RawReceipt {
                success: false,
                logs: Vec::new(),
                ..receipt(2, Vec::new())
            },
        ];
        let mut facts = BlockFacts::default();
        facts.pool_tokens.insert(pool, (addr(0x10), addr(0x20)));
        let (ctx, stats) = assemble(Chain::ETHEREUM, &block(&[1, 2]), &receipts, &facts).unwrap();

        assert_eq!(
            stats,
            AssembleStats {
                txs: 2,
                reverted_txs: 1,
                transfers: 1,
                swaps: 1,
                unverified_swap_logs: 1,
                ambiguous_swap_logs: 1,
            }
        );
        let tx = ctx.enrichment().tx(B256::repeat_byte(1)).unwrap();
        assert_eq!(tx.swaps.len(), 1);
        assert_eq!(tx.transfers.len(), 1);
        assert_eq!(tx.gas.unwrap().gas_used, 21_000);
        let reverted = ctx.enrichment().tx(B256::repeat_byte(2)).unwrap();
        assert!(reverted.swaps.is_empty() && reverted.gas.is_some());
        assert_eq!(ctx.txs(), [B256::repeat_byte(1), B256::repeat_byte(2)]);
    }

    #[test]
    fn needs_lists_every_emitter_but_ignores_reverted_txs() {
        let receipts = vec![
            receipt(1, vec![transfer_log(addr(0x10), addr(1), addr(2), 5)]),
            receipt(2, vec![swap_log(addr(0xCC), [5, 0, 0, 9])]),
            RawReceipt {
                success: false,
                ..receipt(3, vec![transfer_log(addr(0x30), addr(1), addr(2), 5)])
            },
        ];
        let needs = needs(&receipts);
        assert_eq!(needs.tokens, BTreeSet::from([addr(0x10)]));
        assert_eq!(needs.pools, BTreeSet::from([addr(0xCC)]));
    }

    #[test]
    fn a_missing_or_extra_receipt_refuses_the_block() {
        let facts = BlockFacts::default();
        assert!(matches!(
            assemble(
                Chain::ETHEREUM,
                &block(&[1, 2]),
                &[receipt(1, vec![])],
                &facts
            ),
            Err(DecodeError::ReceiptCount { .. })
        ));
        assert!(matches!(
            assemble(
                Chain::ETHEREUM,
                &block(&[1, 2]),
                &[receipt(1, vec![]), receipt(9, vec![])],
                &facts
            ),
            Err(DecodeError::MissingReceipt { .. })
        ));
    }
}
