//! [`ArchiveCtxSource`]: the [`CtxSource`] that produces what the detectors
//! actually read — every transaction, with its receipt, decoded and enriched
//! from an archive node through `chain-enrich`.
//!
//! This is the source `ctx.rs` was a seam for. It is the only one that claims
//! [`Fidelity::Enriched`], so it is the only one `dataset window` accepts, and
//! it lets `dataset export` materialise training rows at full fidelity.
//!
//! A read that fails aborts the block (a [`CtxError`]); a block the node does
//! not know is `None`, which the callers already treat as a missing context.

use async_trait::async_trait;
use chain_enrich::{ArchiveRpc, EnrichConfig, EnrichError, Enricher};
use events::primitives::{BlockRef, Chain};

use crate::ctx::{CtxError, CtxSource, Fidelity, ResolvedCtx};

pub struct ArchiveCtxSource<R> {
    enricher: Enricher<R>,
}

impl<R> std::fmt::Debug for ArchiveCtxSource<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveCtxSource")
            .field("enricher", &self.enricher)
            .finish()
    }
}

impl<R: ArchiveRpc> ArchiveCtxSource<R> {
    /// Connect to the node and check the configuration against it (see
    /// `chain_enrich::Enricher::connect`).
    pub async fn connect(rpc: R, config: EnrichConfig) -> Result<Self, EnrichError> {
        Ok(Self {
            enricher: Enricher::connect(rpc, config).await?,
        })
    }
}

fn source_error(block: u64, detail: impl std::fmt::Display) -> CtxError {
    CtxError::Source {
        block,
        source_error: detail.to_string(),
    }
}

#[async_trait]
impl<R: ArchiveRpc + 'static> CtxSource for ArchiveCtxSource<R> {
    async fn ctx_for(
        &self,
        chain: Chain,
        block: BlockRef,
    ) -> Result<Option<ResolvedCtx>, CtxError> {
        if chain != self.enricher.chain() {
            return Err(source_error(
                block.number,
                format!(
                    "the archive source serves {}, and {chain} was asked for",
                    self.enricher.chain()
                ),
            ));
        }
        match self.enricher.enrich(block).await {
            Ok(Some(enriched)) => Ok(Some(ResolvedCtx {
                ctx: enriched.ctx,
                fidelity: Fidelity::Enriched,
            })),
            Ok(None) => Ok(None),
            Err(err) => Err(source_error(block.number, err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_primitives::{address, Address, Bytes, B256, U256};
    use chain_enrich::decode::{RawBlock, RawLog, RawReceipt, RawTx, TRANSFER_TOPIC};
    use chain_enrich::test_util::FakeChain;
    use chrono::{TimeZone, Utc};
    use events::chain::BlockAssembled;
    use events::{DomainEvent, EventEnvelope};
    use uuid::Uuid;

    use super::*;
    use crate::ctx::StaticCtxFactory;
    use crate::source::VecEventSource;
    use crate::window::{capture_window, CaptureOptions, WindowSpec};

    const USDC: Address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    const T0: i64 = 1_700_000_000;

    fn block() -> BlockRef {
        BlockRef::new(19_000_000, B256::repeat_byte(0xB1))
    }

    fn chain() -> FakeChain {
        let (from, to) = (Address::repeat_byte(0xA1), Address::repeat_byte(0xB2));
        let raw = RawBlock {
            number: block().number,
            hash: block().hash,
            parent_hash: B256::repeat_byte(0xB0),
            timestamp: T0 as u64,
            txs: vec![RawTx {
                hash: B256::repeat_byte(1),
                from,
                to: Some(USDC),
            }],
        };
        let receipt = RawReceipt {
            tx_hash: B256::repeat_byte(1),
            success: true,
            gas_used: 50_000,
            effective_gas_price: 10_000_000_000,
            logs: vec![RawLog {
                address: USDC,
                topics: vec![TRANSFER_TOPIC, from.into_word(), to.into_word()],
                data: Bytes::copy_from_slice(&U256::from(2_500_000u64).to_be_bytes::<32>()),
            }],
        };
        let config = EnrichConfig::builtin(Chain::ETHEREUM).unwrap();
        FakeChain::for_config(&config)
            .block(raw, vec![receipt])
            .token(USDC, 6, "USDC")
    }

    async fn source() -> ArchiveCtxSource<FakeChain> {
        ArchiveCtxSource::connect(chain(), EnrichConfig::builtin(Chain::ETHEREUM).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn resolves_an_enriched_context() {
        let resolved = source()
            .await
            .ctx_for(Chain::ETHEREUM, block())
            .await
            .unwrap()
            .expect("known block");
        assert_eq!(resolved.fidelity, Fidelity::Enriched);
        let tx = resolved.ctx.enrichment().tx(B256::repeat_byte(1)).unwrap();
        assert_eq!(tx.transfers.len(), 1);
        assert!(tx.gas.is_some());
        assert_eq!(resolved.ctx.enrichment().token(USDC).unwrap().decimals, 6);
    }

    #[tokio::test]
    async fn an_unknown_block_is_none_and_a_foreign_chain_is_an_error() {
        let s = source().await;
        let unknown = BlockRef::new(1, B256::repeat_byte(9));
        assert!(s.ctx_for(Chain::ETHEREUM, unknown).await.unwrap().is_none());
        assert!(s.ctx_for(Chain::BASE, block()).await.is_err());
    }

    #[tokio::test]
    async fn a_window_captures_through_the_archive_source() {
        // The path `dataset window` takes in production, with the node faked.
        let events = vec![EventEnvelope::with_metadata(
            Uuid::from_u128(1),
            Utc.timestamp_opt(T0, 0).unwrap(),
            Chain::ETHEREUM,
            DomainEvent::BlockAssembled(BlockAssembled {
                block: block(),
                tx_count: 1,
                trace_available: true,
            }),
        )];
        let spec = WindowSpec {
            chain: Chain::ETHEREUM,
            from: Utc.timestamp_opt(T0, 0).unwrap(),
            to: Utc.timestamp_opt(T0 + 60, 0).unwrap(),
            lookahead_secs: 60,
            name: "archive".into(),
        };
        let factory = StaticCtxFactory::new(Arc::new(source().await));
        let window = capture_window(
            &spec,
            &VecEventSource::new(events),
            &factory,
            CaptureOptions::default(),
        )
        .await
        .expect("an enriched source satisfies the window's bar");
        assert_eq!(window.blocks.len(), 1);
        assert_eq!(window.blocks[0].actions[0].transfers.len(), 1);
        assert_eq!(window.blocks[0].tokens[0].address, USDC);
    }
}
