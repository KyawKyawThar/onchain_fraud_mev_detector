//! [`Enricher`]: one block hash in, the full [`DetectionCtx`] out.
//!
//! ```text
//!   block + receipts ──► needs ──► pool identities ──► venue check (CREATE2)
//!        (by hash)                 (cached)                 │
//!                                                           ▼
//!   prices (at the block) ◄── token metadata (cached) ◄── reserves (at parent)
//!           │
//!           └──► decode::assemble ──► DetectionCtx + EnrichReport
//! ```
//!
//! # Link-or-fail at connect
//!
//! [`Enricher::connect`] checks the node serves the configured chain and that
//! every feed answers `description()` with the configured pair, and reads each
//! feed's decimals once. A wrong URL or a feed address pointing at the wrong
//! market fails boot, not the thousandth block.
//!
//! # State is read by hash, at the right moment
//!
//! Reserves come from the *parent* block (what the pool held before this
//! block's trades, which is what a drain is measured against); prices from the
//! block itself (the answer the market saw by its end). Both by hash, so a
//! reorg cannot answer from a sibling block.
//!
//! # Absence is an answer, failure is not
//!
//! A token without `decimals()` is not an ERC-20, a pool created in this block
//! has no parent reserves, a stale feed is no price: each is recorded as
//! absent and counted in the [`EnrichReport`]. A read that *failed* aborts the
//! block instead, because a context missing facts the chain had would make
//! detectors quiet for the wrong reason.
//!
//! # Caches
//!
//! Token metadata and pool identity are immutable, so they are remembered
//! across blocks in bounded FIFO maps. Only answers are cached, never
//! failures, and "no code at this address" is not cached either: a
//! counterfactual address can gain code later.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Mutex;

use alloy_primitives::{Address, I256};
use bounded_map::BoundedFifoMap;
use detector_api::{DetectionCtx, PoolState, TokenMeta, UsdPrice};
use events::primitives::{BlockRef, Chain};
use futures_util::{stream, StreamExt, TryStreamExt};

use crate::abi;
use crate::config::{EnrichConfig, PriceFeed};
use crate::decode::{self, AssembleStats, BlockFacts, DecodeError, RawBlock};
use crate::rpc::{ArchiveRpc, CallOutcome, RpcError, StateAt};

/// Why a block, or the enricher itself, could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnrichError {
    #[error(transparent)]
    Rpc(#[from] RpcError),
    #[error("the archive node serves chain {found}, not {expected}")]
    WrongChain { expected: Chain, found: u64 },
    #[error("price feed {feed}: {problem}")]
    Feed { feed: Address, problem: String },
    #[error("block {block}: the node answered for {detail}")]
    Inconsistent { block: u64, detail: String },
    #[error(transparent)]
    Decode(#[from] DecodeError),
}

impl EnrichError {
    /// Whether retrying the same block later could succeed.
    pub fn is_transient(&self) -> bool {
        matches!(self, EnrichError::Rpc(e) if e.is_transient())
    }
}

/// Everything enrichment found missing or refused, per block.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EnrichReport {
    pub assemble: AssembleStats,
    /// `Transfer` emitters that do not answer `decimals()`.
    pub non_erc20_tokens: u64,
    /// `Swap` emitters that are not a configured venue's pair.
    pub unverified_pools: u64,
    /// Verified pools with no reserves before this block (created in it).
    pub pools_without_reserves: u64,
    /// Priced tokens whose feed answer was too old for this block.
    pub stale_prices: u64,
    /// Priced tokens whose feed answered nonsense (non-positive, future).
    pub invalid_prices: u64,
}

/// A block, enriched.
#[derive(Debug, Clone)]
pub struct EnrichedBlock {
    pub ctx: DetectionCtx,
    pub report: EnrichReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoolIdentity {
    Verified { token0: Address, token1: Address },
    Unverified,
}

/// The price of a token at a block, or why there is none.
enum PriceRead {
    Price(UsdPrice),
    Stale,
    Invalid,
}

pub struct Enricher<R> {
    rpc: R,
    config: EnrichConfig,
    /// `decimals` per feed, read at connect.
    feed_decimals: BTreeMap<Address, u8>,
    tokens: Mutex<BoundedFifoMap<Address, Option<TokenMeta>>>,
    pools: Mutex<BoundedFifoMap<Address, PoolIdentity>>,
}

impl<R> std::fmt::Debug for Enricher<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enricher")
            .field("chain", &self.config.chain)
            .field("venues", &self.config.venues.len())
            .field("feeds", &self.config.feeds.len())
            .finish_non_exhaustive()
    }
}

const DECIMALS: &str = "decimals()";

impl<R: ArchiveRpc> Enricher<R> {
    /// Check the node and the feeds, then build the enricher (see the module
    /// docs).
    pub async fn connect(rpc: R, config: EnrichConfig) -> Result<Self, EnrichError> {
        let found = rpc.chain_id().await?;
        if found != config.chain.0 {
            return Err(EnrichError::WrongChain {
                expected: config.chain,
                found,
            });
        }

        let mut feed_decimals = BTreeMap::new();
        for feed in &config.feeds {
            let problem = |p: String| EnrichError::Feed {
                feed: feed.feed,
                problem: p,
            };
            let description = match rpc
                .call(feed.feed, abi::call_data("description()"), StateAt::Latest)
                .await?
            {
                CallOutcome::Returned(bytes) => abi::symbol(&bytes),
                CallOutcome::Reverted => None,
            };
            if description.as_deref() != Some(feed.description.as_str()) {
                return Err(problem(format!(
                    "description() is {description:?}, the config says {:?} — the address \
                     points at a different feed",
                    feed.description
                )));
            }
            let decimals = match rpc
                .call(feed.feed, abi::call_data(DECIMALS), StateAt::Latest)
                .await?
            {
                CallOutcome::Returned(bytes) => abi::u8_word(&bytes, 0),
                CallOutcome::Reverted => None,
            };
            let decimals = decimals.ok_or_else(|| problem("no decimals()".into()))?;
            feed_decimals.insert(feed.feed, decimals);
        }

        Ok(Self {
            rpc,
            feed_decimals,
            tokens: Mutex::new(BoundedFifoMap::new(config.token_cache, "token metadata")),
            pools: Mutex::new(BoundedFifoMap::new(config.pool_cache, "pool identity")),
            config,
        })
    }

    pub fn chain(&self) -> Chain {
        self.config.chain
    }

    /// Enrich the block `block` names, or `None` if the node does not know
    /// that hash.
    pub async fn enrich(&self, block: BlockRef) -> Result<Option<EnrichedBlock>, EnrichError> {
        let (raw, receipts) =
            futures_util::try_join!(self.rpc.block(block.hash), self.rpc.receipts(block.hash))?;
        let (Some(raw), Some(receipts)) = (raw, receipts) else {
            return Ok(None);
        };
        if raw.hash != block.hash || raw.number != block.number {
            return Err(EnrichError::Inconsistent {
                block: block.number,
                detail: format!("block {} {}", raw.number, raw.hash),
            });
        }

        let mut report = EnrichReport::default();
        let needs = decode::needs(&receipts);
        let facts = self.facts(&raw, &needs, &mut report).await?;
        let (ctx, stats) = decode::assemble(self.config.chain, &raw, &receipts, &facts)?;
        report.assemble = stats;
        record(&report);
        Ok(Some(EnrichedBlock { ctx, report }))
    }

    async fn facts(
        &self,
        raw: &RawBlock,
        needs: &decode::Needs,
        report: &mut EnrichReport,
    ) -> Result<BlockFacts, EnrichError> {
        let here = StateAt::Block(raw.hash);
        let before = StateAt::Block(raw.parent_hash);
        let mut facts = BlockFacts::default();

        // Pools first: a verified pool's tokens are tokens this block touched.
        let identities = self
            .fan_out(needs.pools.iter().copied(), |pool| {
                self.pool_identity(pool, here)
            })
            .await?;
        let mut tokens = needs.tokens.clone();
        for (pool, identity) in identities {
            match identity {
                PoolIdentity::Verified { token0, token1 } => {
                    facts.pool_tokens.insert(pool, (token0, token1));
                    tokens.extend([token0, token1]);
                }
                PoolIdentity::Unverified => report.unverified_pools += 1,
            }
        }

        let verified: Vec<(Address, (Address, Address))> =
            facts.pool_tokens.iter().map(|(p, t)| (*p, *t)).collect();
        let reserves = self
            .fan_out(verified, |(pool, (token0, token1))| async move {
                self.reserves(pool, token0, token1, before).await
            })
            .await?;
        for (_, state) in reserves {
            match state {
                Some(state) => {
                    facts.pool_states.insert(state.address, state);
                }
                None => report.pools_without_reserves += 1,
            }
        }

        let metadata = self
            .fan_out(tokens.iter().copied(), |token| self.token_meta(token, here))
            .await?;
        for (token, meta) in metadata {
            match meta {
                Some(meta) => {
                    facts.tokens.insert(token, meta);
                }
                None => report.non_erc20_tokens += 1,
            }
        }

        // Keyed by feed index, not `&PriceFeed`: a borrowed key in the stream
        // makes the future's lifetime higher-ranked, and callers need `Send`.
        let feeds: Vec<(Address, usize)> = tokens
            .iter()
            .filter_map(|t| {
                self.config
                    .feeds
                    .iter()
                    .position(|f| f.token == *t)
                    .map(|i| (*t, i))
            })
            .collect();
        let prices = self
            .fan_out(feeds, |(_, i)| self.price(&self.config.feeds[i], raw))
            .await?;
        for ((token, _), read) in prices {
            match read {
                PriceRead::Price(price) => {
                    facts.prices.insert(token, price);
                }
                PriceRead::Stale => report.stale_prices += 1,
                PriceRead::Invalid => report.invalid_prices += 1,
            }
        }
        Ok(facts)
    }

    /// Run `read` over `keys` with the configured concurrency. Results come
    /// back in completion order; every caller folds them into ordered maps.
    async fn fan_out<K, V, F, Fut>(
        &self,
        keys: impl IntoIterator<Item = K>,
        read: F,
    ) -> Result<Vec<(K, V)>, EnrichError>
    where
        K: Copy,
        F: Fn(K) -> Fut,
        Fut: Future<Output = Result<V, EnrichError>>,
    {
        stream::iter(keys)
            .map(|key| {
                let pending = read(key);
                async move { Ok::<_, EnrichError>((key, pending.await?)) }
            })
            .buffer_unordered(self.config.concurrency)
            .try_collect()
            .await
    }

    async fn pool_identity(&self, pool: Address, at: StateAt) -> Result<PoolIdentity, EnrichError> {
        if let Some(known) = lock(&self.pools).get(&pool).copied() {
            return Ok(known);
        }
        let token0 = self.address_call(pool, "token0()", at).await?;
        let token1 = self.address_call(pool, "token1()", at).await?;
        let identity = match (token0, token1) {
            (Some(token0), Some(token1))
                if self
                    .config
                    .venues
                    .iter()
                    .any(|v| v.deployed(pool, token0, token1)) =>
            {
                PoolIdentity::Verified { token0, token1 }
            }
            _ => PoolIdentity::Unverified,
        };
        // A contract that emitted a log has code, so either answer is final.
        lock(&self.pools).put(pool, identity);
        Ok(identity)
    }

    async fn address_call(
        &self,
        to: Address,
        signature: &str,
        at: StateAt,
    ) -> Result<Option<Address>, EnrichError> {
        Ok(
            match self.rpc.call(to, abi::call_data(signature), at).await? {
                CallOutcome::Returned(bytes) if bytes.len() == 32 => abi::address_word(&bytes, 0),
                _ => None,
            },
        )
    }

    async fn reserves(
        &self,
        pool: Address,
        token0: Address,
        token1: Address,
        before: StateAt,
    ) -> Result<Option<PoolState>, EnrichError> {
        let outcome = self
            .rpc
            .call(pool, abi::call_data("getReserves()"), before)
            .await?;
        Ok(match outcome {
            CallOutcome::Returned(bytes) => {
                match (abi::u256_word(&bytes, 0), abi::u256_word(&bytes, 1)) {
                    (Some(r0), Some(r1)) => Some(PoolState::new(pool, token0, token1, r0, r1)),
                    // No code yet at the parent: created in this block.
                    _ => None,
                }
            }
            CallOutcome::Reverted => None,
        })
    }

    async fn token_meta(
        &self,
        token: Address,
        at: StateAt,
    ) -> Result<Option<TokenMeta>, EnrichError> {
        if let Some(known) = lock(&self.tokens).get(&token).cloned() {
            return Ok(known);
        }
        let decimals = match self.rpc.call(token, abi::call_data(DECIMALS), at).await? {
            // Empty bytes: no code. Not cached — the address may gain code.
            CallOutcome::Returned(bytes) if bytes.is_empty() => return Ok(None),
            CallOutcome::Returned(bytes) => abi::u8_word(&bytes, 0),
            CallOutcome::Reverted => None,
        };
        let meta = match decimals {
            None => None,
            Some(decimals) => {
                let symbol = match self.rpc.call(token, abi::call_data("symbol()"), at).await? {
                    CallOutcome::Returned(bytes) => abi::symbol(&bytes),
                    CallOutcome::Reverted => None,
                };
                Some(TokenMeta::new(token, symbol, decimals))
            }
        };
        lock(&self.tokens).put(token, meta.clone());
        Ok(meta)
    }

    async fn price(&self, feed: &PriceFeed, block: &RawBlock) -> Result<PriceRead, EnrichError> {
        let bytes = match self
            .rpc
            .call(
                feed.feed,
                abi::call_data("latestRoundData()"),
                StateAt::Block(block.hash),
            )
            .await?
        {
            CallOutcome::Returned(bytes) => bytes,
            CallOutcome::Reverted => return Ok(PriceRead::Invalid),
        };
        let (Some(answer), Some(updated_at)) =
            (abi::u256_word(&bytes, 1), abi::u256_word(&bytes, 3))
        else {
            return Ok(PriceRead::Invalid);
        };
        // `answer` is an int256.
        let answer = I256::from_raw(answer);
        let Ok(updated_at) = u64::try_from(updated_at) else {
            return Ok(PriceRead::Invalid);
        };
        if answer <= I256::ZERO || updated_at > block.timestamp {
            return Ok(PriceRead::Invalid);
        }
        if block.timestamp - updated_at > feed.max_age_secs {
            return Ok(PriceRead::Stale);
        }
        let decimals = self.feed_decimals.get(&feed.feed).copied().unwrap_or(0);
        let whole = f64::from(answer.into_raw()) / 10f64.powi(i32::from(decimals));
        Ok(match UsdPrice::try_new(whole) {
            Ok(price) => PriceRead::Price(price),
            Err(_) => PriceRead::Invalid,
        })
    }
}

/// A poisoned cache is still a valid cache: every write is a single `put`.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn record(report: &EnrichReport) {
    metrics::counter!("chain_enrich_blocks_total").increment(1);
    for (reason, n) in [
        ("unverified_pool", report.unverified_pools),
        ("unverified_swap_log", report.assemble.unverified_swap_logs),
        ("ambiguous_swap_log", report.assemble.ambiguous_swap_logs),
        ("non_erc20_token", report.non_erc20_tokens),
        ("pool_without_reserves", report.pools_without_reserves),
        ("stale_price", report.stale_prices),
        ("invalid_price", report.invalid_prices),
    ] {
        if n > 0 {
            metrics::counter!("chain_enrich_skipped_total", "reason" => reason).increment(n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::tests::{swap_log, transfer_log};
    use crate::decode::{RawReceipt, RawTx};
    use crate::test_util::FakeChain;
    use alloy_primitives::{address, B256};
    use detector_api::DetectorPlugin;

    const USDC: Address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    const WETH: Address = address!("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
    const USDC_WETH: Address = address!("B4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc");
    const ETH_USD: Address = address!("5f4eC3Df9cbd43714FE2740f5E3616155c5b8419");
    const USDC_USD: Address = address!("8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6");
    const NOW: u64 = 1_700_000_000;
    const USDC_UNIT: u64 = 1_000_000;
    const MILLI_ETH: u64 = 1_000_000_000_000_000;

    fn config() -> EnrichConfig {
        EnrichConfig::builtin(Chain::ETHEREUM).unwrap()
    }

    fn hash(b: u8) -> B256 {
        B256::repeat_byte(b)
    }

    fn block_ref() -> BlockRef {
        BlockRef::new(19_000_000, hash(0xB1))
    }

    fn tx(t: u8, from: Address) -> RawTx {
        RawTx {
            hash: hash(t),
            from,
            to: Some(Address::repeat_byte(0xEE)),
        }
    }

    fn receipt(t: u8, logs: Vec<decode::RawLog>) -> RawReceipt {
        RawReceipt {
            tx_hash: hash(t),
            success: true,
            gas_used: 120_000,
            effective_gas_price: 20_000_000_000,
            logs,
        }
    }

    /// A USDC→WETH→USDC sandwich around a victim on the real pair, plus a
    /// spoofed `Swap` and a transfer from a contract that is not a token.
    fn chain() -> FakeChain {
        let attacker = Address::repeat_byte(0xA1);
        let victim = Address::repeat_byte(0xB2);
        let spoof = Address::repeat_byte(0x5B);
        let not_token = Address::repeat_byte(0x77);
        // Amounts: [amount0In, amount1In, amount0Out, amount1Out];
        // token0 = USDC, token1 = WETH.
        let block = RawBlock {
            number: 19_000_000,
            hash: hash(0xB1),
            parent_hash: hash(0xB0),
            timestamp: NOW,
            txs: vec![
                tx(1, attacker),
                tx(2, victim),
                tx(3, attacker),
                tx(4, victim),
            ],
        };
        let receipts = vec![
            receipt(
                1,
                vec![
                    transfer_log(USDC, attacker, USDC_WETH, 10_000 * USDC_UNIT),
                    swap_log(USDC_WETH, [10_000 * USDC_UNIT, 0, 0, 5_000 * MILLI_ETH]),
                ],
            ),
            receipt(
                2,
                vec![swap_log(
                    USDC_WETH,
                    [2_000 * USDC_UNIT, 0, 0, 900 * MILLI_ETH],
                )],
            ),
            receipt(
                3,
                vec![
                    swap_log(USDC_WETH, [0, 5_000 * MILLI_ETH, 10_200 * USDC_UNIT, 0]),
                    swap_log(spoof, [1, 0, 0, 1]),
                ],
            ),
            receipt(4, vec![transfer_log(not_token, victim, attacker, 1)]),
        ];
        FakeChain::for_config(&config())
            .block(block, receipts)
            .pair(USDC_WETH, USDC, WETH)
            .pair(spoof, USDC, WETH)
            .reserves(
                USDC_WETH,
                hash(0xB0),
                50_000_000 * u128::from(USDC_UNIT),
                20_000 * 10u128.pow(18),
            )
            .token(USDC, 6, "USDC")
            .token(WETH, 18, "WETH")
            .revert(not_token, "decimals()")
            // ETH/USD fresh at $2,000 (8 decimals); USDC/USD two days old.
            .round(ETH_USD, hash(0xB1), 200_000_000_000, NOW - 600)
            .round(USDC_USD, hash(0xB1), 100_000_000, NOW - 172_800)
    }

    async fn enricher(chain: FakeChain) -> Enricher<FakeChain> {
        Enricher::connect(chain, config()).await.expect("connects")
    }

    #[tokio::test]
    async fn a_block_is_enriched_with_verified_facts_only() {
        let e = enricher(chain()).await;
        let EnrichedBlock { ctx, report } = e.enrich(block_ref()).await.unwrap().unwrap();

        assert_eq!(ctx.txs().len(), 4);
        let swaps = &ctx.enrichment().tx(hash(1)).unwrap().swaps;
        assert_eq!(swaps.len(), 1);
        assert_eq!((swaps[0].token_in, swaps[0].token_out), (USDC, WETH));
        assert_eq!(
            ctx.enrichment().tx(hash(3)).unwrap().swaps.len(),
            1,
            "the spoofed Swap is dropped, the real one kept"
        );

        let pool = ctx
            .enrichment()
            .pool(USDC_WETH)
            .expect("reserves before the block");
        assert_eq!(pool.token0, USDC);
        assert_eq!(ctx.enrichment().token(USDC).unwrap().decimals, 6);
        assert_eq!(
            ctx.enrichment().token(WETH).unwrap().symbol.as_deref(),
            Some("WETH")
        );
        assert_eq!(ctx.enrichment().price(WETH).unwrap().get(), 2_000.0);
        assert!(
            ctx.enrichment().price(USDC).is_none(),
            "stale feed is no price"
        );

        assert_eq!(report.unverified_pools, 1);
        assert_eq!(report.assemble.unverified_swap_logs, 1);
        assert_eq!(report.non_erc20_tokens, 1);
        assert_eq!(report.stale_prices, 1);
        assert_eq!(report.assemble.swaps, 3);
    }

    #[tokio::test]
    async fn the_real_sandwich_detector_fires_on_an_enriched_block() {
        // The decoded shape is the one detectors were written against: the
        // attacker's bracket around the victim on the verified pair is found.
        // The attacker's base token is USDC, which this block leaves unpriced
        // (its feed is stale), so the finding is structural rather than valued.
        let e = enricher(chain()).await;
        let ctx = e.enrich(block_ref()).await.unwrap().unwrap().ctx;
        let detector =
            sandwich_detector::SandwichDetector::new(sandwich_detector::SandwichConfig::default());
        let findings = detector.detect(&ctx);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].txs, vec![hash(1), hash(2), hash(3)]);
    }

    #[tokio::test]
    async fn an_unknown_hash_is_none() {
        let e = enricher(chain()).await;
        assert!(e
            .enrich(BlockRef::new(19_000_000, hash(0xFF)))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn immutable_facts_are_read_once() {
        let e = enricher(chain()).await;
        e.enrich(block_ref()).await.unwrap();
        let first = e.rpc.calls();
        e.enrich(block_ref()).await.unwrap();
        let second = e.rpc.calls() - first;
        // Second pass: reserves (1) + two prices. No token or pool reads.
        assert_eq!(second, 3, "first pass made {first}");
    }

    #[tokio::test]
    async fn a_pool_created_in_the_block_keeps_its_swaps_without_reserves() {
        let e = enricher(chain().answer_at(
            USDC_WETH,
            "getReserves()",
            StateAt::Block(hash(0xB0)),
            alloy_primitives::Bytes::new(),
        ))
        .await;
        let EnrichedBlock { ctx, report } = e.enrich(block_ref()).await.unwrap().unwrap();
        assert!(ctx.enrichment().pool(USDC_WETH).is_none());
        assert_eq!(report.pools_without_reserves, 1);
        assert_eq!(report.assemble.swaps, 3);
    }

    #[tokio::test]
    async fn a_failed_read_aborts_the_block_and_says_whether_to_retry() {
        let e = enricher(chain()).await;
        e.rpc.fail_with(RpcError::Transient {
            op: "eth_call",
            detail: "timeout".into(),
        });
        let err = e.enrich(block_ref()).await.unwrap_err();
        assert!(err.is_transient(), "{err}");

        e.rpc.fail_with(RpcError::NotArchive {
            op: "eth_call",
            detail: "missing trie node".into(),
        });
        let err = e.enrich(block_ref()).await.unwrap_err();
        assert!(!err.is_transient());
        assert!(
            err.to_string().contains("archive node is required"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn connect_refuses_the_wrong_chain_or_a_mislabelled_feed() {
        let wrong_chain = FakeChain::new(8453);
        assert!(matches!(
            Enricher::connect(wrong_chain, config()).await,
            Err(EnrichError::WrongChain { found: 8453, .. })
        ));

        let mislabelled = FakeChain::for_config(&config()).answer(
            ETH_USD,
            "description()",
            FakeChain::for_config(&config())
                .call(USDC_USD, abi::call_data("description()"), StateAt::Latest)
                .await
                .map(|o| match o {
                    CallOutcome::Returned(b) => b,
                    CallOutcome::Reverted => unreachable!(),
                })
                .unwrap(),
        );
        let err = Enricher::connect(mislabelled, config()).await.unwrap_err();
        assert!(
            matches!(&err, EnrichError::Feed { feed, .. } if *feed == ETH_USD),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_negative_or_future_answer_is_invalid() {
        let e = enricher(chain().round(ETH_USD, hash(0xB1), -5, NOW - 10)).await;
        let report = e.enrich(block_ref()).await.unwrap().unwrap().report;
        assert_eq!(report.invalid_prices, 1);

        let e = enricher(chain().round(ETH_USD, hash(0xB1), 200_000_000_000, NOW + 60)).await;
        let report = e.enrich(block_ref()).await.unwrap().unwrap().report;
        assert_eq!(report.invalid_prices, 1);
    }
}
