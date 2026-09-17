//! The pre-capture probe (Epic E): does this node, with this config, produce
//! enriched blocks a replay window can use?
//!
//! `config/ethereum-mainnet.json` was written by hand. Its addresses pass the
//! checksum and CREATE2 unit tests, but only a live chain can show that a
//! feed address is the feed it claims to be, or that a venue's factory and
//! init-code hash really prove its pairs. A wrong venue does not error: every
//! pair reads as unverified and the swaps silently vanish, which a replay
//! window would score as perfect precision. So a capture is preceded by
//! [`probe`], run by `dataset probe-archive` and nightly in CI.
//!
//! The verdict has three values, not two, like the load test's:
//!
//! - [`Verdict::Pass`] — the node is an archive node for this chain, every
//!   feed is what the config says, and a sample of old blocks enriched with
//!   transfers, verified swaps and fresh prices.
//! - [`Verdict::Fail`] — something a retry will not fix: a wrong chain or
//!   feed, a pruned node, bad credentials, or a sample that decoded no swaps.
//! - [`Verdict::Inconclusive`] — the node did not answer (rate limit,
//!   timeout, 5xx). Nothing was learned about the config, and reporting that
//!   as a pass or a fail would both be wrong.

use std::fmt;

use crate::config::EnrichConfig;
use crate::enricher::{EnrichError, EnrichReport, Enricher};
use crate::rpc::ArchiveRpc;
use events::primitives::BlockRef;

/// What to sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeOptions {
    /// How far behind the head to read. Far enough that a pruned full node
    /// (which keeps roughly the last 128 states) cannot answer, so a pass
    /// proves archive access.
    pub depth: u64,
    /// Consecutive blocks to enrich. Enough that a V2 swap and several
    /// priced tokens are all but certain to appear on mainnet.
    pub blocks: u64,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            depth: 50_000,
            blocks: 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail,
    Inconclusive,
}

impl Verdict {
    /// The process exit code a CLI reports it as: 0, 1, 2.
    pub fn exit_code(self) -> u8 {
        match self {
            Verdict::Pass => 0,
            Verdict::Fail => 1,
            Verdict::Inconclusive => 2,
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Inconclusive => "INCONCLUSIVE",
        })
    }
}

/// Everything a probe learned, and its verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    pub verdict: Verdict,
    /// Why the verdict is not `Pass`.
    pub reason: Option<String>,
    /// Feeds whose `description()` and `decimals()` checked out. All of them,
    /// or zero if `connect` did not finish.
    pub feeds_verified: usize,
    /// Every block enriched, in order.
    pub blocks: Vec<(u64, EnrichReport)>,
}

impl ProbeReport {
    fn stopped(
        verdict: Verdict,
        reason: String,
        feeds: usize,
        blocks: Vec<(u64, EnrichReport)>,
    ) -> Self {
        Self {
            verdict,
            reason: Some(reason),
            feeds_verified: feeds,
            blocks,
        }
    }

    /// The sample's counters, summed.
    pub fn totals(&self) -> EnrichReport {
        let mut t = EnrichReport::default();
        for (_, r) in &self.blocks {
            t.assemble.txs += r.assemble.txs;
            t.assemble.reverted_txs += r.assemble.reverted_txs;
            t.assemble.transfers += r.assemble.transfers;
            t.assemble.swaps += r.assemble.swaps;
            t.assemble.unverified_swap_logs += r.assemble.unverified_swap_logs;
            t.assemble.ambiguous_swap_logs += r.assemble.ambiguous_swap_logs;
            t.non_erc20_tokens += r.non_erc20_tokens;
            t.unverified_pools += r.unverified_pools;
            t.pools_without_reserves += r.pools_without_reserves;
            t.stale_prices += r.stale_prices;
            t.invalid_prices += r.invalid_prices;
        }
        t
    }
}

impl fmt::Display for ProbeReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "archive probe: {}", self.verdict)?;
        if let Some(reason) = &self.reason {
            writeln!(f, "  reason: {reason}")?;
        }
        writeln!(f, "  feeds verified: {}", self.feeds_verified)?;
        for (number, r) in &self.blocks {
            writeln!(
                f,
                "  block {number}: {} txs, {} transfers, {} verified swaps, {} unverified swap logs, \
                 {} stale / {} invalid prices",
                r.assemble.txs,
                r.assemble.transfers,
                r.assemble.swaps,
                r.assemble.unverified_swap_logs,
                r.stale_prices,
                r.invalid_prices,
            )?;
        }
        Ok(())
    }
}

fn classify(error: &EnrichError) -> Verdict {
    if error.is_transient() {
        Verdict::Inconclusive
    } else {
        Verdict::Fail
    }
}

/// Probe `rpc` with `config` (see the module docs).
#[tracing::instrument(skip(rpc, config), fields(chain = %config.chain))]
pub async fn probe<R: ArchiveRpc>(
    rpc: R,
    config: EnrichConfig,
    options: ProbeOptions,
) -> ProbeReport {
    let feeds = config.feeds.len();
    let enricher = match Enricher::connect(rpc, config).await {
        Ok(e) => e,
        Err(e) => {
            return ProbeReport::stopped(classify(&e), format!("connect: {e}"), 0, Vec::new())
        }
    };

    let head = match enricher.rpc().head_number().await {
        Ok(n) => n,
        Err(e) => {
            let e = EnrichError::from(e);
            return ProbeReport::stopped(classify(&e), format!("head: {e}"), feeds, Vec::new());
        }
    };
    let Some(first) = head.checked_sub(options.depth) else {
        return ProbeReport::stopped(
            Verdict::Fail,
            format!(
                "the node's head is block {head}, shallower than the probe depth {}",
                options.depth
            ),
            feeds,
            Vec::new(),
        );
    };
    let last = first.saturating_add(options.blocks).min(head + 1);

    let mut blocks = Vec::new();
    for number in first..last {
        let hash = match enricher.rpc().block_hash(number).await {
            Ok(Some(hash)) => hash,
            Ok(None) => {
                return ProbeReport::stopped(
                    Verdict::Fail,
                    format!("the node has no block {number} below its own head {head}"),
                    feeds,
                    blocks,
                )
            }
            Err(e) => {
                let e = EnrichError::from(e);
                return ProbeReport::stopped(
                    classify(&e),
                    format!("block {number}: {e}"),
                    feeds,
                    blocks,
                );
            }
        };
        match enricher.enrich(BlockRef::new(number, hash)).await {
            Ok(Some(enriched)) => blocks.push((number, enriched.report)),
            // The hash was canonical a moment ago: a reorg this deep is not
            // a config problem, and not a pass either.
            Ok(None) => {
                return ProbeReport::stopped(
                    Verdict::Inconclusive,
                    format!("block {number} ({hash}) vanished between two reads"),
                    feeds,
                    blocks,
                )
            }
            Err(e) => {
                return ProbeReport::stopped(
                    classify(&e),
                    format!("block {number}: {e}"),
                    feeds,
                    blocks,
                )
            }
        }
    }

    let mut report = ProbeReport {
        verdict: Verdict::Pass,
        reason: None,
        feeds_verified: feeds,
        blocks,
    };
    if let Some(reason) = judge(&report.totals()) {
        report.verdict = Verdict::Fail;
        report.reason = Some(reason);
    }
    tracing::info!(verdict = %report.verdict, blocks = report.blocks.len(), "archive probe finished");
    report
}

/// What a complete sample must show, or why it does not.
fn judge(t: &EnrichReport) -> Option<String> {
    if t.assemble.txs == 0 {
        return Some("the sample holds no transactions".into());
    }
    if t.assemble.transfers == 0 {
        return Some("no ERC-20 transfer decoded".into());
    }
    // A wrong factory or init-code hash does not error: every pair becomes
    // "unverified" and the swaps vanish.
    if t.assemble.swaps == 0 {
        return Some(format!(
            "no swap verified against any configured venue ({} unverified swap logs): check the \
             factory addresses and init-code hashes",
            t.assemble.unverified_swap_logs
        ));
    }
    if t.invalid_prices > 0 {
        return Some(format!(
            "{} feed answers were non-positive or future-dated",
            t.invalid_prices
        ));
    }
    // On ordinary blocks every configured feed should be inside its
    // heartbeat; a stale answer means a `max_age_secs` shorter than the feed
    // actually updates.
    if t.stale_prices > 0 {
        return Some(format!(
            "{} feed answers were older than their max_age_secs: check the configured heartbeats",
            t.stale_prices
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::tests::{swap_log, transfer_log};
    use crate::decode::{RawBlock, RawReceipt, RawTx};
    use crate::rpc::RpcError;
    use crate::test_util::FakeChain;
    use alloy_primitives::{address, Address, B256};
    use events::primitives::Chain;

    const USDC: Address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    const WETH: Address = address!("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
    const USDC_WETH: Address = address!("B4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc");
    const ETH_USD: Address = address!("5f4eC3Df9cbd43714FE2740f5E3616155c5b8419");
    const USDC_USD: Address = address!("8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6");
    const NOW: u64 = 1_700_000_000;
    const NUMBER: u64 = 19_000_000;
    const ONE: ProbeOptions = ProbeOptions {
        depth: 0,
        blocks: 1,
    };

    fn config() -> EnrichConfig {
        EnrichConfig::builtin(Chain::ETHEREUM).unwrap()
    }

    fn hash(b: u8) -> B256 {
        B256::repeat_byte(b)
    }

    /// One block: a USDC → WETH swap on the real pair, prices fresh.
    fn chain(swap_pool: Address) -> FakeChain {
        let trader = Address::repeat_byte(0xA1);
        let block = RawBlock {
            number: NUMBER,
            hash: hash(0xB1),
            parent_hash: hash(0xB0),
            timestamp: NOW,
            txs: vec![RawTx {
                hash: hash(1),
                from: trader,
                to: Some(Address::repeat_byte(0xEE)),
            }],
        };
        let receipts = vec![RawReceipt {
            tx_hash: hash(1),
            success: true,
            gas_used: 120_000,
            effective_gas_price: 20_000_000_000,
            logs: vec![
                transfer_log(USDC, trader, swap_pool, 1_000_000),
                swap_log(swap_pool, [1_000_000, 0, 0, 500]),
            ],
        }];
        FakeChain::for_config(&config())
            .block(block, receipts)
            .pair(USDC_WETH, USDC, WETH)
            .reserves(
                USDC_WETH,
                hash(0xB0),
                50_000_000_000_000,
                20_000 * 10u128.pow(18),
            )
            .token(USDC, 6, "USDC")
            .token(WETH, 18, "WETH")
            .round(ETH_USD, hash(0xB1), 200_000_000_000, NOW - 600)
            .round(USDC_USD, hash(0xB1), 100_000_000, NOW - 600)
    }

    #[tokio::test]
    async fn a_good_node_and_config_pass() {
        let report = probe(chain(USDC_WETH), config(), ONE).await;
        assert_eq!(report.verdict, Verdict::Pass, "{report}");
        assert_eq!(report.feeds_verified, config().feeds.len());
        assert_eq!(report.blocks.len(), 1);
        assert_eq!(report.verdict.exit_code(), 0);
    }

    #[tokio::test]
    async fn swaps_that_no_venue_proves_fail_the_probe() {
        // What a wrong init-code hash looks like: the pool is not the
        // CREATE2 address any venue derives, so nothing is verified.
        let report = probe(chain(Address::repeat_byte(0x5B)), config(), ONE).await;
        assert_eq!(report.verdict, Verdict::Fail, "{report}");
        assert!(report.reason.unwrap().contains("init-code"));
    }

    #[tokio::test]
    async fn a_stale_feed_fails_the_probe() {
        let stale = chain(USDC_WETH).round(USDC_USD, hash(0xB1), 100_000_000, NOW - 200_000);
        let report = probe(stale, config(), ONE).await;
        assert_eq!(report.verdict, Verdict::Fail, "{report}");
        assert!(report.reason.unwrap().contains("max_age_secs"));
    }

    #[tokio::test]
    async fn a_rate_limited_node_is_inconclusive_not_failed() {
        let limited = chain(USDC_WETH);
        limited.fail_with(RpcError::Transient {
            op: "eth_call",
            detail: "HTTP error 429".into(),
        });
        let report = probe(limited, config(), ONE).await;
        assert_eq!(report.verdict, Verdict::Inconclusive, "{report}");
        assert_eq!(report.verdict.exit_code(), 2);
    }

    #[tokio::test]
    async fn a_pruned_node_fails() {
        let pruned = chain(USDC_WETH);
        pruned.fail_with(RpcError::NotArchive {
            op: "eth_call",
            detail: "missing trie node".into(),
        });
        assert_eq!(probe(pruned, config(), ONE).await.verdict, Verdict::Fail);
    }

    #[tokio::test]
    async fn a_misconfigured_feed_fails_at_connect() {
        let wrong = chain(USDC_WETH).answer(
            ETH_USD,
            "description()",
            alloy_primitives::Bytes::from(vec![0u8; 64]),
        );
        let report = probe(wrong, config(), ONE).await;
        assert_eq!(report.verdict, Verdict::Fail, "{report}");
        assert!(report.reason.unwrap().starts_with("connect"));
        assert_eq!(report.feeds_verified, 0);
    }

    #[tokio::test]
    async fn a_chain_shallower_than_the_depth_fails() {
        let report = probe(
            chain(USDC_WETH),
            config(),
            ProbeOptions {
                depth: NUMBER + 1,
                blocks: 1,
            },
        )
        .await;
        assert_eq!(report.verdict, Verdict::Fail);
    }

    #[tokio::test]
    async fn a_missing_block_below_the_head_fails() {
        // Head is NUMBER; ask for the block before it, which this node lacks.
        let report = probe(
            chain(USDC_WETH),
            config(),
            ProbeOptions {
                depth: 1,
                blocks: 1,
            },
        )
        .await;
        assert_eq!(report.verdict, Verdict::Fail, "{report}");
    }
}
