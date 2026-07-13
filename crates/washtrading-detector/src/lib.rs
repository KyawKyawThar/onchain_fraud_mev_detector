//! `wash-trading-v1.0` — the wash-trading detector (§6, §22 Phase 3), and the
//! platform's **first [`Scope::CrossBlock`] detector**.
//!
//! Wash trading manufactures fake volume: one trader (or a tight ring acting as
//! one) buys and sells the *same* pair on the *same* pool over and over, so the
//! token looks liquid and active while their net position barely moves. No single
//! block shows it — a lone round trip is just two ordinary swaps. The pattern only
//! emerges over a **trailing window of blocks**, which is exactly what a
//! [`CrossBlockDetector`](detector_api::CrossBlockDetector) is for: the detection
//! service folds each canonical block into this detector's accumulated
//! [`WashState`] and keeps that state reorg-versioned in `CrossBlockState`, rolling
//! it back to the common ancestor on a `BlockReverted` (§15) so churn on an
//! orphaned branch never fires.
//!
//! # The signature
//!
//! Over the last [`window_blocks`](WashTradingConfig::window_blocks), per
//! `(trader, pool)`, the detector counts swaps in each direction and nets the
//! trader's flow in the pool's reference token. Wash trading is: **many swaps
//! ([`min_swaps`](WashTradingConfig::min_swaps)), in *both* directions, with a net
//! position change that is tiny relative to the gross volume churned**
//! ([`max_net_bps`](WashTradingConfig::max_net_bps)). High gross, ≈ zero net, both
//! ways — that is round-tripping, not directional trading.
//!
//! Attribution-blind (§6): the trader address is the fact that these swaps share a
//! sender, never an identity. To avoid re-alerting on an idle window every block,
//! [`detect`](WashTradingDetector::detect) fires only for pairs that traded in the
//! **current** block, so a finding marks a *fresh* wash swap landing on an
//! already-churning pair. Output is behaviour-only [`Evidence`] with a typed
//! [`WashTradingDetail`].
//!
//! # Known limitation (v1.0)
//!
//! Collusion across *multiple* addresses (A→B→C→A round-tripping) reads as
//! independent traders here; clustering those into one entity is the intelligence
//! service's job (§8), off the hot path. This detector catches the single-address
//! case, which is the common one.

use std::collections::{BTreeMap, VecDeque};

use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

use detector_api::{
    Bps, CrossBlockDetector, DetectionCtx, DetectorId, Evidence, ModelKind, SemVer,
};
use events::primitives::{AlertKind, Confidence};

/// Default trailing window, in blocks (matches `[detectors.wash_trading]
/// window_blocks = 100`, §6).
const DEFAULT_WINDOW_BLOCKS: u32 = 100;
/// Default minimum swaps in the window for a pair to be considered churning.
const DEFAULT_MIN_SWAPS: u32 = 4;
/// Default net/gross ceiling, in basis points (`1_000` = 10%): a trader whose net
/// position moved less than this of the volume they churned is round-tripping.
const DEFAULT_MAX_NET_BPS: u32 = 1_000;

// Confidence policy, facts-only (§6).
/// Base confidence for a pair clearing the swap-count and net-ratio thresholds.
const CONF_BASE: f64 = 0.55;
/// Added per swap beyond [`min_swaps`](WashTradingConfig::min_swaps) — more churn is
/// clearer intent.
const CONF_PER_EXTRA_SWAP: f64 = 0.03;
/// Cap on swaps that contribute to the score.
const MAX_EXTRA_SWAPS: u32 = 7;
/// Added when the net position is *very* flat (below a tenth of the gross ceiling)
/// — the purest wash shape.
const CONF_FLAT_BONUS: f64 = 0.10;

fn default_window_blocks() -> u32 {
    DEFAULT_WINDOW_BLOCKS
}

fn default_min_swaps() -> u32 {
    DEFAULT_MIN_SWAPS
}

fn default_max_net_bps() -> Bps {
    Bps::new(DEFAULT_MAX_NET_BPS)
}

/// Tunable thresholds for the wash-trading detector. Serialized into the model
/// registry's `config_hash` (§6); deserializable so the service can load
/// `[detectors.wash_trading]` from config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WashTradingConfig {
    /// How many trailing blocks of history to accumulate. Sizes both the analytical
    /// window and the service's reorg-snapshot store (via
    /// [`window_blocks`](CrossBlockDetector::window_blocks)).
    #[serde(default = "default_window_blocks")]
    pub window_blocks: u32,
    /// Minimum swaps by one `(trader, pool)` in the window to qualify.
    #[serde(default = "default_min_swaps")]
    pub min_swaps: u32,
    /// Maximum net-position change as a fraction of gross volume, in basis points,
    /// for the activity to read as round-tripping rather than real trading.
    #[serde(default = "default_max_net_bps")]
    pub max_net_bps: Bps,
}

impl Default for WashTradingConfig {
    fn default() -> Self {
        Self {
            window_blocks: default_window_blocks(),
            min_swaps: default_min_swaps(),
            max_net_bps: default_max_net_bps(),
        }
    }
}

/// The `wash-trading-v1.0` detector. Holds its [`WashTradingConfig`]; construct with
/// [`plugin`] for defaults or [`WashTradingDetector::new`] to override.
#[derive(Debug, Clone)]
pub struct WashTradingDetector {
    config: WashTradingConfig,
}

impl WashTradingDetector {
    /// This detector's stable id.
    pub const ID: DetectorId = DetectorId::new("wash-trading");
    /// This build's version: `1.0.0`.
    pub const VERSION: SemVer = SemVer::new(1, 0, 0);

    /// Build the detector with explicit thresholds.
    pub fn new(config: WashTradingConfig) -> Self {
        Self { config }
    }

    /// The active config — what the model registry hashes into `config_hash`.
    pub fn config(&self) -> &WashTradingConfig {
        &self.config
    }
}

/// Construct the detector with default config, ready to register.
pub fn plugin() -> WashTradingDetector {
    WashTradingDetector::new(WashTradingConfig::default())
}

/// One swap folded into the window: the trade plus who made it and where.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WashSwap {
    tx: B256,
    trader: Address,
    pool: Address,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    amount_out: U256,
}

/// One observed block's contribution to the window: its number and the swaps it
/// added. Retained per block so the window can slide (evicting whole blocks) and so
/// a reorg rollback — handled by the service's `CrossBlockState` snapshot store — is
/// a clean discard of this state.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BlockActivity {
    number: u64,
    swaps: Vec<WashSwap>,
}

/// The wash-trading detector's accumulated cross-block state: a sliding window of
/// per-block swap activity, oldest at the front. `Clone` (the service forks it per
/// block) and `Send + 'static` (the scheduler owns it across `.await`) — the
/// [`CrossBlockDetector::State`] contract.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WashState {
    blocks: VecDeque<BlockActivity>,
}

/// The per-`(trader, pool)` tally accumulated across the window.
struct Agg {
    /// The pool's two tokens, canonicalised so direction is stable: `token_a` is the
    /// lower address, `token_b` the higher.
    token_a: Address,
    token_b: Address,
    swap_count: u32,
    /// Swaps that acquired `token_a` (one trading direction).
    buy_count: u32,
    /// Swaps that disposed `token_a` (the other direction).
    sell_count: u32,
    /// Gross `token_a` moved (bought + sold), in raw base units.
    gross_a: U256,
    /// `token_a` received across the window.
    recv_a: U256,
    /// `token_a` spent across the window.
    spent_a: U256,
    /// Implicated tx hashes, in first-seen order (deduplicated).
    txs: Vec<B256>,
}

impl Agg {
    fn new(token_a: Address, token_b: Address) -> Self {
        Self {
            token_a,
            token_b,
            swap_count: 0,
            buy_count: 0,
            sell_count: 0,
            gross_a: U256::ZERO,
            recv_a: U256::ZERO,
            spent_a: U256::ZERO,
            txs: Vec::new(),
        }
    }

    fn fold(&mut self, s: &WashSwap) {
        self.swap_count += 1;
        if s.token_out == self.token_a {
            // Acquired token_a.
            self.buy_count += 1;
            self.recv_a = self.recv_a.saturating_add(s.amount_out);
            self.gross_a = self.gross_a.saturating_add(s.amount_out);
        } else {
            // token_in == token_a: disposed token_a.
            self.sell_count += 1;
            self.spent_a = self.spent_a.saturating_add(s.amount_in);
            self.gross_a = self.gross_a.saturating_add(s.amount_in);
        }
        if self.txs.last() != Some(&s.tx) {
            self.txs.push(s.tx);
        }
    }

    /// `|recv - spent| / gross` in basis points — how far the net position moved
    /// relative to the churn. `None` if nothing was churned (a divide guard).
    fn net_bps(&self) -> Option<Bps> {
        let net = if self.recv_a >= self.spent_a {
            self.recv_a - self.spent_a
        } else {
            self.spent_a - self.recv_a
        };
        Bps::from_ratio_u256(net, self.gross_a)
    }
}

impl CrossBlockDetector for WashTradingDetector {
    type State = WashState;

    fn id(&self) -> DetectorId {
        Self::ID
    }

    fn version(&self) -> SemVer {
        Self::VERSION
    }

    fn kind(&self) -> ModelKind {
        ModelKind::Rule
    }

    fn window_blocks(&self) -> u32 {
        self.config.window_blocks
    }

    fn init_state(&self) -> WashState {
        WashState::default()
    }

    fn observe(&self, ctx: &DetectionCtx, state: &mut WashState) {
        let number = ctx.block().number;
        // Collect this block's swaps, tagged with their sender.
        let mut swaps = Vec::new();
        for tx_hash in ctx.txs() {
            let Some(tx) = ctx.enrichment().tx(*tx_hash) else {
                continue;
            };
            for s in &tx.swaps {
                swaps.push(WashSwap {
                    tx: tx.hash,
                    trader: tx.from,
                    pool: s.pool,
                    token_in: s.token_in,
                    token_out: s.token_out,
                    amount_in: s.amount_in,
                    amount_out: s.amount_out,
                });
            }
        }
        state.blocks.push_back(BlockActivity { number, swaps });

        // Slide the window: drop whole blocks older than `window_blocks` behind the
        // current tip. The service keeps a snapshot per block for reorg rollback; the
        // analytical window lives here, so this is where old activity ages out.
        let cutoff = number.saturating_sub(u64::from(self.config.window_blocks));
        while state.blocks.front().is_some_and(|b| b.number <= cutoff) {
            state.blocks.pop_front();
        }
    }

    fn detect(&self, ctx: &DetectionCtx, state: &WashState) -> Vec<Evidence> {
        let current = ctx.block().number;
        // Pairs that traded in *this* block — the only ones we (re-)evaluate, so an
        // idle churning window doesn't re-fire every block.
        let active: std::collections::BTreeSet<(Address, Address)> = state
            .blocks
            .iter()
            .filter(|b| b.number == current)
            .flat_map(|b| b.swaps.iter().map(|s| (s.trader, s.pool)))
            .collect();
        if active.is_empty() {
            return Vec::new();
        }

        // Aggregate the whole window per (trader, pool).
        let mut aggs: BTreeMap<(Address, Address), Agg> = BTreeMap::new();
        for block in &state.blocks {
            for s in &block.swaps {
                let key = (s.trader, s.pool);
                if !active.contains(&key) {
                    continue;
                }
                let (token_a, token_b) = canonical_pair(s.token_in, s.token_out);
                aggs.entry(key)
                    .or_insert_with(|| Agg::new(token_a, token_b))
                    .fold(s);
            }
        }

        aggs.into_iter()
            .filter_map(|((trader, pool), agg)| self.evidence_for(ctx, trader, pool, &agg))
            .collect()
    }
}

impl WashTradingDetector {
    /// Build a finding for one `(trader, pool)` window aggregate iff it clears the
    /// thresholds (enough swaps, both directions, near-flat net position).
    fn evidence_for(
        &self,
        ctx: &DetectionCtx,
        trader: Address,
        pool: Address,
        agg: &Agg,
    ) -> Option<Evidence> {
        if agg.swap_count < self.config.min_swaps || agg.buy_count == 0 || agg.sell_count == 0 {
            return None;
        }
        let net_bps = agg.net_bps()?;
        if net_bps > self.config.max_net_bps {
            return None;
        }

        let volume_usd = ctx.enrichment().usd_value(agg.token_a, agg.gross_a);
        let confidence = confidence_for(agg.swap_count, self.config.min_swaps, net_bps);

        let detail = WashTradingDetail {
            trader,
            pool,
            token_a: agg.token_a,
            token_b: agg.token_b,
            swap_count: agg.swap_count,
            buy_count: agg.buy_count,
            sell_count: agg.sell_count,
            gross_volume_a: agg.gross_a,
            net_bps,
            volume_usd,
            window_blocks: self.config.window_blocks,
        };
        Some(Evidence::from_detail(
            AlertKind::WashTrading,
            agg.txs.clone(),
            confidence,
            &detail,
        ))
    }
}

/// The typed detail payload of a wash-trading [`Evidence`] (§6). Addresses are
/// facts, not identities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WashTradingDetail {
    /// The address whose round-trips generated the volume — a fact, not a label.
    pub trader: Address,
    pub pool: Address,
    /// The pool's lower-address token (the reference the net/gross are measured in).
    pub token_a: Address,
    /// The pool's higher-address token.
    pub token_b: Address,
    pub swap_count: u32,
    pub buy_count: u32,
    pub sell_count: u32,
    /// Gross `token_a` churned over the window, in raw base units.
    pub gross_volume_a: U256,
    /// Net position change as a fraction of gross (small ⇒ washy).
    pub net_bps: Bps,
    /// The churned volume in USD, when `token_a` has a reference price; else `null`.
    pub volume_usd: Option<f64>,
    /// The window the pattern was measured over.
    pub window_blocks: u32,
}

/// Canonicalise a pool's two tokens by address so the trading direction is stable
/// regardless of which way a given swap went.
fn canonical_pair(token_in: Address, token_out: Address) -> (Address, Address) {
    if token_in <= token_out {
        (token_in, token_out)
    } else {
        (token_out, token_in)
    }
}

/// Facts-only confidence (§6): a base, plus a bonus per swap beyond the minimum
/// (capped), plus a bonus when the net position is very flat — the purest wash.
fn confidence_for(swap_count: u32, min_swaps: u32, net_bps: Bps) -> Confidence {
    let extra = swap_count.saturating_sub(min_swaps).min(MAX_EXTRA_SWAPS);
    let mut score = CONF_BASE + CONF_PER_EXTRA_SWAP * f64::from(extra);
    if net_bps.get() < DEFAULT_MAX_NET_BPS / 10 {
        score += CONF_FLAT_BONUS;
    }
    Confidence::new(score)
}

#[cfg(test)]
mod tests {
    use super::*;
    use detector_api::test_util::{addr, b256, swap, CtxBuilder};
    use detector_api::{DetectionCtx, Swap};
    use events::primitives::{BlockRef, Chain};

    const TKN: u8 = 0x0A; // lower address ⇒ token_a
    const WETH: u8 = 0xEE; // higher address ⇒ token_b
    const POOL: u8 = 0xCC;
    const TRADER: u8 = 0x11;
    const HONEST: u8 = 0x22;

    fn buy_tkn(amount_out: u128) -> Vec<Swap> {
        // WETH → TKN (acquire token_a).
        vec![swap(addr(POOL), addr(WETH), addr(TKN), 1_000, amount_out)]
    }
    fn sell_tkn(amount_in: u128) -> Vec<Swap> {
        // TKN → WETH (dispose token_a).
        vec![swap(addr(POOL), addr(TKN), addr(WETH), amount_in, 1_000)]
    }

    /// A context for block `number` with the given swap-carrying txs.
    fn block_ctx(number: u64, txs: Vec<(u8, u8, Vec<Swap>)>) -> DetectionCtx {
        let mut b =
            CtxBuilder::new().at(Chain::ETHEREUM, BlockRef::new(number, b256(number as u8)));
        for (hash_byte, from, swaps) in txs {
            b = b.tx(b256(hash_byte), addr(from), swaps);
        }
        b.build()
    }

    /// Drive the detector through blocks the way the service does — `observe` then
    /// `detect` per block — returning the findings from the *last* block.
    fn run(detector: &WashTradingDetector, blocks: Vec<DetectionCtx>) -> Vec<Evidence> {
        let mut state = detector.init_state();
        let mut last = Vec::new();
        for ctx in &blocks {
            detector.observe(ctx, &mut state);
            last = detector.detect(ctx, &state);
        }
        last
    }

    fn detail_of(ev: &Evidence) -> WashTradingDetail {
        serde_json::from_value(ev.detail.clone()).expect("detail round-trips as WashTradingDetail")
    }

    #[test]
    fn flags_a_trader_round_tripping_across_blocks() {
        // Buy, sell, buy, sell across four blocks — 4 swaps, both directions, net ≈ 0.
        let blocks = vec![
            block_ctx(1, vec![(0x01, TRADER, buy_tkn(500))]),
            block_ctx(2, vec![(0x02, TRADER, sell_tkn(500))]),
            block_ctx(3, vec![(0x03, TRADER, buy_tkn(500))]),
            block_ctx(4, vec![(0x04, TRADER, sell_tkn(500))]),
        ];
        let found = run(&plugin(), blocks);
        assert_eq!(found.len(), 1);
        let ev = &found[0];
        assert_eq!(ev.kind, AlertKind::WashTrading);

        let d = detail_of(ev);
        assert_eq!(d.trader, addr(TRADER));
        assert_eq!(d.pool, addr(POOL));
        assert_eq!(d.token_a, addr(TKN));
        assert_eq!(d.swap_count, 4);
        assert_eq!(d.buy_count, 2);
        assert_eq!(d.sell_count, 2);
        assert_eq!(d.net_bps, Bps::new(0)); // recv 1000 == spent 1000.
                                            // All four txs implicated, in order.
        assert_eq!(ev.txs, vec![b256(1), b256(2), b256(3), b256(4)]);
    }

    #[test]
    fn ignores_directional_accumulation() {
        // Four buys, no sells — accumulating, not washing.
        let blocks = vec![
            block_ctx(1, vec![(0x01, TRADER, buy_tkn(500))]),
            block_ctx(2, vec![(0x02, TRADER, buy_tkn(500))]),
            block_ctx(3, vec![(0x03, TRADER, buy_tkn(500))]),
            block_ctx(4, vec![(0x04, TRADER, buy_tkn(500))]),
        ];
        assert!(run(&plugin(), blocks).is_empty());
    }

    #[test]
    fn ignores_too_few_swaps() {
        // A single round trip (2 swaps) is below the min_swaps floor.
        let blocks = vec![
            block_ctx(1, vec![(0x01, TRADER, buy_tkn(500))]),
            block_ctx(2, vec![(0x02, TRADER, sell_tkn(500))]),
        ];
        assert!(run(&plugin(), blocks).is_empty());
    }

    #[test]
    fn ignores_high_net_directional_churn() {
        // Both directions and enough swaps, but the trader keeps most of what they
        // bought (net far above the ceiling) — real accumulation, not washing.
        let blocks = vec![
            block_ctx(1, vec![(0x01, TRADER, buy_tkn(1000))]),
            block_ctx(2, vec![(0x02, TRADER, buy_tkn(1000))]),
            block_ctx(3, vec![(0x03, TRADER, buy_tkn(1000))]),
            block_ctx(4, vec![(0x04, TRADER, sell_tkn(10))]),
        ];
        assert!(run(&plugin(), blocks).is_empty());
    }

    #[test]
    fn does_not_refire_on_an_idle_window() {
        let mut state = plugin().init_state();
        let d = plugin();
        // Four wash swaps land through block 4 → fires on block 4.
        for (n, mk) in [
            (1u64, buy_tkn(500)),
            (2, sell_tkn(500)),
            (3, buy_tkn(500)),
            (4, sell_tkn(500)),
        ] {
            let ctx = block_ctx(n, vec![(n as u8, TRADER, mk)]);
            d.observe(&ctx, &mut state);
            let found = d.detect(&ctx, &state);
            if n == 4 {
                assert_eq!(found.len(), 1);
            }
        }
        // Block 5 has no activity for the pair → the still-washy window doesn't re-fire.
        let idle = block_ctx(5, vec![(0x55, HONEST, buy_tkn(500))]);
        d.observe(&idle, &mut state);
        assert!(d.detect(&idle, &state).is_empty());
    }

    #[test]
    fn window_ages_out_old_activity() {
        // A short window of 2 blocks; the earlier round trip ages out before the
        // later one, so the count never reaches min_swaps.
        let detector = WashTradingDetector::new(WashTradingConfig {
            window_blocks: 2,
            ..WashTradingConfig::default()
        });
        let blocks = vec![
            block_ctx(1, vec![(0x01, TRADER, buy_tkn(500))]),
            block_ctx(2, vec![(0x02, TRADER, sell_tkn(500))]),
            block_ctx(10, vec![(0x0a, TRADER, buy_tkn(500))]),
            block_ctx(11, vec![(0x0b, TRADER, sell_tkn(500))]),
        ];
        assert!(run(&detector, blocks).is_empty());
    }

    #[test]
    fn config_round_trips_with_defaults() {
        let cfg: WashTradingConfig =
            serde_json::from_str(r#"{"window_blocks": 50, "min_swaps": 6}"#).unwrap();
        assert_eq!(cfg.window_blocks, 50);
        assert_eq!(cfg.min_swaps, 6);
        assert_eq!(cfg.max_net_bps, Bps::new(DEFAULT_MAX_NET_BPS)); // omitted ⇒ default.
        let defaulted: WashTradingConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(defaulted, WashTradingConfig::default());
    }

    #[test]
    fn exposes_its_identity_through_the_cross_block_seam() {
        let detector = plugin();
        let plug: &dyn CrossBlockDetector<State = WashState> = &detector;
        assert_eq!(plug.id().as_str(), "wash-trading");
        assert_eq!(plug.id(), WashTradingDetector::ID);
        assert_eq!(plug.version(), WashTradingDetector::VERSION);
        assert_eq!(plug.version().to_string(), "1.0.0");
        assert_eq!(plug.kind(), ModelKind::Rule);
        assert_eq!(plug.window_blocks(), DEFAULT_WINDOW_BLOCKS);
    }
}
