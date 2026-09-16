//! Adversarial negatives (§18; Hardening Epic E) — near misses that sit just
//! outside a detector's signature, **by that detector's own definition**, and
//! on which the whole roster must stay silent.
//!
//! The known-incident fixtures prove each signature still fires. These prove
//! the edges hold. Each one keeps everything about an incident except the one
//! property its detector requires, such as the victim, the profit, the
//! repayment, the discount, the drained share, the flat net position or the
//! nibble match. So a detector that loosens that requirement starts firing
//! here and pays for it in precision, on every PR.
//!
//! # What is deliberately not here
//!
//! A near miss is only adversarial if the detector's contract says it must
//! not fire. Two well-known false-positive classes are **inside** a contract
//! and so are not near misses. Each detector's module docs record them as
//! a known limitation:
//!
//! - an LP withdrawing their own large position (rugpull names the *drain*;
//!   intent is attribution's call, §8);
//! - an in-tx add-then-remove of the same liquidity (flashloan names the
//!   *round trip*).
//!
//! Writing either one here would score a detector down for doing what it is
//! specified to do. Whether those findings are *useful* is a question for
//! simulation, which is why only mainnet windows ([`crate::windows`]) can
//! measure a field false-positive rate. These fixtures measure contracts.
//!
//! Every fixture is closed-world ([`Provenance::Adversarial`]): any alert on
//! one is a false positive for the detector that raised it.
//!
//! [`Provenance::Adversarial`]: crate::fixture::Provenance::Adversarial

use alloy_primitives::{Address, B256};
use detector_api::test_util::{addr, b256, swap, transfer};
use detector_api::{BlockBundle, DetectionCtx};
use events::primitives::{BlockRef, Chain};

use super::{at, ETH, USDC_UNIT};
use crate::fixture::Fixture;

const WETH: u8 = 0xAA;
const TKN: u8 = 0xBB;
const USDC: u8 = 0xBD;
const DAI: u8 = 0xBE;
const POOL: u8 = 0xCC;
const POOL_B: u8 = 0xCD;
const ACTOR: u8 = 0x11;
const OTHER: u8 = 0x22;
const PROTOCOL: u8 = 0x99;

// ── sandwich ────────────────────────────────────────────────────────────────

/// A trader buys and sells back around someone else's trade, but that trade
/// goes the *other* way. With no same-direction swap in between there is no
/// victim, and no victim means no sandwich.
pub fn sandwich_without_a_victim() -> Fixture {
    let ctx = at(2_000)
        .priced_token(addr(WETH), 18, 2000.0)
        .priced_token(addr(TKN), 18, 1.0)
        .pool(addr(POOL), addr(WETH), addr(TKN), 1_000, 1_000)
        .tx(
            b256(1),
            addr(ACTOR),
            vec![swap(addr(POOL), addr(WETH), addr(TKN), ETH, 90)],
        )
        .tx(
            b256(2),
            addr(OTHER),
            vec![swap(addr(POOL), addr(TKN), addr(WETH), 80, ETH)],
        )
        .tx(
            b256(3),
            addr(ACTOR),
            vec![swap(addr(POOL), addr(TKN), addr(WETH), 90, ETH + ETH / 20)],
        )
        .build();
    Fixture::adversarial(
        "sandwich near-miss: a round trip around an opposite-direction trade (no victim)",
        vec![ctx],
    )
}

/// A frontrun-victim-backrun bracket that loses money. Profit is the
/// sandwich's definition, not a filter on it: a bracket that recovers less
/// than it spent is two trades.
pub fn sandwich_at_a_loss() -> Fixture {
    let ctx = at(2_001)
        .priced_token(addr(WETH), 18, 2000.0)
        .priced_token(addr(TKN), 18, 1.0)
        .pool(addr(POOL), addr(WETH), addr(TKN), 1_000, 1_000)
        .tx(
            b256(1),
            addr(ACTOR),
            vec![swap(addr(POOL), addr(WETH), addr(TKN), ETH, 90)],
        )
        .tx(
            b256(2),
            addr(OTHER),
            vec![swap(addr(POOL), addr(WETH), addr(TKN), ETH, 80)],
        )
        .tx(
            b256(3),
            addr(ACTOR),
            vec![swap(addr(POOL), addr(TKN), addr(WETH), 90, ETH - ETH / 20)],
        )
        .build();
    Fixture::adversarial(
        "sandwich near-miss: the bracket shape, closed at a loss",
        vec![ctx],
    )
}

/// The bracket's legs land on two different pools. A sandwich lives inside
/// one pool's price, so a sell elsewhere cannot close it.
pub fn sandwich_across_two_pools() -> Fixture {
    let ctx = at(2_002)
        .priced_token(addr(WETH), 18, 2000.0)
        .priced_token(addr(TKN), 18, 1.0)
        .pool(addr(POOL), addr(WETH), addr(TKN), 1_000, 1_000)
        .pool(addr(POOL_B), addr(WETH), addr(TKN), 1_000, 1_000)
        .tx(
            b256(1),
            addr(ACTOR),
            vec![swap(addr(POOL), addr(WETH), addr(TKN), ETH, 90)],
        )
        .tx(
            b256(2),
            addr(OTHER),
            vec![swap(addr(POOL), addr(WETH), addr(TKN), ETH, 80)],
        )
        .tx(
            b256(3),
            addr(ACTOR),
            vec![swap(
                addr(POOL_B),
                addr(TKN),
                addr(WETH),
                90,
                ETH + ETH / 20,
            )],
        )
        .build();
    Fixture::adversarial(
        "sandwich near-miss: frontrun and victim on one pool, backrun on another",
        vec![ctx],
    )
}

/// A real bracket that nets $2, under the $10 profit floor (§6).
pub fn sandwich_below_the_profit_floor() -> Fixture {
    let ctx = at(2_003)
        .priced_token(addr(WETH), 18, 2000.0)
        .priced_token(addr(TKN), 18, 1.0)
        .pool(addr(POOL), addr(WETH), addr(TKN), 1_000, 1_000)
        .tx(
            b256(1),
            addr(ACTOR),
            vec![swap(addr(POOL), addr(WETH), addr(TKN), ETH, 90)],
        )
        .tx(
            b256(2),
            addr(OTHER),
            vec![swap(addr(POOL), addr(WETH), addr(TKN), ETH, 80)],
        )
        .tx(
            b256(3),
            addr(ACTOR),
            vec![swap(
                addr(POOL),
                addr(TKN),
                addr(WETH),
                90,
                ETH + ETH / 1_000,
            )],
        )
        .build();
    Fixture::adversarial(
        "sandwich near-miss: a bracket netting $2, under the $10 floor",
        vec![ctx],
    )
}

// ── arbitrage ───────────────────────────────────────────────────────────────

/// A closed WETH → USDC → WETH cycle that ends 5% down. An arb is risk-free
/// profit, and a losing loop is not that.
pub fn arb_losing_cycle() -> Fixture {
    let ctx = at(2_010)
        .priced_token(addr(WETH), 18, 2000.0)
        .priced_token(addr(USDC), 18, 1.0)
        .tx(
            b256(1),
            addr(ACTOR),
            vec![
                swap(addr(POOL), addr(WETH), addr(USDC), ETH, 2000 * ETH),
                swap(
                    addr(POOL_B),
                    addr(USDC),
                    addr(WETH),
                    2000 * ETH,
                    ETH - ETH / 20,
                ),
            ],
        )
        .build();
    Fixture::adversarial("arb near-miss: a closed cycle that loses 5%", vec![ctx])
}

/// An ordinary two-hop router trade, WETH → USDC → DAI. The intermediate
/// balances, but the route never comes back to WETH, so it is a purchase and
/// not a cycle.
pub fn arb_multi_hop_route() -> Fixture {
    let ctx = at(2_011)
        .priced_token(addr(WETH), 18, 2000.0)
        .priced_token(addr(USDC), 18, 1.0)
        .priced_token(addr(DAI), 18, 1.0)
        .tx(
            b256(1),
            addr(ACTOR),
            vec![
                swap(addr(POOL), addr(WETH), addr(USDC), ETH, 2000 * ETH),
                swap(addr(POOL_B), addr(USDC), addr(DAI), 2000 * ETH, 1999 * ETH),
            ],
        )
        .build();
    Fixture::adversarial(
        "arb near-miss: a two-hop router trade that never returns to its input",
        vec![ctx],
    )
}

/// A profitable cycle worth $0.20, dust under the $10 floor.
pub fn arb_dust_cycle() -> Fixture {
    let ctx = at(2_012)
        .priced_token(addr(WETH), 18, 2000.0)
        .priced_token(addr(USDC), 18, 1.0)
        .tx(
            b256(1),
            addr(ACTOR),
            vec![
                swap(addr(POOL), addr(WETH), addr(USDC), ETH, 2000 * ETH),
                swap(
                    addr(POOL_B),
                    addr(USDC),
                    addr(WETH),
                    2000 * ETH,
                    ETH + ETH / 10_000,
                ),
            ],
        )
        .build();
    Fixture::adversarial(
        "arb near-miss: a closed cycle netting $0.20, under the $10 floor",
        vec![ctx],
    )
}

// ── flash loan ──────────────────────────────────────────────────────────────

/// 100 WETH leaves a lender and only 99 come back. Without full repayment in
/// the same tx it is not a flash loan (a real one would have reverted).
pub fn flashloan_short_repayment() -> Fixture {
    let ctx = at(2_020)
        .priced_token(addr(WETH), 18, 2000.0)
        .transfer_tx(
            b256(1),
            addr(ACTOR),
            vec![
                transfer(addr(WETH), addr(POOL), addr(ACTOR), 100 * ETH),
                transfer(addr(WETH), addr(ACTOR), addr(POOL), 99 * ETH),
            ],
        )
        .build();
    Fixture::adversarial(
        "flashloan near-miss: 100 WETH out, 99 WETH back in one tx",
        vec![ctx],
    )
}

/// A complete borrow-and-repay of 0.1 WETH ($200), under the $1,000
/// notional floor.
pub fn flashloan_below_the_notional_floor() -> Fixture {
    let ctx = at(2_021)
        .priced_token(addr(WETH), 18, 2000.0)
        .transfer_tx(
            b256(1),
            addr(ACTOR),
            vec![
                transfer(addr(WETH), addr(POOL), addr(ACTOR), ETH / 10),
                transfer(addr(WETH), addr(ACTOR), addr(POOL), ETH / 10 + ETH / 10_000),
            ],
        )
        .build();
    Fixture::adversarial(
        "flashloan near-miss: a $200 round trip, under the $1,000 floor",
        vec![ctx],
    )
}

/// A fair swap seen only through its transfer logs: 2,000 USDC in, 1 WETH
/// ($2,000) out of a deep pool. Two tokens, so there is no round trip (not a
/// flash loan). Zero discount, so no seizure (not a liquidation). A
/// thousandth of the reserve, so no drain (not a rug).
pub fn fair_swap_as_transfers() -> Fixture {
    let ctx = at(2_022)
        .priced_token(addr(WETH), 18, 2000.0)
        .priced_token(addr(USDC), 6, 1.0)
        .pool(
            addr(POOL),
            addr(WETH),
            addr(USDC),
            1_000 * ETH,
            2_000_000 * USDC_UNIT,
        )
        .transfer_tx(
            b256(1),
            addr(ACTOR),
            vec![
                transfer(addr(USDC), addr(ACTOR), addr(POOL), 2_000 * USDC_UNIT),
                transfer(addr(WETH), addr(POOL), addr(ACTOR), ETH),
            ],
        )
        .build();
    Fixture::adversarial(
        "flashloan/liquidation/rugpull near-miss: a fair USDC→WETH swap read from transfers",
        vec![ctx],
    )
}

// ── liquidation ─────────────────────────────────────────────────────────────

/// Debt repaid, collateral received, at a 1% edge. That is below the 3%
/// bonus floor that separates a seizure from a favourable trade.
pub fn liquidation_below_the_bonus_floor() -> Fixture {
    let ctx = at(2_030)
        .priced_token(addr(WETH), 18, 2000.0)
        .priced_token(addr(USDC), 6, 1.0)
        .transfer_tx(
            b256(1),
            addr(ACTOR),
            vec![
                transfer(addr(USDC), addr(ACTOR), addr(PROTOCOL), 2_000 * USDC_UNIT),
                transfer(addr(WETH), addr(PROTOCOL), addr(ACTOR), ETH + ETH / 100),
            ],
        )
        .build();
    Fixture::adversarial(
        "liquidation near-miss: a 1% edge, under the 3% bonus floor",
        vec![ctx],
    )
}

/// An 8% discounted seizure against $50 of debt, which is dust under the
/// $100 floor.
pub fn liquidation_dust_debt() -> Fixture {
    let ctx = at(2_031)
        .priced_token(addr(WETH), 18, 2000.0)
        .priced_token(addr(USDC), 6, 1.0)
        .transfer_tx(
            b256(1),
            addr(ACTOR),
            vec![
                transfer(addr(USDC), addr(ACTOR), addr(PROTOCOL), 50 * USDC_UNIT),
                // $54 of WETH.
                transfer(addr(WETH), addr(PROTOCOL), addr(ACTOR), 27 * ETH / 1_000),
            ],
        )
        .build();
    Fixture::adversarial(
        "liquidation near-miss: an 8% seizure against $50 of debt, under the $100 floor",
        vec![ctx],
    )
}

// ── rug pull ────────────────────────────────────────────────────────────────

/// 30% of a pool's reserve leaves in one tx, which is under the 50% drain
/// floor.
pub fn rugpull_partial_withdrawal() -> Fixture {
    let ctx = at(2_040)
        .priced_token(addr(TKN), 0, 1.0)
        .priced_token(addr(WETH), 18, 2000.0)
        .pool(addr(POOL), addr(TKN), addr(WETH), 1_000_000, 1_000)
        .transfer_tx(
            b256(1),
            addr(ACTOR),
            vec![transfer(addr(TKN), addr(POOL), addr(ACTOR), 300_000)],
        )
        .build();
    Fixture::adversarial(
        "rugpull near-miss: 30% of the reserve withdrawn, under the 50% floor",
        vec![ctx],
    )
}

/// 90% of a dust pool, $4,500, is drained. That is under the $10,000
/// pool-size gate.
pub fn rugpull_dust_pool() -> Fixture {
    let ctx = at(2_041)
        .priced_token(addr(TKN), 0, 1.0)
        .priced_token(addr(WETH), 18, 2000.0)
        .pool(addr(POOL), addr(TKN), addr(WETH), 5_000, 1_000)
        .transfer_tx(
            b256(1),
            addr(ACTOR),
            vec![transfer(addr(TKN), addr(POOL), addr(ACTOR), 4_500)],
        )
        .build();
    Fixture::adversarial(
        "rugpull near-miss: 90% of a $5,000 pool, under the $10,000 gate",
        vec![ctx],
    )
}

// ── wash trading ────────────────────────────────────────────────────────────

/// Four swaps on one pool over four blocks, matching the wash fixture's
/// cadence. Each leg is `(is_buy, amount)`: a buy is 1,000 WETH-units in for
/// `amount` TKN out, a sell is `amount` TKN in for 1,000 out.
fn four_block_trader(first_block: u64, legs: [(bool, u128); 4]) -> Vec<DetectionCtx> {
    // Same address ordering as the wash fixture: TKN is token_a.
    const TKN_A: u8 = 0x0A;
    const WETH_B: u8 = 0xEE;
    legs.iter()
        .enumerate()
        .map(|(i, &(is_buy, amount))| {
            let s = if is_buy {
                swap(addr(POOL), addr(WETH_B), addr(TKN_A), 1_000, amount)
            } else {
                swap(addr(POOL), addr(TKN_A), addr(WETH_B), amount, 1_000)
            };
            at(first_block + i as u64)
                .tx(b256(i as u8 + 1), addr(ACTOR), vec![s])
                .build()
        })
        .collect()
}

/// Four buys, no sells: accumulation. The detector requires trading in both
/// directions.
pub fn wash_directional_accumulation() -> Fixture {
    Fixture::adversarial(
        "wash-trading near-miss: four same-direction buys on one pool over 4 blocks",
        four_block_trader(2_050, [(true, 500); 4]),
    )
}

/// Both directions, four swaps, but the trader ends up long 800 of 1,200
/// churned. A 67% net move is a position, not round-tripping, and is far
/// over the 10% ceiling.
pub fn wash_round_trips_with_a_net_position() -> Fixture {
    Fixture::adversarial(
        "wash-trading near-miss: buy/sell/buy/sell that nets 67% long",
        four_block_trader(
            2_060,
            [(true, 500), (false, 100), (true, 500), (false, 100)],
        ),
    )
}

/// A buy/sell/buy that nets exactly flat (500 in, 1,000 out, 500 in) and
/// stops at three swaps, under the four-swap floor. The fourth block is a
/// different trader's sell, so the window still gets traffic on the pool.
///
/// The legs must net to zero. An earlier cut used 500/500/500, which is 33%
/// net-long, so the net ceiling kept it silent rather than the swap floor.
/// `tests/adversarial_boundaries.rs` exists to catch exactly that.
pub fn wash_three_swaps() -> Fixture {
    let mut blocks = four_block_trader(
        2_070,
        [(true, 500), (false, 1_000), (true, 500), (false, 500)],
    );
    // Replace the fourth swap's sender: same pool and shape, another trader.
    const TKN_A: u8 = 0x0A;
    const WETH_B: u8 = 0xEE;
    blocks[3] = at(2_073)
        .tx(
            b256(4),
            addr(OTHER),
            vec![swap(addr(POOL), addr(TKN_A), addr(WETH_B), 500, 1_000)],
        )
        .build();
    Fixture::adversarial(
        "wash-trading near-miss: a flat round trip that stops at three swaps",
        blocks,
    )
}

// ── address poisoning ───────────────────────────────────────────────────────

/// An address whose first and last bytes are fixed and whose middle is
/// `fill`: `head…fill…tail`.
fn shaped(head: [u8; 2], fill: u8, tail: [u8; 2]) -> Address {
    let mut bytes = [fill; 20];
    bytes[..2].copy_from_slice(&head);
    bytes[18..].copy_from_slice(&tail);
    Address::from(bytes)
}

/// A zero-value transfer from an address that shares only 2 leading and 2
/// trailing nibbles with the victim's real counterparty. That happens by
/// chance about once in 65,000 addresses, and the detector requires 4 + 4.
pub fn poisoning_weak_lookalike() -> Fixture {
    let real = shaped([0xAA, 0xBB], 0x11, [0xCC, 0xDD]);
    let near = shaped([0xAA, 0x99], 0x99, [0x99, 0xDD]);
    let ctx = at(2_080)
        .transfer_tx(
            b256(1),
            real,
            vec![transfer(addr(TKN), real, addr(OTHER), 1_000)],
        )
        .transfer_tx(
            b256(2),
            near,
            vec![transfer(addr(TKN), near, addr(OTHER), 0)],
        )
        .build();
    Fixture::adversarial(
        "address-poisoning near-miss: zero-value transfer from a 2+2-nibble match",
        vec![ctx],
    )
}

/// A strong lookalike that sends the victim real value. That makes it a
/// counterparty (a vanity address in ordinary use), not bait.
pub fn poisoning_lookalike_sending_value() -> Fixture {
    let real = shaped([0xAA, 0xBB], 0x11, [0xCC, 0xDD]);
    let vanity = shaped([0xAA, 0xBB], 0x99, [0xCC, 0xDD]);
    let ctx = at(2_081)
        .transfer_tx(
            b256(1),
            real,
            vec![transfer(addr(TKN), real, addr(OTHER), 1_000)],
        )
        .transfer_tx(
            b256(2),
            vanity,
            vec![transfer(addr(TKN), vanity, addr(OTHER), 250)],
        )
        .build();
    Fixture::adversarial(
        "address-poisoning near-miss: a lookalike paying the victim real value",
        vec![ctx],
    )
}

/// A zero-value transfer to an address that moved no value this block, so
/// there is nothing to mimic. Zero-value `Transfer` logs are common contract
/// noise on their own.
pub fn poisoning_zero_value_noise() -> Fixture {
    let ctx = at(2_082)
        .transfer_tx(
            b256(1),
            addr(PROTOCOL),
            vec![transfer(addr(TKN), addr(PROTOCOL), addr(OTHER), 0)],
        )
        .transfer_tx(
            b256(2),
            addr(ACTOR),
            vec![transfer(addr(TKN), addr(ACTOR), addr(POOL), 1_000)],
        )
        .build();
    Fixture::adversarial(
        "address-poisoning near-miss: a zero-value transfer with no counterparty to mimic",
        vec![ctx],
    )
}

// ── whole-block noise ───────────────────────────────────────────────────────

/// A busy, ordinary block: twelve distinct traders on one pool in both
/// directions, interleaved with plain payments. It has the density sandwich
/// and wash detection look at, and none of the same-sender structure either
/// needs.
pub fn busy_ordinary_block() -> Fixture {
    let mut ctx = at(2_090)
        .priced_token(addr(WETH), 18, 2000.0)
        .priced_token(addr(USDC), 6, 1.0)
        .pool(
            addr(POOL),
            addr(WETH),
            addr(USDC),
            1_000 * ETH,
            2_000_000 * USDC_UNIT,
        );
    for i in 0..12u8 {
        let trader = addr(0x30 + i);
        let s = if i % 2 == 0 {
            swap(addr(POOL), addr(WETH), addr(USDC), ETH, 1_990 * USDC_UNIT)
        } else {
            swap(
                addr(POOL),
                addr(USDC),
                addr(WETH),
                2_000 * USDC_UNIT,
                ETH - ETH / 200,
            )
        };
        ctx = ctx.tx(b256(0x40 + i), trader, vec![s]);
        if i % 3 == 0 {
            // A payment to a distinct payee, never returned.
            ctx = ctx.transfer_tx(
                b256(0x60 + i),
                trader,
                vec![transfer(addr(USDC), trader, addr(0x70 + i), 25 * USDC_UNIT)],
            );
        }
    }
    Fixture::adversarial(
        "noise: twelve distinct traders both ways on one pool, plus payments",
        vec![ctx.build()],
    )
}

/// Transactions with no decoded actions. A header-only source is the live
/// state today (§5), and a detector with nothing decoded must report nothing.
pub fn undecoded_block() -> Fixture {
    let txs: Vec<B256> = (1..=20u8).map(b256).collect();
    let ctx = DetectionCtx::new(BlockBundle::new(
        Chain::ETHEREUM,
        BlockRef::new(2_091, b256(0x5A)),
        txs,
    ));
    Fixture::adversarial(
        "noise: a 20-tx block with no decoded actions (header-only source)",
        vec![ctx],
    )
}

/// Every adversarial negative.
pub fn all() -> Vec<Fixture> {
    vec![
        sandwich_without_a_victim(),
        sandwich_at_a_loss(),
        sandwich_across_two_pools(),
        sandwich_below_the_profit_floor(),
        arb_losing_cycle(),
        arb_multi_hop_route(),
        arb_dust_cycle(),
        flashloan_short_repayment(),
        flashloan_below_the_notional_floor(),
        fair_swap_as_transfers(),
        liquidation_below_the_bonus_floor(),
        liquidation_dust_debt(),
        rugpull_partial_withdrawal(),
        rugpull_dust_pool(),
        wash_directional_accumulation(),
        wash_round_trips_with_a_net_position(),
        wash_three_swaps(),
        poisoning_weak_lookalike(),
        poisoning_lookalike_sending_value(),
        poisoning_zero_value_noise(),
        busy_ordinary_block(),
        undecoded_block(),
    ]
}
