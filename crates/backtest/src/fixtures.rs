//! Ground-truth fixtures for the backtest harness (§18, Sprint 10 t2): one
//! known-incident scenario per built-in detector, plus one clean block with no
//! incident at all.
//!
//! Built with [`CtxBuilder`] — the same helper the detectors' own regression
//! tests use — so each incident here is the identical realistic, mainnet-shaped
//! scenario already proven (in that detector's unit tests) to clear its
//! detector's structural signature and profit gate; what's new here is running
//! the *whole* roster over it and checking nothing else fires. The clean block
//! is the precision check every other fixture also gets for free: since all
//! seven detectors run over every fixture's blocks, an unexpected alert from any
//! detector on any fixture — not just this one — counts against that detector's
//! precision.

use alloy_primitives::Address;
use detector_api::test_util::{addr, b256, swap, transfer, CtxBuilder};
use detector_api::DetectorId;
use events::primitives::{AlertKind, BlockRef, Chain};

use crate::fixture::{ExpectedIncident, Fixture};

const ETH: u128 = 1_000_000_000_000_000_000; // 1e18 wei
const USDC_UNIT: u128 = 1_000_000; // 1 USDC (6 decimals)

fn at(block: u64) -> CtxBuilder {
    CtxBuilder::new().at(Chain::ETHEREUM, BlockRef::new(block, b256(block as u8)))
}

/// A textbook sandwich: attacker frontruns a victim's buy on a WETH/TKN pool,
/// then backruns for ~$100 profit (the exact scenario `sandwich-detector`'s
/// `flags_a_textbook_sandwich` proves against in isolation).
pub fn sandwich() -> Fixture {
    const WETH: u8 = 0xAA;
    const TKN: u8 = 0xBB;
    const POOL: u8 = 0xCC;
    const ATTACKER: u8 = 0x11;
    const VICTIM: u8 = 0x22;
    let block = 100;

    let ctx = at(block)
        .priced_token(addr(WETH), 18, 2000.0)
        .priced_token(addr(TKN), 18, 1.0)
        .pool(addr(POOL), addr(WETH), addr(TKN), 1_000, 1_000)
        .tx(
            b256(1),
            addr(ATTACKER),
            vec![swap(addr(POOL), addr(WETH), addr(TKN), ETH, 90)],
        )
        .tx(
            b256(2),
            addr(VICTIM),
            vec![swap(addr(POOL), addr(WETH), addr(TKN), ETH, 80)],
        )
        .tx(
            b256(3),
            addr(ATTACKER),
            vec![swap(addr(POOL), addr(TKN), addr(WETH), 90, ETH + ETH / 20)],
        )
        .build();

    Fixture::single(
        "sandwich: frontrun-victim-backrun bracket on a WETH/TKN pool",
        ctx,
        vec![ExpectedIncident::new(
            block,
            DetectorId::new("sandwich"),
            AlertKind::Sandwich,
            "attacker brackets the victim's buy for ~$100 profit",
        )],
    )
}

/// A two-hop closed-cycle arbitrage, WETH -> USDC -> WETH, netting ~$100 (mirrors
/// `arb-detector`'s `flags_a_two_hop_cycle_with_profit`).
pub fn arb() -> Fixture {
    const WETH: u8 = 0xAA;
    const USDC: u8 = 0xBB;
    const TRADER: u8 = 0x11;
    let block = 200;

    let ctx = at(block)
        .priced_token(addr(WETH), 18, 2000.0)
        .priced_token(addr(USDC), 18, 1.0)
        .tx(
            b256(1),
            addr(TRADER),
            vec![
                swap(addr(0x01), addr(WETH), addr(USDC), ETH, 2000 * ETH),
                swap(
                    addr(0x02),
                    addr(USDC),
                    addr(WETH),
                    2000 * ETH,
                    ETH + ETH / 20,
                ),
            ],
        )
        .build();

    Fixture::single(
        "arb: two-hop closed-cycle WETH -> USDC -> WETH",
        ctx,
        vec![ExpectedIncident::new(
            block,
            DetectorId::new("arb"),
            AlertKind::Arbitrage,
            "one tx closes a two-pool cycle netting ~$100",
        )],
    )
}

/// A textbook flash loan: a pool lends 100 WETH and is repaid 100.1 WETH in the
/// same tx (mirrors `flashloan-detector`'s `flags_a_textbook_flash_loan`).
pub fn flashloan() -> Fixture {
    const WETH: u8 = 0xAA;
    const POOL: u8 = 0xCC;
    const BORROWER: u8 = 0x11;
    let block = 300;

    let ctx = at(block)
        .priced_token(addr(WETH), 18, 2000.0)
        .transfer_tx(
            b256(1),
            addr(BORROWER),
            vec![
                transfer(addr(WETH), addr(POOL), addr(BORROWER), 100 * ETH),
                transfer(addr(WETH), addr(BORROWER), addr(POOL), 100 * ETH + ETH / 10),
            ],
        )
        .build();

    Fixture::single(
        "flashloan: 100 WETH borrowed and repaid with a fee in one tx",
        ctx,
        vec![ExpectedIncident::new(
            block,
            DetectorId::new("flashloan"),
            AlertKind::Flashloan,
            "same-token round trip through one lender in one tx",
        )],
    )
}

/// A discounted seizure: a liquidator repays $2,000 of USDC debt and seizes
/// $2,160 of WETH collateral, an 8% bonus (mirrors `liquidation-detector`'s
/// `flags_a_discounted_seizure`).
pub fn liquidation() -> Fixture {
    const WETH: u8 = 0xAA;
    const USDC: u8 = 0xBB;
    const LIQUIDATOR: u8 = 0x11;
    const PROTOCOL: u8 = 0x99;
    let block = 400;

    let ctx = at(block)
        .priced_token(addr(WETH), 18, 2000.0)
        .priced_token(addr(USDC), 6, 1.0)
        .transfer_tx(
            b256(1),
            addr(LIQUIDATOR),
            vec![
                transfer(
                    addr(USDC),
                    addr(LIQUIDATOR),
                    addr(PROTOCOL),
                    2000 * USDC_UNIT,
                ),
                transfer(
                    addr(WETH),
                    addr(PROTOCOL),
                    addr(LIQUIDATOR),
                    ETH + 8 * ETH / 100,
                ),
            ],
        )
        .build();

    Fixture::single(
        "liquidation: 8% bonus seizure of WETH collateral for USDC debt",
        ctx,
        vec![ExpectedIncident::new(
            block,
            DetectorId::new("liquidation"),
            AlertKind::Liquidation,
            "liquidator nets collateral worth 8% more than the debt repaid",
        )],
    )
}

/// A 90% liquidity drain of a shallow TKN/WETH pool in one tx (mirrors
/// `rugpull-detector`'s `flags_a_large_liquidity_drain`).
pub fn rugpull() -> Fixture {
    const TKN: u8 = 0xAA;
    const WETH: u8 = 0xBB;
    const POOL: u8 = 0xCC;
    const RUGGER: u8 = 0x11;
    let block = 500;

    let ctx = at(block)
        .priced_token(addr(TKN), 0, 1.0)
        .priced_token(addr(WETH), 18, 2000.0)
        .pool(addr(POOL), addr(TKN), addr(WETH), 1_000_000, 1_000)
        .transfer_tx(
            b256(1),
            addr(RUGGER),
            vec![transfer(addr(TKN), addr(POOL), addr(RUGGER), 900_000)],
        )
        .build();

    Fixture::single(
        "rugpull: 90% of a pool's TKN reserve drained in one tx",
        ctx,
        vec![ExpectedIncident::new(
            block,
            DetectorId::new("rugpull"),
            AlertKind::Rugpull,
            "single tx pulls 900,000 of the pool's 1,000,000 TKN reserve",
        )],
    )
}

/// A trader round-tripping WETH/TKN across four blocks — buy, sell, buy, sell,
/// net ~flat — the pattern only visible over the trailing window (mirrors
/// `washtrading-detector`'s `flags_a_trader_round_tripping_across_blocks`). The
/// finding lands on the fourth block, the first at which the window clears
/// `min_swaps`.
pub fn washtrading() -> Fixture {
    const TKN: u8 = 0x0A; // lower address => token_a
    const WETH: u8 = 0xEE; // higher address => token_b
    const POOL: u8 = 0xCC;
    const TRADER: u8 = 0x11;
    let first_block = 600;
    let fire_block = first_block + 3;

    let buy = |amount_out: u128| vec![swap(addr(POOL), addr(WETH), addr(TKN), 1_000, amount_out)];
    let sell = |amount_in: u128| vec![swap(addr(POOL), addr(TKN), addr(WETH), amount_in, 1_000)];

    let blocks = vec![
        at(first_block).tx(b256(1), addr(TRADER), buy(500)).build(),
        at(first_block + 1)
            .tx(b256(2), addr(TRADER), sell(500))
            .build(),
        at(first_block + 2)
            .tx(b256(3), addr(TRADER), buy(500))
            .build(),
        at(fire_block).tx(b256(4), addr(TRADER), sell(500)).build(),
    ];

    Fixture::new(
        "wash-trading: buy/sell/buy/sell round trip on one pool over 4 blocks",
        blocks,
        vec![ExpectedIncident::new(
            fire_block,
            DetectorId::new("wash-trading"),
            AlertKind::WashTrading,
            "4 swaps both directions, ~flat net position over the trailing window",
        )],
    )
}

/// A zero-value bait from a lookalike address, planted alongside the victim's
/// real counterparty in the same block (mirrors `poisoning-detector`'s
/// `flags_a_zero_value_lookalike_bait`).
pub fn poisoning() -> Fixture {
    const VICTIM: u8 = 0x22;
    const TOKEN: u8 = 0x33;
    let block = 700;

    // The real counterparty: 0xAABB…11…CCDD.
    let mut real_bytes = [0x11u8; 20];
    real_bytes[0] = 0xAA;
    real_bytes[1] = 0xBB;
    real_bytes[18] = 0xCC;
    real_bytes[19] = 0xDD;
    let real = Address::from(real_bytes);

    // The lookalike, sharing the real address's first/last two bytes.
    let mut spoof_bytes = [0x99u8; 20];
    spoof_bytes[0] = 0xAA;
    spoof_bytes[1] = 0xBB;
    spoof_bytes[18] = 0xCC;
    spoof_bytes[19] = 0xDD;
    let spoof = Address::from(spoof_bytes);

    let ctx = at(block)
        .transfer_tx(
            b256(1),
            real,
            vec![transfer(addr(TOKEN), real, addr(VICTIM), 1_000)],
        )
        .transfer_tx(
            b256(2),
            spoof,
            vec![transfer(addr(TOKEN), spoof, addr(VICTIM), 0)],
        )
        .build();

    Fixture::single(
        "address-poisoning: zero-value bait from an 8-nibble lookalike",
        ctx,
        vec![ExpectedIncident::new(
            block,
            DetectorId::new("address-poisoning"),
            AlertKind::AddressPoisoning,
            "spoofer matches the victim's real same-block counterparty's first/last 4 nibbles",
        )],
    )
}

/// An ordinary block: one plain swap, one plain transfer, nothing structural —
/// the precision check. Any detector that fires here (or on any other fixture's
/// blocks, outside its own ground truth) is a false positive.
pub fn clean_block() -> Fixture {
    const WETH: u8 = 0xAA;
    const USDC: u8 = 0xBB;
    const POOL: u8 = 0xCC;
    const ALICE: u8 = 0x01;
    const BOB: u8 = 0x02;
    let block = 900;

    let ctx = at(block)
        .priced_token(addr(WETH), 18, 2000.0)
        .priced_token(addr(USDC), 6, 1.0)
        .tx(
            b256(1),
            addr(ALICE),
            vec![swap(
                addr(POOL),
                addr(WETH),
                addr(USDC),
                ETH,
                1_900 * USDC_UNIT,
            )],
        )
        .transfer_tx(
            b256(2),
            addr(ALICE),
            vec![transfer(addr(USDC), addr(ALICE), addr(BOB), 50 * USDC_UNIT)],
        )
        .build();

    Fixture::single(
        "clean: one ordinary swap and one plain transfer, no incident",
        ctx,
        Vec::new(),
    )
}

/// Every fixture the backtest replays: one known incident per built-in
/// detector, plus the clean block.
pub fn all() -> Vec<Fixture> {
    vec![
        sandwich(),
        arb(),
        flashloan(),
        liquidation(),
        rugpull(),
        washtrading(),
        poisoning(),
        clean_block(),
    ]
}
