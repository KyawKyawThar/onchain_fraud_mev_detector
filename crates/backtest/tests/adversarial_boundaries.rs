//! The adversarial near misses sit **on** the boundaries they claim to probe
//! (Epic E).
//!
//! A near miss that stays silent proves little if it would stay silent for
//! some unrelated reason, such as a missing price or a pool the detector
//! cannot see. That kind of fixture keeps passing after the boundary it names
//! has been deleted. So each threshold near miss here is replayed through its
//! own detector twice:
//!
//! - once at the shipped config, where it must stay silent (the backtest
//!   proves this for the whole roster too);
//! - once with *only that one threshold* loosened, where it must fire.
//!
//! The structural near misses (no victim, a losing cycle, a short repayment,
//! …) have no knob to loosen. They are pinned by the detector's definition
//! and documented in `fixtures::adversarial`.

use backtest::fixtures::adversarial;
use backtest::{Fixture, Provenance};
use detector_api::{Bps, CrossBlockDetector, DetectorPlugin, Evidence, UsdPrice};

fn zero_usd() -> UsdPrice {
    UsdPrice::try_new(0.0).unwrap()
}

/// Findings of a `Block`-scoped detector over a fixture's blocks.
fn block_findings(detector: &dyn DetectorPlugin, fixture: &Fixture) -> Vec<Evidence> {
    fixture
        .blocks
        .iter()
        .flat_map(|ctx| detector.detect(ctx))
        .collect()
}

/// Findings of a cross-block detector folded over a fixture's blocks in order.
fn window_findings<D: CrossBlockDetector>(detector: &D, fixture: &Fixture) -> Vec<Evidence> {
    let mut state = detector.init_state();
    let mut findings = Vec::new();
    for ctx in &fixture.blocks {
        detector.observe(ctx, &mut state);
        findings.extend(detector.detect(ctx, &state));
    }
    findings
}

/// Silent as shipped, firing once loosened.
fn assert_on_the_edge(name: &str, shipped: Vec<Evidence>, loosened: Vec<Evidence>) {
    assert!(
        shipped.is_empty(),
        "{name}: fires at the shipped config: {shipped:?}"
    );
    assert!(
        !loosened.is_empty(),
        "{name}: stays silent even with its threshold loosened, so it is not probing that \
         threshold"
    );
}

#[test]
fn sandwich_dust_sits_on_the_profit_floor() {
    use sandwich_detector::{SandwichConfig, SandwichDetector};
    let fixture = adversarial::sandwich_below_the_profit_floor();
    assert_on_the_edge(
        "sandwich dust",
        block_findings(&SandwichDetector::new(SandwichConfig::default()), &fixture),
        block_findings(
            &SandwichDetector::new(SandwichConfig {
                min_profit_usd: zero_usd(),
            }),
            &fixture,
        ),
    );
}

#[test]
fn arb_dust_sits_on_the_profit_floor() {
    use arb_detector::{ArbConfig, ArbDetector};
    let fixture = adversarial::arb_dust_cycle();
    assert_on_the_edge(
        "arb dust",
        block_findings(&ArbDetector::new(ArbConfig::default()), &fixture),
        block_findings(
            &ArbDetector::new(ArbConfig {
                min_profit_usd: zero_usd(),
            }),
            &fixture,
        ),
    );
}

#[test]
fn small_flashloan_sits_on_the_notional_floor() {
    use flashloan_detector::{FlashloanConfig, FlashloanDetector};
    let fixture = adversarial::flashloan_below_the_notional_floor();
    assert_on_the_edge(
        "small flash loan",
        block_findings(
            &FlashloanDetector::new(FlashloanConfig::default()),
            &fixture,
        ),
        block_findings(
            &FlashloanDetector::new(FlashloanConfig {
                min_loan_usd: zero_usd(),
            }),
            &fixture,
        ),
    );
}

#[test]
fn thin_liquidation_sits_on_the_bonus_floor() {
    use liquidation_detector::{LiquidationConfig, LiquidationDetector};
    let fixture = adversarial::liquidation_below_the_bonus_floor();
    assert_on_the_edge(
        "1% liquidation",
        block_findings(
            &LiquidationDetector::new(LiquidationConfig::default()),
            &fixture,
        ),
        block_findings(
            &LiquidationDetector::new(LiquidationConfig {
                min_bonus_bps: Bps::new(50),
                ..LiquidationConfig::default()
            }),
            &fixture,
        ),
    );
}

#[test]
fn dust_liquidation_sits_on_the_debt_floor() {
    use liquidation_detector::{LiquidationConfig, LiquidationDetector};
    let fixture = adversarial::liquidation_dust_debt();
    assert_on_the_edge(
        "$50 liquidation",
        block_findings(
            &LiquidationDetector::new(LiquidationConfig::default()),
            &fixture,
        ),
        block_findings(
            &LiquidationDetector::new(LiquidationConfig {
                min_debt_usd: zero_usd(),
                ..LiquidationConfig::default()
            }),
            &fixture,
        ),
    );
}

#[test]
fn partial_withdrawal_sits_on_the_drain_floor() {
    use rugpull_detector::{RugpullConfig, RugpullDetector};
    let fixture = adversarial::rugpull_partial_withdrawal();
    assert_on_the_edge(
        "30% withdrawal",
        block_findings(&RugpullDetector::new(RugpullConfig::default()), &fixture),
        block_findings(
            &RugpullDetector::new(RugpullConfig {
                min_drain_bps: Bps::new(2_000),
                ..RugpullConfig::default()
            }),
            &fixture,
        ),
    );
}

#[test]
fn dust_pool_drain_sits_on_the_pool_size_gate() {
    use rugpull_detector::{RugpullConfig, RugpullDetector};
    let fixture = adversarial::rugpull_dust_pool();
    assert_on_the_edge(
        "dust pool",
        block_findings(&RugpullDetector::new(RugpullConfig::default()), &fixture),
        block_findings(
            &RugpullDetector::new(RugpullConfig {
                min_pool_usd: zero_usd(),
                ..RugpullConfig::default()
            }),
            &fixture,
        ),
    );
}

#[test]
fn three_swap_round_trip_sits_on_the_swap_floor() {
    use washtrading_detector::{WashTradingConfig, WashTradingDetector};
    let fixture = adversarial::wash_three_swaps();
    assert_on_the_edge(
        "three swaps",
        window_findings(
            &WashTradingDetector::new(WashTradingConfig::default()),
            &fixture,
        ),
        window_findings(
            &WashTradingDetector::new(WashTradingConfig {
                min_swaps: 3,
                ..WashTradingConfig::default()
            }),
            &fixture,
        ),
    );
}

#[test]
fn net_long_round_trip_sits_on_the_net_ceiling() {
    use washtrading_detector::{WashTradingConfig, WashTradingDetector};
    let fixture = adversarial::wash_round_trips_with_a_net_position();
    assert_on_the_edge(
        "67% net",
        window_findings(
            &WashTradingDetector::new(WashTradingConfig::default()),
            &fixture,
        ),
        window_findings(
            &WashTradingDetector::new(WashTradingConfig {
                max_net_bps: Bps::new(7_000),
                ..WashTradingConfig::default()
            }),
            &fixture,
        ),
    );
}

#[test]
fn weak_lookalike_sits_on_the_nibble_floor() {
    use poisoning_detector::{PoisoningConfig, PoisoningDetector};
    let fixture = adversarial::poisoning_weak_lookalike();
    assert_on_the_edge(
        "2+2 nibbles",
        block_findings(
            &PoisoningDetector::new(PoisoningConfig::default()),
            &fixture,
        ),
        block_findings(
            &PoisoningDetector::new(PoisoningConfig {
                min_prefix_nibbles: 2,
                min_suffix_nibbles: 2,
            }),
            &fixture,
        ),
    );
}

#[test]
fn every_adversarial_fixture_is_a_near_miss_expecting_nothing() {
    for fixture in adversarial::all() {
        assert_eq!(
            fixture.provenance(),
            Provenance::Adversarial,
            "{}",
            fixture.name
        );
        assert!(fixture.expected().is_empty(), "{}", fixture.name);
    }
}
