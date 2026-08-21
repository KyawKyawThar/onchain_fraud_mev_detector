//! Decode a raw event log into a [`LendingEvent`] (§16.1): the log-decode half
//! of the position tracker, sibling to [`crate::decode`]'s calldata decode.
//! Covers the position-changing events of Aave V3's `Pool` contract and
//! Compound v2's `CToken` markets — the two protocol shapes named in the task
//! (§16.1: "Aave/Compound-shape").
//!
//! Hand-rolled ABI word reads over `topics`/`data`, mirroring [`crate::decode`]'s
//! calldata-word discipline — but topic0 (the event signature hash) is computed
//! from the declared signature string via `keccak256` at match time rather than
//! hand-transcribed as a 32-byte literal: a 4-byte selector is small enough to
//! safely hand-copy and pin with a self-verifying test ([`crate::decode`] does
//! exactly that), but a 32-byte hash invites a silent transcription error with
//! nothing forcing it to be re-checked. Computing it from the signature is the
//! same *fact*, just represented in a form that can't drift from it.
//!
//! Both protocols normalize into one [`LendingEvent`] so [`crate::position`]'s
//! fold logic never branches on protocol beyond the `protocol` field already
//! attached to each variant.

use std::collections::HashMap;
use std::sync::LazyLock;

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};

use crate::abi_words::{addr_at, addr_from_word, u256_at};
use crate::position::{PositionKey, Protocol};

/// A decoded protocol-level lending event — supply/withdraw/borrow/repay/
/// liquidate, unified across Aave and Compound. Amounts are raw base units of
/// their asset (no decimal/USD adjustment — see `position` module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LendingEvent {
    Supply {
        protocol: Protocol,
        account: Address,
        asset: Address,
        amount: U256,
    },
    Withdraw {
        protocol: Protocol,
        account: Address,
        asset: Address,
        amount: U256,
    },
    Borrow {
        protocol: Protocol,
        account: Address,
        asset: Address,
        amount: U256,
    },
    Repay {
        protocol: Protocol,
        account: Address,
        asset: Address,
        amount: U256,
    },
    Liquidation {
        protocol: Protocol,
        account: Address,
        debt_asset: Address,
        debt_repaid: U256,
        collateral_asset: Address,
        collateral_seized: U256,
    },
}

impl LendingEvent {
    /// The `(protocol, account)` this event's position update keys on.
    pub fn position_key(&self) -> PositionKey {
        let (protocol, account) = match *self {
            LendingEvent::Supply {
                protocol, account, ..
            }
            | LendingEvent::Withdraw {
                protocol, account, ..
            }
            | LendingEvent::Borrow {
                protocol, account, ..
            }
            | LendingEvent::Repay {
                protocol, account, ..
            }
            | LendingEvent::Liquidation {
                protocol, account, ..
            } => (protocol, account),
        };
        PositionKey { protocol, account }
    }
}

/// A raw event log, reduced to the fields decoding needs — the log analogue of
/// [`crate::source::PendingTx`]'s "cheap facts" discipline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLog {
    /// The emitting contract — for Compound, this *is* the asset/market
    /// (the cToken address); for Aave it's the shared `Pool` contract, and the
    /// reserve asset instead comes from an indexed topic.
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
}

/// keccak256 of an event's declared Solidity signature — its `topics[0]`.
fn topic0(signature: &str) -> B256 {
    keccak256(signature.as_bytes())
}

// ── Aave V3 `Pool` events ───────────────────────────────────────────────────
// Signatures pinned against the real `IPool`/`Pool.sol` ABI. Indexed params
// (up to 3, plus topic0) sit in `topics`; the rest are ABI-encoded words in
// `data`, in declaration order.

const AAVE_SUPPLY_SIG: &str = "Supply(address,address,address,uint256,uint16)";
const AAVE_WITHDRAW_SIG: &str = "Withdraw(address,address,address,uint256)";
const AAVE_BORROW_SIG: &str = "Borrow(address,address,address,uint256,uint8,uint256,uint16)";
const AAVE_REPAY_SIG: &str = "Repay(address,address,address,uint256,bool)";
const AAVE_LIQUIDATION_CALL_SIG: &str =
    "LiquidationCall(address,address,address,uint256,uint256,address,bool)";

// ── Compound v2 `CToken` events ─────────────────────────────────────────────
// None of Compound v2's core market events index any parameter; every field is
// an ABI-encoded word in `data`, in declaration order. The market itself
// (`RawLog::address`) is the asset.

const COMPOUND_MINT_SIG: &str = "Mint(address,uint256,uint256)";
const COMPOUND_REDEEM_SIG: &str = "Redeem(address,uint256,uint256)";
const COMPOUND_BORROW_SIG: &str = "Borrow(address,uint256,uint256,uint256)";
const COMPOUND_REPAY_BORROW_SIG: &str = "RepayBorrow(address,address,uint256,uint256,uint256)";
const COMPOUND_LIQUIDATE_BORROW_SIG: &str =
    "LiquidateBorrow(address,address,uint256,address,uint256)";

/// One event's decoder, keyed by its `topics[0]`.
type Decoder = fn(&RawLog) -> Option<LendingEvent>;

/// `topic0 → decoder`, built once on first use rather than recomputing up to
/// ten `keccak256` hashes on *every* `decode_log` call — a block's lending
/// logs are filtered to a handful of contracts (`position_source.rs`), but
/// still include every other event those contracts emit (Aave's
/// `ReserveDataUpdated`, ERC-20 `Transfer`/`Approval`, …), so an unrecognized
/// log is the common case this table turns into an O(1) miss instead of a
/// worst-case ten-hash scan.
static DISPATCH: LazyLock<HashMap<B256, Decoder>> = LazyLock::new(|| {
    HashMap::from([
        (topic0(AAVE_SUPPLY_SIG), decode_aave_supply as Decoder),
        (topic0(AAVE_WITHDRAW_SIG), decode_aave_withdraw as Decoder),
        (topic0(AAVE_BORROW_SIG), decode_aave_borrow as Decoder),
        (topic0(AAVE_REPAY_SIG), decode_aave_repay as Decoder),
        (
            topic0(AAVE_LIQUIDATION_CALL_SIG),
            decode_aave_liquidation_call as Decoder,
        ),
        (topic0(COMPOUND_MINT_SIG), decode_compound_mint as Decoder),
        (
            topic0(COMPOUND_REDEEM_SIG),
            decode_compound_redeem as Decoder,
        ),
        (
            topic0(COMPOUND_BORROW_SIG),
            decode_compound_borrow as Decoder,
        ),
        (
            topic0(COMPOUND_REPAY_BORROW_SIG),
            decode_compound_repay_borrow as Decoder,
        ),
        (
            topic0(COMPOUND_LIQUIDATE_BORROW_SIG),
            decode_compound_liquidate_borrow as Decoder,
        ),
    ])
});

/// Decode one [`RawLog`] into a [`LendingEvent`], or `None` for a log this
/// tracker doesn't recognize (any other contract event, or one too short to
/// hold its declared params — a malformed/truncated log is treated the same as
/// unrecognized rather than guessing).
pub fn decode_log(log: &RawLog) -> Option<LendingEvent> {
    let topic0_hash = log.topics.first()?;
    DISPATCH.get(topic0_hash)?(log)
}

// ── Aave decoders ────────────────────────────────────────────────────────────
// `Supply(address indexed reserve, address user, address indexed onBehalfOf,
//          uint256 amount, uint16 indexed referralCode)`
// The position is tracked against `onBehalfOf` (who actually ends up holding
// the collateral), not `user` (who called `supply`) — the same distinction
// Aave's own health-factor accounting makes.
fn decode_aave_supply(log: &RawLog) -> Option<LendingEvent> {
    let reserve = topic_addr(log, 1)?;
    let on_behalf_of = topic_addr(log, 2)?;
    let amount = u256_at(&log.data, 1)?; // data: [user, amount]
    Some(LendingEvent::Supply {
        protocol: Protocol::Aave,
        account: on_behalf_of,
        asset: reserve,
        amount,
    })
}

/// `Withdraw(address indexed reserve, address indexed user, address indexed to,
///            uint256 amount)`
fn decode_aave_withdraw(log: &RawLog) -> Option<LendingEvent> {
    let reserve = topic_addr(log, 1)?;
    let user = topic_addr(log, 2)?;
    let amount = u256_at(&log.data, 0)?; // data: [amount]
    Some(LendingEvent::Withdraw {
        protocol: Protocol::Aave,
        account: user,
        asset: reserve,
        amount,
    })
}

/// `Borrow(address indexed reserve, address user, address indexed onBehalfOf,
///          uint256 amount, uint8 interestRateMode, uint256 borrowRate,
///          uint16 indexed referralCode)`
fn decode_aave_borrow(log: &RawLog) -> Option<LendingEvent> {
    let reserve = topic_addr(log, 1)?;
    let on_behalf_of = topic_addr(log, 2)?;
    let amount = u256_at(&log.data, 1)?; // data: [user, amount, rateMode, borrowRate]
    Some(LendingEvent::Borrow {
        protocol: Protocol::Aave,
        account: on_behalf_of,
        asset: reserve,
        amount,
    })
}

/// `Repay(address indexed reserve, address indexed user, address indexed
///         repayer, uint256 amount, bool useATokens)`
fn decode_aave_repay(log: &RawLog) -> Option<LendingEvent> {
    let reserve = topic_addr(log, 1)?;
    let user = topic_addr(log, 2)?;
    let amount = u256_at(&log.data, 0)?; // data: [amount, useATokens]
    Some(LendingEvent::Repay {
        protocol: Protocol::Aave,
        account: user,
        asset: reserve,
        amount,
    })
}

/// `LiquidationCall(address indexed collateralAsset, address indexed debtAsset,
///                    address indexed user, uint256 debtToCover,
///                    uint256 liquidatedCollateralAmount, address liquidator,
///                    bool receiveAToken)`
fn decode_aave_liquidation_call(log: &RawLog) -> Option<LendingEvent> {
    let collateral_asset = topic_addr(log, 1)?;
    let debt_asset = topic_addr(log, 2)?;
    let user = topic_addr(log, 3)?;
    // data: [debtToCover, liquidatedCollateralAmount, liquidator, receiveAToken]
    let debt_to_cover = u256_at(&log.data, 0)?;
    let liquidated_collateral_amount = u256_at(&log.data, 1)?;
    Some(LendingEvent::Liquidation {
        protocol: Protocol::Aave,
        account: user,
        debt_asset,
        debt_repaid: debt_to_cover,
        collateral_asset,
        collateral_seized: liquidated_collateral_amount,
    })
}

// ── Compound decoders ───────────────────────────────────────────────────────
// Every param is in `data` (none indexed); the market is `log.address`.

/// `Mint(address minter, uint256 mintAmount, uint256 mintTokens)`
fn decode_compound_mint(log: &RawLog) -> Option<LendingEvent> {
    let minter = addr_at(&log.data, 0)?;
    let mint_amount = u256_at(&log.data, 1)?;
    Some(LendingEvent::Supply {
        protocol: Protocol::Compound,
        account: minter,
        asset: log.address,
        amount: mint_amount,
    })
}

/// `Redeem(address redeemer, uint256 redeemAmount, uint256 redeemTokens)`
fn decode_compound_redeem(log: &RawLog) -> Option<LendingEvent> {
    let redeemer = addr_at(&log.data, 0)?;
    let redeem_amount = u256_at(&log.data, 1)?;
    Some(LendingEvent::Withdraw {
        protocol: Protocol::Compound,
        account: redeemer,
        asset: log.address,
        amount: redeem_amount,
    })
}

/// `Borrow(address borrower, uint256 borrowAmount, uint256 accountBorrows,
///          uint256 totalBorrows)`
fn decode_compound_borrow(log: &RawLog) -> Option<LendingEvent> {
    let borrower = addr_at(&log.data, 0)?;
    let borrow_amount = u256_at(&log.data, 1)?;
    Some(LendingEvent::Borrow {
        protocol: Protocol::Compound,
        account: borrower,
        asset: log.address,
        amount: borrow_amount,
    })
}

/// `RepayBorrow(address payer, address borrower, uint256 repayAmount,
///               uint256 accountBorrows, uint256 totalBorrows)`
fn decode_compound_repay_borrow(log: &RawLog) -> Option<LendingEvent> {
    let borrower = addr_at(&log.data, 1)?;
    let repay_amount = u256_at(&log.data, 2)?;
    Some(LendingEvent::Repay {
        protocol: Protocol::Compound,
        account: borrower,
        asset: log.address,
        amount: repay_amount,
    })
}

/// `LiquidateBorrow(address liquidator, address borrower, uint256 repayAmount,
///                    address cTokenCollateral, uint256 seizeTokens)`
///
/// `seizeTokens` is denominated in the *collateral* cToken, not its
/// underlying — see `position` module docs' liquidation note.
fn decode_compound_liquidate_borrow(log: &RawLog) -> Option<LendingEvent> {
    let borrower = addr_at(&log.data, 1)?;
    let repay_amount = u256_at(&log.data, 2)?;
    let c_token_collateral = addr_at(&log.data, 3)?;
    let seize_tokens = u256_at(&log.data, 4)?;
    Some(LendingEvent::Liquidation {
        protocol: Protocol::Compound,
        account: borrower,
        debt_asset: log.address,
        debt_repaid: repay_amount,
        collateral_asset: c_token_collateral,
        collateral_seized: seize_tokens,
    })
}

// ── Topic helpers ────────────────────────────────────────────────────────────
// `data`-word reads (`addr_at`/`u256_at`) are the shared `crate::abi_words`
// primitives (imported above) — the same reads `crate::decode` does over
// calldata, just over a log's `data` bytes here.

/// The address at indexed topic slot `topic_index` (1-based within `topics`,
/// since `topics[0]` is always the event signature).
fn topic_addr(log: &RawLog, topic_index: usize) -> Option<Address> {
    let topic = log.topics.get(topic_index)?;
    Some(addr_from_word(topic.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `topic0` this module dispatches on must be distinct — a collision
    /// would silently misroute one event's log as another's, and a colliding
    /// insert into `DISPATCH` would silently keep only one of the two entries.
    /// (The signature strings themselves were checked by hand against the
    /// canonical `aave/aave-v3-core` `IPool.sol` and
    /// `compound-finance/compound-protocol` `CToken.sol` event declarations —
    /// the risk this module's doc comment flags is a transcription error in a
    /// hand-copied *hash*, which computing `topic0` from the signature at
    /// match time avoids entirely; this test covers the one remaining failure
    /// mode, two signatures hashing the same.) Checked against the real
    /// production dispatch table, not a parallel hand-rolled list, so it can't
    /// silently drift from what `decode_log` actually dispatches on.
    #[test]
    fn every_topic0_is_distinct() {
        const SIGNATURE_COUNT: usize = 10;
        assert_eq!(
            DISPATCH.len(),
            SIGNATURE_COUNT,
            "a topic0 collision would have collapsed two entries into one"
        );
    }

    fn addr(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }

    fn topic_of(a: Address) -> B256 {
        let mut word = [0u8; 32];
        word[12..32].copy_from_slice(a.as_slice());
        B256::from(word)
    }

    fn u256_word(v: u64) -> [u8; 32] {
        U256::from(v).to_be_bytes()
    }

    fn addr_word(a: Address) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..32].copy_from_slice(a.as_slice());
        w
    }

    #[test]
    fn decodes_aave_supply_against_on_behalf_of_not_the_caller() {
        let reserve = addr(0x01);
        let caller = addr(0x02);
        let on_behalf_of = addr(0x03);
        let mut data = Vec::new();
        data.extend_from_slice(&addr_word(caller)); // user (data, not indexed)
        data.extend_from_slice(&u256_word(1_500)); // amount

        let log = RawLog {
            address: addr(0xAA), // the shared Aave Pool contract
            topics: vec![
                topic0(AAVE_SUPPLY_SIG),
                topic_of(reserve),
                topic_of(on_behalf_of),
                topic_of(addr(0x00)), // referralCode topic (irrelevant here)
            ],
            data: Bytes::from(data),
        };

        let event = decode_log(&log).expect("recognized Aave Supply");
        assert_eq!(
            event,
            LendingEvent::Supply {
                protocol: Protocol::Aave,
                account: on_behalf_of,
                asset: reserve,
                amount: U256::from(1_500u64),
            }
        );
    }

    #[test]
    fn decodes_aave_withdraw() {
        let reserve = addr(0x11);
        let user = addr(0x22);
        let mut data = Vec::new();
        data.extend_from_slice(&u256_word(750));

        let log = RawLog {
            address: addr(0xAA),
            topics: vec![
                topic0(AAVE_WITHDRAW_SIG),
                topic_of(reserve),
                topic_of(user),
                topic_of(addr(0x99)), // `to`
            ],
            data: Bytes::from(data),
        };

        assert_eq!(
            decode_log(&log).unwrap(),
            LendingEvent::Withdraw {
                protocol: Protocol::Aave,
                account: user,
                asset: reserve,
                amount: U256::from(750u64),
            }
        );
    }

    #[test]
    fn decodes_aave_borrow() {
        let reserve = addr(0x11);
        let caller = addr(0x22);
        let on_behalf_of = addr(0x33);
        let mut data = Vec::new();
        data.extend_from_slice(&addr_word(caller));
        data.extend_from_slice(&u256_word(400));
        data.extend_from_slice(&u256_word(2)); // interestRateMode
        data.extend_from_slice(&u256_word(50)); // borrowRate

        let log = RawLog {
            address: addr(0xAA),
            topics: vec![
                topic0(AAVE_BORROW_SIG),
                topic_of(reserve),
                topic_of(on_behalf_of),
                topic_of(addr(0x00)),
            ],
            data: Bytes::from(data),
        };

        assert_eq!(
            decode_log(&log).unwrap(),
            LendingEvent::Borrow {
                protocol: Protocol::Aave,
                account: on_behalf_of,
                asset: reserve,
                amount: U256::from(400u64),
            }
        );
    }

    #[test]
    fn decodes_aave_repay() {
        let reserve = addr(0x11);
        let user = addr(0x22);
        let mut data = Vec::new();
        data.extend_from_slice(&u256_word(200));
        data.extend_from_slice(&u256_word(0)); // useATokens = false

        let log = RawLog {
            address: addr(0xAA),
            topics: vec![
                topic0(AAVE_REPAY_SIG),
                topic_of(reserve),
                topic_of(user),
                topic_of(addr(0x44)), // repayer
            ],
            data: Bytes::from(data),
        };

        assert_eq!(
            decode_log(&log).unwrap(),
            LendingEvent::Repay {
                protocol: Protocol::Aave,
                account: user,
                asset: reserve,
                amount: U256::from(200u64),
            }
        );
    }

    #[test]
    fn decodes_aave_liquidation_call() {
        let collateral_asset = addr(0x11);
        let debt_asset = addr(0x22);
        let user = addr(0x33);
        let mut data = Vec::new();
        data.extend_from_slice(&u256_word(600)); // debtToCover
        data.extend_from_slice(&u256_word(660)); // liquidatedCollateralAmount
        data.extend_from_slice(&addr_word(addr(0x55))); // liquidator
        data.extend_from_slice(&u256_word(1)); // receiveAToken

        let log = RawLog {
            address: addr(0xAA),
            topics: vec![
                topic0(AAVE_LIQUIDATION_CALL_SIG),
                topic_of(collateral_asset),
                topic_of(debt_asset),
                topic_of(user),
            ],
            data: Bytes::from(data),
        };

        assert_eq!(
            decode_log(&log).unwrap(),
            LendingEvent::Liquidation {
                protocol: Protocol::Aave,
                account: user,
                debt_asset,
                debt_repaid: U256::from(600u64),
                collateral_asset,
                collateral_seized: U256::from(660u64),
            }
        );
    }

    #[test]
    fn decodes_compound_mint_keying_the_asset_off_the_market_address() {
        let minter = addr(0x11);
        let market = addr(0xC1);
        let mut data = Vec::new();
        data.extend_from_slice(&addr_word(minter));
        data.extend_from_slice(&u256_word(900)); // mintAmount
        data.extend_from_slice(&u256_word(890)); // mintTokens

        let log = RawLog {
            address: market,
            topics: vec![topic0(COMPOUND_MINT_SIG)],
            data: Bytes::from(data),
        };

        assert_eq!(
            decode_log(&log).unwrap(),
            LendingEvent::Supply {
                protocol: Protocol::Compound,
                account: minter,
                asset: market,
                amount: U256::from(900u64),
            }
        );
    }

    #[test]
    fn decodes_compound_redeem() {
        let redeemer = addr(0x11);
        let market = addr(0xC2);
        let mut data = Vec::new();
        data.extend_from_slice(&addr_word(redeemer));
        data.extend_from_slice(&u256_word(300));
        data.extend_from_slice(&u256_word(295));

        let log = RawLog {
            address: market,
            topics: vec![topic0(COMPOUND_REDEEM_SIG)],
            data: Bytes::from(data),
        };

        assert_eq!(
            decode_log(&log).unwrap(),
            LendingEvent::Withdraw {
                protocol: Protocol::Compound,
                account: redeemer,
                asset: market,
                amount: U256::from(300u64),
            }
        );
    }

    #[test]
    fn decodes_compound_borrow() {
        let borrower = addr(0x11);
        let market = addr(0xC3);
        let mut data = Vec::new();
        data.extend_from_slice(&addr_word(borrower));
        data.extend_from_slice(&u256_word(150)); // borrowAmount
        data.extend_from_slice(&u256_word(150)); // accountBorrows
        data.extend_from_slice(&u256_word(9_000)); // totalBorrows

        let log = RawLog {
            address: market,
            topics: vec![topic0(COMPOUND_BORROW_SIG)],
            data: Bytes::from(data),
        };

        assert_eq!(
            decode_log(&log).unwrap(),
            LendingEvent::Borrow {
                protocol: Protocol::Compound,
                account: borrower,
                asset: market,
                amount: U256::from(150u64),
            }
        );
    }

    #[test]
    fn decodes_compound_repay_borrow() {
        let payer = addr(0x11);
        let borrower = addr(0x22);
        let market = addr(0xC4);
        let mut data = Vec::new();
        data.extend_from_slice(&addr_word(payer));
        data.extend_from_slice(&addr_word(borrower));
        data.extend_from_slice(&u256_word(120)); // repayAmount
        data.extend_from_slice(&u256_word(30)); // accountBorrows
        data.extend_from_slice(&u256_word(8_880)); // totalBorrows

        let log = RawLog {
            address: market,
            topics: vec![topic0(COMPOUND_REPAY_BORROW_SIG)],
            data: Bytes::from(data),
        };

        assert_eq!(
            decode_log(&log).unwrap(),
            LendingEvent::Repay {
                protocol: Protocol::Compound,
                account: borrower,
                asset: market,
                amount: U256::from(120u64),
            }
        );
    }

    #[test]
    fn decodes_compound_liquidate_borrow() {
        let liquidator = addr(0x11);
        let borrower = addr(0x22);
        let market = addr(0xC5);
        let c_token_collateral = addr(0xC6);
        let mut data = Vec::new();
        data.extend_from_slice(&addr_word(liquidator));
        data.extend_from_slice(&addr_word(borrower));
        data.extend_from_slice(&u256_word(80)); // repayAmount
        data.extend_from_slice(&addr_word(c_token_collateral));
        data.extend_from_slice(&u256_word(88)); // seizeTokens

        let log = RawLog {
            address: market,
            topics: vec![topic0(COMPOUND_LIQUIDATE_BORROW_SIG)],
            data: Bytes::from(data),
        };

        assert_eq!(
            decode_log(&log).unwrap(),
            LendingEvent::Liquidation {
                protocol: Protocol::Compound,
                account: borrower,
                debt_asset: market,
                debt_repaid: U256::from(80u64),
                collateral_asset: c_token_collateral,
                collateral_seized: U256::from(88u64),
            }
        );
    }

    #[test]
    fn an_unrecognized_topic0_decodes_to_none() {
        let log = RawLog {
            address: addr(0xAA),
            topics: vec![B256::repeat_byte(0xEE)],
            data: Bytes::new(),
        };
        assert!(decode_log(&log).is_none());
    }

    #[test]
    fn a_log_with_no_topics_decodes_to_none() {
        let log = RawLog {
            address: addr(0xAA),
            topics: vec![],
            data: Bytes::new(),
        };
        assert!(decode_log(&log).is_none());
    }

    #[test]
    fn truncated_data_decodes_to_none_rather_than_panicking() {
        let log = RawLog {
            address: addr(0xAA),
            topics: vec![
                topic0(AAVE_WITHDRAW_SIG),
                topic_of(addr(0x11)),
                topic_of(addr(0x22)),
                topic_of(addr(0x33)),
            ],
            data: Bytes::from(vec![0x01, 0x02]), // far short of one word
        };
        assert!(decode_log(&log).is_none());
    }
}
