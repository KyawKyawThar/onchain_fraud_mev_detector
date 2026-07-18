//! Decode a pending transaction's calldata into the same decoded-action
//! shapes `detection` models (§6/§16): [`TxActions`]/[`Swap`]/[`TokenTransfer`]
//! from `detector_api::enrichment`, reused verbatim rather than redefined, so
//! a future predict-engine heuristic that wants the richer shape (Sprint 16+)
//! doesn't need a translation layer.
//!
//! Covers two selector families — ERC-20 `transfer`/`transferFrom` and the
//! Uniswap-V2 router's `swapExact*` family — matched on the calldata's first
//! 4 bytes. An unrecognized selector (or calldata too short to hold its
//! declared parameters) decodes to an empty [`TxActions`]: the same "honestly
//! not enriched" stance `Enrichment::default()` takes for a header-only
//! source, rather than guessing.
//!
//! The [`Swap::pool`] field is filled with the *router* address (`tx.to`),
//! not the underlying pair contract — recovering the actual Uniswap-V2 pair
//! address needs a CREATE2 computation over `(factory, token0, token1)` that
//! calldata alone doesn't carry, and that's out of scope for a first decode
//! pass over raw calldata.

use alloy_primitives::{Address, U256};
use detector_api::{Swap, TokenTransfer, TxActions};

use crate::source::PendingTx;

const ERC20_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const ERC20_TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
const UNIV2_SWAP_EXACT_ETH_FOR_TOKENS: [u8; 4] = [0x7f, 0xf3, 0x6a, 0xb5];
const UNIV2_SWAP_EXACT_TOKENS_FOR_ETH: [u8; 4] = [0x18, 0xcb, 0xaf, 0xe5];
const UNIV2_SWAP_EXACT_TOKENS_FOR_TOKENS: [u8; 4] = [0x38, 0xed, 0x17, 0x39];

/// One decoded action, unified across the two selector families so
/// [`decode_tx`] can match on it once and move `base` exactly once on every
/// path, rather than cloning it per arm.
enum Decoded {
    Transfer(TokenTransfer),
    Swap(Swap),
}

/// Decode `tx`'s calldata into its [`TxActions`]. Infallible: an unrecognized
/// or malformed call just yields no swaps/transfers.
pub fn decode_tx(tx: &PendingTx) -> TxActions {
    let base = TxActions::new(tx.hash, tx.from, tx.to);

    let Some(selector) = selector(&tx.input) else {
        return base;
    };
    let params = &tx.input[4..];

    let decoded = match selector {
        ERC20_TRANSFER => decode_erc20_transfer(params, tx).map(Decoded::Transfer),
        ERC20_TRANSFER_FROM => decode_erc20_transfer_from(params, tx).map(Decoded::Transfer),
        UNIV2_SWAP_EXACT_ETH_FOR_TOKENS => {
            decode_swap_exact_eth_for_tokens(params, tx).map(Decoded::Swap)
        }
        UNIV2_SWAP_EXACT_TOKENS_FOR_ETH | UNIV2_SWAP_EXACT_TOKENS_FOR_TOKENS => {
            decode_swap_exact_tokens_for_x(params, tx).map(Decoded::Swap)
        }
        _ => None,
    };

    match decoded {
        Some(Decoded::Transfer(transfer)) => base.with_transfers(vec![transfer]),
        Some(Decoded::Swap(swap)) => base.with_swaps(vec![swap]),
        None => base,
    }
}

fn selector(input: &[u8]) -> Option<[u8; 4]> {
    input.get(0..4)?.try_into().ok()
}

fn decode_erc20_transfer(params: &[u8], tx: &PendingTx) -> Option<TokenTransfer> {
    let to = addr_at(params, 0)?;
    let amount = u256_at(params, 1)?;
    Some(TokenTransfer {
        // The token contract is whatever address the tx itself calls.
        token: tx.to.unwrap_or(Address::ZERO),
        from: tx.from,
        to,
        amount,
    })
}

fn decode_erc20_transfer_from(params: &[u8], tx: &PendingTx) -> Option<TokenTransfer> {
    let from = addr_at(params, 0)?;
    let to = addr_at(params, 1)?;
    let amount = u256_at(params, 2)?;
    Some(TokenTransfer {
        token: tx.to.unwrap_or(Address::ZERO),
        from,
        to,
        amount,
    })
}

fn decode_swap_exact_eth_for_tokens(params: &[u8], tx: &PendingTx) -> Option<Swap> {
    let amount_out_min = u256_at(params, 0)?;
    let path = address_array_at(params, 1)?;
    let (token_in, token_out) = (*path.first()?, *path.last()?);
    Some(Swap {
        pool: tx.to.unwrap_or(Address::ZERO),
        token_in,
        token_out,
        amount_in: tx.value,
        amount_out: amount_out_min,
    })
}

fn decode_swap_exact_tokens_for_x(params: &[u8], tx: &PendingTx) -> Option<Swap> {
    let amount_in = u256_at(params, 0)?;
    let amount_out_min = u256_at(params, 1)?;
    let path = address_array_at(params, 2)?;
    let (token_in, token_out) = (*path.first()?, *path.last()?);
    Some(Swap {
        pool: tx.to.unwrap_or(Address::ZERO),
        token_in,
        token_out,
        amount_in,
        amount_out: amount_out_min,
    })
}

/// The 32-byte word at `byte_offset` into `params` (the calldata *after* the
/// 4-byte selector), or `None` if `params` is too short to hold it.
fn word_at(params: &[u8], byte_offset: usize) -> Option<[u8; 32]> {
    let end = byte_offset.checked_add(32)?;
    params.get(byte_offset..end)?.try_into().ok()
}

/// A right-aligned `address` at head slot `word_index` (a static parameter).
fn addr_at(params: &[u8], word_index: usize) -> Option<Address> {
    let word = word_at(params, word_index * 32)?;
    Some(Address::from_slice(&word[12..32]))
}

/// A `uint256` at head slot `word_index`.
fn u256_at(params: &[u8], word_index: usize) -> Option<U256> {
    word_at(params, word_index * 32).map(U256::from_be_bytes)
}

/// A dynamic `address[]` whose head slot `offset_word_index` holds a byte
/// offset (relative to the start of `params`) to its `[length, elem0, elem1,
/// …]` tail — standard Solidity ABI dynamic-array encoding.
///
/// Bounds the decoded length: a hostile/malformed calldata claiming a huge
/// array must not force an unbounded allocation.
fn address_array_at(params: &[u8], offset_word_index: usize) -> Option<Vec<Address>> {
    const MAX_PATH_LEN: usize = 32;

    let offset: usize = u256_at(params, offset_word_index)?.try_into().ok()?;
    let len: usize = U256::from_be_bytes(word_at(params, offset)?)
        .try_into()
        .ok()?;
    if len == 0 || len > MAX_PATH_LEN {
        return None;
    }

    let mut path = Vec::with_capacity(len);
    for i in 0..len {
        let elem_offset = offset.checked_add(32)?.checked_add(i.checked_mul(32)?)?;
        let word = word_at(params, elem_offset)?;
        path.push(Address::from_slice(&word[12..32]));
    }
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{keccak256, Bytes, B256};

    /// The selector table above is five hand-transcribed 4-byte constants —
    /// exactly the kind of thing that's silently wrong forever, since every
    /// other test in this module encodes its fixture calldata with the same
    /// constants it decodes with (self-consistent, not self-*verifying*).
    /// Pin each one against the actual `keccak256` of its declared signature
    /// so a transcription error fails loudly here instead of only against a
    /// real router in production.
    #[test]
    fn selectors_match_their_declared_signatures() {
        let cases: &[([u8; 4], &str)] = &[
            (ERC20_TRANSFER, "transfer(address,uint256)"),
            (ERC20_TRANSFER_FROM, "transferFrom(address,address,uint256)"),
            (
                UNIV2_SWAP_EXACT_ETH_FOR_TOKENS,
                "swapExactETHForTokens(uint256,address[],address,uint256)",
            ),
            (
                UNIV2_SWAP_EXACT_TOKENS_FOR_ETH,
                "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
            ),
            (
                UNIV2_SWAP_EXACT_TOKENS_FOR_TOKENS,
                "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
            ),
        ];
        for (selector, signature) in cases {
            let hash = keccak256(signature.as_bytes());
            assert_eq!(
                selector.as_slice(),
                &hash[..4],
                "selector for `{signature}` doesn't match its keccak256"
            );
        }
    }

    fn addr(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }

    fn pending_tx(to: Option<Address>, value: U256, input: Vec<u8>) -> PendingTx {
        PendingTx {
            hash: B256::repeat_byte(0x01),
            from: addr(0xF0),
            to,
            input: Bytes::from(input),
            value,
        }
    }

    /// Left-pad `value` into a 32-byte big-endian word (the ABI encoding of a
    /// static `uint256`/`address` parameter).
    fn word32(value: &[u8]) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[32 - value.len()..].copy_from_slice(value);
        w
    }

    fn addr_word(a: Address) -> [u8; 32] {
        word32(a.as_slice())
    }

    fn u256_word(v: u64) -> [u8; 32] {
        U256::from(v).to_be_bytes()
    }

    #[test]
    fn unrecognized_selector_decodes_to_no_actions() {
        let tx = pending_tx(Some(addr(1)), U256::ZERO, vec![0xde, 0xad, 0xbe, 0xef]);
        let actions = decode_tx(&tx);
        assert!(actions.swaps.is_empty());
        assert!(actions.transfers.is_empty());
        assert_eq!(actions.from, tx.from);
    }

    #[test]
    fn too_short_calldata_decodes_to_no_actions() {
        // A real selector but truncated params.
        let mut input = ERC20_TRANSFER.to_vec();
        input.extend_from_slice(&addr_word(addr(2))[..10]);
        let tx = pending_tx(Some(addr(9)), U256::ZERO, input);
        let actions = decode_tx(&tx);
        assert!(actions.transfers.is_empty());
    }

    #[test]
    fn decodes_erc20_transfer() {
        let recipient = addr(0x22);
        let mut input = ERC20_TRANSFER.to_vec();
        input.extend_from_slice(&addr_word(recipient));
        input.extend_from_slice(&u256_word(1_500_000));
        let token = addr(0x77);
        let tx = pending_tx(Some(token), U256::ZERO, input);

        let actions = decode_tx(&tx);
        assert_eq!(actions.transfers.len(), 1);
        let transfer = &actions.transfers[0];
        assert_eq!(transfer.to, recipient);
        assert_eq!(transfer.amount, U256::from(1_500_000u64));
    }

    #[test]
    fn decodes_erc20_transfer_from() {
        let from = addr(0x33);
        let to = addr(0x44);
        let mut input = ERC20_TRANSFER_FROM.to_vec();
        input.extend_from_slice(&addr_word(from));
        input.extend_from_slice(&addr_word(to));
        input.extend_from_slice(&u256_word(42));
        let tx = pending_tx(Some(addr(0x88)), U256::ZERO, input);

        let actions = decode_tx(&tx);
        assert_eq!(actions.transfers.len(), 1);
        assert_eq!(actions.transfers[0].from, from);
        assert_eq!(actions.transfers[0].to, to);
        assert_eq!(actions.transfers[0].amount, U256::from(42u64));
    }

    #[test]
    fn decodes_swap_exact_eth_for_tokens() {
        let weth = addr(0xE0);
        let usdc = addr(0xC0);
        let recipient = addr(0x55);

        let mut input = UNIV2_SWAP_EXACT_ETH_FOR_TOKENS.to_vec();
        input.extend_from_slice(&u256_word(100)); // amountOutMin
        input.extend_from_slice(&u256_word(128)); // offset to path (4 head words * 32)
        input.extend_from_slice(&addr_word(recipient)); // to
        input.extend_from_slice(&u256_word(9_999_999_999)); // deadline
                                                            // Tail: path = [weth, usdc]
        input.extend_from_slice(&u256_word(2)); // length
        input.extend_from_slice(&addr_word(weth));
        input.extend_from_slice(&addr_word(usdc));

        let router = addr(0xAA);
        let tx = pending_tx(Some(router), U256::from(1_000_000_000u64), input);

        let actions = decode_tx(&tx);
        assert_eq!(actions.swaps.len(), 1);
        let swap = &actions.swaps[0];
        assert_eq!(swap.pool, router);
        assert_eq!(swap.token_in, weth);
        assert_eq!(swap.token_out, usdc);
        assert_eq!(swap.amount_in, U256::from(1_000_000_000u64));
        assert_eq!(swap.amount_out, U256::from(100u64));
    }

    #[test]
    fn decodes_swap_exact_tokens_for_tokens() {
        let dai = addr(0xD0);
        let usdt = addr(0xD1);
        let recipient = addr(0x66);

        let mut input = UNIV2_SWAP_EXACT_TOKENS_FOR_TOKENS.to_vec();
        input.extend_from_slice(&u256_word(5_000)); // amountIn
        input.extend_from_slice(&u256_word(4_900)); // amountOutMin
        input.extend_from_slice(&u256_word(160)); // offset to path (5 head words * 32)
        input.extend_from_slice(&addr_word(recipient)); // to
        input.extend_from_slice(&u256_word(9_999_999_999)); // deadline
        input.extend_from_slice(&u256_word(2)); // path length
        input.extend_from_slice(&addr_word(dai));
        input.extend_from_slice(&addr_word(usdt));

        let router = addr(0xBB);
        let tx = pending_tx(Some(router), U256::ZERO, input);

        let actions = decode_tx(&tx);
        assert_eq!(actions.swaps.len(), 1);
        let swap = &actions.swaps[0];
        assert_eq!(swap.token_in, dai);
        assert_eq!(swap.token_out, usdt);
        assert_eq!(swap.amount_in, U256::from(5_000u64));
        assert_eq!(swap.amount_out, U256::from(4_900u64));
    }

    #[test]
    fn oversized_path_length_is_rejected() {
        let mut input = UNIV2_SWAP_EXACT_TOKENS_FOR_TOKENS.to_vec();
        input.extend_from_slice(&u256_word(1));
        input.extend_from_slice(&u256_word(1));
        input.extend_from_slice(&u256_word(160));
        input.extend_from_slice(&addr_word(addr(1)));
        input.extend_from_slice(&u256_word(1));
        // Claim an absurd length with no backing data.
        input.extend_from_slice(&u256_word(1_000_000));

        let tx = pending_tx(Some(addr(0xCC)), U256::ZERO, input);
        let actions = decode_tx(&tx);
        assert!(actions.swaps.is_empty());
    }
}
