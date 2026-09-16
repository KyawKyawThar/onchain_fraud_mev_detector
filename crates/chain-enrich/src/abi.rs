//! The Solidity ABI reading this crate needs: 4-byte selectors, static head
//! words, and the two shapes a token's `symbol()` comes back in.
//!
//! Strict on purpose. A word that should hold an `address` but has non-zero
//! high bytes is malformed, not an address with extra decoration; the caller
//! treats it as "not the contract we thought", which is the safe reading of
//! arbitrary on-chain return data.
//!
//! `predictive` keeps a crate-private copy of the word readers for calldata;
//! they are the obvious next adopter of this module.

use alloy_primitives::{keccak256, Address, Bytes, U256};

/// The 4-byte selector of a function signature, e.g. `decimals()`.
pub fn selector(signature: &str) -> [u8; 4] {
    let hash = keccak256(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

/// Calldata for a function that takes no arguments.
pub fn call_data(signature: &str) -> Bytes {
    Bytes::copy_from_slice(&selector(signature))
}

/// The 32-byte word at word index `index`.
pub fn word(bytes: &[u8], index: usize) -> Option<[u8; 32]> {
    let start = index.checked_mul(32)?;
    bytes.get(start..start.checked_add(32)?)?.try_into().ok()
}

/// A `uint256` at word `index`.
pub fn u256_word(bytes: &[u8], index: usize) -> Option<U256> {
    word(bytes, index).map(U256::from_be_bytes)
}

/// An `address` at word `index`, refusing a word with non-zero high bytes.
pub fn address_word(bytes: &[u8], index: usize) -> Option<Address> {
    let w = word(bytes, index)?;
    w[..12]
        .iter()
        .all(|b| *b == 0)
        .then(|| Address::from_slice(&w[12..]))
}

/// A `uint8` at word `index` (e.g. `decimals()`), refusing anything wider.
pub fn u8_word(bytes: &[u8], index: usize) -> Option<u8> {
    u8::try_from(u256_word(bytes, index)?).ok()
}

/// The longest symbol kept. Anything longer is not a ticker.
const MAX_SYMBOL_LEN: usize = 32;

/// A token's `symbol()` return, in either shape tokens use: an ABI `string`,
/// or a zero-padded `bytes32` (MKR and other early tokens).
///
/// Best effort, and display-only by contract (`TokenMeta::symbol` is never
/// branched on): anything that is not short, printable UTF-8 is `None`.
pub fn symbol(bytes: &[u8]) -> Option<String> {
    let raw = dynamic_bytes(bytes).or_else(|| {
        (bytes.len() == 32).then(|| {
            let end = bytes.iter().position(|b| *b == 0).unwrap_or(32);
            bytes[..end].to_vec()
        })
    })?;
    let text = String::from_utf8(raw).ok()?;
    let printable = !text.is_empty()
        && text.len() <= MAX_SYMBOL_LEN
        && text.chars().all(|c| c.is_ascii_graphic() || c == ' ');
    printable.then_some(text)
}

/// A single ABI-encoded dynamic `bytes`/`string` return: offset, length, data.
fn dynamic_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    let offset = usize::try_from(u256_word(bytes, 0)?).ok()?;
    if offset != 32 {
        return None;
    }
    let len = usize::try_from(u256_word(bytes, 1)?).ok()?;
    if len > MAX_SYMBOL_LEN {
        return None;
    }
    bytes.get(64..64 + len).map(<[u8]>::to_vec)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(value: u64) -> [u8; 32] {
        U256::from(value).to_be_bytes()
    }

    #[test]
    fn selectors_match_the_well_known_values() {
        assert_eq!(selector("decimals()"), [0x31, 0x3c, 0xe5, 0x67]);
        assert_eq!(selector("symbol()"), [0x95, 0xd8, 0x9b, 0x41]);
        assert_eq!(selector("token0()"), [0x0d, 0xfe, 0x16, 0x81]);
        assert_eq!(selector("token1()"), [0xd2, 0x12, 0x20, 0xa7]);
        assert_eq!(selector("getReserves()"), [0x09, 0x02, 0xf1, 0xac]);
        assert_eq!(selector("latestRoundData()"), [0xfe, 0xaf, 0x96, 0x8c]);
        assert_eq!(selector("description()"), [0x72, 0x84, 0xe4, 0x16]);
    }

    #[test]
    fn an_address_word_with_high_bytes_is_refused() {
        let mut good = [0u8; 32];
        good[31] = 1;
        assert_eq!(address_word(&good, 0), Some(Address::with_last_byte(1)));
        let mut bad = good;
        bad[0] = 1;
        assert_eq!(address_word(&bad, 0), None);
        assert_eq!(address_word(&good[..31], 0), None);
    }

    #[test]
    fn decimals_wider_than_a_byte_are_refused() {
        assert_eq!(u8_word(&w(18), 0), Some(18));
        assert_eq!(u8_word(&w(256), 0), None);
    }

    #[test]
    fn symbols_decode_from_string_and_bytes32() {
        let mut string = Vec::new();
        string.extend_from_slice(&w(32));
        string.extend_from_slice(&w(4));
        let mut data = [0u8; 32];
        data[..4].copy_from_slice(b"USDC");
        string.extend_from_slice(&data);
        assert_eq!(symbol(&string).as_deref(), Some("USDC"));

        let mut bytes32 = [0u8; 32];
        bytes32[..3].copy_from_slice(b"MKR");
        assert_eq!(symbol(&bytes32).as_deref(), Some("MKR"));
    }

    #[test]
    fn hostile_symbols_are_dropped() {
        let mut control = [0u8; 32];
        control[..3].copy_from_slice(b"A\nB");
        assert_eq!(symbol(&control), None);
        assert_eq!(symbol(&[0u8; 32]), None, "empty");
        let mut huge = Vec::new();
        huge.extend_from_slice(&w(32));
        huge.extend_from_slice(&w(1_000_000));
        assert_eq!(symbol(&huge), None);
    }
}
