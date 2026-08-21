//! Shared ABI word-reading primitives: pull a right-aligned 32-byte word out
//! of a byte slice and reinterpret it as an `address`/`uint256`.
//!
//! Both [`crate::decode`] (calldata) and [`crate::lending_decode`] (log data)
//! read the same standard Solidity ABI head encoding — a static `address`/
//! `uint256` parameter is a right-aligned 32-byte word — over different byte
//! sources, so the primitive lives once here rather than as two independent
//! copies. [`word_at_offset`] (a raw byte offset) is the one extra primitive
//! [`crate::decode::address_array_at`] needs on top of [`word_at`]'s word-index
//! convenience, for walking a dynamic `address[]`'s ABI-encoded tail.

use alloy_primitives::{Address, U256};

/// The 32-byte word at byte offset `byte_offset` into `bytes`.
pub(crate) fn word_at_offset(bytes: &[u8], byte_offset: usize) -> Option<[u8; 32]> {
    let end = byte_offset.checked_add(32)?;
    bytes.get(byte_offset..end)?.try_into().ok()
}

/// The 32-byte word at word index `word_index` (0-based) into `bytes`.
pub(crate) fn word_at(bytes: &[u8], word_index: usize) -> Option<[u8; 32]> {
    word_at_offset(bytes, word_index.checked_mul(32)?)
}

/// A right-aligned `address` decoded from a 32-byte ABI word.
pub(crate) fn addr_from_word(word: [u8; 32]) -> Address {
    Address::from_slice(&word[12..32])
}

/// A right-aligned `address` at word index `word_index`.
pub(crate) fn addr_at(bytes: &[u8], word_index: usize) -> Option<Address> {
    word_at(bytes, word_index).map(addr_from_word)
}

/// A `uint256` at word index `word_index`.
pub(crate) fn u256_at(bytes: &[u8], word_index: usize) -> Option<U256> {
    word_at(bytes, word_index).map(U256::from_be_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word32(value: &[u8]) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[32 - value.len()..].copy_from_slice(value);
        w
    }

    #[test]
    fn word_at_reads_by_word_index() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&word32(&[1]));
        bytes.extend_from_slice(&word32(&[2]));
        assert_eq!(word_at(&bytes, 0), Some(word32(&[1])));
        assert_eq!(word_at(&bytes, 1), Some(word32(&[2])));
        assert_eq!(word_at(&bytes, 2), None, "past the end");
    }

    #[test]
    fn word_at_offset_reads_by_raw_byte_offset() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&word32(&[9]));
        assert_eq!(word_at_offset(&bytes, 0), Some(word32(&[9])));
        assert_eq!(word_at_offset(&bytes, 1), None, "too short from offset 1");
    }

    #[test]
    fn addr_at_reads_the_right_aligned_20_bytes() {
        let addr = Address::repeat_byte(0xAB);
        let mut word = [0u8; 32];
        word[12..32].copy_from_slice(addr.as_slice());
        assert_eq!(addr_at(&word, 0), Some(addr));
    }

    #[test]
    fn u256_at_reads_a_big_endian_word() {
        let mut bytes = word32(&[0]).to_vec();
        bytes[31] = 42;
        assert_eq!(u256_at(&bytes, 0), Some(U256::from(42u64)));
    }

    #[test]
    fn out_of_bounds_reads_are_none_not_a_panic() {
        assert_eq!(word_at(&[0u8; 10], 0), None);
        assert_eq!(addr_at(&[], 0), None);
        assert_eq!(u256_at(&[1, 2, 3], 5), None);
    }
}
