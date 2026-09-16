//! Where a keyed record lands on a topic — one pure function shared by the
//! producer's partitioner (`event_bus`) and the capacity plan (`capacity`), so
//! the partition a record is sent to and the partition the plan prices are the
//! same computation, not two that agree today.
//!
//! Two kinds of key reach a topic ([`crate::PartitionKey`]):
//!
//! * **A chain key** is the bare decimal chain id. It goes to the chain's
//!   registered slot ([`Chain::partition_slot`]), so chains never collide by
//!   accident of a hash.
//! * **Every other key** (alert, incident, customer, finding) is a UUID. Those
//!   are high-cardinality and spread by CRC-32, the same function librdkafka's
//!   default `consistent_random` partitioner uses — so moving producers onto
//!   this function changes where no business-keyed record lands.
//!
//! The two are distinguishable from the bytes alone because a UUID's rendering
//! always contains `-`, and a chain key is only ASCII digits.

use crate::primitives::Chain;

/// CRC-32 (IEEE 802.3, reflected polynomial `0xEDB88320`) — librdkafka's
/// `rd_crc32` and zlib's `crc32`.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// The slot of a chain key, if `key` is one and the chain is registered.
pub fn chain_slot_for_key(key: &[u8]) -> Option<u32> {
    if key.is_empty() || !key.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let id: u64 = std::str::from_utf8(key).ok()?.parse().ok()?;
    Chain(id).partition_slot()
}

/// The partition for `key` on a topic of `partition_count` partitions.
///
/// A registered chain goes to its slot; anything else — a business key, or a
/// chain this build has no slot for — spreads by CRC-32. A count of zero is
/// treated as one, so the result is always a valid partition index.
pub fn partition_for_key(key: &[u8], partition_count: u32) -> u32 {
    let count = partition_count.max(1);
    match chain_slot_for_key(key) {
        Some(slot) => slot % count,
        None => crc32(key) % count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PartitionKey;
    use uuid::Uuid;

    fn key(k: &PartitionKey) -> Vec<u8> {
        k.to_string().into_bytes()
    }

    #[test]
    fn crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    /// The bug the registry replaced: under CRC-32, Ethereum and Base share
    /// partition 2 of 3.
    #[test]
    fn the_hash_collided_where_the_slots_do_not() {
        assert_eq!(crc32(b"1") % 3, crc32(b"8453") % 3);
        let eth = key(&PartitionKey::Chain(Chain::ETHEREUM));
        let base = key(&PartitionKey::Chain(Chain::BASE));
        for count in [2, 3, 6, 12, 48] {
            assert_ne!(
                partition_for_key(&eth, count),
                partition_for_key(&base, count),
                "known chains must not share a partition at {count}"
            );
        }
    }

    /// Growing the count keeps every chain whose slot is already below it on
    /// the same partition — the property that makes a partition increase safe
    /// for per-chain ordering.
    #[test]
    fn growing_the_partition_count_does_not_move_a_chain() {
        for chain in Chain::KNOWN {
            let k = key(&PartitionKey::Chain(*chain));
            assert_eq!(partition_for_key(&k, 3), partition_for_key(&k, 12));
        }
    }

    #[test]
    fn every_known_chain_has_a_unique_slot() {
        let mut slots: Vec<u32> = Chain::KNOWN
            .iter()
            .map(|c| {
                c.partition_slot()
                    .unwrap_or_else(|| panic!("{c} is known but has no partition slot"))
            })
            .collect();
        slots.sort_unstable();
        let before = slots.len();
        slots.dedup();
        assert_eq!(slots.len(), before, "two known chains share a slot");
    }

    /// Business keys keep librdkafka's placement, so adopting this function
    /// moves no alert, incident or customer stream.
    #[test]
    fn a_business_key_lands_where_librdkafka_put_it() {
        let customer = Uuid::from_u128(0xC0FFEE).to_string();
        assert_eq!(chain_slot_for_key(customer.as_bytes()), None);
        assert_eq!(
            partition_for_key(customer.as_bytes(), 12),
            crc32(customer.as_bytes()) % 12
        );
    }

    #[test]
    fn an_unregistered_chain_falls_back_to_the_hash() {
        assert_eq!(partition_for_key(b"10", 7), crc32(b"10") % 7);
        assert_eq!(
            partition_for_key(b"1", 0),
            0,
            "a zero count is one partition"
        );
    }
}
