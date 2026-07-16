//! [`BoundedFifoMap`] — a `HashMap` bounded to a fixed number of distinct
//! keys, FIFO-evicting the oldest on overflow.
//!
//! The bounded-memory discipline every buffering consumer in this crate
//! shares (mirrors `simulation::projection`'s `OrphanBuffer`): an attacker (or
//! a stalled upstream partition) flooding a correlation buffer with entries
//! that never resolve must not grow memory without bound. Extracted from
//! [`crate::attribution`] when the block-production consumer (§10) needed the
//! identical structure for its own cross-topic buffers.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

/// A `HashMap` bounded to `capacity` distinct keys, FIFO-evicting the oldest
/// on overflow. `what` names the buffer in the eviction warning so multiple
/// bounded buffers in one consumer stay distinguishable.
pub(crate) struct BoundedFifoMap<K, V> {
    capacity: usize,
    what: &'static str,
    entries: HashMap<K, V>,
    order: VecDeque<K>,
}

impl<K: Eq + Hash + Copy + std::fmt::Display, V> BoundedFifoMap<K, V> {
    pub(crate) fn new(capacity: usize, what: &'static str) -> Self {
        Self {
            capacity,
            what,
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Insert/overwrite `key`. Evicts the oldest distinct key first if this is
    /// a *new* key and the map is at capacity.
    pub(crate) fn put(&mut self, key: K, value: V) {
        if !self.entries.contains_key(&key) {
            self.evict_to_fit();
            self.order.push_back(key);
        }
        self.entries.insert(key, value);
    }

    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key)
    }

    /// Mutable access to an existing entry — appending to a `Vec` value in
    /// place without the take-then-put dance (which would duplicate the key in
    /// the eviction order).
    pub(crate) fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.entries.get_mut(key)
    }

    /// Remove and return the value for `key`, if buffered.
    pub(crate) fn take(&mut self, key: &K) -> Option<V> {
        self.entries.remove(key)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    fn evict_to_fit(&mut self) {
        if self.capacity == 0 {
            return;
        }
        while self.entries.len() >= self.capacity {
            match self.order.pop_front() {
                Some(oldest) => {
                    if self.entries.remove(&oldest).is_some() {
                        tracing::warn!(
                            key = %oldest,
                            capacity = self.capacity,
                            what = self.what,
                            "bounded buffer is full; evicting the oldest entry — \
                             check for a stalled upstream partition"
                        );
                        break;
                    }
                    // Already drained by `take`: freed a slot for free, keep popping.
                }
                None => break,
            }
        }
    }
}

impl<K: Eq + Hash + Copy + std::fmt::Display, T> BoundedFifoMap<K, Vec<T>> {
    /// Retain only the elements matching `keep` inside every buffered `Vec`
    /// value — how a consumer scrubs a since-retracted item out of its pending
    /// buffers without knowing which key it was buffered under.
    pub(crate) fn retain_values(&mut self, mut keep: impl FnMut(&T) -> bool) {
        for value in self.entries.values_mut() {
            value.retain(&mut keep);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The map evicts the oldest distinct key once full, and taking an entry
    /// frees its slot.
    #[test]
    fn bounded_map_evicts_oldest_and_take_frees_a_slot() {
        let mut map: BoundedFifoMap<u32, u8> = BoundedFifoMap::new(2, "test");

        map.put(1, 10);
        map.put(2, 20);
        map.put(1, 11); // overwrite: no eviction, still 2 keys
        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&1), Some(&11));

        map.put(3, 30); // full: evicts key 1 (oldest)
        assert_eq!(map.len(), 2, "still bounded");
        assert!(map.get(&1).is_none());
        assert_eq!(map.get(&2), Some(&20));

        assert_eq!(map.take(&2), Some(20));
        assert_eq!(map.len(), 1);
        map.put(4, 40); // slot freed by take: no eviction of 3
        assert_eq!(map.get(&3), Some(&30));
        assert_eq!(map.get(&4), Some(&40));
    }

    /// `get_mut` mutates in place without disturbing the eviction order.
    #[test]
    fn get_mut_edits_in_place() {
        let mut map: BoundedFifoMap<u32, Vec<u8>> = BoundedFifoMap::new(2, "test");
        map.put(1, vec![1]);
        map.get_mut(&1).expect("present").push(2);
        assert_eq!(map.get(&1), Some(&vec![1, 2]));

        // Still evicts key 1 first — the in-place edit didn't refresh its age.
        map.put(2, vec![]);
        map.put(3, vec![]);
        assert!(map.get(&1).is_none());
    }
}
