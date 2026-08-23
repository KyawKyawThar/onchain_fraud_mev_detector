//! [`BoundedFifoMap`] — a `HashMap` bounded to a fixed number of distinct
//! keys, FIFO-evicting the oldest on overflow.
//!
//! The bounded-memory discipline every correlation/orphan buffer on the
//! backbone shares: an attacker (or a stalled upstream partition) flooding a
//! buffer with entries that never resolve must not grow memory without
//! bound. Originally grown inside `intelligence::attribution` (Sprint 7 t4),
//! then copy-pasted byte-for-byte (with the same doc comment admitting it)
//! into `intelligence::production_consumer` (§10), `rule_engine::consumer`
//! (Sprint 9 t4) and `notification::consumer` (Sprint 12), plus two more
//! independently-written buffers in `simulation` (Sprint 6 t5, Sprint 17
//! t4) — five near-identical copies across five crates before this got
//! pulled out. If you're about to write a sixth, depend on this instead.
//!
//! This crate deliberately stays a primitive: `put`/`get`/`get_mut`/`take`
//! plus the `Vec`-value `retain_values` convenience. "Buffer this value under
//! this key, appending if one already exists, and tell me whether it was
//! new" is a policy each call site's own value type decides differently
//! (compare-then-skip-duplicates for a `Vec<Terminal>`, plain overwrite for a
//! `(String, DateTime<Utc>)`) — composed by the caller on top of these
//! primitives, not baked in here.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

/// A `HashMap` bounded to `capacity` distinct keys, FIFO-evicting the oldest
/// on overflow. `what` names the buffer in the eviction warning so multiple
/// bounded buffers in one consumer stay distinguishable in logs.
#[derive(Debug)]
pub struct BoundedFifoMap<K, V> {
    capacity: usize,
    what: &'static str,
    entries: HashMap<K, V>,
    order: VecDeque<K>,
}

impl<K: Eq + Hash + Copy + std::fmt::Display, V> BoundedFifoMap<K, V> {
    /// `capacity` is the max distinct keys held at once; `0` means unbounded
    /// (a deliberate opt-out, not the default — every production call site
    /// should pass a real cap). `what` names this buffer in eviction warnings.
    pub fn new(capacity: usize, what: &'static str) -> Self {
        Self {
            capacity,
            what,
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Insert/overwrite `key`. Evicts the oldest distinct key first if this is
    /// a *new* key and the map is at capacity.
    pub fn put(&mut self, key: K, value: V) {
        if !self.entries.contains_key(&key) {
            self.evict_to_fit();
            self.order.push_back(key);
        }
        self.entries.insert(key, value);
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key)
    }

    /// Mutable access to an existing entry — appending to a `Vec` value in
    /// place without the take-then-put dance (which would duplicate the key in
    /// the eviction order).
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.entries.get_mut(key)
    }

    /// Remove and return the value for `key`, if buffered.
    pub fn take(&mut self, key: &K) -> Option<V> {
        self.entries.remove(key)
    }

    /// Distinct keys currently buffered — the gauge a consuming shell exports
    /// for alarming on a non-draining buffer (§19).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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
    pub fn retain_values(&mut self, mut keep: impl FnMut(&T) -> bool) {
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

    #[test]
    fn zero_capacity_is_unbounded() {
        let mut map: BoundedFifoMap<u32, u8> = BoundedFifoMap::new(0, "test");
        for key in 0..1000u32 {
            map.put(key, 1);
        }
        assert_eq!(map.len(), 1000);
    }

    #[test]
    fn retain_values_scrubs_matching_elements_across_every_key() {
        let mut map: BoundedFifoMap<u32, Vec<u8>> = BoundedFifoMap::new(0, "test");
        map.put(1, vec![1, 2, 3]);
        map.put(2, vec![2, 4]);

        map.retain_values(|value| *value != 2);

        assert_eq!(map.get(&1), Some(&vec![1, 3]));
        assert_eq!(map.get(&2), Some(&vec![4]));
    }
}
