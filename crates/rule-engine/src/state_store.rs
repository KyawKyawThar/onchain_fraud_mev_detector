//! Redis persistence for in-flight temporal windows (§9, Sprint 9 t3) — the
//! storage half of the imperative shell around [`crate::temporal`]'s pure
//! core. One key per `(rule_id, address)` machine, JSON value, **TTL-bounded**:
//! the pure `step` closes windows exactly by block arithmetic, so a key whose
//! TTL lapses is by definition a window no future event could extend — expiry
//! *is* the window closing, which is what makes bounded storage sound (no
//! compaction job, no unbounded keyspace).
//!
//! Unlike the intelligence hot cache (`intelligence::cache`, whose shape this
//! mirrors), this store is **correctness-bearing, not an optimization**: there
//! is no system of record behind it to fall back to — losing a key silently
//! forgets a customer's half-matched window. That is why the worker shell
//! ([`crate::worker`]) *retries* transient faults instead of treating them as
//! misses, and why only a `Malformed` value (which re-reads identically
//! forever) is ever discarded.
//!
//! [`TemporalStateStore`] is the seam: production is [`RedisTemporalStore`],
//! tests use `test_util::InMemoryTemporalStore` — the same double discipline
//! as `RuleStore` and `HotCache`.

use std::time::Duration;

use async_trait::async_trait;
use events::primitives::{AccountAddress, RuleId};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use uuid::Uuid;

use crate::temporal::TemporalState;

/// Identity of one temporal machine: which rule's clause, for which subject
/// address (§9: state is keyed by rule + address). The partition key for
/// worker ownership is the `address` half alone (§17 —
/// [`crate::worker::partition_for`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StateKey {
    pub rule_id: RuleId,
    pub address: AccountAddress,
}

/// A failure talking to (or decoding from) the state store. Same
/// transient-vs-permanent contract as every other store in the system
/// (`db::is_permanent`, `CacheError`): its [`event_bus::Transience`] impl
/// is what the worker branches on to decide retry vs discard.
#[derive(Debug, thiserror::Error)]
pub enum StateStoreError {
    /// A Redis round-trip failed. Transient unless Redis says the value has
    /// the wrong shape or didn't parse — those re-read identically.
    #[error("redis round-trip failed")]
    Redis(#[from] redis::RedisError),

    /// A stored value no longer deserializes (written by another build, or
    /// corrupted). Permanent for this key — the machine restarts from idle
    /// (the same stance `temporal::step` takes on wrong-variant state).
    #[error("stored temporal state is malformed: {what}")]
    Malformed { what: String },
}

impl event_bus::Transience for StateStoreError {
    /// Whether retrying could plausibly succeed.
    fn is_transient(&self) -> bool {
        match self {
            StateStoreError::Malformed { .. } => false,
            StateStoreError::Redis(err) => db::redis::is_transient(err),
        }
    }
}

/// How a clause's block window translates to a key TTL. The §9 contract is
/// "TTL expiry ≡ window close", which needs `TTL ≥ the window's wall-clock
/// span`; since [`crate::temporal::step`] already expires windows *exactly*
/// (by block arithmetic), an oversized TTL only delays garbage collection —
/// it can never change an answer. So the policy doubles the estimate rather
/// than chasing per-chain precision:
///
/// `ttl = max(block_time × within_blocks × 2, floor)`
///
/// The ×2 slack absorbs slow blocks and clock skew; the floor keeps tiny
/// windows from expiring between two closely spaced events that Redis, the
/// consumer, and the chain see at slightly different times.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtlPolicy {
    /// Expected wall-clock time per block of the consumed chain(s). The
    /// default is Ethereum mainnet's 12s; a deployment consuming faster
    /// chains can keep it — overestimating only delays GC (see above).
    pub block_time: Duration,
    /// Minimum TTL regardless of window size.
    pub floor: Duration,
}

impl Default for TtlPolicy {
    fn default() -> Self {
        Self {
            block_time: Duration::from_secs(12),
            floor: Duration::from_secs(60),
        }
    }
}

impl TtlPolicy {
    /// The TTL for a clause spanning `within_blocks` blocks.
    pub fn ttl_for(&self, within_blocks: u64) -> Duration {
        let blocks = u32::try_from(within_blocks.saturating_mul(2)).unwrap_or(u32::MAX);
        self.block_time.saturating_mul(blocks).max(self.floor)
    }
}

/// Where in-flight temporal windows live. Object-safe; production is
/// [`RedisTemporalStore`], tests use the in-memory double in
/// [`crate::test_util`].
///
/// Concurrency contract: the store itself does no locking — soundness of the
/// read-modify-write (`load` → `temporal::step` → `save`) comes from the §17
/// partitioning invariant that **one worker owns all keys for an address**
/// ([`crate::worker`]). Callers outside that ownership discipline may only
/// read.
#[async_trait]
pub trait TemporalStateStore: Send + Sync {
    /// The persisted machine for `key`, if one is in flight. `None` is the
    /// idle machine (never stored — TTL expiry and explicit [`clear`]
    /// (Self::clear) both land here).
    async fn load(&self, key: &StateKey) -> Result<Option<TemporalState>, StateStoreError>;

    /// Persist an in-flight machine, replacing whole, bounded by `ttl` (from
    /// [`TtlPolicy::ttl_for`] of the clause's window).
    async fn save(
        &self,
        key: &StateKey,
        state: &TemporalState,
        ttl: Duration,
    ) -> Result<(), StateStoreError>;

    /// Drop a machine (it fired, rewound to nothing, or its rule vanished).
    /// Idempotent — clearing an absent key is fine.
    async fn clear(&self, key: &StateKey) -> Result<(), StateStoreError>;

    /// Every key with an in-flight machine — the §15 rewind's work list.
    /// Keys only, not values: the pool scans **once**, routes each key to
    /// its owning worker, and the owner re-reads it — so the rewind
    /// read-modify-write stays inside the single-writer discipline.
    ///
    /// Rewinds are reorg-rate rare and the keyspace is TTL-bounded, so a
    /// full enumeration (Redis `SCAN`) is deliberate — no per-block index to
    /// keep consistent on the hot path.
    async fn in_flight_keys(&self) -> Result<Vec<StateKey>, StateStoreError>;
}

/// Prefix for every temporal-state key, and what [`in_flight_keys`]
/// (TemporalStateStore::in_flight_keys) scans for.
const KEY_PREFIX: &str = "rules:temporal:";

/// The Redis key for one machine: `rules:temporal:{rule_uuid}:{0xaddress}`
/// (lowercase hex address, same rendering as the intelligence cache keys).
fn redis_key(key: &StateKey) -> String {
    format!("{KEY_PREFIX}{}:{:#x}", key.rule_id, key.address)
}

/// The inverse of [`redis_key`] — parse a scanned key back into its identity.
/// `None` means the key is not ours (foreign junk under our prefix): the
/// scanner skips it rather than failing the whole rewind.
fn parse_redis_key(raw: &str) -> Option<StateKey> {
    let rest = raw.strip_prefix(KEY_PREFIX)?;
    let (rule, address) = rest.split_once(':')?;
    Some(StateKey {
        rule_id: RuleId(Uuid::parse_str(rule).ok()?),
        address: address.parse().ok()?,
    })
}

/// Redis-backed [`TemporalStateStore`]. Cheap to clone —
/// [`ConnectionManager`] is a self-reconnecting handle over one multiplexed
/// connection (a Redis blip is a retried command, not a dead worker).
#[derive(Clone)]
pub struct RedisTemporalStore {
    conn: ConnectionManager,
}

impl RedisTemporalStore {
    /// Connect and prove Redis is reachable (fail-fast at boot: the manager
    /// performs the initial connect + `PING` here) — via the shared
    /// [`db::redis::connect`] every Redis-backed store in the workspace uses.
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        let conn = db::redis::connect(url).await?;
        Ok(Self { conn })
    }
}

#[async_trait]
impl TemporalStateStore for RedisTemporalStore {
    async fn load(&self, key: &StateKey) -> Result<Option<TemporalState>, StateStoreError> {
        let mut conn = self.conn.clone();
        let raw: Option<String> = conn.get(redis_key(key)).await?;
        raw.map(|json| {
            serde_json::from_str(&json).map_err(|err| StateStoreError::Malformed {
                what: format!("state for {}: {err}", redis_key(key)),
            })
        })
        .transpose()
    }

    async fn save(
        &self,
        key: &StateKey,
        state: &TemporalState,
        ttl: Duration,
    ) -> Result<(), StateStoreError> {
        let json = serde_json::to_string(state).map_err(|err| StateStoreError::Malformed {
            what: format!("encoding state: {err}"),
        })?;
        let mut conn = self.conn.clone();
        // SETEX: value and bound land atomically — a key can never exist
        // without its TTL (the boundedness guarantee, §9).
        let _: () = conn
            .set_ex(redis_key(key), json, ttl.as_secs().max(1))
            .await?;
        Ok(())
    }

    async fn clear(&self, key: &StateKey) -> Result<(), StateStoreError> {
        let mut conn = self.conn.clone();
        // UNLINK: reclaim off-thread, same semantics as DEL for readers.
        let _: () = conn.unlink(redis_key(key)).await?;
        Ok(())
    }

    async fn in_flight_keys(&self) -> Result<Vec<StateKey>, StateStoreError> {
        let mut conn = self.conn.clone();
        let mut raw_keys = Vec::new();
        {
            // SCAN, never KEYS: cursor-based, doesn't stall the server. The
            // iterator borrows the connection, so collect first.
            let mut iter = conn
                .scan_match::<_, String>(format!("{KEY_PREFIX}*"))
                .await?;
            while let Some(item) = iter.next_item().await {
                raw_keys.push(item?);
            }
        }
        Ok(raw_keys
            .iter()
            .filter_map(|raw| {
                let parsed = parse_redis_key(raw);
                if parsed.is_none() {
                    // Not ours (or written by an incompatible build): skip it
                    // — its TTL will collect it — rather than fail the rewind.
                    tracing::warn!(key = %raw, "skipping unparseable temporal-state key");
                }
                parsed
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use event_bus::Transience;

    fn key(rule_byte: u128, addr_byte: u8) -> StateKey {
        StateKey {
            rule_id: RuleId(Uuid::from_u128(rule_byte)),
            address: Address::repeat_byte(addr_byte),
        }
    }

    /// The key is the whole contract between save/load/clear and the rewind
    /// scan — pin its shape and its round-trip.
    #[test]
    fn redis_key_is_prefixed_and_round_trips() {
        let key = key(7, 0xAB);
        let raw = redis_key(&key);
        assert_eq!(
            raw,
            "rules:temporal:00000000-0000-0000-0000-000000000007:\
             0xabababababababababababababababababababab"
        );
        assert_eq!(parse_redis_key(&raw), Some(key));
    }

    #[test]
    fn foreign_keys_do_not_parse() {
        // Wrong prefix, missing address, junk uuid, junk address.
        for raw in [
            "intel:labels:0xabab",
            "rules:temporal:not-a-uuid:0xabababababababababababababababababababab",
            "rules:temporal:00000000-0000-0000-0000-000000000007",
            "rules:temporal:00000000-0000-0000-0000-000000000007:zz",
        ] {
            assert_eq!(parse_redis_key(raw), None, "{raw} must not parse");
        }
    }

    #[test]
    fn ttl_policy_doubles_the_window_and_floors_small_ones() {
        let policy = TtlPolicy::default();
        // §9 example: 100 blocks × 12s × 2 = 2400s.
        assert_eq!(policy.ttl_for(100), Duration::from_secs(2400));
        // A 2-block window would be 48s — floored to 60s.
        assert_eq!(policy.ttl_for(2), Duration::from_secs(60));
        // Absurd windows saturate instead of overflowing.
        assert!(policy.ttl_for(u64::MAX) >= policy.ttl_for(1_000_000));
    }

    #[test]
    fn error_classifies_transient_vs_permanent() {
        assert!(!StateStoreError::Malformed { what: "x".into() }.is_transient());
        let io = redis::RedisError::from(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "reset",
        ));
        assert!(StateStoreError::Redis(io).is_transient());
    }
}
