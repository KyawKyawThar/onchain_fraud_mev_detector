//! The Redis hot-path cache (§8, §14): labels and risk scores for the reads
//! that cannot afford Postgres — the synchronous screening decision (§11) and
//! the predictive pipeline's cached entity labels (§16).
//!
//! **TTL-backed, evicted on update** (§8): correctness comes from explicit
//! [`HotCache::evict`] whenever the underlying truth changes (a label lands, a
//! score recomputes, an entity merges); the TTL is only the staleness backstop
//! for a missed eviction. The cache is an *optimization, never the record* —
//! on any cache fault the caller falls back to the Postgres store, so a Redis
//! outage degrades latency, not answers.
//!
//! Layout: labels live at `intel:labels:{address}` as one JSON array (read and
//! replaced whole); scores live in a hash `intel:scores:{address}` keyed by
//! `model_version` (§8.3: score cache entries are keyed
//! `(address, model_version)`), so evicting an address is two key deletes — no
//! `SCAN` over the keyspace.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::primitives::{AccountAddress, Confidence};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};

use crate::model::{address_key, LabelRecord};

/// A failure talking to (or decoding from) the cache. Carries the same
/// retry-vs-permanent split as the stores; most callers instead treat any
/// cache fault as a miss and fall back to Postgres.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    /// A Redis round-trip failed. Transient unless Redis says the value has
    /// the wrong shape or didn't parse — those re-read identically.
    #[error("redis round-trip failed")]
    Redis(#[from] redis::RedisError),

    /// A cached value no longer deserializes (written by another build).
    /// Permanent for this entry — the fix is eviction, not retry.
    #[error("cached value is malformed: {what}")]
    Malformed { what: String },
}

impl CacheError {
    /// Whether retrying could plausibly succeed. Mirrors the store contract.
    pub fn is_transient(&self) -> bool {
        match self {
            CacheError::Malformed { .. } => false,
            CacheError::Redis(err) => !matches!(
                err.kind(),
                redis::ErrorKind::UnexpectedReturnType | redis::ErrorKind::Parse
            ),
        }
    }
}

/// The cached form of a risk score (§8.3) — the two independent axes plus the
/// model version that computed them. The full factor breakdown stays in the
/// system of record; the hot path needs only the decision inputs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CachedScore {
    /// 0–100, "how risky".
    pub score: u8,
    /// 0–1, "how sure" — never conflated with `score` (§8.3).
    pub confidence: Confidence,
    pub model_version: String,
    pub computed_at: DateTime<Utc>,
}

/// The hot-path cache seam. Object-safe; production is [`RedisHotCache`],
/// tests use the in-memory double in [`crate::test_util`].
#[async_trait]
pub trait HotCache: Send + Sync {
    /// The cached active-label set for an address, if present.
    async fn labels(
        &self,
        address: &AccountAddress,
    ) -> Result<Option<Vec<LabelRecord>>, CacheError>;

    /// Cache the active-label set for an address (replaces whole).
    ///
    /// Staleness bound: cache-aside has an unavoidable race (read old rows →
    /// truth updates + evicts → stale put lands), so the **TTL, not eviction
    /// alone, is the staleness guarantee** — do not "optimize" the TTL to
    /// hours without accepting that window.
    async fn put_labels(
        &self,
        address: &AccountAddress,
        labels: &[LabelRecord],
    ) -> Result<(), CacheError>;

    /// The cached score for `(address, model_version)` (§8.3), if present.
    async fn score(
        &self,
        address: &AccountAddress,
        model_version: &str,
    ) -> Result<Option<CachedScore>, CacheError>;

    /// Cache a recomputed score under its model version.
    async fn put_score(
        &self,
        address: &AccountAddress,
        score: &CachedScore,
    ) -> Result<(), CacheError>;

    /// Drop everything cached for an address — called on every update to the
    /// underlying truth (label added/revoked, score recomputed, entity
    /// merged). Eviction, not overwrite, so a concurrent reader can never see
    /// a half-updated pair (§8).
    async fn evict(&self, address: &AccountAddress) -> Result<(), CacheError>;

    /// Evict many addresses. The default loops over [`evict`](Self::evict) so
    /// every double stays correct by construction; [`RedisHotCache`] overrides
    /// it with pipelined `UNLINK`s — a feed import (§8.1) touches thousands of
    /// addresses, and one round-trip per address is not a production path.
    async fn evict_many(&self, addresses: &[AccountAddress]) -> Result<(), CacheError> {
        for address in addresses {
            self.evict(address).await?;
        }
        Ok(())
    }
}

/// How many addresses one eviction pipeline batches: large enough that a feed
/// import is a handful of round-trips, small enough that a single command
/// buffer stays modest.
const EVICT_PIPELINE_CHUNK: usize = 1024;

/// The Redis key holding an address's cached label set.
fn labels_key(address: &AccountAddress) -> String {
    format!("intel:labels:{}", address_key(address))
}

/// The Redis hash holding an address's cached scores, one field per
/// `model_version`.
fn scores_key(address: &AccountAddress) -> String {
    format!("intel:scores:{}", address_key(address))
}

/// Redis-backed [`HotCache`]. Cheap to clone — [`ConnectionManager`] is a
/// self-reconnecting handle over one multiplexed connection.
#[derive(Clone)]
pub struct RedisHotCache {
    conn: ConnectionManager,
    ttl: Duration,
}

impl RedisHotCache {
    /// Connect to Redis and prove it is reachable (fail-fast at boot: the
    /// manager performs the initial connect + `PING` here).
    pub async fn connect(url: &str, ttl: Duration) -> Result<Self, CacheError> {
        let client = redis::Client::open(url)?;
        let conn = ConnectionManager::new(client).await?;
        Ok(Self { conn, ttl })
    }

    /// TTL in whole seconds, floored at 1 (Redis rejects 0).
    fn ttl_secs(&self) -> u64 {
        self.ttl.as_secs().max(1)
    }
}

#[async_trait]
impl HotCache for RedisHotCache {
    async fn labels(
        &self,
        address: &AccountAddress,
    ) -> Result<Option<Vec<LabelRecord>>, CacheError> {
        let mut conn = self.conn.clone();
        let raw: Option<String> = conn.get(labels_key(address)).await?;
        raw.map(|json| {
            serde_json::from_str(&json).map_err(|err| CacheError::Malformed {
                what: format!("labels for {}: {err}", address_key(address)),
            })
        })
        .transpose()
    }

    async fn put_labels(
        &self,
        address: &AccountAddress,
        labels: &[LabelRecord],
    ) -> Result<(), CacheError> {
        let json = serde_json::to_string(labels).map_err(|err| CacheError::Malformed {
            what: format!("encoding labels: {err}"),
        })?;
        let mut conn = self.conn.clone();
        let _: () = conn
            .set_ex(labels_key(address), json, self.ttl_secs())
            .await?;
        Ok(())
    }

    async fn score(
        &self,
        address: &AccountAddress,
        model_version: &str,
    ) -> Result<Option<CachedScore>, CacheError> {
        let mut conn = self.conn.clone();
        let raw: Option<String> = conn.hget(scores_key(address), model_version).await?;
        raw.map(|json| {
            serde_json::from_str(&json).map_err(|err| CacheError::Malformed {
                what: format!("score for {}: {err}", address_key(address)),
            })
        })
        .transpose()
    }

    async fn put_score(
        &self,
        address: &AccountAddress,
        score: &CachedScore,
    ) -> Result<(), CacheError> {
        let json = serde_json::to_string(score).map_err(|err| CacheError::Malformed {
            what: format!("encoding score: {err}"),
        })?;
        let key = scores_key(address);
        let mut conn = self.conn.clone();
        let _: () = conn.hset(&key, &score.model_version, json).await?;
        // Key-level TTL: the whole hash is the staleness backstop; per-field
        // freshness is handled by eviction on recompute.
        let _: () = conn.expire(&key, self.ttl_secs() as i64).await?;
        Ok(())
    }

    async fn evict(&self, address: &AccountAddress) -> Result<(), CacheError> {
        let mut conn = self.conn.clone();
        // UNLINK: reclaim off-thread, same semantics as DEL for the reader.
        let _: () = conn
            .unlink(&[labels_key(address), scores_key(address)])
            .await?;
        Ok(())
    }

    async fn evict_many(&self, addresses: &[AccountAddress]) -> Result<(), CacheError> {
        let mut conn = self.conn.clone();
        for chunk in addresses.chunks(EVICT_PIPELINE_CHUNK) {
            let mut pipe = redis::pipe();
            for address in chunk {
                pipe.unlink(&[labels_key(address), scores_key(address)])
                    .ignore();
            }
            let _: () = pipe.query_async(&mut conn).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;

    /// The two keys per address are the whole eviction surface — pin their
    /// shape so evict() and the writers can never disagree.
    #[test]
    fn cache_keys_are_prefixed_and_lowercase() {
        let addr = Address::repeat_byte(0xAB);
        assert_eq!(
            labels_key(&addr),
            "intel:labels:0xabababababababababababababababababababab"
        );
        assert_eq!(
            scores_key(&addr),
            "intel:scores:0xabababababababababababababababababababab"
        );
    }

    #[test]
    fn cache_error_classifies_transient_vs_permanent() {
        assert!(!CacheError::Malformed { what: "x".into() }.is_transient());
        let io = redis::RedisError::from(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "reset",
        ));
        assert!(CacheError::Redis(io).is_transient());
    }

    #[test]
    fn cached_score_round_trips_through_json() {
        let score = CachedScore {
            score: 87,
            confidence: Confidence::new(0.91),
            model_version: "1.4.2".into(),
            computed_at: DateTime::<Utc>::from_timestamp(1_000, 0).unwrap(),
        };
        let json = serde_json::to_string(&score).unwrap();
        let back: CachedScore = serde_json::from_str(&json).unwrap();
        assert_eq!(back, score);
    }
}
