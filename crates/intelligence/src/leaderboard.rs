//! The builder/relay leaderboard read (§10, Sprint 11 t2) — the aggregation
//! behind the public `GET /v1/builders`.
//!
//! It reads exactly the surface [`crate::production_store`] writes: the
//! append-only `block_production` snapshots. As that module's docs promise, the
//! current state of a block is its latest snapshot per `(chain, block_hash)` by
//! `snapshot_at` (argMax), excluding reverted blocks (§15) — so this module's
//! [`LATEST_BLOCKS_SQL`] collapses the firehose to one row per canonical block
//! first, then aggregates.
//!
//! Two views come out of that read:
//!
//! - **Top builders** ([`BuilderStats`]) — one row per `fee_recipient`, ranked
//!   by confirmed sandwich volume (the headline number the task names), with
//!   the arb/other counts, block count and summed USD alongside.
//! - **Relay market share by MEV type** ([`RelayStats`]) — one row per
//!   configured relay, its raw counts plus its *share* (0–1) of every relay-
//!   delivered block's sandwich/arb/other volume. Shares are **derived at read**
//!   ([`derive_relay_shares`]), never stored — the same "rates come from the
//!   ratio, not a second column" stance as the per-detector metrics design.
//!
//! The ClickHouse query is the only I/O; the share math is a pure function with
//! its own unit tests, so the interesting logic is testable without a database.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use clickhouse::Client;
use events::primitives::Chain;
use serde::{Deserialize, Serialize};

/// A clamped builder-row cap — a validated newtype in the spirit of
/// [`events::primitives::Confidence`], so the invariant "a leaderboard is a
/// bounded top-N" lives in the type, not in a `remember-to-call-it` helper.
///
/// Unlike `Confidence`, [`Limit::new`] *clamps* rather than *rejects*: an
/// out-of-range confidence is a caller bug worth a hard error, but an over-eager
/// `limit` is a reasonable request we simply serve at the cap. A `0` (the
/// proto's "unset") becomes [`Limit::DEFAULT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit(u32);

impl Limit {
    /// Builder-row cap when the caller doesn't name one.
    pub const DEFAULT: u32 = 20;
    /// Hard ceiling — a leaderboard is a top-N, not a table dump.
    pub const MAX: u32 = 200;

    /// Clamp a requested cap into `[1, MAX]`; `0` (unset) becomes [`Self::DEFAULT`].
    pub fn new(requested: u32) -> Self {
        Self(match requested {
            0 => Self::DEFAULT,
            n => n.min(Self::MAX),
        })
    }

    /// The clamped value, for the SQL `LIMIT` bind.
    pub fn get(self) -> u32 {
        self.0
    }
}

impl Default for Limit {
    fn default() -> Self {
        Self(Self::DEFAULT)
    }
}

/// What the caller asks for: which chain, how many builder rows, and an
/// optional recency floor. Constructed at the gRPC boundary — a store that
/// receives one can trust every field is already valid (`limit` clamped,
/// `chain` a real id).
#[derive(Debug, Clone)]
pub struct LeaderboardQuery {
    pub chain: Chain,
    /// Clamped builder-row cap (relays are unbounded — the configured set is
    /// small by construction).
    pub limit: Limit,
    /// Only blocks whose latest snapshot is at/after this instant count. `None`
    /// aggregates over all history.
    pub since: Option<DateTime<Utc>>,
}

/// One builder's confirmed production over the queried window, keyed by its
/// payout address (`fee_recipient`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BuilderStats {
    /// The builder's payout address, lowercase 0x-hex (the stored key).
    pub fee_recipient: String,
    /// The builder's display name as intelligence knows it (the strongest
    /// non-empty `BuilderAddress` label seen); empty when unlabeled.
    pub builder_label: String,
    pub blocks_produced: u64,
    pub sandwich_count: u64,
    pub arb_count: u64,
    pub other_mev_count: u64,
    pub mev_extracted_usd: f64,
}

/// One relay's confirmed delivery share, with its market share per MEV type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayStats {
    /// The configured relay name (from `MEV_RELAY_ENDPOINTS`, never hardcoded).
    pub relay: String,
    pub blocks_delivered: u64,
    pub sandwich_count: u64,
    pub arb_count: u64,
    pub other_mev_count: u64,
    pub mev_extracted_usd: f64,
    /// This relay's fraction (0–1) of all relay-delivered sandwiches in the
    /// window. `0.0` when no relay delivered a sandwich.
    pub sandwich_share: f64,
    pub arb_share: f64,
    pub other_mev_share: f64,
}

/// The full leaderboard: builders ranked by sandwich volume, relays with
/// derived market share.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Leaderboard {
    pub builders: Vec<BuilderStats>,
    pub relays: Vec<RelayStats>,
}

/// A failure reading the leaderboard. ClickHouse faults are I/O — transient (a
/// read has no side effect, so a retry is always safe).
#[derive(Debug, thiserror::Error)]
pub enum LeaderboardError {
    #[error("clickhouse round-trip failed")]
    Clickhouse(#[from] clickhouse::error::Error),
}

impl event_bus::Transience for LeaderboardError {
    fn is_transient(&self) -> bool {
        matches!(self, LeaderboardError::Clickhouse(_))
    }
}

/// The read seam. Object-safe; production is [`ClickhouseLeaderboard`], tests
/// use the double in [`crate::test_util`].
#[async_trait]
pub trait LeaderboardStore: Send + Sync {
    async fn leaderboard(&self, query: &LeaderboardQuery) -> Result<Leaderboard, LeaderboardError>;
}

/// Collapse the append-only firehose to the current state of each canonical
/// block: the latest snapshot per `(chain, block_hash)` by `snapshot_at`,
/// dropping blocks reverted by a reorg (§15). The two aggregations below select
/// from this subquery.
///
/// Two bound placeholders, in order: `chain`, then a `since` unix-millis floor
/// (`0` to include all history — the latest snapshot's ms is always ≥ 0).
const LATEST_BLOCKS_SQL: &str = "\
    SELECT \
        argMax(fee_recipient, snapshot_at)     AS fee_recipient, \
        max(builder_label)                     AS builder_label, \
        argMax(relay, snapshot_at)             AS relay, \
        argMax(mev_extracted_usd, snapshot_at) AS mev_extracted_usd, \
        argMax(sandwich_count, snapshot_at)    AS sandwich_count, \
        argMax(arb_count, snapshot_at)         AS arb_count, \
        argMax(other_mev_count, snapshot_at)   AS other_mev_count, \
        argMax(reverted, snapshot_at)          AS reverted, \
        max(toUnixTimestamp64Milli(snapshot_at)) AS last_ms \
    FROM block_production \
    WHERE chain = ? \
    GROUP BY chain, block_hash \
    HAVING reverted = 0 AND last_ms >= ?";
// NOTE: `builder_label` is `max(...)` (not argMax) deliberately — a builder's
// label may be '' on the block where its record first opened and only be minted
// on a later fold; the lexicographic max keeps a non-empty name over the ''.

/// ClickHouse-backed [`LeaderboardStore`]. Cheap to clone (the client is
/// `Arc`-cheap).
#[derive(Clone)]
pub struct ClickhouseLeaderboard {
    client: Client,
}

impl ClickhouseLeaderboard {
    /// Wrap a ClickHouse client (see
    /// [`crate::adjacency::build_clickhouse_client`]).
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

/// A builder aggregate row as ClickHouse returns it — `count()`/`sum(UInt32)`
/// widen to `UInt64`, `sum(Float64)` stays `Float64`.
#[derive(Debug, clickhouse::Row, Deserialize)]
struct BuilderAggRow {
    fee_recipient: String,
    builder_label: String,
    blocks_produced: u64,
    sandwich_count: u64,
    arb_count: u64,
    other_mev_count: u64,
    mev_extracted_usd: f64,
}

impl From<BuilderAggRow> for BuilderStats {
    fn from(row: BuilderAggRow) -> Self {
        Self {
            fee_recipient: row.fee_recipient,
            builder_label: row.builder_label,
            blocks_produced: row.blocks_produced,
            sandwich_count: row.sandwich_count,
            arb_count: row.arb_count,
            other_mev_count: row.other_mev_count,
            mev_extracted_usd: row.mev_extracted_usd,
        }
    }
}

/// A relay aggregate row — the raw counts, before shares are derived.
#[derive(Debug, Clone, PartialEq, clickhouse::Row, Deserialize)]
pub struct RelayAggRow {
    pub relay: String,
    pub blocks_delivered: u64,
    pub sandwich_count: u64,
    pub arb_count: u64,
    pub other_mev_count: u64,
    pub mev_extracted_usd: f64,
}

#[async_trait]
impl LeaderboardStore for ClickhouseLeaderboard {
    async fn leaderboard(&self, query: &LeaderboardQuery) -> Result<Leaderboard, LeaderboardError> {
        let since_ms = query
            .since
            .map(|at| at.timestamp_millis())
            .unwrap_or(0)
            .max(0);
        let chain = query.chain.id();

        let builders: Vec<BuilderAggRow> = self
            .client
            .query(&format!(
                "SELECT \
                    fee_recipient, \
                    max(builder_label)     AS builder_label, \
                    count()                AS blocks_produced, \
                    sum(sandwich_count)    AS sandwich_count, \
                    sum(arb_count)         AS arb_count, \
                    sum(other_mev_count)   AS other_mev_count, \
                    sum(mev_extracted_usd) AS mev_extracted_usd \
                 FROM ({LATEST_BLOCKS_SQL}) \
                 GROUP BY fee_recipient \
                 ORDER BY sandwich_count DESC, mev_extracted_usd DESC, fee_recipient ASC \
                 LIMIT ?"
            ))
            .bind(chain)
            .bind(since_ms)
            .bind(u64::from(query.limit.get()))
            .fetch_all()
            .await?;

        let relays: Vec<RelayAggRow> = self
            .client
            .query(&format!(
                "SELECT \
                    relay, \
                    count()                AS blocks_delivered, \
                    sum(sandwich_count)    AS sandwich_count, \
                    sum(arb_count)         AS arb_count, \
                    sum(other_mev_count)   AS other_mev_count, \
                    sum(mev_extracted_usd) AS mev_extracted_usd \
                 FROM ({LATEST_BLOCKS_SQL}) \
                 WHERE relay != '' \
                 GROUP BY relay \
                 ORDER BY blocks_delivered DESC, relay ASC"
            ))
            .bind(chain)
            .bind(since_ms)
            .fetch_all()
            .await?;

        Ok(Leaderboard {
            builders: builders.into_iter().map(BuilderStats::from).collect(),
            relays: derive_relay_shares(relays),
        })
    }
}

/// Turn raw relay aggregates into [`RelayStats`] with each relay's market share
/// per MEV type: its count of a type over the total of that type across every
/// relay in the set. A zero total yields a `0.0` share (no relay captured any
/// of that type), never a NaN.
pub fn derive_relay_shares(rows: Vec<RelayAggRow>) -> Vec<RelayStats> {
    let total_sandwich: u64 = rows.iter().map(|r| r.sandwich_count).sum();
    let total_arb: u64 = rows.iter().map(|r| r.arb_count).sum();
    let total_other: u64 = rows.iter().map(|r| r.other_mev_count).sum();

    rows.into_iter()
        .map(|row| RelayStats {
            sandwich_share: share(row.sandwich_count, total_sandwich),
            arb_share: share(row.arb_count, total_arb),
            other_mev_share: share(row.other_mev_count, total_other),
            relay: row.relay,
            blocks_delivered: row.blocks_delivered,
            sandwich_count: row.sandwich_count,
            arb_count: row.arb_count,
            other_mev_count: row.other_mev_count,
            mev_extracted_usd: row.mev_extracted_usd,
        })
        .collect()
}

/// `part / whole` as an `f64` share, guarding the zero-total case.
fn share(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 / whole as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agg(relay: &str, sandwich: u64, arb: u64, other: u64) -> RelayAggRow {
        RelayAggRow {
            relay: relay.to_owned(),
            blocks_delivered: sandwich + arb + other,
            sandwich_count: sandwich,
            arb_count: arb,
            other_mev_count: other,
            mev_extracted_usd: 0.0,
        }
    }

    #[test]
    fn shares_sum_to_one_per_mev_type() {
        let stats = derive_relay_shares(vec![
            agg("flashbots", 30, 10, 0),
            agg("ultrasound", 10, 30, 5),
        ]);
        // sandwich: 30/40 and 10/40.
        assert!((stats[0].sandwich_share - 0.75).abs() < 1e-9);
        assert!((stats[1].sandwich_share - 0.25).abs() < 1e-9);
        // arb: 10/40 and 30/40.
        assert!((stats[0].arb_share - 0.25).abs() < 1e-9);
        assert!((stats[1].arb_share - 0.75).abs() < 1e-9);
        let sandwich_total: f64 = stats.iter().map(|s| s.sandwich_share).sum();
        assert!((sandwich_total - 1.0).abs() < 1e-9);
    }

    #[test]
    fn a_zero_total_yields_zero_shares_not_nan() {
        let stats = derive_relay_shares(vec![agg("flashbots", 0, 5, 0)]);
        assert_eq!(stats[0].sandwich_share, 0.0);
        assert!(stats[0].sandwich_share.is_finite());
        // The type that *did* occur is fully attributed to the sole relay.
        assert!((stats[0].arb_share - 1.0).abs() < 1e-9);
        assert_eq!(stats[0].other_mev_share, 0.0);
    }

    #[test]
    fn raw_counts_pass_through_unchanged() {
        let stats = derive_relay_shares(vec![agg("flashbots", 3, 2, 1)]);
        assert_eq!(stats[0].relay, "flashbots");
        assert_eq!(stats[0].sandwich_count, 3);
        assert_eq!(stats[0].arb_count, 2);
        assert_eq!(stats[0].other_mev_count, 1);
        assert_eq!(stats[0].blocks_delivered, 6);
    }

    #[test]
    fn empty_relay_set_is_empty() {
        assert!(derive_relay_shares(vec![]).is_empty());
    }

    #[test]
    fn limit_clamps_and_defaults() {
        assert_eq!(Limit::new(0).get(), Limit::DEFAULT); // unset → default
        assert_eq!(Limit::new(5).get(), 5); // in range → unchanged
        assert_eq!(Limit::new(10_000).get(), Limit::MAX); // over cap → clamped
    }
}
