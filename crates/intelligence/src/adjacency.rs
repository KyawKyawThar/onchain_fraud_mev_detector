//! The ClickHouse address-adjacency store (§8.2, §14): the full address graph
//! as append-only edge observations, read back as **degree-capped**
//! neighborhoods.
//!
//! The degree cap is §8.2's "critical" rule, enforced *in the store seam* so
//! no caller can forget it: [`AdjacencyStore::neighbors`] requires a cap and
//! reports whether it was hit ([`Neighborhood::capped`]), which a graph walk
//! must treat as "infrastructure endpoint — stop here". A CEX hot wallet,
//! bridge or router connects to millions of addresses; walking through one
//! collapses the graph into noise.
//!
//! Edges are directed facts (`src funded dst`); a *neighborhood* is the
//! undirected union of both directions, served index-first from the table's
//! `(chain, src, …)` ordering plus the `by_dst` projection.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use clickhouse::Client;
use events::primitives::{AccountAddress, Chain};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::config::ClickhouseConfig;
use crate::model::{
    address_key, parse_address_key, AddressEdge, AddressKeyError, AdjacencyEdge, EdgeHistory,
    EdgeKind, Neighborhood,
};

/// A failure appending to or querying the graph. ClickHouse faults are I/O —
/// always transient; a malformed stored address is permanent for that row.
#[derive(Debug, thiserror::Error)]
pub enum GraphError {
    #[error("clickhouse round-trip failed")]
    Clickhouse(#[from] clickhouse::error::Error),

    /// A stored address no longer parses. The row is bad; retrying re-reads
    /// the same bytes.
    #[error("stored value is malformed: {what}")]
    Malformed { what: String },
}

impl From<AddressKeyError> for GraphError {
    fn from(err: AddressKeyError) -> Self {
        GraphError::Malformed {
            what: err.to_string(),
        }
    }
}

impl event_bus::Transience for GraphError {
    /// Whether retrying could plausibly succeed — the shared retry/skip
    /// contract.
    fn is_transient(&self) -> bool {
        matches!(self, GraphError::Clickhouse(_))
    }
}

/// One slice of the address keyspace — how the §20.3 embedding sweep scales
/// horizontally.
///
/// The sweep carries in-process cursor state, so replicas cannot simply be
/// added: two of them would each walk the *whole* active set and do identical
/// work twice. A hash shard partitions the keyspace instead, with **no
/// coordination and no rebalancing protocol** — each replica is handed its
/// index and owns exactly the addresses that hash into it. `cityHash64` is
/// evaluated inside ClickHouse, so a shard reads only its own rows rather than
/// filtering someone else's in Rust.
///
/// Declaring this up front matters more than using it: retrofitting a shard
/// key onto a keyspace that is already being walked means a flag day, while an
/// unsharded deployment is just [`Shard::SINGLE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shard {
    index: u32,
    total: u32,
}

/// An out-of-range shard — a deployment misconfiguration, caught at boot
/// rather than as a silently empty sweep.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ShardError {
    #[error("shard total must be at least 1")]
    ZeroTotal,
    #[error("shard index {index} is outside 0..{total}")]
    IndexOutOfRange { index: u32, total: u32 },
}

impl Shard {
    /// The whole keyspace — an unsharded deployment.
    pub const SINGLE: Shard = Shard { index: 0, total: 1 };

    /// Parse, don't validate: an out-of-range shard cannot be constructed, so
    /// no read has to re-check it. An index at or past `total` would select
    /// nothing at all — a deployment that silently embeds no addresses, which
    /// is the failure this rejects at boot.
    pub fn new(index: u32, total: u32) -> Result<Self, ShardError> {
        if total == 0 {
            return Err(ShardError::ZeroTotal);
        }
        if index >= total {
            return Err(ShardError::IndexOutOfRange { index, total });
        }
        Ok(Self { index, total })
    }

    pub fn index(self) -> u32 {
        self.index
    }

    pub fn total(self) -> u32 {
        self.total
    }

    /// Whether this shard covers the whole keyspace (so a read can skip the
    /// predicate entirely).
    pub fn is_single(self) -> bool {
        self.total == 1
    }

    /// The SQL predicate selecting this shard's slice of `column`, or an
    /// always-true clause for [`Self::SINGLE`]. Both operands are integers we
    /// constructed, so there is no injection surface.
    fn predicate(self, column: &str) -> String {
        if self.is_single() {
            "1".to_owned()
        } else {
            format!("cityHash64({column}) % {} = {}", self.total, self.index)
        }
    }
}

impl Default for Shard {
    fn default() -> Self {
        Self::SINGLE
    }
}

impl std::fmt::Display for Shard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.index, self.total)
    }
}

/// The append-only graph seam. Object-safe; production is
/// [`ClickhouseAdjacency`], tests use the in-memory double in
/// [`crate::test_util`].
#[async_trait]
pub trait AdjacencyStore: Send + Sync {
    /// Append edge observations (immutable; duplicates are harmless extra
    /// rows the `DISTINCT` reads collapse).
    async fn append(&self, edges: &[AdjacencyEdge]) -> Result<(), GraphError>;

    /// The distinct neighbors of `address` in either direction, degree-capped:
    /// at most `cap` neighbors are returned and [`Neighborhood::capped`] says
    /// whether more exist (§8.2 — a capped node is a walk boundary, not a
    /// recursion point). Deterministic order (sorted by address).
    async fn neighbors(
        &self,
        chain: Chain,
        address: &AccountAddress,
        cap: u32,
    ) -> Result<Neighborhood, GraphError>;

    /// The degree-capped neighborhoods of *many* addresses at once — the
    /// batched form of [`Self::neighbors`] the entity-graph walk (§8.2/§11)
    /// uses to expand a whole BFS frontier in one round-trip instead of one
    /// query per node. Returns exactly one [`Neighborhood`] per input address
    /// (an address with no edges maps to an empty, un-capped neighborhood), so
    /// the caller can look up each frontier node unconditionally.
    ///
    /// The default loops [`Self::neighbors`] (correct, but N round-trips) so a
    /// double or a future backend gets a working implementation for free; the
    /// ClickHouse impl overrides it with a single `LIMIT … BY source` query,
    /// which is the whole point on the hot read path.
    async fn neighbors_many(
        &self,
        chain: Chain,
        addresses: &[AccountAddress],
        cap: u32,
    ) -> Result<std::collections::HashMap<AccountAddress, Neighborhood>, GraphError> {
        let mut out = std::collections::HashMap::with_capacity(addresses.len());
        for address in addresses {
            out.insert(*address, self.neighbors(chain, address, cap).await?);
        }
        Ok(out)
    }

    /// The exact distinct-neighbor count — the hub-ness measure (metrics,
    /// hub-labeling); the walk itself only needs [`Self::neighbors`].
    async fn degree(&self, chain: Chain, address: &AccountAddress) -> Result<u64, GraphError>;

    /// Like [`Self::neighbors`], but restricted to the given edge kinds — the
    /// entity-clustering walk (§8.2) only trusts a subset of the recorded
    /// facts (funder/deployer/profit-receiver/code-hash; `Interacted` is too
    /// weak a signal for identity). The cap is still evaluated against the
    /// *filtered* count: a CEX hot wallet is a hub through `Funded` edges
    /// alone, so filtering first and capping second is what keeps it a stop
    /// signal rather than a bridge.
    async fn clustering_neighbors(
        &self,
        chain: Chain,
        address: &AccountAddress,
        kinds: &[EdgeKind],
        cap: u32,
    ) -> Result<Neighborhood, GraphError>;

    /// The address's own observations — both directions, resolved into
    /// subject-relative [`AddressEdge`]s — most recent first, capped at `cap`
    /// rows ([`EdgeHistory::truncated`] says the cap was hit). The §20.3
    /// behavior embedding reads exactly this.
    ///
    /// Where [`Self::neighbors`] answers "who", this answers "what, in which
    /// direction, and when" — cadence and flow shape are properties of the
    /// *observations*, not of the distinct neighbor set, so collapsing to
    /// neighbors first would erase the signal.
    ///
    /// Redelivered appends are collapsed (the store is append-only and a
    /// duplicated write is a legal extra row): an observation is distinct by
    /// its full `(counterparty, kind, direction, evidence, block, time)`
    /// tuple, so two genuine interactions in different transactions stay two
    /// rows while a re-appended one stays one.
    async fn edge_history(
        &self,
        chain: Chain,
        address: &AccountAddress,
        cap: u32,
    ) -> Result<EdgeHistory, GraphError>;

    /// The capped observation histories of *many* addresses at once — the
    /// batched form of [`Self::edge_history`], and the read the embedding
    /// sweep actually issues.
    ///
    /// The sweep processes a *page* of addresses, so one query per address is
    /// a round trip per address on the hot path of the largest job this
    /// service runs. The default loops (correct, N round trips) so a double
    /// gets a working implementation for free; the ClickHouse impl overrides
    /// it with a single `LIMIT cap BY subject` query — exactly the shape
    /// [`Self::neighbors_many`] already uses for the entity-graph frontier.
    ///
    /// Returns one entry per input address (an address with no observations
    /// maps to an empty, un-truncated history), so a caller can look each up
    /// unconditionally.
    async fn edge_history_many(
        &self,
        chain: Chain,
        addresses: &[AccountAddress],
        cap: u32,
    ) -> Result<std::collections::HashMap<AccountAddress, EdgeHistory>, GraphError> {
        let mut out = std::collections::HashMap::with_capacity(addresses.len());
        for address in addresses {
            out.insert(*address, self.edge_history(chain, address, cap).await?);
        }
        Ok(out)
    }

    /// Addresses with at least one observation at/after `since`, in ascending
    /// address order, starting strictly after `after` — the paged candidate
    /// list the scheduled embedding sweep walks.
    ///
    /// Cursor-paged rather than offset-paged so a sweep that runs out of
    /// budget resumes where it stopped instead of re-reading the same prefix
    /// forever (the starvation this shape exists to prevent); `limit` bounds
    /// each page, and the caller bounds how many pages one tick takes.
    ///
    /// `shard` restricts the page to one slice of the keyspace so several
    /// sweep replicas can walk disjoint sets with no coordination; an
    /// unsharded deployment passes [`Shard::SINGLE`].
    async fn active_addresses(
        &self,
        chain: Chain,
        since: DateTime<Utc>,
        after: Option<AccountAddress>,
        limit: u32,
        shard: Shard,
    ) -> Result<Vec<AccountAddress>, GraphError>;
}

/// One stored edge row. Field order mirrors the `address_adjacency` columns;
/// `ingested_at` is intentionally absent (ClickHouse fills its `DEFAULT`).
#[derive(Debug, Clone, PartialEq, Eq, clickhouse::Row, Serialize, Deserialize)]
pub struct EdgeRow {
    pub chain: u64,
    pub src: String,
    pub dst: String,
    pub kind: String,
    pub evidence: String,
    pub block_number: u64,
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    pub observed_at: DateTime<Utc>,
}

impl EdgeRow {
    /// Total mapping from the domain edge — nothing here can fail.
    pub fn from_edge(edge: &AdjacencyEdge) -> Self {
        Self {
            chain: edge.chain.id(),
            src: address_key(&edge.src),
            dst: address_key(&edge.dst),
            kind: <&str>::from(edge.kind).to_owned(),
            evidence: edge.evidence.clone(),
            block_number: edge.block_number,
            observed_at: edge.observed_at,
        }
    }
}

/// One `(source, neighbor)` pair from the batched [`ClickhouseAdjacency::neighbors_many`]
/// read — the flat shape ClickHouse returns before it's grouped by source.
#[derive(Debug, clickhouse::Row, Deserialize)]
struct NeighborRow {
    source: String,
    neighbor: String,
}

/// One observation from [`ClickhouseAdjacency::edge_history`], already
/// resolved to the subject's point of view by the query's `1 AS outbound` /
/// `0 AS outbound` projection.
#[derive(Debug, clickhouse::Row, Deserialize)]
struct EdgeHistoryRow {
    counterparty: String,
    kind: String,
    outbound: u8,
    block_number: u64,
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    observed_at: DateTime<Utc>,
}

/// One observation from the *batched* history read, carrying which subject it
/// belongs to so the flat result can be grouped.
#[derive(Debug, clickhouse::Row, Deserialize)]
struct SubjectEdgeRow {
    subject: String,
    counterparty: String,
    kind: String,
    outbound: u8,
    block_number: u64,
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    observed_at: DateTime<Utc>,
}

impl TryFrom<EdgeHistoryRow> for AddressEdge {
    type Error = GraphError;

    /// Fallible in exactly the two ways a stored row can be corrupt: an
    /// address that no longer parses, and a `kind` outside the closed enum
    /// (a row written by a build that knew a variant this one doesn't).
    fn try_from(row: EdgeHistoryRow) -> Result<Self, GraphError> {
        Ok(AddressEdge {
            counterparty: parse_address_key(&row.counterparty)?,
            kind: row.kind.parse().map_err(|_| GraphError::Malformed {
                what: format!("edge kind {:?} is not a known EdgeKind", row.kind),
            })?,
            outbound: row.outbound != 0,
            block_number: row.block_number,
            observed_at: row.observed_at,
        })
    }
}

/// Both directions of a neighborhood, as one indexed subquery: the outbound
/// half rides the table ORDER BY, the inbound half the `by_dst` projection.
const NEIGHBOR_SET_SQL: &str = "\
    SELECT dst AS neighbor FROM address_adjacency WHERE chain = ? AND src = ? \
    UNION DISTINCT \
    SELECT src AS neighbor FROM address_adjacency WHERE chain = ? AND dst = ?";

/// ClickHouse-backed [`AdjacencyStore`]. Cheap to clone (the client is
/// `Arc`-cheap).
#[derive(Clone)]
pub struct ClickhouseAdjacency {
    client: Client,
}

impl ClickhouseAdjacency {
    /// Wrap a ClickHouse client (see [`build_clickhouse_client`]).
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Liveness probe for boot-time fail-fast, mirroring the event store's.
    pub async fn ping(&self) -> Result<(), GraphError> {
        let _: u8 = self.client.query("SELECT 1").fetch_one().await?;
        Ok(())
    }
}

#[async_trait]
impl AdjacencyStore for ClickhouseAdjacency {
    async fn append(&self, edges: &[AdjacencyEdge]) -> Result<(), GraphError> {
        if edges.is_empty() {
            return Ok(());
        }
        let mut insert = self.client.insert::<EdgeRow>("address_adjacency").await?;
        for edge in edges {
            insert.write(&EdgeRow::from_edge(edge)).await?;
        }
        insert.end().await?;
        Ok(())
    }

    async fn neighbors(
        &self,
        chain: Chain,
        address: &AccountAddress,
        cap: u32,
    ) -> Result<Neighborhood, GraphError> {
        let key = address_key(address);
        // Fetch cap+1 so "there was more" is observable without a second
        // (count) query; ORDER BY makes both the result and *which* neighbors
        // survive the cap deterministic.
        let rows: Vec<String> = self
            .client
            .query(&format!(
                "SELECT neighbor FROM ({NEIGHBOR_SET_SQL}) ORDER BY neighbor LIMIT ?"
            ))
            .bind(chain.id())
            .bind(&key)
            .bind(chain.id())
            .bind(&key)
            .bind(u64::from(cap) + 1)
            .fetch_all()
            .await?;

        let capped = rows.len() > cap as usize;
        rows.into_iter()
            .take(cap as usize)
            .map(|raw| Ok(parse_address_key(&raw)?))
            .collect::<Result<Vec<_>, GraphError>>()
            .map(|neighbors| Neighborhood { neighbors, capped })
    }

    async fn neighbors_many(
        &self,
        chain: Chain,
        addresses: &[AccountAddress],
        cap: u32,
    ) -> Result<std::collections::HashMap<AccountAddress, Neighborhood>, GraphError> {
        use std::collections::HashMap;

        if addresses.is_empty() {
            return Ok(HashMap::new());
        }

        // Frontier addresses are canonical lowercase 0x-hex — produced by
        // `address_key`/`parse_address_key`, never user free-text — so inlining
        // them as an `IN (…)` list is injection-safe, exactly the stance
        // `clustering_neighbors` takes for its kind list. The `?` binds stay
        // reserved for `chain`. `cap + 1` per source is an integer literal (no
        // injection surface) so "there was more" stays observable per node
        // without a second count query, the same trick single `neighbors` uses.
        let keys: Vec<String> = addresses.iter().map(address_key).collect();
        let in_list = keys
            .iter()
            .map(|k| format!("'{k}'"))
            .collect::<Vec<_>>()
            .join(",");
        let per_source = u64::from(cap) + 1;
        let sql = format!(
            "SELECT source, neighbor FROM ( \
                SELECT src AS source, dst AS neighbor FROM address_adjacency \
                  WHERE chain = ? AND src IN ({in_list}) \
                UNION DISTINCT \
                SELECT dst AS source, src AS neighbor FROM address_adjacency \
                  WHERE chain = ? AND dst IN ({in_list}) \
             ) ORDER BY source, neighbor LIMIT {per_source} BY source"
        );

        let rows: Vec<NeighborRow> = self
            .client
            .query(&sql)
            .bind(chain.id())
            .bind(chain.id())
            .fetch_all()
            .await?;

        // Group the flat (source, neighbor) rows by source. Order is preserved
        // per source (the query's `ORDER BY source, neighbor`), so the cap
        // selects a deterministic prefix.
        let mut grouped: HashMap<String, Vec<String>> = HashMap::new();
        for row in rows {
            grouped.entry(row.source).or_default().push(row.neighbor);
        }

        // One neighborhood per *input* address, whether or not it had any rows.
        let mut out = HashMap::with_capacity(addresses.len());
        for (address, key) in addresses.iter().zip(keys.iter()) {
            let raw = grouped.remove(key).unwrap_or_default();
            let capped = raw.len() as u64 > u64::from(cap);
            let neighbors = raw
                .into_iter()
                .take(cap as usize)
                .map(|raw| Ok(parse_address_key(&raw)?))
                .collect::<Result<Vec<_>, GraphError>>()?;
            out.insert(*address, Neighborhood { neighbors, capped });
        }
        Ok(out)
    }

    async fn degree(&self, chain: Chain, address: &AccountAddress) -> Result<u64, GraphError> {
        let key = address_key(address);
        let degree: u64 = self
            .client
            .query(&format!(
                "SELECT uniqExact(neighbor) FROM ({NEIGHBOR_SET_SQL})"
            ))
            .bind(chain.id())
            .bind(&key)
            .bind(chain.id())
            .bind(&key)
            .fetch_one()
            .await?;
        Ok(degree)
    }

    async fn clustering_neighbors(
        &self,
        chain: Chain,
        address: &AccountAddress,
        kinds: &[EdgeKind],
        cap: u32,
    ) -> Result<Neighborhood, GraphError> {
        let key = address_key(address);
        // `kinds` are our own closed-enum wire strings (never user input), so
        // baking them into the SQL text is safe — the crate's `?` binding is
        // reserved for the address/chain values below.
        let kind_list = kinds
            .iter()
            .map(|kind| format!("'{}'", <&str>::from(*kind)))
            .collect::<Vec<_>>()
            .join(",");
        let neighbor_set_sql = format!(
            "SELECT dst AS neighbor FROM address_adjacency \
             WHERE chain = ? AND src = ? AND kind IN ({kind_list}) \
             UNION DISTINCT \
             SELECT src AS neighbor FROM address_adjacency \
             WHERE chain = ? AND dst = ? AND kind IN ({kind_list})"
        );
        let rows: Vec<String> = self
            .client
            .query(&format!(
                "SELECT neighbor FROM ({neighbor_set_sql}) ORDER BY neighbor LIMIT ?"
            ))
            .bind(chain.id())
            .bind(&key)
            .bind(chain.id())
            .bind(&key)
            .bind(u64::from(cap) + 1)
            .fetch_all()
            .await?;

        let capped = rows.len() > cap as usize;
        rows.into_iter()
            .take(cap as usize)
            .map(|raw| Ok(parse_address_key(&raw)?))
            .collect::<Result<Vec<_>, GraphError>>()
            .map(|neighbors| Neighborhood { neighbors, capped })
    }

    async fn edge_history(
        &self,
        chain: Chain,
        address: &AccountAddress,
        cap: u32,
    ) -> Result<EdgeHistory, GraphError> {
        let key = address_key(address);
        // `DISTINCT` inside, projection outside: the distinctness that matters
        // is the *observation* (evidence included), while `evidence` itself is
        // not a feature, so it is selected only to make the de-duplication
        // right and dropped before it reaches the caller.
        //
        // `cap + 1` rows so "there was more" is observable without a second
        // count query (the same trick `neighbors` uses), and the full ORDER BY
        // — down to the tie-breakers — makes *which* observations survive the
        // cap deterministic, which is what lets a truncated history still be a
        // well-defined recency window.
        let sql = format!(
            "SELECT counterparty, kind, outbound, block_number, observed_at FROM ( \
                SELECT DISTINCT dst AS counterparty, kind, 1 AS outbound, evidence, \
                       block_number, observed_at \
                  FROM address_adjacency WHERE chain = {chain} AND src = ? \
                UNION ALL \
                SELECT DISTINCT src AS counterparty, kind, 0 AS outbound, evidence, \
                       block_number, observed_at \
                  FROM address_adjacency WHERE chain = {chain} AND dst = ? \
             ) ORDER BY observed_at DESC, block_number DESC, counterparty ASC, \
                        kind ASC, outbound DESC \
               LIMIT ?",
            chain = chain.id()
        );

        let rows: Vec<EdgeHistoryRow> = self
            .client
            .query(&sql)
            .bind(&key)
            .bind(&key)
            .bind(u64::from(cap) + 1)
            .fetch_all()
            .await?;

        let truncated = rows.len() > cap as usize;
        let edges = rows
            .into_iter()
            .take(cap as usize)
            .map(AddressEdge::try_from)
            .collect::<Result<Vec<_>, GraphError>>()?;
        Ok(EdgeHistory { edges, truncated })
    }

    async fn edge_history_many(
        &self,
        chain: Chain,
        addresses: &[AccountAddress],
        cap: u32,
    ) -> Result<std::collections::HashMap<AccountAddress, EdgeHistory>, GraphError> {
        use std::collections::HashMap;

        if addresses.is_empty() {
            return Ok(HashMap::new());
        }
        // Subject addresses are canonical lowercase 0x-hex produced by
        // `address_key` — never user free-text — so inlining them as an
        // `IN (...)` list is injection-safe, the same stance `neighbors_many`
        // takes. `LIMIT cap + 1 BY subject` keeps "there was more" observable
        // per subject without a second count query, and the full ORDER BY
        // makes *which* observations survive the cap deterministic per
        // subject — the property that lets a truncated history still be a
        // well-defined recency window.
        let keys: Vec<String> = addresses.iter().map(address_key).collect();
        let in_list = keys
            .iter()
            .map(|k| format!("'{k}'"))
            .collect::<Vec<_>>()
            .join(",");
        let per_subject = u64::from(cap) + 1;
        let sql = format!(
            "SELECT subject, counterparty, kind, outbound, block_number, observed_at FROM ( \
                SELECT DISTINCT src AS subject, dst AS counterparty, kind, 1 AS outbound, \
                       evidence, block_number, observed_at \
                  FROM address_adjacency WHERE chain = {chain} AND src IN ({in_list}) \
                UNION ALL \
                SELECT DISTINCT dst AS subject, src AS counterparty, kind, 0 AS outbound, \
                       evidence, block_number, observed_at \
                  FROM address_adjacency WHERE chain = {chain} AND dst IN ({in_list}) \
             ) ORDER BY subject, observed_at DESC, block_number DESC, counterparty ASC, \
                        kind ASC, outbound DESC \
               LIMIT {per_subject} BY subject",
            chain = chain.id()
        );

        let rows: Vec<SubjectEdgeRow> = self.client.query(&sql).fetch_all().await?;

        // Group the flat rows by subject; per-subject order is preserved by the
        // query's ORDER BY, so the cap selects a deterministic prefix.
        let mut grouped: HashMap<String, Vec<AddressEdge>> = HashMap::new();
        for row in rows {
            let subject = row.subject.clone();
            grouped.entry(subject).or_default().push(AddressEdge {
                counterparty: parse_address_key(&row.counterparty)?,
                kind: row.kind.parse().map_err(|_| GraphError::Malformed {
                    what: format!("edge kind {:?} is not a known EdgeKind", row.kind),
                })?,
                outbound: row.outbound != 0,
                block_number: row.block_number,
                observed_at: row.observed_at,
            });
        }

        // One history per *input* address, whether or not it had any rows.
        let mut out = HashMap::with_capacity(addresses.len());
        for (address, key) in addresses.iter().zip(keys.iter()) {
            let mut edges = grouped.remove(key).unwrap_or_default();
            let truncated = edges.len() as u64 > u64::from(cap);
            edges.truncate(cap as usize);
            out.insert(*address, EdgeHistory { edges, truncated });
        }
        Ok(out)
    }

    async fn active_addresses(
        &self,
        chain: Chain,
        since: DateTime<Utc>,
        after: Option<AccountAddress>,
        limit: u32,
        shard: Shard,
    ) -> Result<Vec<AccountAddress>, GraphError> {
        // The cursor is our own canonical lowercase 0x-hex (never user
        // free-text), so inlining it is injection-safe — the same stance
        // `neighbors_many` takes for its address `IN` list. An absent cursor
        // becomes `''`, which sorts below every real key, so the first page
        // needs no second query shape.
        let cursor = after.as_ref().map(address_key).unwrap_or_default();
        // The recency floor is bound as **epoch milliseconds** through
        // `fromUnixTimestamp64Milli`, not as a `DateTime<Utc>`: the crate would
        // serialize that through chrono's default `Serialize`, which is
        // RFC3339 (`…T…Z`) — a format ClickHouse's `DateTime64` literal parser
        // does not reliably accept. An integer has one interpretation.
        // The shard predicate is pushed into *both* branches rather than
        // filtered outside them: a replica must read only its own slice, not
        // read everyone's and discard.
        let sql = format!(
            "SELECT DISTINCT address FROM ( \
                SELECT src AS address FROM address_adjacency \
                  WHERE chain = {chain} AND observed_at >= fromUnixTimestamp64Milli(?) \
                    AND src > '{cursor}' AND {src_shard} \
                UNION DISTINCT \
                SELECT dst AS address FROM address_adjacency \
                  WHERE chain = {chain} AND observed_at >= fromUnixTimestamp64Milli(?) \
                    AND dst > '{cursor}' AND {dst_shard} \
             ) ORDER BY address LIMIT ?",
            chain = chain.id(),
            src_shard = shard.predicate("src"),
            dst_shard = shard.predicate("dst"),
        );

        let since_millis = since.timestamp_millis();
        let rows: Vec<String> = self
            .client
            .query(&sql)
            .bind(since_millis)
            .bind(since_millis)
            .bind(u64::from(limit))
            .fetch_all()
            .await?;

        rows.iter().map(|raw| Ok(parse_address_key(raw)?)).collect()
    }
}

/// Build the ClickHouse client from config. Does no I/O — the first real
/// connection happens on the first query. Mirrors event-store / simulation
/// (different services own different tables, so they share the shape, not the
/// code).
pub fn build_clickhouse_client(cfg: &ClickhouseConfig) -> Client {
    Client::default()
        .with_url(&cfg.url)
        .with_user(&cfg.user)
        .with_password(cfg.password.expose_secret())
        .with_database(&cfg.database)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EdgeKind;
    use alloy_primitives::Address;
    use event_bus::Transience;

    #[test]
    fn edge_row_mapping_is_total_and_lowercase() {
        let edge = AdjacencyEdge {
            chain: Chain::ETHEREUM,
            src: Address::repeat_byte(0xAA),
            dst: Address::repeat_byte(0xBB),
            kind: EdgeKind::Funded,
            evidence: "0xdeadbeef".into(),
            block_number: 123,
            observed_at: DateTime::<Utc>::from_timestamp(1_000, 0).unwrap(),
        };
        let row = EdgeRow::from_edge(&edge);
        assert_eq!(row.chain, 1);
        assert_eq!(row.src, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(row.dst, "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        assert_eq!(row.kind, "funded");
        assert_eq!(row.block_number, 123);
    }

    #[test]
    fn graph_error_classifies_transient_vs_permanent() {
        assert!(
            GraphError::Clickhouse(clickhouse::error::Error::Custom("io".into())).is_transient()
        );
        assert!(!GraphError::Malformed { what: "x".into() }.is_transient());
    }
}
