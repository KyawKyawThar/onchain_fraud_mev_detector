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
    address_key, parse_address_key, AddressKeyError, AdjacencyEdge, EdgeKind, Neighborhood,
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
